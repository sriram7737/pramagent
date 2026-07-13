"""
pramagent.backends.redis_backend
=================================
Backend adapters for distributed state. Two implementations share one
interface (AbstractBackend) so layers can be written once and wired to either.

AbstractBackend
    Minimal KV + pub/sub contract. Only what the HITL registry, isolation
    memory, and rate limiter actually need — no leaky abstraction.

InProcessBackend  (default)
    Thread-safe in-process dict + asyncio.Event. Works for single-process
    deployments and all tests. Zero dependencies.

RedisBackend
    Redis-backed via the `redis` package (optional dep). Supports multi-worker
    / multi-instance deployments. Uses connection pooling, exponential backoff
    retry, and a circuit breaker so a Redis blip doesn't take the whole system
    down. Falls back gracefully — callers catch RedisUnavailable.

Why two classes instead of one with a feature flag?
    The Liskov substitution principle: swap the backend, behaviour is identical.
    A flag-guarded class adds an implicit contract violation that tests will
    miss. Two clean implementations are easier to audit.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import random
import time
from abc import ABC, abstractmethod
from threading import Lock
from typing import Any, Optional

log = logging.getLogger(__name__)


class RedisUnavailable(RuntimeError):
    """Raised when Redis is configured but unreachable."""


class BackendCircuitOpen(RuntimeError):
    """Raised when the backend circuit breaker has tripped."""


# ─────────────────────────────── interface ────────────────────────────────

class AbstractBackend(ABC):
    """Minimal distributed-state contract."""

    # ── KV store ──────────────────────────────────────────────────────────

    @abstractmethod
    def set(self, key: str, value: Any, *, ttl_s: Optional[int] = None) -> None:
        """Set a JSON-serialisable value, optionally with a TTL in seconds."""

    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Return the stored value, or None if missing / expired."""

    @abstractmethod
    def delete(self, key: str) -> None:
        """Remove a key (no-op if absent)."""

    @abstractmethod
    def increment(self, key: str, *, ttl_s: Optional[int] = None) -> int:
        """Atomically increment an integer counter and return the new value."""

    # ── token-bucket helpers ──────────────────────────────────────────────

    @abstractmethod
    def tb_allow(self, key: str, *, capacity: float,
                 refill_per_sec: float, cost: float = 1.0) -> tuple[bool, float]:
        """Consume `cost` tokens from a bucket identified by `key`.

        Returns (allowed, retry_after_seconds).
        The bucket is created on first access with `capacity` tokens.
        """

    # ── event / signalling ────────────────────────────────────────────────

    @abstractmethod
    def signal(self, key: str, value: Any) -> None:
        """Publish a signal on `key`. Waiters blocked in `wait()` are woken."""

    @abstractmethod
    async def wait(self, key: str, *, timeout_s: float) -> Optional[Any]:
        """Block until a signal arrives on `key` or `timeout_s` elapses.

        Returns the signalled value, or None on timeout.
        """

    # ── tenant memory (list) ──────────────────────────────────────────────

    @abstractmethod
    def memory_append(self, scope: str, item: str) -> None:
        """Append `item` to the memory list for `scope`."""

    @abstractmethod
    def memory_get(self, scope: str) -> list[str]:
        """Return the full memory list for `scope`."""

    @abstractmethod
    def memory_clear(self, scope: str) -> None:
        """Delete the memory list for `scope`."""


# ──────────────────────────── in-process ──────────────────────────────────

class InProcessBackend(AbstractBackend):
    """Thread-safe in-process implementation. Zero external dependencies."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[Any, Optional[float]]] = {}  # key -> (val, expires_at)
        self._lock = Lock()
        self._events: dict[str, asyncio.Event] = {}
        self._event_values: dict[str, Any] = {}

    # ── internal ──────────────────────────────────────────────────────────

    def _expired(self, expires_at: Optional[float]) -> bool:
        return expires_at is not None and time.monotonic() > expires_at

    def _get_raw(self, key: str) -> Optional[Any]:
        entry = self._store.get(key)
        if entry is None:
            return None
        val, exp = entry
        if self._expired(exp):
            del self._store[key]
            return None
        return val

    # ── KV ────────────────────────────────────────────────────────────────

    def set(self, key: str, value: Any, *, ttl_s: Optional[int] = None) -> None:
        exp = time.monotonic() + ttl_s if ttl_s else None
        with self._lock:
            self._store[key] = (value, exp)

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            return self._get_raw(key)

    def delete(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def increment(self, key: str, *, ttl_s: Optional[int] = None) -> int:
        with self._lock:
            current = self._get_raw(key) or 0
            new = int(current) + 1
            exp = time.monotonic() + ttl_s if ttl_s else None
            self._store[key] = (new, exp)
            return new

    def history_append(self, key: str, value: str, *, max_len: int,
                       ttl_s: Optional[int] = None) -> list[str]:
        """Atomically append to a bounded list and return the updated window."""
        with self._lock:
            lst = list(self._get_raw(key) or [])
            lst.append(value)
            lst = lst[-max_len:]
            exp = time.monotonic() + ttl_s if ttl_s else None
            self._store[key] = (lst, exp)
            return list(lst)

    # ── token bucket ──────────────────────────────────────────────────────

    def tb_allow(self, key: str, *, capacity: float,
                 refill_per_sec: float, cost: float = 1.0) -> tuple[bool, float]:
        now = time.monotonic()
        tb_key = f"__tb:{key}"
        with self._lock:
            entry = self._get_raw(tb_key)
            if entry is None:
                tokens, last = float(capacity), now
            else:
                tokens, last = entry
            tokens = min(capacity, tokens + (now - last) * refill_per_sec)
            if tokens >= cost:
                self._store[tb_key] = ((tokens - cost, now), None)
                return True, 0.0
            deficit = cost - tokens
            retry = deficit / refill_per_sec
            self._store[tb_key] = ((tokens, now), None)
            return False, retry

    # ── event ─────────────────────────────────────────────────────────────

    def signal(self, key: str, value: Any) -> None:
        with self._lock:
            self._event_values[key] = value
            ev = self._events.get(key)
        if ev is not None:
            ev.set()

    async def wait(self, key: str, *, timeout_s: float) -> Optional[Any]:
        with self._lock:
            # if already signalled, return immediately
            if key in self._event_values:
                val = self._event_values.pop(key)
                self._events.pop(key, None)
                return val
            ev = self._events.setdefault(key, asyncio.Event())
        try:
            await asyncio.wait_for(asyncio.shield(ev.wait()), timeout=timeout_s)
        except asyncio.TimeoutError:
            return None
        with self._lock:
            val = self._event_values.pop(key, None)
            self._events.pop(key, None)
        return val

    # ── memory ────────────────────────────────────────────────────────────

    def memory_append(self, scope: str, item: str) -> None:
        mkey = f"__mem:{scope}"
        with self._lock:
            lst = list(self._get_raw(mkey) or [])
            lst.append(item)
            self._store[mkey] = (lst, None)

    def memory_get(self, scope: str) -> list[str]:
        mkey = f"__mem:{scope}"
        with self._lock:
            return list(self._get_raw(mkey) or [])

    def memory_clear(self, scope: str) -> None:
        mkey = f"__mem:{scope}"
        with self._lock:
            self._store.pop(mkey, None)


# ──────────────────────────── retry helper ────────────────────────────────

def _retry_sync(fn, *, max_attempts: int = 3, base_delay_s: float = 0.1,
                max_delay_s: float = 2.0, exceptions=(Exception,)):
    """Run fn() with exponential backoff + jitter.  Returns fn() result."""
    for attempt in range(max_attempts):
        try:
            return fn()
        except exceptions as exc:
            if attempt == max_attempts - 1:
                raise
            # Retry jitter does not require cryptographic randomness.
            delay = min(base_delay_s * (2 ** attempt) + random.uniform(0, 0.05), max_delay_s)  # nosec B311
            log.warning("backend retry %d/%d after %.2fs: %s", attempt + 1, max_attempts, delay, exc)
            time.sleep(delay)


# ─────────────────────────── circuit breaker ──────────────────────────────

class _CircuitBreaker:
    """Simple half-open circuit breaker for backend calls.

    States: CLOSED (normal) → OPEN (tripped) → HALF_OPEN (probe) → CLOSED
    """
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(self, threshold: int = 5, cooldown_s: float = 30.0) -> None:
        self._threshold = threshold
        self._cooldown_s = cooldown_s
        self._failures = 0
        self._opened_at: Optional[float] = None
        self._state = self.CLOSED
        self._lock = Lock()

    @property
    def state(self) -> str:
        with self._lock:
            return self._effective_state()

    def _effective_state(self) -> str:
        if self._state == self.OPEN:
            if time.monotonic() - self._opened_at >= self._cooldown_s:
                return self.HALF_OPEN
        return self._state

    def allow(self) -> bool:
        with self._lock:
            st = self._effective_state()
            if st == self.OPEN:
                return False
            return True  # CLOSED or HALF_OPEN: let one through

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._state = self.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self._threshold:
                self._state = self.OPEN
                self._opened_at = time.monotonic()
                log.error("Backend circuit breaker OPENED after %d failures", self._failures)

    def __call__(self, fn):
        """Decorator: wrap a sync call with circuit-breaker protection."""
        def wrapper(*args, **kwargs):
            if not self.allow():
                raise BackendCircuitOpen("backend circuit breaker is open")
            try:
                result = fn(*args, **kwargs)
                self.record_success()
                return result
            except Exception:
                self.record_failure()
                raise
        return wrapper


# ──────────────────────────── Redis-backed ────────────────────────────────

class RedisBackend(AbstractBackend):
    """Redis-backed backend for multi-worker deployments.

    Requires: ``pip install redis``

    Features
    --------
    - Connection pooling (redis.ConnectionPool, max_connections configurable)
    - Exponential backoff retry on transient errors (up to max_retries attempts)
    - Circuit breaker: opens after `breaker_threshold` consecutive failures,
      cools down for `breaker_cooldown_s` seconds before allowing probes
    - Startup validation: ping() on construction, raises RedisUnavailable early
    - Pub/sub for event signalling uses a lightweight Redis key-poll approach
      (set key + asyncio.sleep loop) to avoid spawning a separate subscriber
      thread. For high-volume HITL approvals, swap to a proper Pub/Sub channel.
    """

    _POLL_INTERVAL_S = 0.25   # how often to check for an event in wait()

    def __init__(
        self,
        client: Any,
        *,
        max_retries: int = 3,
        base_delay_s: float = 0.1,
        breaker_threshold: int = 5,
        breaker_cooldown_s: float = 30.0,
        fail_open: bool = False,
    ) -> None:
        """Pass a connected ``redis.Redis`` client (pooled or plain)."""
        self._r = client
        self._max_retries = max_retries
        self._base_delay_s = base_delay_s
        # fail_open: see tb_allow() -- defaults to False (fail closed) since
        # a rate limiter that silently stops limiting during a Redis outage
        # is not actually a rate limiter at that moment. Pass True only if
        # an unmetered request burst during an outage is an acceptable
        # trade-off for your deployment.
        self._fail_open = fail_open
        self._breaker = _CircuitBreaker(
            threshold=breaker_threshold,
            cooldown_s=breaker_cooldown_s,
        )

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        max_connections: int = 10,
        max_retries: int = 3,
        base_delay_s: float = 0.1,
        breaker_threshold: int = 5,
        breaker_cooldown_s: float = 30.0,
        fail_open: bool = False,
        **kwargs: Any,
    ) -> "RedisBackend":
        """Convenience constructor with connection pooling.

        ``RedisBackend.from_url('redis://localhost:6379/0', max_connections=20)``
        """
        try:
            import redis  # type: ignore
        except ImportError as e:
            raise RedisUnavailable(
                "redis package not installed; run: pip install redis"
            ) from e
        pool = redis.ConnectionPool.from_url(
            url,
            max_connections=max_connections,
            decode_responses=True,
            **kwargs,
        )
        client = redis.Redis(connection_pool=pool)
        # Compose URLs embed the password (redis://:pw@host) — redact before
        # the URL reaches a log line or exception message (P2-7/T2-9).
        safe_url = url.split("@")[-1] if "@" in url else url
        try:
            client.ping()
        except Exception as e:
            raise RedisUnavailable(f"Redis not reachable at {safe_url}: {e}") from e
        log.info("RedisBackend connected: %s (pool max=%d)", safe_url, max_connections)
        return cls(
            client,
            max_retries=max_retries,
            base_delay_s=base_delay_s,
            breaker_threshold=breaker_threshold,
            breaker_cooldown_s=breaker_cooldown_s,
            fail_open=fail_open,
        )

    def _call(self, fn):
        """Execute fn() with circuit-breaker guard and retry."""
        if not self._breaker.allow():
            raise BackendCircuitOpen("Redis circuit breaker is open")
        try:
            result = _retry_sync(
                fn,
                max_attempts=self._max_retries,
                base_delay_s=self._base_delay_s,
            )
            self._breaker.record_success()
            return result
        except Exception:
            self._breaker.record_failure()
            raise

    # ── KV ────────────────────────────────────────────────────────────────

    def set(self, key: str, value: Any, *, ttl_s: Optional[int] = None) -> None:
        serialised = json.dumps(value)
        if ttl_s:
            self._call(lambda: self._r.setex(key, ttl_s, serialised))
        else:
            self._call(lambda: self._r.set(key, serialised))

    def get(self, key: str) -> Optional[Any]:
        raw = self._call(lambda: self._r.get(key))
        return json.loads(raw) if raw is not None else None

    def delete(self, key: str) -> None:
        self._call(lambda: self._r.delete(key))

    def increment(self, key: str, *, ttl_s: Optional[int] = None) -> int:
        def _incr():
            val = self._r.incr(key)
            if ttl_s and val == 1:
                # only set TTL on first creation so repeated increments don't reset it
                self._r.expire(key, ttl_s)
            return int(val)
        return self._call(_incr)

    # ── bounded list append (Lua script for atomicity) ────────────────────
    # RPUSH + LTRIM + EXPIRE in one atomic unit so concurrent same-session
    # appends from different workers never lose updates (ToolGuard chain
    # detection relies on this).

    _HISTORY_SCRIPT = """
local key     = KEYS[1]
local value   = ARGV[1]
local max_len = tonumber(ARGV[2])
local ttl     = tonumber(ARGV[3])

redis.call('RPUSH', key, value)
redis.call('LTRIM', key, -max_len, -1)
if ttl > 0 then
    redis.call('EXPIRE', key, ttl)
end
return redis.call('LRANGE', key, 0, -1)
"""

    def history_append(self, key: str, value: str, *, max_len: int,
                       ttl_s: Optional[int] = None) -> list[str]:
        """Atomically append to a bounded Redis list and return the window."""
        def _run():
            script = self._r.register_script(self._HISTORY_SCRIPT)
            return script(keys=[key], args=[value, int(max_len), int(ttl_s or 0)])
        return [str(item) for item in self._call(_run)]

    # ── token bucket (Lua script for atomicity) ───────────────────────────

    _TB_SCRIPT = """
local key      = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill   = tonumber(ARGV[2])
local cost     = tonumber(ARGV[3])
local now      = tonumber(ARGV[4])

local data = redis.call('HMGET', key, 'tokens', 'last')
local tokens = tonumber(data[1])
local last   = tonumber(data[2])

if tokens == nil then
    tokens = capacity
    last   = now
end

tokens = math.min(capacity, tokens + (now - last) * refill)

if tokens >= cost then
    redis.call('HMSET', key, 'tokens', tokens - cost, 'last', now)
    return {1, 0}
else
    local deficit = cost - tokens
    local retry   = deficit / refill
    redis.call('HMSET', key, 'tokens', tokens, 'last', now)
    return {0, retry * 1000}   -- retry in ms (returned as int)
end
"""

    def tb_allow(self, key: str, *, capacity: float,
                 refill_per_sec: float, cost: float = 1.0) -> tuple[bool, float]:
        tb_key = f"__tb:{key}"
        now = time.monotonic()
        try:
            def _run():
                script = self._r.register_script(self._TB_SCRIPT)
                return script(keys=[tb_key], args=[capacity, refill_per_sec, cost, now])
            result = self._call(_run)
            allowed, retry_ms = result
            return bool(allowed), float(retry_ms) / 1000.0
        except (BackendCircuitOpen, Exception):
            if self._fail_open:
                # Explicit opt-in only (see __init__): don't DoS ourselves
                # if Redis is down, at the cost of no rate limiting during
                # the outage.
                return True, 0.0
            # Fail closed by default -- see __init__.
            return False, 1.0

    # ── event (key-poll approach) ─────────────────────────────────────────

    def signal(self, key: str, value: Any) -> None:
        ev_key = f"__ev:{key}"
        self._call(lambda: self._r.setex(ev_key, 600, json.dumps(value)))

    async def wait(self, key: str, *, timeout_s: float) -> Optional[Any]:
        ev_key = f"__ev:{key}"
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                raw = await asyncio.to_thread(self._r.getdel, ev_key)
            except Exception:
                raw = None
            if raw is not None:
                return json.loads(raw)
            remaining = deadline - time.monotonic()
            await asyncio.sleep(min(self._POLL_INTERVAL_S, max(0, remaining)))
        return None

    # ── memory ────────────────────────────────────────────────────────────

    def memory_append(self, scope: str, item: str) -> None:
        self._call(lambda: self._r.rpush(f"__mem:{scope}", item))

    def memory_get(self, scope: str) -> list[str]:
        return self._call(lambda: self._r.lrange(f"__mem:{scope}", 0, -1))

    def memory_clear(self, scope: str) -> None:
        self._call(lambda: self._r.delete(f"__mem:{scope}"))

    # ── health ────────────────────────────────────────────────────────────

    def ping(self) -> bool:
        """Returns True if Redis is reachable, False otherwise."""
        try:
            self._r.ping()
            return True
        except Exception:
            return False

    @property
    def circuit_state(self) -> str:
        return self._breaker.state
