"""
pramagent.ratelimit
===================
Per-key token-bucket rate limiter for the HTTP service.

Default: in-process, thread-safe (InProcessBackend). For multi-worker
deployments pass a RedisBackend so rate limits are shared across instances::

    from pramagent.backends import RedisBackend
    from pramagent.ratelimit import TokenBucket

    limiter = TokenBucket(
        capacity=100,
        refill_per_sec=10,
        backend=RedisBackend.from_url(os.environ["REDIS_URL"]),
    )

Rate keys
---------
When auth is enabled the key is the tenant id. When auth is disabled the key
is the client IP. Both come from the FastAPI request via the dependency wired
in the app factory.
"""
from __future__ import annotations

from typing import Optional, Any


class TokenBucket:
    """Token-bucket rate limiter. Backend is pluggable (in-process or Redis)."""

    def __init__(
        self,
        capacity: int,
        refill_per_sec: float,
        backend: Optional[Any] = None,
    ) -> None:
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        if backend is None:
            from .backends import InProcessBackend
            backend = InProcessBackend()
        self._backend = backend

    def allow(self, key: str, cost: float = 1.0) -> tuple[bool, float]:
        """Consume cost tokens for key. Returns (allowed, retry_after_seconds)."""
        return self._backend.tb_allow(
            key,
            capacity=float(self.capacity),
            refill_per_sec=self.refill_per_sec,
            cost=cost,
        )


class AuthFailureGuard:
    """Escalating lockout on repeated invalid-credential attempts.

    Distinct from TokenBucket: a request-volume rate limit throttles requests
    whether they succeed or fail, so a credential-guessing attacker can spend
    an entire rate budget on invalid attempts and simply wait out the refill.
    This tracks only FAILURES, keyed by peer (typically client IP): once
    `threshold` failures land within `window_s` of each other, further
    attempts are rejected outright for an exponentially growing cooldown —
    independent of whatever capacity the request-rate bucket still has. A
    single success resets the counter for that key.

    Backend is pluggable (in-process or Redis), same as TokenBucket, so the
    lockout state is shared across replicas when a RedisBackend is configured
    — otherwise a distributed brute-force attempt spread across workers would
    never trip an in-process-only counter.
    """

    def __init__(
        self,
        threshold: int = 10,
        window_s: int = 300,
        base_lockout_s: float = 30.0,
        max_lockout_s: float = 900.0,
        backend: Optional[Any] = None,
    ) -> None:
        self.threshold = threshold
        self.window_s = window_s
        self.base_lockout_s = base_lockout_s
        self.max_lockout_s = max_lockout_s
        if backend is None:
            from .backends import InProcessBackend
            backend = InProcessBackend()
        self._backend = backend

    def locked_out(self, key: str) -> float:
        """Return an approximate remaining-lockout hint in seconds, or 0.0
        if not currently locked. The backend's own TTL is the actual source
        of truth for when the lock clears; the returned value approximates
        "seconds to wait" rather than tracking exact elapsed time, which is
        an acceptable trade for a security control (erring toward telling a
        caller to wait slightly longer, never shorter, is the safe
        direction)."""
        value = self._backend.get(f"authlock:{key}")
        return float(value) if value is not None else 0.0

    def record_failure(self, key: str) -> None:
        count = self._backend.increment(f"authfail:{key}", ttl_s=self.window_s)
        if count >= self.threshold:
            extra = count - self.threshold
            lockout_s = min(self.max_lockout_s, self.base_lockout_s * (2 ** extra))
            self._backend.set(f"authlock:{key}", lockout_s, ttl_s=int(lockout_s) + 1)

    def record_success(self, key: str) -> None:
        self._backend.delete(f"authfail:{key}")
        self._backend.delete(f"authlock:{key}")
