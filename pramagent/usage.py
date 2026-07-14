"""
pramagent.usage
===============
Per-tenant usage accounting and quota enforcement.

This is deliberately small and deterministic: it counts calls, tool validation
requests, and provider spend inside a rolling window. The tracker can use the
in-process store for tests/dev or any backend implementing get/set for shared
state in multi-worker deployments.
"""
from __future__ import annotations

import logging
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Callable, Optional

from .security import validate_http_url


log = logging.getLogger(__name__)


def _env_int_optional(*names: str) -> Optional[int]:
    for name in names:
        raw = os.environ.get(name)
        if raw is not None and raw.strip() != "":
            try:
                return int(raw)
            except ValueError:
                log.warning("invalid integer env %s=%r; ignoring", name, raw)
                return None
    return None


def _env_float_optional(*names: str) -> Optional[float]:
    for name in names:
        raw = os.environ.get(name)
        if raw is not None and raw.strip() != "":
            try:
                return float(raw)
            except ValueError:
                log.warning("invalid float env %s=%r; ignoring", name, raw)
                return None
    return None


def _env_str_optional(*names: str) -> str:
    for name in names:
        raw = os.environ.get(name)
        if raw is not None and raw.strip() != "":
            return raw.strip()
    return ""


@dataclass(frozen=True)
class UsageLimits:
    max_calls: Optional[int] = None
    max_tool_validations: Optional[int] = None
    max_cost_usd: Optional[float] = None
    window_s: int = 86_400

    @property
    def enabled(self) -> bool:
        return any(
            value is not None
            for value in (self.max_calls, self.max_tool_validations, self.max_cost_usd)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_calls": self.max_calls,
            "max_tool_validations": self.max_tool_validations,
            "max_cost_usd": self.max_cost_usd,
            "window_s": self.window_s,
        }


@dataclass(frozen=True)
class UsageSnapshot:
    tenant_id: str
    window_started_at: float
    window_ends_at: float
    calls: int = 0
    tool_validations: int = 0
    cost_usd: float = 0.0
    limits: UsageLimits = UsageLimits()

    def remaining_calls(self) -> Optional[int]:
        if self.limits.max_calls is None:
            return None
        return max(0, self.limits.max_calls - self.calls)

    def remaining_tool_validations(self) -> Optional[int]:
        if self.limits.max_tool_validations is None:
            return None
        return max(0, self.limits.max_tool_validations - self.tool_validations)

    def remaining_cost_usd(self) -> Optional[float]:
        if self.limits.max_cost_usd is None:
            return None
        return max(0.0, self.limits.max_cost_usd - self.cost_usd)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "window_started_at": self.window_started_at,
            "window_ends_at": self.window_ends_at,
            "calls": self.calls,
            "tool_validations": self.tool_validations,
            "cost_usd": self.cost_usd,
            "limits": self.limits.to_dict(),
            "remaining": {
                "calls": self.remaining_calls(),
                "tool_validations": self.remaining_tool_validations(),
                "cost_usd": self.remaining_cost_usd(),
            },
        }


@dataclass(frozen=True)
class UsageDecision:
    allowed: bool
    reason: str = ""
    retry_after_s: float = 0.0
    snapshot: Optional[UsageSnapshot] = None


PendingUsageEvent = tuple[str, str, float, UsageSnapshot, dict[str, Any]]


@dataclass(frozen=True)
class UsageEvent:
    event_type: str
    tenant_id: str
    amount: float
    created_at: float
    snapshot: UsageSnapshot
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "tenant_id": self.tenant_id,
            "amount": self.amount,
            "created_at": self.created_at,
            "snapshot": self.snapshot.to_dict(),
            "metadata": dict(self.metadata),
        }


class UsageEventSink:
    """Interface for analytics/billing hooks."""

    def emit(self, event: UsageEvent) -> None:
        raise NotImplementedError


@dataclass(frozen=True)
class UsageLedgerEntry:
    """Append-only usage ledger entry with a local hash chain."""

    sequence: int
    event: UsageEvent
    prev_hash: str
    this_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "event": self.event.to_dict(),
            "prev_hash": self.prev_hash,
            "this_hash": self.this_hash,
        }


class InMemoryUsageLedger(UsageEventSink):
    """Append-only usage ledger for billing/metering pilots.

    This is not a billing provider. It gives deployments a deterministic,
    tamper-evident local ledger that can be mirrored to Stripe/Chargebee or a
    warehouse by another sink.

    GROWTH CAP (P2-2): the ledger is deliberately NOT silently truncated — a
    hash-chained ledger that drops its oldest links can no longer verify from
    genesis, which would defeat its purpose as billing evidence. Instead a
    warning is logged once when entries exceed WARN_ENTRIES (~tens of MB of
    RAM). In-memory storage is a pilot tool: long-lived production processes
    must mirror events to a durable sink (webhook/warehouse) and restart the
    ledger on rotation, or back it with a persistent store.
    """

    GENESIS_HASH = "0" * 64
    WARN_ENTRIES = 100_000

    def __init__(self) -> None:
        self._entries: list[UsageLedgerEntry] = []
        self._lock = Lock()
        self._warned = False

    def emit(self, event: UsageEvent) -> None:
        with self._lock:
            prev_hash = self._entries[-1].this_hash if self._entries else self.GENESIS_HASH
            sequence = len(self._entries) + 1
            this_hash = self._hash(sequence, prev_hash, event)
            self._entries.append(
                UsageLedgerEntry(
                    sequence=sequence,
                    event=event,
                    prev_hash=prev_hash,
                    this_hash=this_hash,
                )
            )
            if not self._warned and len(self._entries) > self.WARN_ENTRIES:
                self._warned = True
                log.warning(
                    "InMemoryUsageLedger exceeds %d entries and grows without "
                    "bound; mirror to a durable sink and rotate the process, "
                    "or back the ledger with persistent storage",
                    self.WARN_ENTRIES)

    def entries(
        self,
        *,
        tenant_id: str = "",
        limit: int = 100,
    ) -> list[UsageLedgerEntry]:
        with self._lock:
            rows = list(self._entries)
        if tenant_id:
            rows = [row for row in rows if row.event.tenant_id == tenant_id]
        return rows[-max(1, limit):]

    def verify_chain(self) -> bool:
        with self._lock:
            entries = list(self._entries)
        prev_hash = self.GENESIS_HASH
        for expected_sequence, entry in enumerate(entries, start=1):
            if entry.sequence != expected_sequence:
                return False
            if entry.prev_hash != prev_hash:
                return False
            if entry.this_hash != self._hash(entry.sequence, entry.prev_hash, entry.event):
                return False
            prev_hash = entry.this_hash
        return True

    def to_dict(
        self,
        *,
        tenant_id: str = "",
        limit: int = 100,
    ) -> dict[str, Any]:
        rows = self.entries(tenant_id=tenant_id, limit=limit)
        return {
            "ledger_type": "in_memory_hash_chain",
            "chain_valid": self.verify_chain(),
            "entries": [row.to_dict() for row in rows],
        }

    @staticmethod
    def _hash(sequence: int, prev_hash: str, event: UsageEvent) -> str:
        payload = {
            "sequence": sequence,
            "prev_hash": prev_hash,
            "event": event.to_dict(),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class InMemoryUsageSink(UsageEventSink):
    """Test/dev sink that keeps emitted usage events in memory."""

    def __init__(self) -> None:
        self.events: list[UsageEvent] = []

    def emit(self, event: UsageEvent) -> None:
        self.events.append(event)


class WebhookUsageSink(UsageEventSink):
    """Best-effort JSON webhook for billing/analytics ingestion.

    This is intentionally fail-open: billing outage must not break the trust
    pipeline. Production deployments should put a durable queue in front of the
    actual billing provider.
    """

    def __init__(
        self,
        url: str,
        *,
        secret: str = "",
        timeout_s: float = 2.0,
    ) -> None:
        self.url = validate_http_url(
            url,
            allow_http_localhost=True,
            context="billing webhook URL",
        )
        self.secret = secret
        self.timeout_s = timeout_s

    def emit(self, event: UsageEvent) -> None:
        data = json.dumps(event.to_dict(), sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.secret:
            headers["X-Pramagent-Billing-Secret"] = self.secret
        req = urllib.request.Request(
            self.url,
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            # Billing webhook URL is validated in __init__.
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:  # nosec B310
                if resp.status >= 400:
                    log.warning("billing webhook returned HTTP %s", resp.status)
        except (urllib.error.URLError, TimeoutError) as exc:
            log.warning("billing webhook failed open: %s", exc)


class UsageTracker:
    """Windowed per-tenant usage tracker.

    Limits are disabled by default. Set any max value to enforce that quota.
    Backend errors fail open by default so a quota store outage does not become
    a production outage; set fail_open=False (or PRAMAGENT_QUOTA_FAIL_OPEN=0)
    for stricter deployments.

    This default is intentionally the opposite of RedisBackend's rate limiter
    (fail_open=False there — see redis_backend.py). The two controls guard
    against different failure modes: a rate limiter that stops limiting
    during an outage exposes the service to unbounded, unauthenticated abuse
    from any caller — a security concern. A quota tracker that stops
    enforcing during an outage only risks a tenant's own call/cost budget
    overrunning its configured cap for the duration of that outage — a
    self-inflicted billing/availability trade-off, not an attacker-facing
    one. Prioritizing availability here (don't let a quota-store blip 429
    every tenant) over strict spend enforcement is a deliberate choice, not
    an oversight; set PRAMAGENT_QUOTA_FAIL_OPEN=0 if a deployment's cost
    controls need to be strict even at the expense of availability during a
    quota-backend outage (ISSUE-9).
    """

    def __init__(
        self,
        limits: Optional[UsageLimits] = None,
        *,
        backend: Optional[Any] = None,
        namespace: str = "pramagent:usage",
        now_fn: Optional[Callable[[], float]] = None,
        fail_open: bool = True,
        event_sinks: Optional[list[UsageEventSink]] = None,
        ledger: Optional[InMemoryUsageLedger] = None,
    ) -> None:
        self.limits = limits or UsageLimits()
        self.backend = backend
        self.namespace = namespace
        self.now_fn = now_fn or time.time
        self.fail_open = fail_open
        self.ledger = ledger
        self.event_sinks = list(event_sinks or [])
        if self.ledger is not None:
            self.event_sinks.insert(0, self.ledger)
        self._local: dict[str, dict[str, Any]] = {}
        self._lock = Lock()

    @classmethod
    def from_env(cls, *, backend: Optional[Any] = None) -> "UsageTracker":
        limits = UsageLimits(
            max_calls=_env_int_optional("PRAMAGENT_QUOTA_CALLS"),
            max_tool_validations=_env_int_optional("PRAMAGENT_QUOTA_TOOL_VALIDATIONS"),
            max_cost_usd=_env_float_optional("PRAMAGENT_QUOTA_COST_USD"),
            window_s=_env_int_optional("PRAMAGENT_QUOTA_WINDOW_S") or 86_400,
        )
        fail_open_raw = os.environ.get("PRAMAGENT_QUOTA_FAIL_OPEN", "true").lower()
        fail_open = fail_open_raw not in {"0", "false", "no", "off"}
        sinks: list[UsageEventSink] = []
        webhook_url = _env_str_optional("PRAMAGENT_BILLING_WEBHOOK_URL")
        if webhook_url:
            sinks.append(
                WebhookUsageSink(
                    webhook_url,
                    secret=_env_str_optional("PRAMAGENT_BILLING_WEBHOOK_SECRET"),
                    timeout_s=_env_float_optional(
                        "PRAMAGENT_BILLING_WEBHOOK_TIMEOUT_S") or 2.0,
                )
            )
        ledger = None
        ledger_mode = _env_str_optional(
            "PRAMAGENT_USAGE_LEDGER",
            "PRAMAGENT_BILLING_LEDGER",   # legacy alias
        ).lower()
        if ledger_mode in {"1", "true", "yes", "on", "memory", "in-memory", "hash-chain"}:
            ledger = InMemoryUsageLedger()
        return cls(
            limits=limits,
            backend=backend,
            fail_open=fail_open,
            event_sinks=sinks,
            ledger=ledger,
        )

    @property
    def enabled(self) -> bool:
        return self.limits.enabled

    def reserve_call(self, tenant_id: str) -> UsageDecision:
        return self._reserve(tenant_id, call_delta=1, event_type="call_reserved")

    def reserve_tool_validation(self, tenant_id: str) -> UsageDecision:
        return self._reserve(
            tenant_id,
            tool_delta=1,
            event_type="tool_validation_reserved",
        )

    def record_cost(self, tenant_id: str, cost_usd: float) -> UsageDecision:
        if cost_usd <= 0:
            return UsageDecision(True, snapshot=self.snapshot(tenant_id))
        return self._reserve(
            tenant_id,
            cost_delta=float(cost_usd),
            enforce_before=False,
            event_type="cost_recorded",
            event_amount=float(cost_usd),
        )

    def snapshot(self, tenant_id: str) -> UsageSnapshot:
        state = self._load_state(tenant_id)
        return self._snapshot(tenant_id, state)

    def ledger_report(self, *, tenant_id: str = "", limit: int = 100) -> dict[str, Any]:
        if self.ledger is None:
            return {
                "ledger_type": "none",
                "chain_valid": True,
                "entries": [],
            }
        return self.ledger.to_dict(tenant_id=tenant_id, limit=limit)

    def _reserve(
        self,
        tenant_id: str,
        *,
        call_delta: int = 0,
        tool_delta: int = 0,
        cost_delta: float = 0.0,
        enforce_before: bool = True,
        event_type: str = "",
        event_amount: Optional[float] = None,
    ) -> UsageDecision:
        if not self.enabled and not self.event_sinks:
            return UsageDecision(True, snapshot=self.snapshot(tenant_id))

        pending_event: Optional[PendingUsageEvent] = None
        try:
            with self._lock:
                state = self._load_state(tenant_id)
                snap = self._snapshot(tenant_id, state)
                reason = self._quota_reason(
                    snap,
                    call_delta=call_delta if enforce_before else 0,
                    tool_delta=tool_delta if enforce_before else 0,
                    cost_delta=cost_delta if enforce_before else 0.0,
                )
                if reason:
                    pending_event = (
                        "quota_blocked",
                        tenant_id,
                        0.0,
                        snap,
                        {"reason": reason},
                    )
                    decision = UsageDecision(
                        False,
                        reason=reason,
                        retry_after_s=max(0.0, snap.window_ends_at - self.now_fn()),
                        snapshot=snap,
                    )
                else:
                    state["calls"] = int(state.get("calls", 0)) + call_delta
                    state["tool_validations"] = int(
                        state.get("tool_validations", 0)
                    ) + tool_delta
                    state["cost_usd"] = float(state.get("cost_usd", 0.0)) + cost_delta
                    self._save_state(tenant_id, state)
                    snap = self._snapshot(tenant_id, state)
                    if event_type:
                        amount = event_amount
                        if amount is None:
                            amount = float(call_delta or tool_delta or cost_delta)
                        pending_event = (event_type, tenant_id, amount, snap, {})
                    decision = UsageDecision(True, snapshot=snap)
            if pending_event:
                self._emit_event_tuple(pending_event)
            return decision
        except Exception as exc:
            if self.fail_open:
                log.warning("usage tracker failed open for tenant=%s: %s", tenant_id, exc)
                return UsageDecision(True, reason="usage tracker failed open")
            raise

    def _quota_reason(
        self,
        snap: UsageSnapshot,
        *,
        call_delta: int,
        tool_delta: int,
        cost_delta: float,
    ) -> str:
        if (
            self.limits.max_calls is not None
            and snap.calls + call_delta > self.limits.max_calls
        ):
            return f"tenant call quota exceeded: {snap.calls}/{self.limits.max_calls}"
        if (
            self.limits.max_tool_validations is not None
            and snap.tool_validations + tool_delta > self.limits.max_tool_validations
        ):
            return (
                "tenant tool-validation quota exceeded: "
                f"{snap.tool_validations}/{self.limits.max_tool_validations}"
            )
        if (
            self.limits.max_cost_usd is not None
            and snap.cost_usd + cost_delta > self.limits.max_cost_usd
        ):
            return (
                "tenant cost quota exceeded: "
                f"{snap.cost_usd:.6f}/{self.limits.max_cost_usd:.6f}"
            )
        return ""

    def _snapshot(self, tenant_id: str, state: dict[str, Any]) -> UsageSnapshot:
        started = float(state.get("window_started_at", self.now_fn()))
        return UsageSnapshot(
            tenant_id=tenant_id,
            window_started_at=started,
            window_ends_at=started + self.limits.window_s,
            calls=int(state.get("calls", 0)),
            tool_validations=int(state.get("tool_validations", 0)),
            cost_usd=float(state.get("cost_usd", 0.0)),
            limits=self.limits,
        )

    def _empty_state(self) -> dict[str, Any]:
        return {
            "window_started_at": self.now_fn(),
            "calls": 0,
            "tool_validations": 0,
            "cost_usd": 0.0,
        }

    def _load_state(self, tenant_id: str) -> dict[str, Any]:
        key = self._key(tenant_id)
        state = self.backend.get(key) if self.backend is not None else self._local.get(key)
        if not isinstance(state, dict):
            state = self._empty_state()
        started = float(state.get("window_started_at", self.now_fn()))
        if self.now_fn() - started >= self.limits.window_s:
            state = self._empty_state()
        return dict(state)

    def _save_state(self, tenant_id: str, state: dict[str, Any]) -> None:
        key = self._key(tenant_id)
        ttl = max(1, int(self.limits.window_s * 2))
        if self.backend is not None:
            self.backend.set(key, state, ttl_s=ttl)
        else:
            self._local[key] = dict(state)

    def _key(self, tenant_id: str) -> str:
        return f"{self.namespace}:{tenant_id or 'default'}"

    def _emit_event(
        self,
        event_type: str,
        tenant_id: str,
        *,
        amount: float,
        snapshot: UsageSnapshot,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        if not self.event_sinks:
            return
        event = UsageEvent(
            event_type=event_type,
            tenant_id=tenant_id,
            amount=amount,
            created_at=self.now_fn(),
            snapshot=snapshot,
            metadata=metadata or {},
        )
        for sink in self.event_sinks:
            try:
                sink.emit(event)
            except Exception as exc:
                log.warning("usage event sink failed open: %s", exc)
                if not self.fail_open:
                    raise

    def _emit_event_tuple(
        self,
        pending_event: PendingUsageEvent,
    ) -> None:
        event_type, tenant_id, amount, snapshot, metadata = pending_event
        self._emit_event(
            event_type,
            tenant_id,
            amount=amount,
            snapshot=snapshot,
            metadata=metadata,
        )
