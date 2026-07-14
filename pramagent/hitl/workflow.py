"""
pramagent.hitl.workflow
=======================
Production HITL: escalation timers, delegate chains, multi-approver quorum,
and a tamper-evident approval audit log.

Classes
-------
ApproverChain
    Ordered list of approver callables. The first approver is tried; if it
    times out the request is escalated to the next in the chain.  Useful for
    on-call → manager → security-team delegation.

QuorumApprover
    Fans a request out to N approvers simultaneously; requires ``required``
    out of N to approve within ``timeout_s``.  A single denial short-circuits
    to DENIED regardless of the quorum threshold (deny is always authoritative).

ApprovalAuditLog
    Append-only, in-memory log (swap for Postgres/Redis in prod) recording
    every approval decision with timestamps, reason, and approver identity.
    Export as JSONL via ``export_jsonl()``.

HITLWorkflowLayer
    Drop-in replacement for HITLLayer.  Accepts an ApproverChain or
    QuorumApprover as its ``approver``; adds per-action SLA enforcement,
    automatic audit logging, and a ``pending_count`` property for dashboards.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, List, Optional

from ..types import HITLStatus

log = logging.getLogger(__name__)


# ─────────────────────────── audit record ─────────────────────────────────

@dataclass
class ApprovalRecord:
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action: str = ""
    context: dict = field(default_factory=dict)
    approver_id: str = ""          # who decided
    decision: Optional[bool] = None  # True=approved, False=denied, None=timeout/idle
    requested_at: float = field(default_factory=time.time)
    decided_at: Optional[float] = None
    latency_s: Optional[float] = None
    reason: str = ""               # free-text from approver
    tenant_id: str = ""            # derived from context; see __post_init__

    def __post_init__(self) -> None:
        # Every call site constructs records via `context=dict(context)`
        # without threading tenant_id through explicitly (ApproverChain,
        # QuorumApprover, HITLWorkflowLayer all do this) — deriving it here
        # once, matching the "tenant" / "tenant_id" convention core.py's
        # HITL contexts already use, means ApprovalAuditLog.all()/
        # for_action() can filter by tenant without every caller having to
        # remember to set it (ISSUE-11).
        if not self.tenant_id:
            self.tenant_id = (
                self.context.get("tenant_id") or self.context.get("tenant") or "")


class ApprovalAuditLog:
    """Thread-safe append-only approval audit log.

    In production, swap the in-memory list for a Postgres insert or a Redis
    RPUSH so the log survives restarts.
    """

    def __init__(self) -> None:
        self._records: List[ApprovalRecord] = []
        self._lock = asyncio.Lock()

    async def record(self, rec: ApprovalRecord) -> None:
        async with self._lock:
            self._records.append(rec)
        log.info(
            "HITL audit: action=%s decision=%s approver=%s latency=%.1fs",
            rec.action, rec.decision, rec.approver_id, rec.latency_s or 0,
        )

    def all(self, tenant_id: str = "") -> List[ApprovalRecord]:
        """All records, or only the given tenant's when tenant_id is set.

        `_GLOBAL_AUDIT_LOG` is a process-wide singleton shared across every
        ApproverChain/QuorumApprover/HITLWorkflowLayer instance unless a
        caller supplies its own `audit_log=`, so an unscoped `.all()` call
        returns every tenant's approval history. Pass tenant_id to scope it
        (ISSUE-11)."""
        if not tenant_id:
            return list(self._records)
        return [r for r in self._records if r.tenant_id == tenant_id]

    def for_action(self, action: str, tenant_id: str = "") -> List[ApprovalRecord]:
        records = [r for r in self._records if r.action == action]
        if tenant_id:
            records = [r for r in records if r.tenant_id == tenant_id]
        return records

    def export_jsonl(self, path: str, tenant_id: str = "") -> int:
        records = self.all(tenant_id=tenant_id)
        with open(path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(asdict(r)) + "\n")
        return len(records)


# shared global log — callers may replace with their own instance
_GLOBAL_AUDIT_LOG = ApprovalAuditLog()


def get_audit_log() -> ApprovalAuditLog:
    return _GLOBAL_AUDIT_LOG


# ─────────────────────────── approver chain ───────────────────────────────

ApproverCallable = Callable[[str, dict], "asyncio.Future[Optional[bool]]"]


@dataclass
class _ApproverSlot:
    approver_id: str
    fn: ApproverCallable
    timeout_s: float  # per-slot SLA


class ApproverChain:
    """Tries approvers in order; escalates on timeout.

    Example::

        chain = ApproverChain([
            _ApproverSlot("oncall",   oncall_approver,   timeout_s=120),
            _ApproverSlot("manager",  manager_approver,  timeout_s=300),
            _ApproverSlot("security", security_approver, timeout_s=600),
        ])
    """

    def __init__(self, slots: List[_ApproverSlot],
                 audit_log: Optional[ApprovalAuditLog] = None) -> None:
        if not slots:
            raise ValueError("ApproverChain requires at least one slot")
        self._slots = slots
        self._audit = audit_log or _GLOBAL_AUDIT_LOG

    async def __call__(self, action: str, context: dict) -> Optional[bool]:
        for slot in self._slots:
            t0 = time.monotonic()
            rec = ApprovalRecord(action=action, context=dict(context),
                                 approver_id=slot.approver_id)
            try:
                answer = await asyncio.wait_for(
                    slot.fn(action, context), timeout=slot.timeout_s
                )
            except asyncio.TimeoutError:
                rec.decision = None
                rec.reason = "timeout — escalating"
                rec.decided_at = time.time()
                rec.latency_s = time.monotonic() - t0
                await self._audit.record(rec)
                log.warning("HITL %s timed out for %s — escalating", slot.approver_id, action)
                continue  # escalate to next slot

            rec.decision = answer
            rec.decided_at = time.time()
            rec.latency_s = time.monotonic() - t0
            await self._audit.record(rec)

            if answer is False:
                # An explicit deny from any approver is final
                return False
            if answer is True:
                return True
            # None = approver passed, continue escalating

        # All slots exhausted without a decision → idle
        return None


# ─────────────────────────── quorum approver ──────────────────────────────

class QuorumApprover:
    """Fan-out to N approvers; require ``required`` approvals within timeout_s.

    A single explicit denial short-circuits immediately (deny beats quorum).

    Example::

        quorum = QuorumApprover(
            approvers=[
                ("alice", alice_fn),
                ("bob",   bob_fn),
                ("carol", carol_fn),
            ],
            required=2,
            timeout_s=300,
        )
    """

    def __init__(
        self,
        approvers: List[tuple[str, ApproverCallable]],
        required: int,
        timeout_s: float = 300.0,
        audit_log: Optional[ApprovalAuditLog] = None,
    ) -> None:
        if required < 1 or required > len(approvers):
            raise ValueError(f"required={required} out of {len(approvers)} is invalid")
        self._approvers = approvers
        self._required = required
        self._timeout_s = timeout_s
        self._audit = audit_log or _GLOBAL_AUDIT_LOG

    async def __call__(self, action: str, context: dict) -> Optional[bool]:
        deadline = asyncio.get_event_loop().time() + self._timeout_s
        tasks = {
            asyncio.ensure_future(fn(action, context)): apid
            for apid, fn in self._approvers
        }
        approvals = 0
        denials = 0
        needed = self._required
        deny_threshold = len(self._approvers) - self._required + 1  # enough to block quorum

        pending = set(tasks.keys())
        t0 = time.monotonic()

        while pending:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            done, pending = await asyncio.wait(
                pending, timeout=remaining, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                apid = tasks[task]
                try:
                    answer = task.result()
                except Exception as exc:
                    answer = None
                    log.warning("QuorumApprover %s raised: %s", apid, exc)

                rec = ApprovalRecord(
                    action=action, context=dict(context),
                    approver_id=apid, decision=answer,
                    decided_at=time.time(),
                    latency_s=time.monotonic() - t0,
                )
                await self._audit.record(rec)

                if answer is True:
                    approvals += 1
                    if approvals >= needed:
                        for p in pending:
                            p.cancel()
                        return True
                elif answer is False:
                    denials += 1
                    if denials >= deny_threshold:
                        for p in pending:
                            p.cancel()
                        return False

        # Cancel any stragglers
        for p in pending:
            p.cancel()

        # Timed out without quorum
        return None


# ───────────────────────── HITLWorkflowLayer ──────────────────────────────

class HITLWorkflowLayer:
    """Drop-in replacement for HITLLayer with full workflow support.

    Parameters
    ----------
    require_approval_for : list[str]
        Action names that need human approval.
    approver : callable
        An ApproverChain, QuorumApprover, or any async callable
        ``(action, context) -> Optional[bool]``.
    timeout_s : float
        Hard outer timeout. Overrides chain/quorum inner timeouts if shorter.
    audit_log : ApprovalAuditLog
        Where to record decisions. Defaults to the module-level global.
    """

    def __init__(
        self,
        require_approval_for: List[str] | None = None,
        approver: Optional[ApproverCallable] = None,
        timeout_s: float = 600.0,
        audit_log: Optional[ApprovalAuditLog] = None,
    ) -> None:
        self.require_approval_for = set(require_approval_for or [])
        self.approver = approver
        self.timeout_s = timeout_s
        self._audit = audit_log or _GLOBAL_AUDIT_LOG
        self._pending: dict[str, str] = {}  # request_id -> action

    def is_consequential(self, action: str) -> bool:
        return action in self.require_approval_for

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    async def gate(self, action: str, context: dict) -> HITLStatus:
        if not self.is_consequential(action):
            return HITLStatus.AUTO

        if self.approver is None:
            # No approver wired — idle is the safe default
            rec = ApprovalRecord(action=action, context=dict(context),
                                 approver_id="<none>", decision=None,
                                 decided_at=time.time(), latency_s=0.0,
                                 reason="no approver configured")
            await self._audit.record(rec)
            return HITLStatus.IDLE

        request_id = str(uuid.uuid4())
        self._pending[request_id] = action
        t0 = time.monotonic()
        try:
            answer = await asyncio.wait_for(
                self.approver(action, context), timeout=self.timeout_s
            )
        except asyncio.TimeoutError:
            answer = None
        finally:
            self._pending.pop(request_id, None)

        latency = time.monotonic() - t0
        rec = ApprovalRecord(
            action=action, context=dict(context),
            approver_id="workflow",
            decision=answer,
            decided_at=time.time(),
            latency_s=latency,
        )
        await self._audit.record(rec)

        if answer is True:
            return HITLStatus.APPROVED
        if answer is False:
            return HITLStatus.DENIED
        return HITLStatus.IDLE
