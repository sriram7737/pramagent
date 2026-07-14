"""
pramagent.queue.base
====================
Protocol + in-memory reference implementation for persistent HITL queues.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Protocol, runtime_checkable


class RequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass
class QueuedRequest:
    request_id: str
    action: str
    context: dict
    tenant_id: str = "default"
    created_at: float = field(default_factory=time.time)
    decided_at: Optional[float] = None
    status: str = RequestStatus.PENDING.value
    decided_by: str = ""
    notes: str = ""

    @classmethod
    def new(cls, action: str, context: dict, *, tenant_id: str = "default") -> "QueuedRequest":
        return cls(request_id=str(uuid.uuid4()), action=action,
                   context=dict(context), tenant_id=tenant_id)


@runtime_checkable
class HITLQueueStore(Protocol):
    """Persistent approval queue. Every backend implements this."""

    def enqueue(self, request: QueuedRequest) -> str:
        """Persist a new pending request. Returns the request_id."""
        ...

    def get(self, request_id: str,
            tenant_id: Optional[str] = None) -> Optional[QueuedRequest]:
        """Fetch a single request, or None. When tenant_id is given, a row
        belonging to a different tenant is invisible (returns None) — this is
        the cross-tenant isolation boundary for callers that act on a
        request_id supplied from outside (e.g. a REST decide endpoint)."""
        ...

    def list_pending(self, tenant_id: Optional[str] = None,
                     limit: int = 100) -> list[QueuedRequest]:
        """Return outstanding requests (status == PENDING)."""
        ...

    def decide(self, request_id: str, *, approved: bool,
               decided_by: str = "", notes: str = "",
               tenant_id: Optional[str] = None) -> bool:
        """Record an approve/deny decision. Returns True if a pending row was
        updated. When tenant_id is given, a request owned by another tenant
        is not updated (returns False)."""
        ...

    def expire(self, request_id: str,
               tenant_id: Optional[str] = None) -> bool:
        """Mark a request as expired (timeout). Returns True if updated.
        tenant_id scopes the update the same way decide() does."""
        ...


# ──────────────────────────── in-memory reference ──────────────────────────
class InMemoryHITLQueue:
    """Default in-process queue. Lost on restart. Useful for tests + demos."""

    def __init__(self) -> None:
        self._rows: dict[str, QueuedRequest] = {}

    def enqueue(self, request: QueuedRequest) -> str:
        self._rows[request.request_id] = request
        return request.request_id

    def get(self, request_id: str,
            tenant_id: Optional[str] = None) -> Optional[QueuedRequest]:
        r = self._rows.get(request_id)
        if r is None or (tenant_id is not None and r.tenant_id != tenant_id):
            return None
        return r

    def list_pending(self, tenant_id: Optional[str] = None,
                     limit: int = 100) -> list[QueuedRequest]:
        out = [r for r in self._rows.values()
               if r.status == RequestStatus.PENDING.value
               and (tenant_id is None or r.tenant_id == tenant_id)]
        out.sort(key=lambda r: r.created_at)
        return out[:limit]

    def decide(self, request_id: str, *, approved: bool,
               decided_by: str = "", notes: str = "",
               tenant_id: Optional[str] = None) -> bool:
        r = self._rows.get(request_id)
        if r is None or r.status != RequestStatus.PENDING.value:
            return False
        if tenant_id is not None and r.tenant_id != tenant_id:
            return False
        r.status = (RequestStatus.APPROVED.value if approved
                    else RequestStatus.DENIED.value)
        r.decided_at = time.time()
        r.decided_by = decided_by
        r.notes = notes
        return True

    def expire(self, request_id: str,
               tenant_id: Optional[str] = None) -> bool:
        r = self._rows.get(request_id)
        if r is None or r.status != RequestStatus.PENDING.value:
            return False
        if tenant_id is not None and r.tenant_id != tenant_id:
            return False
        r.status = RequestStatus.EXPIRED.value
        r.decided_at = time.time()
        return True


# ──────────────── serialization helpers (used by sqlite + postgres) ────────
def to_row(req: QueuedRequest) -> dict:
    return {
        "request_id": req.request_id,
        "action": req.action,
        "context": json.dumps(req.context, sort_keys=True),
        "tenant_id": req.tenant_id,
        "created_at": req.created_at,
        "decided_at": req.decided_at,
        "status": req.status,
        "decided_by": req.decided_by,
        "notes": req.notes,
    }


def from_row(row: dict) -> QueuedRequest:
    ctx = row.get("context") or "{}"
    if isinstance(ctx, (bytes, bytearray)):
        ctx = ctx.decode("utf-8")
    if isinstance(ctx, str):
        try:
            ctx = json.loads(ctx)
        except Exception:
            ctx = {}
    return QueuedRequest(
        request_id=row["request_id"],
        action=row["action"],
        context=ctx,
        tenant_id=row.get("tenant_id") or "default",
        created_at=float(row.get("created_at") or time.time()),
        decided_at=(float(row["decided_at"]) if row.get("decided_at") is not None else None),
        status=row.get("status") or RequestStatus.PENDING.value,
        decided_by=row.get("decided_by") or "",
        notes=row.get("notes") or "",
    )
