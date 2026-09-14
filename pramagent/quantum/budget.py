"""Atomic shot and cost reservations for quantum execution."""
from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

__all__ = [
    "QuantumBudgetDecision",
    "QuantumBudgetLedgerBackend",
    "QuantumBudgetLedger",
    "QuantumBudgetLimits",
    "QuantumBudgetReconciliation",
    "QuantumBudgetSnapshot",
]


@runtime_checkable
class QuantumBudgetLedgerBackend(Protocol):
    """Storage contract shared by local and distributed budget ledgers."""

    def snapshot(self, tenant_id: str, session_id: str) -> "QuantumBudgetSnapshot": ...

    def reserve(
        self,
        *,
        tenant_id: str,
        session_id: str,
        circuit_name: str,
        estimated_shots: int,
        estimated_cost_usd: float,
        limits: "QuantumBudgetLimits",
    ) -> "QuantumBudgetDecision": ...

    def release(self, reservation_id: str) -> bool: ...

    def mark_uncertain(self, reservation_id: str) -> bool: ...

    def reconcile(
        self,
        reservation_id: str,
        *,
        actual_shots: int,
        actual_cost_usd: float,
        limits: "QuantumBudgetLimits",
    ) -> "QuantumBudgetReconciliation": ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class QuantumBudgetLimits:
    """Session limits enforced while the reservation transaction is locked."""

    max_shots: int
    max_cost_usd: float

    def __post_init__(self) -> None:
        if self.max_shots < 0:
            raise ValueError("max_shots must be non-negative")
        if self.max_cost_usd < 0:
            raise ValueError("max_cost_usd must be non-negative")


@dataclass(frozen=True)
class QuantumBudgetSnapshot:
    shots: int
    cost_usd: float


@dataclass(frozen=True)
class QuantumBudgetDecision:
    allowed: bool
    reason: str
    before: QuantumBudgetSnapshot
    after: QuantumBudgetSnapshot
    reservation_id: str | None = None


@dataclass(frozen=True)
class QuantumBudgetReconciliation:
    reservation_id: str
    before: QuantumBudgetSnapshot
    after: QuantumBudgetSnapshot
    over_limit: bool


class QuantumBudgetLedger:
    """SQLite-backed reservation ledger shared by threads and processes.

    Reservations count against the budget before a QNode starts. A successful
    call is reconciled to measured usage; a call whose execution outcome is
    unknown remains charged at its estimate until an operator reconciles it.
    """

    _ACTIVE_STATUSES = ("reserved", "reconciled", "uncertain")

    def __init__(self, path: str | Path, *, timeout: float = 30.0) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.path,
            timeout=timeout,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout = 30000")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS quantum_budget_reservations (
                reservation_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                circuit_name TEXT NOT NULL,
                estimated_shots INTEGER NOT NULL CHECK (estimated_shots >= 0),
                estimated_cost_usd REAL NOT NULL CHECK (estimated_cost_usd >= 0),
                actual_shots INTEGER CHECK (actual_shots >= 0),
                actual_cost_usd REAL CHECK (actual_cost_usd >= 0),
                status TEXT NOT NULL CHECK (
                    status IN ('reserved', 'reconciled', 'released', 'uncertain')
                ),
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_quantum_budget_session
            ON quantum_budget_reservations (tenant_id, session_id, status)
            """
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "QuantumBudgetLedger":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @staticmethod
    def _validate_amounts(shots: int, cost_usd: float) -> tuple[int, float]:
        shots = int(shots)
        cost_usd = round(float(cost_usd), 6)
        if shots < 0 or cost_usd < 0:
            raise ValueError("shots and cost_usd must be non-negative")
        return shots, cost_usd

    def _snapshot_locked(self, tenant_id: str, session_id: str) -> QuantumBudgetSnapshot:
        placeholders = ",".join("?" for _ in self._ACTIVE_STATUSES)
        row = self._conn.execute(
            f"""
            SELECT
                COALESCE(SUM(CASE
                    WHEN status = 'reconciled' THEN actual_shots
                    ELSE estimated_shots
                END), 0),
                COALESCE(SUM(CASE
                    WHEN status = 'reconciled' THEN actual_cost_usd
                    ELSE estimated_cost_usd
                END), 0.0)
            FROM quantum_budget_reservations
            WHERE tenant_id = ? AND session_id = ?
              AND status IN ({placeholders})
            """,
            (tenant_id, session_id, *self._ACTIVE_STATUSES),
        ).fetchone()
        return QuantumBudgetSnapshot(int(row[0] or 0), round(float(row[1] or 0.0), 6))

    def snapshot(self, tenant_id: str, session_id: str) -> QuantumBudgetSnapshot:
        with self._lock:
            return self._snapshot_locked(tenant_id, session_id)

    def reserve(
        self,
        *,
        tenant_id: str,
        session_id: str,
        circuit_name: str,
        estimated_shots: int,
        estimated_cost_usd: float,
        limits: QuantumBudgetLimits,
    ) -> QuantumBudgetDecision:
        """Atomically check the session limit and reserve the estimated spend."""
        shots, cost = self._validate_amounts(estimated_shots, estimated_cost_usd)
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                before = self._snapshot_locked(tenant_id, session_id)
                after = QuantumBudgetSnapshot(
                    before.shots + shots,
                    round(before.cost_usd + cost, 6),
                )
                reasons: list[str] = []
                if after.shots > limits.max_shots:
                    reasons.append(
                        f"session shots {after.shots} exceed limit {limits.max_shots}"
                    )
                if after.cost_usd > limits.max_cost_usd + 1e-9:
                    reasons.append(
                        "session cost "
                        f"${after.cost_usd:.6f} exceeds limit ${limits.max_cost_usd:.6f}"
                    )
                if reasons:
                    self._conn.rollback()
                    return QuantumBudgetDecision(False, "; ".join(reasons), before, after)

                reservation_id = uuid.uuid4().hex
                now = time.time()
                self._conn.execute(
                    """
                    INSERT INTO quantum_budget_reservations (
                        reservation_id, tenant_id, session_id, circuit_name,
                        estimated_shots, estimated_cost_usd, status,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'reserved', ?, ?)
                    """,
                    (
                        reservation_id,
                        tenant_id,
                        session_id,
                        circuit_name,
                        shots,
                        cost,
                        now,
                        now,
                    ),
                )
                self._conn.commit()
                return QuantumBudgetDecision(
                    True,
                    "quantum budget reserved",
                    before,
                    after,
                    reservation_id,
                )
            except Exception:
                self._conn.rollback()
                raise

    def release(self, reservation_id: str) -> bool:
        """Release a reservation when policy refuses the call before execution."""
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE quantum_budget_reservations
                SET status = 'released', updated_at = ?
                WHERE reservation_id = ? AND status = 'reserved'
                """,
                (time.time(), reservation_id),
            )
            return cursor.rowcount == 1

    def mark_uncertain(self, reservation_id: str) -> bool:
        """Keep the estimate charged when execution may have reached a provider."""
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE quantum_budget_reservations
                SET status = 'uncertain', updated_at = ?
                WHERE reservation_id = ? AND status = 'reserved'
                """,
                (time.time(), reservation_id),
            )
            return cursor.rowcount == 1

    def reconcile(
        self,
        reservation_id: str,
        *,
        actual_shots: int,
        actual_cost_usd: float,
        limits: QuantumBudgetLimits,
    ) -> QuantumBudgetReconciliation:
        """Replace one reservation's estimate with authoritative actual usage."""
        shots, cost = self._validate_amounts(actual_shots, actual_cost_usd)
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                row = self._conn.execute(
                    """
                    SELECT tenant_id, session_id, status
                    FROM quantum_budget_reservations WHERE reservation_id = ?
                    """,
                    (reservation_id,),
                ).fetchone()
                if row is None:
                    raise KeyError(f"unknown quantum reservation: {reservation_id}")
                tenant_id, session_id, status = row
                if status == "released":
                    raise ValueError("cannot reconcile a released quantum reservation")
                before = self._snapshot_locked(tenant_id, session_id)
                self._conn.execute(
                    """
                    UPDATE quantum_budget_reservations
                    SET actual_shots = ?, actual_cost_usd = ?,
                        status = 'reconciled', updated_at = ?
                    WHERE reservation_id = ?
                    """,
                    (shots, cost, time.time(), reservation_id),
                )
                after = self._snapshot_locked(tenant_id, session_id)
                self._conn.commit()
                return QuantumBudgetReconciliation(
                    reservation_id=reservation_id,
                    before=before,
                    after=after,
                    over_limit=(
                        after.shots > limits.max_shots
                        or after.cost_usd > limits.max_cost_usd + 1e-9
                    ),
                )
            except Exception:
                self._conn.rollback()
                raise
