"""Distributed Postgres reservations for quantum shots and provider cost."""
from __future__ import annotations

import hashlib
import re
import time
import uuid
from collections.abc import Callable
from typing import Any

from .._pg import connect as pg_connect
from .budget import (
    QuantumBudgetDecision,
    QuantumBudgetLimits,
    QuantumBudgetReconciliation,
    QuantumBudgetSnapshot,
)

__all__ = ["PostgresQuantumBudgetLedger"]

_SAFE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
_ACTIVE_STATUSES = ("reserved", "reconciled", "uncertain")


class PostgresQuantumBudgetLedger:
    """Postgres budget ledger that serializes each tenant/session globally.

    A transaction-scoped advisory lock is derived from the tenant and session.
    Unlike locking existing reservation rows, this also serializes the first
    reservation for a session whose ledger is still empty.
    """

    def __init__(
        self,
        dsn: str,
        *,
        table: str = "pramagent_quantum_budget_reservations",
        connect_factory: Callable[[str], Any] | None = None,
    ) -> None:
        if not dsn or not str(dsn).strip():
            raise ValueError("Postgres quantum budget DSN is required")
        if not _SAFE_NAME.fullmatch(table):
            raise ValueError(f"unsafe table name: {table!r}")
        self.dsn = str(dsn)
        self.table = table
        self._table_identifier = '"' + table + '"'
        self._connect_factory = connect_factory or pg_connect
        self._run(self._create_schema)

    def close(self) -> None:
        """Connections are transaction-scoped, so there is nothing to close."""

    def __enter__(self) -> "PostgresQuantumBudgetLedger":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @staticmethod
    def _validate_amounts(shots: int, cost_usd: float) -> tuple[int, float]:
        shots = int(shots)
        cost_usd = round(float(cost_usd), 6)
        if shots < 0 or cost_usd < 0:
            raise ValueError("shots and cost_usd must be non-negative")
        return shots, cost_usd

    @staticmethod
    def _lock_id(tenant_id: str, session_id: str) -> int:
        material = f"{tenant_id}\0{session_id}".encode("utf-8")
        return int.from_bytes(hashlib.sha256(material).digest()[:8], "big", signed=True)

    def _run(self, fn: Callable[[Any], Any]) -> Any:
        connection = self._connect_factory(self.dsn)
        try:
            with connection.cursor() as cursor:
                result = fn(cursor)
            connection.commit()
            return result
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _create_schema(self, cursor: Any) -> None:
        cursor.execute(
            self._query("""
            CREATE TABLE IF NOT EXISTS {table} (
                reservation_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                circuit_name TEXT NOT NULL,
                estimated_shots BIGINT NOT NULL CHECK (estimated_shots >= 0),
                estimated_cost_usd NUMERIC(20, 6) NOT NULL
                    CHECK (estimated_cost_usd >= 0),
                actual_shots BIGINT CHECK (actual_shots >= 0),
                actual_cost_usd NUMERIC(20, 6) CHECK (actual_cost_usd >= 0),
                status TEXT NOT NULL CHECK (
                    status IN ('reserved', 'reconciled', 'released', 'uncertain')
                ),
                created_at DOUBLE PRECISION NOT NULL,
                updated_at DOUBLE PRECISION NOT NULL
            )
            """)
        )
        cursor.execute(
            self._query("""
            CREATE INDEX IF NOT EXISTS {session_index}
            ON {table} (tenant_id, session_id, status)
            """)
        )

    def _query(self, template: str) -> str:
        """Compose static SQL with the constructor-validated identifier only."""
        return template.replace("{table}", self._table_identifier).replace(
            "{session_index}", '"idx_' + self.table + '_session"'
        )

    def _lock_scope(self, cursor: Any, tenant_id: str, session_id: str) -> None:
        cursor.execute(
            "SELECT pg_advisory_xact_lock(%s)",
            (self._lock_id(tenant_id, session_id),),
        )

    def _snapshot(
        self, cursor: Any, tenant_id: str, session_id: str
    ) -> QuantumBudgetSnapshot:
        cursor.execute(
            self._query("""
            SELECT
                COALESCE(SUM(CASE
                    WHEN status = 'reconciled' THEN actual_shots
                    ELSE estimated_shots
                END), 0),
                COALESCE(SUM(CASE
                    WHEN status = 'reconciled' THEN actual_cost_usd
                    ELSE estimated_cost_usd
                END), 0.0)
            FROM {table}
            WHERE tenant_id = %s AND session_id = %s
              AND status IN (%s, %s, %s)
            """),
            (tenant_id, session_id, *_ACTIVE_STATUSES),
        )
        row = cursor.fetchone()
        return QuantumBudgetSnapshot(
            int(row[0] or 0), round(float(row[1] or 0.0), 6)
        )

    def snapshot(self, tenant_id: str, session_id: str) -> QuantumBudgetSnapshot:
        def operation(cursor: Any) -> QuantumBudgetSnapshot:
            self._lock_scope(cursor, tenant_id, session_id)
            return self._snapshot(cursor, tenant_id, session_id)

        return self._run(operation)

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
        shots, cost = self._validate_amounts(estimated_shots, estimated_cost_usd)

        def operation(cursor: Any) -> QuantumBudgetDecision:
            self._lock_scope(cursor, tenant_id, session_id)
            before = self._snapshot(cursor, tenant_id, session_id)
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
                    f"session cost ${after.cost_usd:.6f} exceeds limit "
                    f"${limits.max_cost_usd:.6f}"
                )
            if reasons:
                return QuantumBudgetDecision(False, "; ".join(reasons), before, after)

            reservation_id = uuid.uuid4().hex
            now = time.time()
            cursor.execute(
                self._query("""
                INSERT INTO {table} (
                    reservation_id, tenant_id, session_id, circuit_name,
                    estimated_shots, estimated_cost_usd, status,
                    created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, 'reserved', %s, %s)
                """),
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
            return QuantumBudgetDecision(
                True,
                "quantum budget reserved",
                before,
                after,
                reservation_id,
            )

        return self._run(operation)

    def release(self, reservation_id: str) -> bool:
        def operation(cursor: Any) -> bool:
            cursor.execute(
                self._query("""
                UPDATE {table}
                SET status = 'released', updated_at = %s
                WHERE reservation_id = %s AND status = 'reserved'
                """),
                (time.time(), reservation_id),
            )
            return cursor.rowcount == 1

        return self._run(operation)

    def mark_uncertain(self, reservation_id: str) -> bool:
        def operation(cursor: Any) -> bool:
            cursor.execute(
                self._query("""
                UPDATE {table}
                SET status = 'uncertain', updated_at = %s
                WHERE reservation_id = %s AND status = 'reserved'
                """),
                (time.time(), reservation_id),
            )
            return cursor.rowcount == 1

        return self._run(operation)

    def reconcile(
        self,
        reservation_id: str,
        *,
        actual_shots: int,
        actual_cost_usd: float,
        limits: QuantumBudgetLimits,
    ) -> QuantumBudgetReconciliation:
        shots, cost = self._validate_amounts(actual_shots, actual_cost_usd)

        def operation(cursor: Any) -> QuantumBudgetReconciliation:
            cursor.execute(
                self._query("""
                SELECT tenant_id, session_id, status
                FROM {table}
                WHERE reservation_id = %s
                FOR UPDATE
                """),
                (reservation_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise KeyError(f"unknown quantum reservation: {reservation_id}")
            tenant_id, session_id, status = row
            if status == "released":
                raise ValueError("cannot reconcile a released quantum reservation")
            self._lock_scope(cursor, tenant_id, session_id)
            before = self._snapshot(cursor, tenant_id, session_id)
            cursor.execute(
                self._query("""
                UPDATE {table}
                SET actual_shots = %s, actual_cost_usd = %s,
                    status = 'reconciled', updated_at = %s
                WHERE reservation_id = %s
                """),
                (shots, cost, time.time(), reservation_id),
            )
            after = self._snapshot(cursor, tenant_id, session_id)
            return QuantumBudgetReconciliation(
                reservation_id=reservation_id,
                before=before,
                after=after,
                over_limit=(
                    after.shots > limits.max_shots
                    or after.cost_usd > limits.max_cost_usd + 1e-9
                ),
            )

        return self._run(operation)
