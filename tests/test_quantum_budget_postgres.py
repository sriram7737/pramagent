from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from pramagent.quantum import (
    PostgresQuantumBudgetLedger,
    QuantumBudgetLedgerBackend,
    QuantumBudgetLimits,
)


@dataclass
class _FakeDB:
    rows: dict[str, dict] = field(default_factory=dict)


class _FakeCursor:
    def __init__(self, db: _FakeDB):
        self.db = db
        self.rowcount = 0
        self._row = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        statement = " ".join(str(sql).lower().split())
        params = tuple(params or ())
        self.rowcount = 0
        self._row = None
        if statement.startswith("create table") or statement.startswith("create index"):
            return
        if "pg_advisory_xact_lock" in statement:
            self._row = (None,)
            return
        if statement.startswith("select coalesce(sum(case"):
            tenant_id, session_id = params[:2]
            active = set(params[2:])
            rows = [
                row
                for row in self.db.rows.values()
                if row["tenant_id"] == tenant_id
                and row["session_id"] == session_id
                and row["status"] in active
            ]
            shots = sum(
                row["actual_shots"]
                if row["status"] == "reconciled"
                else row["estimated_shots"]
                for row in rows
            )
            cost = sum(
                row["actual_cost_usd"]
                if row["status"] == "reconciled"
                else row["estimated_cost_usd"]
                for row in rows
            )
            self._row = (shots, cost)
            return
        if statement.startswith("insert into"):
            (
                reservation_id,
                tenant_id,
                session_id,
                circuit_name,
                estimated_shots,
                estimated_cost_usd,
                created_at,
                updated_at,
            ) = params
            self.db.rows[reservation_id] = {
                "reservation_id": reservation_id,
                "tenant_id": tenant_id,
                "session_id": session_id,
                "circuit_name": circuit_name,
                "estimated_shots": estimated_shots,
                "estimated_cost_usd": estimated_cost_usd,
                "actual_shots": None,
                "actual_cost_usd": None,
                "status": "reserved",
                "created_at": created_at,
                "updated_at": updated_at,
            }
            self.rowcount = 1
            return
        if statement.startswith("select tenant_id, session_id, status"):
            row = self.db.rows.get(params[0])
            self._row = (
                (row["tenant_id"], row["session_id"], row["status"])
                if row
                else None
            )
            return
        if "set actual_shots" in statement:
            shots, cost, updated_at, reservation_id = params
            row = self.db.rows[reservation_id]
            row.update(
                actual_shots=shots,
                actual_cost_usd=cost,
                status="reconciled",
                updated_at=updated_at,
            )
            self.rowcount = 1
            return
        if statement.startswith("update"):
            updated_at, reservation_id = params
            row = self.db.rows.get(reservation_id)
            if row and row["status"] == "reserved":
                row["status"] = (
                    "released" if "status = 'released'" in statement else "uncertain"
                )
                row["updated_at"] = updated_at
                self.rowcount = 1
            return
        raise AssertionError(f"unexpected SQL: {statement}")

    def fetchone(self):
        return self._row


class _FakeConnection:
    def __init__(self, db: _FakeDB):
        self.db = db
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return _FakeCursor(self.db)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        pass


@pytest.fixture
def ledger():
    db = _FakeDB()
    value = PostgresQuantumBudgetLedger(
        "postgresql://unit-test",
        connect_factory=lambda _dsn: _FakeConnection(db),
    )
    return value, db


def test_postgres_ledger_implements_shared_contract(ledger):
    value, _ = ledger
    assert isinstance(value, QuantumBudgetLedgerBackend)


def test_postgres_reserve_reconcile_release_and_session_isolation(ledger):
    value, _ = ledger
    limits = QuantumBudgetLimits(max_shots=100, max_cost_usd=5.0)

    first = value.reserve(
        tenant_id="acme",
        session_id="session-a",
        circuit_name="projection",
        estimated_shots=60,
        estimated_cost_usd=1.5,
        limits=limits,
    )
    blocked = value.reserve(
        tenant_id="acme",
        session_id="session-a",
        circuit_name="projection",
        estimated_shots=50,
        estimated_cost_usd=1.0,
        limits=limits,
    )
    isolated = value.reserve(
        tenant_id="acme",
        session_id="session-b",
        circuit_name="projection",
        estimated_shots=50,
        estimated_cost_usd=1.0,
        limits=limits,
    )

    assert first.allowed is True
    assert blocked.allowed is False
    assert isolated.allowed is True
    reconciled = value.reconcile(
        first.reservation_id,
        actual_shots=80,
        actual_cost_usd=2.0,
        limits=limits,
    )
    assert reconciled.after.shots == 80
    assert reconciled.after.cost_usd == 2.0
    assert value.release(isolated.reservation_id) is True
    assert value.snapshot("acme", "session-b").shots == 0


def test_postgres_uncertain_reservation_remains_charged(ledger):
    value, _ = ledger
    limits = QuantumBudgetLimits(max_shots=64, max_cost_usd=0.0)
    reserved = value.reserve(
        tenant_id="acme",
        session_id="uncertain",
        circuit_name="hardware",
        estimated_shots=64,
        estimated_cost_usd=0.0,
        limits=limits,
    )

    assert value.mark_uncertain(reserved.reservation_id) is True
    assert value.snapshot("acme", "uncertain").shots == 64
    assert value.reserve(
        tenant_id="acme",
        session_id="uncertain",
        circuit_name="hardware",
        estimated_shots=1,
        estimated_cost_usd=0.0,
        limits=limits,
    ).allowed is False


def test_postgres_ledger_rejects_unsafe_table_before_connecting():
    called = False

    def connect(_dsn):
        nonlocal called
        called = True

    with pytest.raises(ValueError, match="unsafe table"):
        PostgresQuantumBudgetLedger(
            "postgresql://unit-test",
            table="budget;drop",
            connect_factory=connect,
        )
    assert called is False
