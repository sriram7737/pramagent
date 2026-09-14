from __future__ import annotations

import os
import threading
import uuid

import pytest

from pramagent.quantum import PostgresQuantumBudgetLedger, QuantumBudgetLimits


@pytest.mark.skipif(
    not os.environ.get("PRAMAGENT_TEST_POSTGRES_DSN"),
    reason="set PRAMAGENT_TEST_POSTGRES_DSN to run the live Postgres test",
)
def test_live_postgres_serializes_competing_first_reservations():
    dsn = os.environ["PRAMAGENT_TEST_POSTGRES_DSN"]
    table = f"quantum_budget_test_{uuid.uuid4().hex[:12]}"
    ledgers = [
        PostgresQuantumBudgetLedger(dsn, table=table),
        PostgresQuantumBudgetLedger(dsn, table=table),
    ]
    limits = QuantumBudgetLimits(max_shots=100, max_cost_usd=1.0)
    barrier = threading.Barrier(2)
    decisions = []
    errors = []

    def reserve(ledger):
        try:
            barrier.wait()
            decisions.append(ledger.reserve(
                tenant_id="acme",
                session_id="shared",
                circuit_name="live-concurrency",
                estimated_shots=60,
                estimated_cost_usd=0.5,
                limits=limits,
            ))
        except Exception as exc:  # pragma: no cover - reported by the main thread
            errors.append(exc)

    threads = [threading.Thread(target=reserve, args=(ledger,)) for ledger in ledgers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    assert not any(thread.is_alive() for thread in threads)
    assert errors == []
    assert sorted(decision.allowed for decision in decisions) == [False, True]
    assert ledgers[0].snapshot("acme", "shared").shots == 60
