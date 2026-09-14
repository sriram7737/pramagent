from __future__ import annotations

import threading

import pytest

from pramagent import Pramagent
from pramagent.quantum import (
    GuardedQNode,
    PennyLaneQuantumBudgetExceeded,
    QuantumBudgetLedger,
    QuantumBudgetLimits,
    make_quantum_policies,
)


class _Shots:
    def __init__(self, total_shots: int):
        self.total_shots = total_shots


class _Device:
    name = "default.qubit"

    def __init__(self, shots: int):
        self.shots = _Shots(shots)


class _QNode:
    def __init__(self, shots: int = 300, *, fail: bool = False):
        self.device = _Device(shots)
        self.fail = fail
        self.calls = 0

        def circuit(theta):
            return theta

        self.func = circuit

    def __call__(self, theta):
        self.calls += 1
        if self.fail:
            raise RuntimeError("provider outcome unknown")
        return theta


class _Resources:
    depth = 2
    num_wires = 2


def _specs(_qnode, *_args, **_kwargs):
    return {"resources": _Resources()}


def _armor(*, max_shots_per_call: int = 1_000) -> Pramagent:
    armor = Pramagent()
    for policy in make_quantum_policies(
        max_shots_per_call=max_shots_per_call,
        max_shots_per_session=10_000,
        max_cost_usd_per_session=0.0,
    ):
        armor.tool_guard.register(policy)
    return armor


def test_atomic_reservation_allows_only_one_concurrent_spender(tmp_path):
    path = tmp_path / "quantum-budget.db"
    ledgers = [QuantumBudgetLedger(path), QuantumBudgetLedger(path)]
    limits = QuantumBudgetLimits(max_shots=100, max_cost_usd=0.0)
    barrier = threading.Barrier(2)
    decisions = []
    result_lock = threading.Lock()

    def reserve(ledger):
        barrier.wait()
        decision = ledger.reserve(
            tenant_id="acme",
            session_id="session",
            circuit_name="caption",
            estimated_shots=60,
            estimated_cost_usd=0.0,
            limits=limits,
        )
        with result_lock:
            decisions.append(decision)

    threads = [threading.Thread(target=reserve, args=(ledger,)) for ledger in ledgers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert sorted(decision.allowed for decision in decisions) == [False, True]
    assert ledgers[0].snapshot("acme", "session").shots == 60
    for ledger in ledgers:
        ledger.close()


def test_reconciliation_replaces_estimate_and_reports_overrun(tmp_path):
    ledger = QuantumBudgetLedger(tmp_path / "quantum-budget.db")
    limits = QuantumBudgetLimits(max_shots=500, max_cost_usd=1.0)
    decision = ledger.reserve(
        tenant_id="acme",
        session_id="session",
        circuit_name="caption",
        estimated_shots=200,
        estimated_cost_usd=0.20,
        limits=limits,
    )

    reconciled = ledger.reconcile(
        decision.reservation_id,
        actual_shots=700,
        actual_cost_usd=0.70,
        limits=limits,
    )

    assert reconciled.before.shots == 200
    assert reconciled.after.shots == 700
    assert reconciled.after.cost_usd == 0.70
    assert reconciled.over_limit is True


def test_released_reservation_no_longer_counts(tmp_path):
    ledger = QuantumBudgetLedger(tmp_path / "quantum-budget.db")
    limits = QuantumBudgetLimits(max_shots=500, max_cost_usd=0.0)
    decision = ledger.reserve(
        tenant_id="acme",
        session_id="session",
        circuit_name="caption",
        estimated_shots=300,
        estimated_cost_usd=0.0,
        limits=limits,
    )

    assert ledger.release(decision.reservation_id)
    assert ledger.snapshot("acme", "session").shots == 0


def test_policy_block_releases_pre_execution_reservation(tmp_path):
    ledger = QuantumBudgetLedger(tmp_path / "quantum-budget.db")
    qnode = _QNode(shots=300)
    guarded = GuardedQNode(
        qnode,
        _armor(max_shots_per_call=100),
        tenant_id="acme",
        session_id="session",
        specs_func=_specs,
        budget_ledger=ledger,
        budget_limits=QuantumBudgetLimits(max_shots=1_000, max_cost_usd=0.0),
    )

    with pytest.raises(PennyLaneQuantumBudgetExceeded):
        guarded(0.2)

    assert qnode.calls == 0
    assert ledger.snapshot("acme", "session").shots == 0


def test_execution_error_keeps_estimate_as_uncertain_spend(tmp_path):
    ledger = QuantumBudgetLedger(tmp_path / "quantum-budget.db")
    qnode = _QNode(shots=300, fail=True)
    armor = _armor()
    guarded = GuardedQNode(
        qnode,
        armor,
        tenant_id="acme",
        session_id="session",
        specs_func=_specs,
        budget_ledger=ledger,
        budget_limits=QuantumBudgetLimits(max_shots=500, max_cost_usd=0.0),
    )

    with pytest.raises(RuntimeError, match="provider outcome unknown"):
        guarded(0.2)

    assert ledger.snapshot("acme", "session").shots == 300
    payloads = [record["payload"] for record in armor.audit.records()]
    assert payloads[-1]["event"] == "quantum_execution_uncertain"
    assert payloads[-1]["reservation_id"]


def test_measured_usage_is_reconciled_into_atomic_budget(tmp_path):
    ledger = QuantumBudgetLedger(tmp_path / "quantum-budget.db")
    qnode = _QNode(shots=200)
    armor = _armor()

    def meter(node, *args, **kwargs):
        return node(*args, **kwargs), {"shots": 450, "executions": 3}

    guarded = GuardedQNode(
        qnode,
        armor,
        tenant_id="acme",
        session_id="session",
        specs_func=_specs,
        meter_func=meter,
        budget_ledger=ledger,
        budget_limits=QuantumBudgetLimits(max_shots=500, max_cost_usd=0.0),
    )

    assert guarded(0.2) == 0.2
    assert ledger.snapshot("acme", "session").shots == 450
    with pytest.raises(PennyLaneQuantumBudgetExceeded):
        guarded(0.3)
    assert qnode.calls == 1


def test_budget_ledger_and_limits_must_be_configured_together(tmp_path):
    with pytest.raises(ValueError, match="configured together"):
        GuardedQNode(
            _QNode(),
            _armor(),
            specs_func=_specs,
            budget_ledger=QuantumBudgetLedger(tmp_path / "quantum-budget.db"),
        )
