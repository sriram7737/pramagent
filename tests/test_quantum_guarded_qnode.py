import importlib.util
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))
_MODULE_PATH = _REPO_ROOT / "examples" / "quantum" / "guarded_qnode.py"
_SPEC = importlib.util.spec_from_file_location("guarded_qnode_example", _MODULE_PATH)
guarded_qnode_example = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(guarded_qnode_example)

ApprovalRequired = guarded_qnode_example.ApprovalRequired
GuardedQNode = guarded_qnode_example.GuardedQNode
QuantumBudgetExceeded = guarded_qnode_example.QuantumBudgetExceeded
make_quantum_policies = guarded_qnode_example.make_quantum_policies
from pramagent import Pramagent, SideEffect, Verdict
from pramagent.conformance import is_read_only_side_effect


class _Shots:
    def __init__(self, total_shots):
        self.total_shots = total_shots


class _Device:
    def __init__(self, name, shots):
        self.name = name
        self.shots = _Shots(shots)


class _Resources:
    depth = 3
    num_wires = 2


class _QNode:
    def __init__(self, name="default.qubit", shots=500):
        self.device = _Device(name, shots)
        self.calls = 0

        def circuit(theta):
            return theta

        self.func = circuit

    def __call__(self, theta):
        self.calls += 1
        return {"value": theta}


def _specs(_qnode, *_args, **_kwargs):
    return {"resources": _Resources()}


def _armor(
    *,
    max_shots_per_call=500,
    max_shots_per_session=1_000,
    max_cost=0.0,
    hardware_requires_approval=True,
):
    armor = Pramagent()
    for policy in make_quantum_policies(
        max_shots_per_call=max_shots_per_call,
        max_shots_per_session=max_shots_per_session,
        max_cost_usd_per_session=max_cost,
        hardware_requires_approval=hardware_requires_approval,
    ):
        armor.tool_guard.register(policy)
    return armor


def _quantum_payloads(armor):
    return [
        rec["payload"] for rec in armor.audit.records()
        if rec["payload"].get("source") == "quantum_adapter"
    ]


def test_metered_compute_side_effect_is_between_compute_and_write():
    assert SideEffect.METERED_COMPUTE == "metered_compute"
    assert SideEffect.is_at_least(SideEffect.METERED_COMPUTE, SideEffect.COMPUTE)
    assert not SideEffect.is_at_least(SideEffect.METERED_COMPUTE, SideEffect.WRITE)
    assert is_read_only_side_effect(SideEffect.METERED_COMPUTE)


def test_guarded_qnode_allows_and_audits_executed_simulator_call():
    armor = _armor()
    qnode = _QNode(shots=500)
    guarded = GuardedQNode(
        qnode,
        armor,
        session_id="s",
        specs_func=_specs,
        joules_per_shot=0.001,
    )

    assert guarded(0.3) == {"value": 0.3}
    assert qnode.calls == 1
    assert armor.audit.verify_chain()
    payload = _quantum_payloads(armor)[0]
    assert payload["event"] == "quantum_call_executed"
    assert payload["verdict"] == "allow"
    assert payload["shots"] == 500
    assert payload["depth"] == 3
    assert payload["estimated_joules"] == 0.5
    assert payload["session_shots_after"] == 500


def test_guarded_qnode_blocks_per_call_shot_budget_before_execution():
    armor = _armor(max_shots_per_call=499)
    qnode = _QNode(shots=500)
    guarded = GuardedQNode(qnode, armor, session_id="s", specs_func=_specs)

    with pytest.raises(QuantumBudgetExceeded):
        guarded(0.3)

    assert qnode.calls == 0
    payload = _quantum_payloads(armor)[0]
    assert payload["event"] == "quantum_call_blocked"
    assert payload["shots"] == 500
    assert "schema violation" in payload["reason"]
    assert armor.audit.verify_chain()


def test_guarded_qnode_blocks_cumulative_session_shots():
    armor = _armor(max_shots_per_session=1_000)
    qnode = _QNode(shots=500)
    guarded = GuardedQNode(qnode, armor, session_id="s", specs_func=_specs)

    guarded(0.1)
    guarded(0.2)
    with pytest.raises(QuantumBudgetExceeded):
        guarded(0.3)

    assert qnode.calls == 2
    payloads = _quantum_payloads(armor)
    assert [p["event"] for p in payloads] == [
        "quantum_call_executed",
        "quantum_call_executed",
        "quantum_call_blocked",
    ]
    assert payloads[-1]["session_shots_after"] == 1_500


def test_hardware_escalates_when_priced_and_approval_required():
    armor = _armor(max_cost=10_000.0)
    qnode = _QNode(name="braket:rigetti:cepheus", shots=500)
    guarded = GuardedQNode(qnode, armor, session_id="s", specs_func=_specs)

    with pytest.raises(ApprovalRequired) as excinfo:
        guarded(0.3)

    assert qnode.calls == 0
    assert excinfo.value.decision.verdict == Verdict.ESCALATE
    payload = _quantum_payloads(armor)[0]
    assert payload["event"] == "quantum_call_escalated"
    assert payload["tool_name"] == "quantum_execute_hw"
    assert payload["pricing_key"] == "braket:rigetti"
    assert payload["est_cost_usd"] == 0.5125


def test_unknown_hardware_pricing_fails_closed_before_toolguard():
    armor = _armor(max_cost=10_000.0)
    qnode = _QNode(name="ibm_brisbane", shots=500)
    guarded = GuardedQNode(qnode, armor, session_id="s", specs_func=_specs)

    with pytest.raises(QuantumBudgetExceeded, match="no price configured"):
        guarded(0.3)

    assert qnode.calls == 0
    payload = _quantum_payloads(armor)[0]
    assert payload["event"] == "quantum_pricing_refused"
    assert payload["verdict"] == "block"
    assert payload["shots"] == 500
    assert payload["wires"] == 2
    assert payload["depth"] == 3
    assert payload["pricing_key"] == "ibm"
    assert armor.audit.verify_chain()
