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
# Register before exec so @dataclass can resolve `from __future__ import
# annotations` field types via sys.modules[cls.__module__].
sys.modules[_SPEC.name] = guarded_qnode_example
_SPEC.loader.exec_module(guarded_qnode_example)

ApprovalRequired = guarded_qnode_example.ApprovalRequired
GuardedQNode = guarded_qnode_example.GuardedQNode
QuantumBudgetExceeded = guarded_qnode_example.QuantumBudgetExceeded
QuantumPolicyViolation = guarded_qnode_example.QuantumPolicyViolation
InputPolicy = guarded_qnode_example.InputPolicy
CircuitPolicy = guarded_qnode_example.CircuitPolicy
ResultPolicy = guarded_qnode_example.ResultPolicy
make_quantum_policies = guarded_qnode_example.make_quantum_policies
from pramagent import Pramagent, SideEffect, Verdict
from pramagent.conformance import is_read_only_side_effect


class _StructuredResources:
    """Resources shaped like qml.specs()[...].resources: gate_types is a
    name->count map, gate_sizes maps qubits-per-gate to count."""
    def __init__(self, gate_types=None, gate_sizes=None, depth=3, num_wires=2):
        self.gate_types = gate_types or {"Hadamard": 1, "CNOT": 1}
        self.gate_sizes = gate_sizes or {1: 1, 2: 1}
        self.depth = depth
        self.num_wires = num_wires
        self.num_gates = sum(self.gate_types.values())


class _CurrentPennyLaneResources:
    """PennyLane 0.45 SpecsResources exposes num_allocs and measurements."""
    gate_types = {"RX": 4, "RY": 4, "CNOT": 3}
    gate_sizes = {1: 8, 2: 3}
    measurements = {"expval(PauliZ)": 4}
    num_allocs = 4
    depth = 5
    num_gates = 11


def _structured_specs(specs_dict):
    def _f(_qnode, *_args, **_kwargs):
        return specs_dict
    return _f


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
        self.executed_shots = None

        def circuit(theta, shots=None):
            return theta

        self.func = circuit

    def __call__(self, theta, shots=None):
        # PennyLane honors a call-time shots override; record what actually ran.
        self.calls += 1
        self.executed_shots = (
            shots if shots is not None else self.device.shots.total_shots
        )
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


def test_call_time_shots_override_is_metered_before_execution():
    # F1: a call-time shots= override must be metered (and blocked) against the
    # per-call budget, not silently executed while the device default is priced.
    armor = _armor(max_shots_per_call=100, max_shots_per_session=10_000)
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(qnode, armor, session_id="s", specs_func=_specs)

    with pytest.raises(QuantumBudgetExceeded):
        guarded(0.3, shots=5_000)

    assert qnode.calls == 0                 # never executed
    assert qnode.executed_shots is None
    payload = _quantum_payloads(armor)[0]
    assert payload["event"] == "quantum_call_blocked"
    assert payload["shots"] == 5_000        # metered the override, not the default
    assert armor.audit.verify_chain()


def test_call_time_shots_override_within_budget_is_metered_correctly():
    # F1 (allow path): an in-budget override is metered at the override value.
    armor = _armor(max_shots_per_call=500, max_shots_per_session=10_000)
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(qnode, armor, session_id="s", specs_func=_specs)

    guarded(0.3, shots=300)

    assert qnode.executed_shots == 300
    payload = _quantum_payloads(armor)[0]
    assert payload["event"] == "quantum_call_executed"
    assert payload["shots"] == 300
    assert payload["session_shots_after"] == 300


def test_session_budget_shared_across_adapter_instances():
    # F2: session shot budget survives re-wrapping the same (tenant, session)
    # with a fresh adapter instance — it is derived from the audit trail, not
    # from volatile per-instance memory.
    armor = _armor(max_shots_per_session=150)
    qnode = _QNode(shots=100)
    g1 = GuardedQNode(qnode, armor, tenant_id="t", session_id="sess", specs_func=_specs)
    g1(0.1)

    g2 = GuardedQNode(qnode, armor, tenant_id="t", session_id="sess", specs_func=_specs)
    with pytest.raises(QuantumBudgetExceeded):
        g2(0.2)                             # 100 + 100 = 200 > 150, still enforced

    assert qnode.calls == 1
    payloads = _quantum_payloads(armor)
    assert [p["event"] for p in payloads] == [
        "quantum_call_executed",
        "quantum_call_blocked",
    ]
    assert payloads[-1]["session_shots_after"] == 200


def test_hardware_name_with_simulator_prefix_is_not_free():
    # F3: a hardware provider token forces a hardware classification even under
    # a simulator-looking prefix, so the call is priced and escalated.
    armor = _armor(max_cost=10_000.0)
    qnode = _QNode(name="default.ionq_forte", shots=500)
    guarded = GuardedQNode(qnode, armor, session_id="s", specs_func=_specs)

    with pytest.raises(ApprovalRequired):
        guarded(0.3)

    assert qnode.calls == 0
    payload = _quantum_payloads(armor)[0]
    assert payload["event"] == "quantum_call_escalated"
    assert payload["device_kind"] == "hardware"
    assert payload["pricing_key"] == "braket:ionq"
    assert payload["est_cost_usd"] > 0


def test_unparseable_shot_count_fails_closed():
    # F4: an uninterpretable shot count is refused, not metered as zero.
    armor = _armor(max_cost=10_000.0)
    qnode = _QNode(name="braket:ionq:forte", shots=500)
    qnode.device.shots = object()           # opaque: no total_shots, not int()-able
    guarded = GuardedQNode(qnode, armor, session_id="s", specs_func=_specs)

    with pytest.raises(QuantumBudgetExceeded, match="could not determine shot count"):
        guarded(0.3)

    assert qnode.calls == 0
    payload = _quantum_payloads(armor)[0]
    assert payload["event"] == "quantum_shots_unparseable"
    assert payload["verdict"] == "block"
    assert armor.audit.verify_chain()


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


# == Measured metering + estimate-vs-actual reconciliation =====================

def _meter_x(multiplier, executions=3):
    """Stub meter: reports actual shots = device_shots * multiplier, modeling
    gradient/mitigation execution multiplicity a single-circuit estimate misses.
    Mirrors the (result, {"shots", "executions"}) contract of the real
    pennylane_tracker_meter."""
    def _meter(qnode, *args, **kwargs):
        result = qnode(*args, **kwargs)
        device_shots = qnode.device.shots.total_shots
        return result, {"shots": device_shots * multiplier, "executions": executions}
    return _meter


def test_reconciliation_records_measured_vs_estimated():
    armor = _armor(max_shots_per_call=500, max_shots_per_session=10_000)
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(
        qnode, armor, session_id="s", specs_func=_specs, meter_func=_meter_x(3),
    )

    guarded(0.3)

    payloads = _quantum_payloads(armor)
    assert [p["event"] for p in payloads] == [
        "quantum_call_executed",
        "quantum_cost_reconciled",
    ]
    recon = payloads[-1]
    assert recon["est_shots"] == 100
    assert recon["actual_shots"] == 300          # 3x multiplicity
    assert recon["shots_variance"] == 200
    assert recon["actual_executions"] == 3
    assert recon["over_estimate"] is True
    assert armor.audit.verify_chain()


def test_reconciled_actual_drives_session_budget():
    # Budget must accrue MEASURED spend, not the single-circuit estimate:
    # with 2x multiplicity a second call that would fit the estimate is blocked.
    armor = _armor(max_shots_per_call=500, max_shots_per_session=1_000)
    qnode = _QNode(shots=400)
    guarded = GuardedQNode(
        qnode, armor, session_id="s", specs_func=_specs, meter_func=_meter_x(2),
    )

    guarded(0.1)                                  # est 400, actual 800 (reconciled)
    with pytest.raises(QuantumBudgetExceeded):
        guarded(0.2)                              # 800 + 400 = 1200 > 1000 -> block

    assert qnode.calls == 1
    events = [p["event"] for p in _quantum_payloads(armor)]
    assert events == [
        "quantum_call_executed",
        "quantum_cost_reconciled",
        "quantum_call_blocked",
    ]
    # estimate-only would have counted 400 and allowed the second call
    assert armor.audit.verify_chain()


def test_no_meter_func_keeps_estimate_only_behavior():
    armor = _armor(max_shots_per_call=500, max_shots_per_session=10_000)
    qnode = _QNode(shots=400)
    guarded = GuardedQNode(qnode, armor, session_id="s", specs_func=_specs)

    guarded(0.1)

    events = [p["event"] for p in _quantum_payloads(armor)]
    assert events == ["quantum_call_executed"]    # no reconciliation event
    assert _quantum_payloads(armor)[0]["session_shots_after"] == 400


# == Input Summary Guard (item 1) ==============================================

def test_input_guard_rejects_non_finite_before_specs():
    armor = _armor()
    qnode = _QNode(shots=100)
    specs_seen = {"called": False}

    def _tracking_specs(_q, *_a, **_k):
        specs_seen["called"] = True
        return {"resources": _Resources()}

    guarded = GuardedQNode(
        qnode, armor, session_id="s", specs_func=_tracking_specs,
        input_policy=InputPolicy(require_finite=True),
    )

    with pytest.raises(QuantumPolicyViolation, match="non-finite"):
        guarded(float("nan"))

    assert qnode.calls == 0
    assert specs_seen["called"] is False        # rejected BEFORE circuit build
    payload = _quantum_payloads(armor)[0]
    assert payload["event"] == "quantum_input_rejected"
    assert payload["verdict"] == "block"
    assert armor.audit.verify_chain()


def test_input_guard_rejects_oversized_batch():
    armor = _armor()
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(
        qnode, armor, session_id="s", specs_func=_specs,
        input_policy=InputPolicy(max_batch_size=8),
    )
    with pytest.raises(QuantumPolicyViolation, match="batch size"):
        guarded([0.1] * 16)
    assert qnode.calls == 0


def test_input_guard_rejects_out_of_range_angle():
    armor = _armor()
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(
        qnode, armor, session_id="s", specs_func=_specs,
        input_policy=InputPolicy(angle_min=-3.15, angle_max=3.15),
    )
    with pytest.raises(QuantumPolicyViolation, match="angle_max"):
        guarded(10.0)
    assert qnode.calls == 0


def test_input_guard_rejects_disallowed_dtype():
    np = pytest.importorskip("numpy")
    armor = _armor()
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(
        qnode, armor, session_id="s", specs_func=_specs,
        input_policy=InputPolicy(allowed_dtypes={"float32", "float64"}),
    )
    with pytest.raises(QuantumPolicyViolation, match="dtype"):
        guarded(np.array([1, 2, 3], dtype=np.int8))
    assert qnode.calls == 0


def test_input_guard_allows_clean_input():
    armor = _armor()
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(
        qnode, armor, session_id="s", specs_func=_specs,
        input_policy=InputPolicy(require_finite=True, angle_min=-3.15,
                                 angle_max=3.15, max_batch_size=32),
    )
    assert guarded(0.3) == {"value": 0.3}
    assert qnode.calls == 1
    assert _quantum_payloads(armor)[0]["event"] == "quantum_call_executed"


# == Circuit Structure Guard (item 2) =========================================

def _struct_specs(**overrides):
    res = _StructuredResources(
        gate_types=overrides.pop("gate_types", {"Hadamard": 1, "CNOT": 2, "Toffoli": 1}),
        gate_sizes=overrides.pop("gate_sizes", {1: 1, 2: 2, 3: 1}),
        depth=overrides.pop("depth", 4),
        num_wires=overrides.pop("num_wires", 3),
    )
    for k, v in overrides.pop("res_attrs", {}).items():
        setattr(res, k, v)
    specs = {"resources": res}
    specs.update(overrides)
    return _structured_specs(specs)


def test_circuit_guard_blocks_disallowed_gate():
    armor = _armor()
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(
        qnode, armor, session_id="s", specs_func=_struct_specs(),
        circuit_policy=CircuitPolicy(disallowed_gates={"Toffoli"}),
    )
    with pytest.raises(QuantumPolicyViolation, match="disallowed gate"):
        guarded(0.3)
    assert qnode.calls == 0
    payload = _quantum_payloads(armor)[0]
    assert payload["event"] == "quantum_structure_rejected"
    assert payload["gate_list_hash"]            # fingerprint recorded on reject
    assert armor.audit.verify_chain()


def test_circuit_guard_enforces_gate_allowlist():
    armor = _armor()
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(
        qnode, armor, session_id="s", specs_func=_struct_specs(),
        circuit_policy=CircuitPolicy(allowed_gates={"Hadamard", "CNOT"}),
    )
    with pytest.raises(QuantumPolicyViolation, match="allow-list"):
        guarded(0.3)
    assert qnode.calls == 0


def test_circuit_guard_caps_entanglers():
    armor = _armor()
    qnode = _QNode(shots=100)
    # gate_sizes {1:1, 2:2, 3:1} -> entanglers (size>=2) = 3
    guarded = GuardedQNode(
        qnode, armor, session_id="s", specs_func=_struct_specs(),
        circuit_policy=CircuitPolicy(max_entanglers=2),
    )
    with pytest.raises(QuantumPolicyViolation, match="entangler"):
        guarded(0.3)
    assert qnode.calls == 0
    assert _quantum_payloads(armor)[0]["num_entanglers"] == 3


def test_circuit_guard_reads_current_pennylane_wires_and_measurements():
    armor = _armor()
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(
        qnode, armor, session_id="s",
        specs_func=_structured_specs({
            "resources": _CurrentPennyLaneResources(),
            "num_device_wires": 4,
        }),
        circuit_policy=CircuitPolicy(max_wires=3, max_measurements=3),
    )
    with pytest.raises(QuantumPolicyViolation, match="wire count 4"):
        guarded(0.3)
    assert qnode.calls == 0
    payload = _quantum_payloads(armor)[0]
    assert payload["num_measurements"] == 4


def test_circuit_guard_caps_trainable_params():
    armor = _armor()
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(
        qnode, armor, session_id="s",
        specs_func=_struct_specs(num_trainable_params=5),
        circuit_policy=CircuitPolicy(max_trainable_params=3),
    )
    with pytest.raises(QuantumPolicyViolation, match="trainable"):
        guarded(0.3)
    assert qnode.calls == 0


def test_circuit_guard_blocks_mid_circuit_measurements():
    armor = _armor()
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(
        qnode, armor, session_id="s",
        specs_func=_struct_specs(res_attrs={"num_mid_circuit_measurements": 1}),
        circuit_policy=CircuitPolicy(allow_mid_circuit_measurements=False),
    )
    with pytest.raises(QuantumPolicyViolation, match="mid-circuit"):
        guarded(0.3)
    assert qnode.calls == 0


def test_circuit_guard_allows_conforming_circuit():
    armor = _armor()
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(
        qnode, armor, session_id="s", specs_func=_struct_specs(),
        circuit_policy=CircuitPolicy(
            allowed_gates={"Hadamard", "CNOT", "Toffoli"},
            max_entanglers=5, max_depth=10, max_wires=8,
        ),
    )
    assert guarded(0.3) == {"value": 0.3}
    assert qnode.calls == 1


# == Result Sanity Guard (item 4) =============================================

def test_result_guard_rejects_out_of_range_expval():
    armor = _armor(max_shots_per_call=500)
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(
        qnode, armor, session_id="s", specs_func=_specs,
        result_policy=ResultPolicy(min_value=-1.0, max_value=1.0),
    )
    with pytest.raises(QuantumPolicyViolation, match="result max"):
        guarded(5.0)                            # returns {"value": 5.0}

    assert qnode.calls == 1                     # executed (shots already spent)
    events = [p["event"] for p in _quantum_payloads(armor)]
    assert events == ["quantum_call_executed", "quantum_result_rejected"]
    # spend was still counted for the real execution
    assert _quantum_payloads(armor)[0]["session_shots_after"] == 100


def test_result_guard_rejects_non_finite_result():
    armor = _armor()
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(
        qnode, armor, session_id="s", specs_func=_specs,
        result_policy=ResultPolicy(require_finite=True),
    )
    with pytest.raises(QuantumPolicyViolation, match="non-finite"):
        guarded(float("nan"))                   # returns {"value": nan}
    assert qnode.calls == 1


# == Replayable fingerprint (item 7) ==========================================

def test_fingerprint_is_recorded_and_deterministic():
    armor = _armor()
    qnode = _QNode(shots=100)
    guarded = GuardedQNode(qnode, armor, session_id="s", specs_func=_struct_specs())

    guarded(0.3)
    guarded(0.3)                                # identical call
    guarded(0.7)                                # different weights

    payloads = _quantum_payloads(armor)
    for p in payloads:
        assert p["fingerprint"]
        assert p["gate_list_hash"]
        assert p["input_hash"]
    # same circuit + same inputs -> identical fingerprint
    assert payloads[0]["fingerprint"] == payloads[1]["fingerprint"]
    # changed weights -> different input hash -> different fingerprint
    assert payloads[0]["input_hash"] != payloads[2]["input_hash"]
    assert payloads[0]["fingerprint"] != payloads[2]["fingerprint"]
    # circuit identity (gate list) is stable across the weight change
    assert payloads[0]["gate_list_hash"] == payloads[2]["gate_list_hash"]
