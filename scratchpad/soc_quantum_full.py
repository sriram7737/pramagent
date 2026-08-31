"""
SOC adversarial harness v2  -  budget guards (A-series) + policy guards (B-series).

Every scenario runs the real guard and reports HELD (enforced) or BYPASS.
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path("C:/Users/srira/OneDrive/Desktop/veritrace")
sys.path.insert(0, str(ROOT))
MOD = ROOT / "examples" / "quantum" / "guarded_qnode.py"
spec = importlib.util.spec_from_file_location("gq", MOD)
gq = importlib.util.module_from_spec(spec)
sys.modules["gq"] = gq
spec.loader.exec_module(gq)

from pramagent import Pramagent

G = gq.GuardedQNode
mk = gq.make_quantum_policies
Budget = gq.QuantumBudgetExceeded
Approval = gq.ApprovalRequired
Policy = gq.QuantumPolicyViolation
InputPolicy = gq.InputPolicy
CircuitPolicy = gq.CircuitPolicy
ResultPolicy = gq.ResultPolicy


def armor(**kw):
    a = Pramagent()
    for pol in mk(**kw):
        a.tool_guard.register(pol)
    return a


def qpay(a):
    return [r["payload"] for r in a.audit.records()
            if r["payload"].get("source") == "quantum_adapter"]


class QN:
    class _S:
        def __init__(s, n): s.total_shots = n
    class _D:
        def __init__(s, name, n): s.name = name; s.shots = QN._S(n)
    def __init__(self, name="default.qubit", device_shots=100, result=None):
        self.device = self._D(name, device_shots)
        self.executed_with_shots = None
        self._result = result
        def circuit(theta, shots=None): return theta
        self.func = circuit
    def __call__(self, theta, shots=None):
        self.executed_with_shots = shots if shots is not None else self.device.shots.total_shots
        if self._result is not None:
            return self._result
        return {"value": theta}


def res(gate_types=None, gate_sizes=None, depth=2, wires=2, **attrs):
    class R: pass
    r = R()
    r.gate_types = gate_types or {"Hadamard": 1, "CNOT": 1}
    r.gate_sizes = gate_sizes or {1: 1, 2: 1}
    r.depth = depth
    r.num_wires = wires
    for k, v in attrs.items():
        setattr(r, k, v)
    return r


def specs_of(resources, **top):
    def _f(_q, *_a, **_k):
        d = {"resources": resources}
        d.update(top)
        return d
    return _f


plain_specs = specs_of(res())

results = []
def rec(gid, name, held, detail):
    results.append((gid, held))
    print("[" + ("HELD  " if held else "BYPASS") + "] " + gid + "  " + name)
    print("         " + detail)


print("=" * 78)
print("SOC ADVERSARIAL HARNESS v2  budget + policy guards")
print("=" * 78)

# ---------- A-series: budget (regression from v1) ----------
a = armor(max_shots_per_call=100)
qn = QN(device_shots=100)
g = G(qn, a, session_id="s", specs_func=plain_specs)
try:
    g(0.3, shots=5_000_000)
    rec("A1", "call-time shots override vs per-call budget",
        qn.executed_with_shots is None, "executed=" + str(qn.executed_with_shots))
except (Budget, Approval):
    rec("A1", "call-time shots override vs per-call budget", True, "blocked before execution")

a = armor(max_shots_per_call=1000, max_cost_usd_per_session=0.0)
qn = QN(name="default.ionq_forte_hw", device_shots=500)
g = G(qn, a, session_id="s", specs_func=plain_specs)
ran = False
try:
    g(0.3); ran = True
except (Approval, Budget):
    pass
p = qpay(a)[-1]
rec("A4", "hardware masked by simulator prefix",
    not (ran and p["device_kind"] == "simulator"),
    "kind=" + p["device_kind"] + " pricing=" + p["pricing_key"] + " ran=" + str(ran))

# ---------- B-series: policy guards ----------

# B1: NaN tensor
a = armor()
qn = QN(device_shots=100)
g = G(qn, a, session_id="s", specs_func=plain_specs, input_policy=InputPolicy(require_finite=True))
try:
    g(float("nan")); rec("B1", "NaN tensor input", qn.executed_with_shots is None, "executed")
except Policy as e:
    rec("B1", "NaN tensor input", True, str(e))

# B2: oversized batch
a = armor()
qn = QN(device_shots=100)
g = G(qn, a, session_id="s", specs_func=plain_specs, input_policy=InputPolicy(max_batch_size=8))
try:
    g([0.1] * 64); rec("B2", "oversized batch", qn.executed_with_shots is None, "executed")
except Policy as e:
    rec("B2", "oversized batch (64 > 8)", True, str(e))

# B3: weird dtype
import numpy as np
a = armor()
qn = QN(device_shots=100)
g = G(qn, a, session_id="s", specs_func=plain_specs,
      input_policy=InputPolicy(allowed_dtypes={"float32", "float64"}))
try:
    g(np.array([1, 2, 3], dtype=np.int8))
    rec("B3", "disallowed dtype (int8)", qn.executed_with_shots is None, "executed")
except Policy as e:
    rec("B3", "disallowed dtype (int8)", True, str(e))

# B4: out-of-range angle
a = armor()
qn = QN(device_shots=100)
g = G(qn, a, session_id="s", specs_func=plain_specs,
      input_policy=InputPolicy(angle_min=-3.15, angle_max=3.15))
try:
    g(100.0); rec("B4", "angle out of range", qn.executed_with_shots is None, "executed")
except Policy as e:
    rec("B4", "angle out of range (100 rad)", True, str(e))

# B5: unexpected gate
a = armor()
qn = QN(device_shots=100)
sp = specs_of(res(gate_types={"Hadamard": 1, "CNOT": 1, "QubitUnitary": 1},
                  gate_sizes={1: 1, 2: 2}))
g = G(qn, a, session_id="s", specs_func=sp,
      circuit_policy=CircuitPolicy(allowed_gates={"Hadamard", "CNOT", "RX", "RY", "RZ"}))
try:
    g(0.3); rec("B5", "unexpected gate (QubitUnitary)", qn.executed_with_shots is None, "executed")
except Policy as e:
    rec("B5", "unexpected gate (QubitUnitary)", True, str(e))

# B6: unbounded depth
a = armor()
qn = QN(device_shots=100)
sp = specs_of(res(depth=100000))
g = G(qn, a, session_id="s", specs_func=sp, circuit_policy=CircuitPolicy(max_depth=50))
try:
    g(0.3); rec("B6", "unbounded circuit depth", qn.executed_with_shots is None, "executed")
except Policy as e:
    rec("B6", "unbounded depth (100000 > 50)", True, str(e))

# B7: mid-circuit measurement injected
a = armor()
qn = QN(device_shots=100)
sp = specs_of(res(num_mid_circuit_measurements=3))
g = G(qn, a, session_id="s", specs_func=sp,
      circuit_policy=CircuitPolicy(allow_mid_circuit_measurements=False))
try:
    g(0.3); rec("B7", "mid-circuit measurement", qn.executed_with_shots is None, "executed")
except Policy as e:
    rec("B7", "mid-circuit measurement injected", True, str(e))

# B8: result outside expected range
a = armor(max_shots_per_call=500)
qn = QN(device_shots=100, result={"expval": 42.0})
g = G(qn, a, session_id="s", specs_func=plain_specs,
      result_policy=ResultPolicy(min_value=-1.0, max_value=1.0))
try:
    g(0.3)
    rec("B8", "result outside [-1,1]", False, "returned out-of-range result to caller")
except Policy as e:
    evs = [x["event"] for x in qpay(a)]
    rec("B8", "result outside [-1,1] (expval=42)",
        "quantum_result_rejected" in evs, str(e))

# B9: changed weights hash (drift signal)
a = armor()
qn = QN(device_shots=100)
g = G(qn, a, session_id="s", specs_func=plain_specs)
g(0.3); g(0.3); g(0.9)
ps = qpay(a)
same = ps[0]["input_hash"] == ps[1]["input_hash"]
drift = ps[0]["input_hash"] != ps[2]["input_hash"]
rec("B9", "weight/input drift visible in fingerprint",
    same and drift,
    "identical-call hashes match=" + str(same) + ", drifted-call differs=" + str(drift) +
    ", fingerprint recorded=" + str(bool(ps[0]["fingerprint"])))

# B11 / B12: PennyLane 0.45 specs shape (num_allocs for wires, measurements
# dict for measurements). With the pre-fix extractor these read as 0/None so
# max_wires / max_measurements were silently ineffective against real qml.specs.
class R045:
    gate_types = {"RX": 4, "RY": 4, "CNOT": 3}
    gate_sizes = {1: 8, 2: 3}
    measurements = {"expval(PauliZ)": 4}
    num_allocs = 4
    depth = 5
    num_gates = 11

a = armor()
qn = QN(device_shots=100)
g = G(qn, a, session_id="s", specs_func=specs_of(R045()),
      circuit_policy=CircuitPolicy(max_wires=2))
try:
    g(0.3)
    rec("B11", "PennyLane-0.45 wires via num_allocs vs max_wires",
        qn.executed_with_shots is None, "executed (num_allocs not read)")
except Policy as e:
    rec("B11", "PennyLane-0.45 wires via num_allocs (4 > max_wires 2)", True, str(e))

a = armor()
qn = QN(device_shots=100)
g = G(qn, a, session_id="s", specs_func=specs_of(R045()),
      circuit_policy=CircuitPolicy(max_measurements=2))
try:
    g(0.3)
    rec("B12", "PennyLane-0.45 measurements dict vs max_measurements",
        qn.executed_with_shots is None, "executed (measurements not read)")
except Policy as e:
    rec("B12", "PennyLane-0.45 measurements dict (4 > max_measurements 2)", True, str(e))

# B13: audit chain intact
rec("B13", "audit chain verifiable after policy attacks", a.audit.verify_chain(),
    "verify_chain()=" + str(a.audit.verify_chain()))

print("=" * 78)
bypasses = [g for g, held in results if not held]
print("SUMMARY: " + str(len(results)) + " scenarios, " + str(len(bypasses)) + " BYPASS(es).")
print("=" * 78)
