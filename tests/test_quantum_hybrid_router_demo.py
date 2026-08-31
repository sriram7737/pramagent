import importlib.util
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

_GUARD_PATH = _REPO_ROOT / "examples" / "quantum" / "guarded_qnode.py"
_GUARD_SPEC = importlib.util.spec_from_file_location("guarded_qnode", _GUARD_PATH)
guarded_qnode = importlib.util.module_from_spec(_GUARD_SPEC)
assert _GUARD_SPEC.loader is not None
sys.modules[_GUARD_SPEC.name] = guarded_qnode
_GUARD_SPEC.loader.exec_module(guarded_qnode)

_ROUTER_PATH = _REPO_ROOT / "examples" / "quantum" / "hybrid_router_demo.py"
_ROUTER_SPEC = importlib.util.spec_from_file_location("hybrid_router_demo", _ROUTER_PATH)
hybrid_router_demo = importlib.util.module_from_spec(_ROUTER_SPEC)
assert _ROUTER_SPEC.loader is not None
sys.modules[_ROUTER_SPEC.name] = hybrid_router_demo
_ROUTER_SPEC.loader.exec_module(hybrid_router_demo)

GuardedQNode = guarded_qnode.GuardedQNode
make_quantum_policies = guarded_qnode.make_quantum_policies
HybridQuantumRouter = hybrid_router_demo.HybridQuantumRouter
DifficultyScore = hybrid_router_demo.DifficultyScore
StubDifficultyScorer = hybrid_router_demo.StubDifficultyScorer
from pramagent import Pramagent


class _Score:
    def __init__(self, value, reason="test"):
        self._value = value
        self._reason = reason

    def score(self, _query, _features=None):
        return DifficultyScore(self._value, self._reason)


class _Shots:
    def __init__(self, total_shots):
        self.total_shots = total_shots


class _Device:
    def __init__(self, name="default.qubit", shots=500):
        self.name = name
        self.shots = _Shots(shots)


class _QNode:
    def __init__(self, name="default.qubit", shots=500):
        self.device = _Device(name, shots)
        self.calls = 0

        def circuit(theta):
            return theta

        self.func = circuit

    def __call__(self, theta):
        self.calls += 1
        return {"path": "quantum", "theta": theta}


class _Resources:
    depth = 4
    num_wires = 4
    gate_types = {"RX": 4, "CNOT": 3}
    gate_sizes = {1: 4, 2: 3}
    num_gates = 7


def _specs(_qnode, *_args, **_kwargs):
    return {"resources": _Resources(), "num_trainable_params": 4, "num_observables": 4}


def _armor(
    *,
    max_shots_per_session=1_000,
    max_cost_usd_per_session=0.0,
    hardware_requires_approval=True,
):
    armor = Pramagent()
    for policy in make_quantum_policies(
        max_shots_per_call=500,
        max_shots_per_session=max_shots_per_session,
        max_cost_usd_per_session=max_cost_usd_per_session,
        hardware_requires_approval=hardware_requires_approval,
    ):
        armor.tool_guard.register(policy)
    return armor


def _router(armor, scorer, guarded):
    calls = {"classical": 0}

    def classical_fn(query, features):
        calls["classical"] += 1
        return {"path": "classical", "query": query, "features": features}

    def quantum_fn(_query, features):
        return guarded(features)

    router = HybridQuantumRouter(
        classical_fn=classical_fn,
        quantum_fn=quantum_fn,
        armor=armor,
        scorer=scorer,
        difficulty_threshold=0.7,
        quantum_meta_getter=lambda: guarded.last_event,
        session_id="s",
    )
    return router, calls


def _payloads(armor, source):
    return [
        rec["payload"] for rec in armor.audit.records()
        if rec["payload"].get("source") == source
    ]


def test_low_difficulty_uses_classical_and_audits_decision():
    armor = _armor()
    qnode = _QNode()
    guarded = GuardedQNode(qnode, armor, session_id="s", specs_func=_specs)
    router, calls = _router(armor, _Score(0.2, "easy"), guarded)

    result = router.route("clear caption request", 0.1)

    assert result.chosen_path == "classical"
    assert result.reason == "below_threshold"
    assert result.output["path"] == "classical"
    assert qnode.calls == 0
    assert calls["classical"] == 1
    decisions = _payloads(armor, "quantum_hybrid_router")
    assert decisions[-1]["chosen_path"] == "classical"
    assert decisions[-1]["difficulty_reason"] == "easy"
    assert armor.audit.verify_chain()


def test_high_difficulty_uses_guarded_quantum_when_budget_allows():
    armor = _armor()
    qnode = _QNode()
    guarded = GuardedQNode(qnode, armor, session_id="s", specs_func=_specs)
    router, calls = _router(armor, _Score(0.9, "hard"), guarded)

    result = router.route("ambiguous hard request", 0.4)

    assert result.chosen_path == "quantum"
    assert result.reason == "quantum_allowed"
    assert result.output["path"] == "quantum"
    assert qnode.calls == 1
    assert calls["classical"] == 0
    assert result.quantum_event == "quantum_call_executed"
    assert result.fingerprint
    assert result.input_hash
    decisions = _payloads(armor, "quantum_hybrid_router")
    assert decisions[-1]["chosen_path"] == "quantum"
    assert decisions[-1]["fingerprint"] == result.fingerprint
    assert armor.audit.verify_chain()


def test_quantum_budget_block_falls_back_to_classical_and_audits_guard_event():
    armor = _armor(max_shots_per_session=500)
    qnode = _QNode()
    guarded = GuardedQNode(qnode, armor, session_id="s", specs_func=_specs)
    router, calls = _router(armor, _Score(0.9, "forced-hard"), guarded)

    first = router.route("ambiguous hard request", 0.4)
    second = router.route("ambiguous hard request after budget", 0.6)

    assert first.chosen_path == "quantum"
    assert second.chosen_path == "classical"
    assert second.reason == "quantum_guard_fallback:QuantumBudgetExceeded"
    assert second.quantum_event == "quantum_call_blocked"
    assert qnode.calls == 1
    assert calls["classical"] == 1
    quantum_events = _payloads(armor, "quantum_adapter")
    assert [event["event"] for event in quantum_events] == [
        "quantum_call_executed",
        "quantum_call_blocked",
    ]
    assert armor.audit.verify_chain()


def test_quantum_escalation_falls_back_to_classical_without_hitl_consent():
    armor = _armor(
        hardware_requires_approval=True,
        max_cost_usd_per_session=2.0,
    )
    qnode = _QNode(name="braket.aws.quera", shots=100)
    guarded = GuardedQNode(
        qnode,
        armor,
        session_id="s",
        specs_func=_specs,
        provider_hint="braket",
    )
    router, calls = _router(armor, _Score(0.95, "hardware-path"), guarded)

    result = router.route("ambiguous hardware request", 0.3)

    assert result.chosen_path == "classical"
    assert result.reason == "quantum_guard_fallback:ApprovalRequired"
    assert result.quantum_event == "quantum_call_escalated"
    assert qnode.calls == 0
    assert calls["classical"] == 1
    assert armor.audit.verify_chain()


def test_router_uses_call_local_quantum_metadata_not_shared_log_tail():
    armor = _armor()
    qnode = _QNode()
    guarded = GuardedQNode(qnode, armor, tenant_id="tenant-b", session_id="b", specs_func=_specs)
    calls = {"classical": 0}

    def classical_fn(query, features):
        calls["classical"] += 1
        return {"path": "classical", "query": query, "features": features}

    def quantum_fn(_query, features):
        output = guarded(features)
        armor.audit.append({
            "source": "quantum_adapter",
            "event": "quantum_call_executed",
            "tenant_id": "tenant-a",
            "session_id": "a",
            "fingerprint": "foreign-fingerprint",
            "gate_list_hash": "foreign-gates",
            "input_hash": "foreign-input",
        })
        return output

    router = HybridQuantumRouter(
        classical_fn=classical_fn,
        quantum_fn=quantum_fn,
        armor=armor,
        scorer=_Score(0.9, "race"),
        difficulty_threshold=0.7,
        quantum_meta_getter=lambda: guarded.last_event,
        tenant_id="tenant-b",
        session_id="b",
    )

    result = router.route("ambiguous session b request", 0.5)

    assert result.chosen_path == "quantum"
    assert result.fingerprint == guarded.last_event["fingerprint"]
    assert result.fingerprint != "foreign-fingerprint"
    decisions = _payloads(armor, "quantum_hybrid_router")
    assert decisions[-1]["tenant_id"] == "tenant-b"
    assert decisions[-1]["fingerprint"] == guarded.last_event["fingerprint"]
    assert armor.audit.verify_chain()


def test_stub_difficulty_scorer_is_deterministic_and_labeled():
    scorer = StubDifficultyScorer()

    hard = scorer.score("ambiguous hard scene")
    easy = scorer.score("plain scene")

    assert hard.value >= 0.7
    assert hard.reason.startswith("stub_")
    assert easy.value < 0.7
    assert easy.reason.startswith("stub_")
