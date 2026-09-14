"""Governed hybrid routing demo with an explicitly synthetic difficulty score.

The reusable router is packaged in ``pramagent.quantum``. This example supplies
a deterministic scorer and tiny inference functions so the routing and budget
behavior can run without a VLM download. It is not a quantum-advantage claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pramagent import Pramagent
from pramagent.quantum import DifficultyScore, HybridQuantumRouter
from pramagent.quantum.guarded_qnode import GuardedQNode, make_quantum_policies


@dataclass(frozen=True)
class StubDifficultyScorer:
    """Demo-only keyword scorer; replace it with a calibrated model signal."""

    threshold_hint: float = 0.8
    hard_keywords: tuple[str, ...] = ("ambiguous", "hard", "uncertain", "edge")
    length_threshold: int = 120

    def score(self, query: str, features: Any = None) -> DifficultyScore:
        lowered = query.lower()
        if any(token in lowered for token in self.hard_keywords):
            return DifficultyScore(self.threshold_hint, "stub_keyword_match")
        if len(query) >= self.length_threshold:
            return DifficultyScore(self.threshold_hint, "stub_length_threshold")
        return DifficultyScore(0.1, "stub_default_easy")


class _DemoShots:
    total_shots = 500


class _DemoDevice:
    name = "default.qubit"
    shots = _DemoShots()


class _DemoQNode:
    device = _DemoDevice()

    def __init__(self) -> None:
        def caption_projection(theta):
            return theta

        self.func = caption_projection

    def __call__(self, theta):
        return {"caption": f"quantum-refined score={round(float(theta), 3)}"}


def _demo_specs(_qnode, *_args, **_kwargs):
    class Resources:
        depth = 4
        num_wires = 4
        gate_types = {"RX": 4, "CNOT": 3}
        gate_sizes = {1: 4, 2: 3}
        num_gates = 7

    return {"resources": Resources(), "num_trainable_params": 4, "num_observables": 4}


def build_demo_router() -> HybridQuantumRouter:
    armor = Pramagent()
    for policy in make_quantum_policies(
        max_shots_per_call=500,
        max_shots_per_session=500,
    ):
        armor.tool_guard.register(policy)
    guarded = GuardedQNode(
        _DemoQNode(),
        armor,
        session_id="hybrid-demo",
        specs_func=_demo_specs,
        joules_per_shot=0.001,
    )

    def classical_fn(query: str, features: Any) -> dict[str, str]:
        return {"caption": f"classical caption for {query[:24]}"}

    def quantum_fn(_query: str, features: Any) -> Any:
        return guarded(features)

    return HybridQuantumRouter(
        classical_fn=classical_fn,
        quantum_fn=quantum_fn,
        armor=armor,
        scorer=StubDifficultyScorer(),
        quantum_meta_getter=lambda: guarded.last_event,
        session_id="hybrid-demo",
    )


if __name__ == "__main__":
    router = build_demo_router()
    for query, feature in (
        ("clear image of a cup", 0.2),
        ("ambiguous image with hard occlusion", 0.4),
        ("another ambiguous hard case after budget is spent", 0.6),
    ):
        print(router.route(query, feature))
    print("chain_valid", router.armor.audit.verify_chain())
