"""Governed hybrid classical/quantum routing demo for Pramagent.

The router is intentionally a governance example, not a quantum-advantage
claim. The difficulty scorer below is a labeled stub; production users should
replace it with a calibrated ambiguity or uncertainty signal from their model.

This demo serves a classical fallback when HITL approval would be required. A
deployment that wants humans in the loop can replace that policy with queueing.
If a post-execution result guard rejects a quantum result, the fallback still
costs quantum shots; the GuardedQNode audit event remains the spend record.
"""
from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal, Protocol

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pramagent import Pramagent

try:  # Support both direct script execution and package imports in tests.
    from .guarded_qnode import (
        ApprovalRequired,
        GuardedQNode,
        QuantumBudgetExceeded,
        QuantumPolicyViolation,
        make_quantum_policies,
    )
except ImportError:  # pragma: no cover
    from guarded_qnode import (  # type: ignore
        ApprovalRequired,
        GuardedQNode,
        QuantumBudgetExceeded,
        QuantumPolicyViolation,
        make_quantum_policies,
    )

RoutePath = Literal["classical", "quantum"]
InferenceFn = Callable[[str, Any], Any]


@dataclass(frozen=True)
class DifficultyScore:
    value: float
    reason: str


class DifficultyScorer(Protocol):
    """Pluggable interface for a real model uncertainty or ambiguity signal."""

    def score(self, query: str, features: Any = None) -> DifficultyScore:
        ...


@dataclass(frozen=True)
class StubDifficultyScorer:
    """Deterministic demo scorer.

    This is a placeholder so the Pramagent example can demonstrate governed
    routing without claiming that keyword/length heuristics detect semantic
    difficulty. Replace it with an adapter-owned scorer for real experiments.
    """

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


@dataclass(frozen=True)
class RouterResult:
    output: Any
    chosen_path: RoutePath
    difficulty: float
    reason: str
    quantum_event: str = ""
    fingerprint: str = ""
    gate_list_hash: str = ""
    input_hash: str = ""


class HybridQuantumRouter:
    """Route difficult inputs to a guarded quantum path when policy allows it."""

    def __init__(
        self,
        *,
        classical_fn: InferenceFn,
        quantum_fn: InferenceFn,
        armor: Pramagent,
        scorer: DifficultyScorer | None = None,
        difficulty_threshold: float = 0.7,
        quantum_meta_getter: Callable[[], dict[str, Any]] | None = None,
        tenant_id: str = "default",
        session_id: str = "default",
    ) -> None:
        self.classical_fn = classical_fn
        self.quantum_fn = quantum_fn
        self.armor = armor
        self.scorer = scorer or StubDifficultyScorer()
        self.difficulty_threshold = float(difficulty_threshold)
        self.quantum_meta_getter = quantum_meta_getter
        self.tenant_id = tenant_id
        self.session_id = session_id

    def route(self, query: str, features: Any = None) -> RouterResult:
        score = self.scorer.score(query, features)
        if score.value < self.difficulty_threshold:
            output = self.classical_fn(query, features)
            return self._finish(
                query=query,
                output=output,
                chosen_path="classical",
                score=score,
                reason="below_threshold",
            )

        try:
            output = self.quantum_fn(query, features)
        except (ApprovalRequired, QuantumBudgetExceeded, QuantumPolicyViolation) as exc:
            output = self.classical_fn(query, features)
            quantum_meta = self._quantum_meta()
            return self._finish(
                query=query,
                output=output,
                chosen_path="classical",
                score=score,
                reason=f"quantum_guard_fallback:{exc.__class__.__name__}",
                quantum_meta=quantum_meta,
            )

        quantum_meta = self._quantum_meta()
        return self._finish(
            query=query,
            output=output,
            chosen_path="quantum",
            score=score,
            reason="quantum_allowed",
            quantum_meta=quantum_meta,
        )

    def _finish(
        self,
        *,
        query: str,
        output: Any,
        chosen_path: RoutePath,
        score: DifficultyScore,
        reason: str,
        quantum_meta: dict[str, Any] | None = None,
    ) -> RouterResult:
        quantum_meta = quantum_meta or {}
        result = RouterResult(
            output=output,
            chosen_path=chosen_path,
            difficulty=score.value,
            reason=reason,
            quantum_event=str(quantum_meta.get("event", "")),
            fingerprint=str(quantum_meta.get("fingerprint", "")),
            gate_list_hash=str(quantum_meta.get("gate_list_hash", "")),
            input_hash=str(quantum_meta.get("input_hash", "")),
        )
        self.armor.audit.append({
            "source": "quantum_hybrid_router",
            "event": "hybrid_route_decision",
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "query_id": hashlib.sha256(query.encode("utf-8")).hexdigest()[:16],
            "chosen_path": result.chosen_path,
            "difficulty": result.difficulty,
            "difficulty_reason": score.reason,
            "reason": result.reason,
            "quantum_event": result.quantum_event,
            "fingerprint": result.fingerprint,
            "gate_list_hash": result.gate_list_hash,
            "input_hash": result.input_hash,
        })
        return result

    def _quantum_meta(self) -> dict[str, Any]:
        if self.quantum_meta_getter is None:
            return {}
        return dict(self.quantum_meta_getter() or {})


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
        quantum_meta_getter=lambda: guarded.last_event,
        session_id="hybrid-demo",
    )


if __name__ == "__main__":  # pragma: no cover - manual demo
    router = build_demo_router()
    for query, feature in (
        ("clear image of a cup", 0.2),
        ("ambiguous image with hard occlusion", 0.4),
        ("another ambiguous hard case after budget is spent", 0.6),
    ):
        result = router.route(query, feature)
        print(result)
    print("chain_valid", router.armor.audit.verify_chain())
