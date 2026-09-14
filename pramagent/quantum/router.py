"""Governed routing between classical and quantum inference functions."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Literal, Protocol

from pramagent import Pramagent

from .guarded_qnode import ApprovalRequired, QuantumBudgetExceeded, QuantumPolicyViolation

RoutePath = Literal["classical", "quantum"]
InferenceFn = Callable[[str, Any], Any]


@dataclass(frozen=True)
class DifficultyScore:
    value: float
    reason: str


class DifficultyScorer(Protocol):
    def score(self, query: str, features: Any = None) -> DifficultyScore:
        """Return a calibrated score in the closed interval [0, 1]."""


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
    """Use quantum inference only for difficult inputs allowed by policy."""

    def __init__(
        self,
        *,
        classical_fn: InferenceFn,
        quantum_fn: InferenceFn,
        armor: Pramagent,
        scorer: DifficultyScorer,
        difficulty_threshold: float = 0.7,
        quantum_meta_getter: Callable[[], dict[str, Any]] | None = None,
        tenant_id: str = "default",
        session_id: str = "default",
    ) -> None:
        if not 0.0 <= difficulty_threshold <= 1.0:
            raise ValueError("difficulty_threshold must be between 0 and 1")
        self.classical_fn = classical_fn
        self.quantum_fn = quantum_fn
        self.armor = armor
        self.scorer = scorer
        self.difficulty_threshold = float(difficulty_threshold)
        self.quantum_meta_getter = quantum_meta_getter
        self.tenant_id = tenant_id
        self.session_id = session_id

    def route(self, query: str, features: Any = None) -> RouterResult:
        score = self.scorer.score(query, features)
        if not 0.0 <= score.value <= 1.0:
            raise ValueError("difficulty scorer returned a value outside [0, 1]")
        if score.value < self.difficulty_threshold:
            return self._finish(
                query=query,
                output=self.classical_fn(query, features),
                chosen_path="classical",
                score=score,
                reason="below_threshold",
            )

        try:
            output = self.quantum_fn(query, features)
        except (ApprovalRequired, QuantumBudgetExceeded, QuantumPolicyViolation) as error:
            return self._finish(
                query=query,
                output=self.classical_fn(query, features),
                chosen_path="classical",
                score=score,
                reason=f"quantum_guard_fallback:{error.__class__.__name__}",
                quantum_meta=self._quantum_meta(),
            )
        return self._finish(
            query=query,
            output=output,
            chosen_path="quantum",
            score=score,
            reason="quantum_allowed",
            quantum_meta=self._quantum_meta(),
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
        self.armor.audit.append(
            {
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
            }
        )
        return result

    def _quantum_meta(self) -> dict[str, Any]:
        if self.quantum_meta_getter is None:
            return {}
        return dict(self.quantum_meta_getter() or {})
