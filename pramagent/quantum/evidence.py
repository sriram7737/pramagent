"""Provider-neutral evidence records for quantum execution."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from typing import Any

__all__ = ["QuantumEvidenceError", "QuantumExecutionEvidence"]


class QuantumEvidenceError(ValueError):
    """Raised when execution evidence is incomplete or internally inconsistent."""


@dataclass(frozen=True)
class QuantumExecutionEvidence:
    provider: str
    backend: str
    execution_id: str
    workload: str
    device_kind: str
    circuit_hash: str
    shots_requested: int
    shots_observed: int
    status: str = "completed"
    pricing_model: str = "unknown"
    estimated_cost_usd: float | None = None
    actual_cost_usd: float | None = None
    queue_seconds: float | None = None
    usage_seconds: float | None = None
    submitted_at: float | None = None
    completed_at: float | None = None
    counts: dict[str, int] | None = None
    schema_version: str = "1.0"
    evidence_hash: str = ""

    def _material(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("evidence_hash", None)
        if payload["counts"] is not None:
            payload["counts"] = dict(sorted(payload["counts"].items()))
        return payload

    def computed_hash(self) -> str:
        encoded = json.dumps(
            self._material(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def seal(self) -> "QuantumExecutionEvidence":
        self.validate(require_hash=False)
        return replace(self, evidence_hash=self.computed_hash())

    def validate(self, *, require_hash: bool = True) -> None:
        if not self.provider or not self.backend or not self.execution_id:
            raise QuantumEvidenceError("provider, backend, and execution_id are required")
        if self.device_kind not in {"simulator", "hardware"}:
            raise QuantumEvidenceError("device_kind must be simulator or hardware")
        if self.status not in {"completed", "failed", "uncertain"}:
            raise QuantumEvidenceError("unsupported quantum evidence status")
        if self.shots_requested < 0 or self.shots_observed < 0:
            raise QuantumEvidenceError("shot counts must be non-negative")
        for label, value in (
            ("estimated_cost_usd", self.estimated_cost_usd),
            ("actual_cost_usd", self.actual_cost_usd),
            ("queue_seconds", self.queue_seconds),
            ("usage_seconds", self.usage_seconds),
        ):
            if value is not None and value < 0:
                raise QuantumEvidenceError(f"{label} must be non-negative")
        if len(self.circuit_hash) != 64 or any(
            char not in "0123456789abcdef" for char in self.circuit_hash.lower()
        ):
            raise QuantumEvidenceError("circuit_hash must be a SHA-256 hex digest")
        if self.counts is not None:
            if any(int(value) < 0 for value in self.counts.values()):
                raise QuantumEvidenceError("measurement counts must be non-negative")
            if self.status == "completed" and sum(self.counts.values()) != self.shots_observed:
                raise QuantumEvidenceError(
                    "measurement counts do not match shots_observed"
                )
        if require_hash and self.evidence_hash != self.computed_hash():
            raise QuantumEvidenceError("quantum evidence hash mismatch")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "QuantumExecutionEvidence":
        evidence = cls(**raw)
        evidence.validate()
        return evidence
