"""Sealed calibration canaries and their bindings to quantum workloads."""
from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import asdict, dataclass, replace
from typing import Any, TYPE_CHECKING

from .evidence import QuantumExecutionEvidence

if TYPE_CHECKING:
    from ..core import Pramagent

__all__ = [
    "CalibrationBindingError",
    "CalibrationCanaryEvidence",
    "CalibrationWorkloadBinding",
    "record_calibration_workload_binding",
]


class CalibrationBindingError(ValueError):
    """Raised when a canary cannot authorize or bind to a workload."""


def _hash_payload(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value.lower())


def _finite(value: float) -> bool:
    return math.isfinite(float(value))


@dataclass(frozen=True)
class CalibrationCanaryEvidence:
    provider: str
    backend: str
    execution_id: str
    execution_evidence_hash: str
    completed_at: float
    metric_name: str
    metric_value: float
    minimum_value: float
    passed: bool
    valid_for_seconds: float
    physical_qubits: tuple[int, ...] = ()
    calibration_snapshot_at: float | None = None
    layout_error_profile: dict[str, Any] | None = None
    schema_version: str = "1.0"
    canary_hash: str = ""

    def _material(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("canary_hash", None)
        return payload

    def computed_hash(self) -> str:
        return _hash_payload(self._material())

    def seal(self) -> "CalibrationCanaryEvidence":
        self.validate(require_hash=False)
        return replace(self, canary_hash=self.computed_hash())

    def validate(self, *, require_hash: bool = True) -> None:
        if not self.provider or not self.backend or not self.execution_id:
            raise CalibrationBindingError("provider, backend, and execution_id are required")
        if not _valid_sha256(self.execution_evidence_hash):
            raise CalibrationBindingError("execution_evidence_hash must be SHA-256")
        if not _finite(self.completed_at) or self.completed_at <= 0:
            raise CalibrationBindingError("completed_at must be positive")
        if not self.metric_name:
            raise CalibrationBindingError("metric_name is required")
        if not _finite(self.metric_value) or not _finite(self.minimum_value):
            raise CalibrationBindingError("calibration metric values must be finite")
        if not _finite(self.valid_for_seconds) or self.valid_for_seconds <= 0:
            raise CalibrationBindingError("valid_for_seconds must be positive")
        if any(
            not isinstance(qubit, int) or isinstance(qubit, bool) or qubit < 0
            for qubit in self.physical_qubits
        ):
            raise CalibrationBindingError("physical qubits must be non-negative")
        if self.calibration_snapshot_at is not None and (
            not _finite(self.calibration_snapshot_at)
            or self.calibration_snapshot_at <= 0
            or self.calibration_snapshot_at > self.completed_at
        ):
            raise CalibrationBindingError(
                "calibration_snapshot_at must precede canary completion"
            )
        if self.layout_error_profile is not None:
            total = self.layout_error_profile.get("total_error_proxy")
            if (
                total is None
                or not _finite(total)
                or not 0.0 <= float(total) <= 1.0
            ):
                raise CalibrationBindingError(
                    "layout error profile needs a bounded total_error_proxy"
                )
        if self.passed != (self.metric_value >= self.minimum_value):
            raise CalibrationBindingError("canary pass flag does not match its metric")
        if require_hash and self.canary_hash != self.computed_hash():
            raise CalibrationBindingError("calibration canary hash mismatch")

    def age_at(self, timestamp: float) -> float:
        return float(timestamp) - self.completed_at

    def assert_usable(
        self,
        *,
        provider: str,
        backend: str,
        at: float | None = None,
        max_age_seconds: float | None = None,
    ) -> float:
        self.validate()
        if not self.passed:
            raise CalibrationBindingError("calibration canary did not pass")
        if provider != self.provider or backend != self.backend:
            raise CalibrationBindingError("calibration provider/backend does not match workload")
        effective_max_age = self.valid_for_seconds
        if max_age_seconds is not None:
            if max_age_seconds <= 0:
                raise CalibrationBindingError("max_age_seconds must be positive")
            effective_max_age = min(effective_max_age, float(max_age_seconds))
        age = self.age_at(time.time() if at is None else at)
        if age < 0:
            raise CalibrationBindingError("workload timestamp predates calibration completion")
        if age > effective_max_age:
            raise CalibrationBindingError(
                f"calibration canary is stale: {age:.3f}s > {effective_max_age:.3f}s"
            )
        return age

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CalibrationCanaryEvidence":
        values = dict(raw)
        values["physical_qubits"] = tuple(values.get("physical_qubits") or ())
        canary = cls(**values)
        canary.validate()
        return canary


@dataclass(frozen=True)
class CalibrationWorkloadBinding:
    provider: str
    backend: str
    calibration_execution_id: str
    calibration_hash: str
    workload_execution_id: str
    workload_evidence_hash: str
    workload_circuit_hash: str
    calibration_completed_at: float
    workload_submitted_at: float
    workload_completed_at: float
    calibration_age_seconds: float
    max_age_seconds: float
    bound_at: float
    schema_version: str = "1.0"
    binding_hash: str = ""

    def _material(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("binding_hash", None)
        return payload

    def computed_hash(self) -> str:
        return _hash_payload(self._material())

    def seal(self) -> "CalibrationWorkloadBinding":
        self.validate(require_hash=False)
        return replace(self, binding_hash=self.computed_hash())

    def validate(self, *, require_hash: bool = True) -> None:
        if not self.provider or not self.backend:
            raise CalibrationBindingError("provider and backend are required")
        for label, value in (
            ("calibration_hash", self.calibration_hash),
            ("workload_evidence_hash", self.workload_evidence_hash),
            ("workload_circuit_hash", self.workload_circuit_hash),
        ):
            if not _valid_sha256(value):
                raise CalibrationBindingError(f"{label} must be SHA-256")
        if not self.calibration_execution_id or not self.workload_execution_id:
            raise CalibrationBindingError("both execution IDs are required")
        timestamps = (
            self.calibration_completed_at,
            self.workload_submitted_at,
            self.workload_completed_at,
            self.bound_at,
        )
        if any(not _finite(value) or value <= 0 for value in timestamps):
            raise CalibrationBindingError("binding timestamps must be positive and finite")
        if self.workload_submitted_at < self.calibration_completed_at:
            raise CalibrationBindingError("workload submission predates calibration")
        if self.workload_completed_at < self.workload_submitted_at:
            raise CalibrationBindingError("workload completion predates submission")
        if self.bound_at < self.workload_completed_at:
            raise CalibrationBindingError("binding predates workload completion")
        expected_age = self.workload_submitted_at - self.calibration_completed_at
        if abs(self.calibration_age_seconds - expected_age) > 1e-6:
            raise CalibrationBindingError("calibration age does not match timestamps")
        if (
            not _finite(self.calibration_age_seconds)
            or not _finite(self.max_age_seconds)
            or self.calibration_age_seconds < 0
            or self.max_age_seconds <= 0
        ):
            raise CalibrationBindingError("calibration age values are invalid")
        if self.calibration_age_seconds > self.max_age_seconds + 1e-9:
            raise CalibrationBindingError("calibration binding exceeds its age policy")
        if require_hash and self.binding_hash != self.computed_hash():
            raise CalibrationBindingError("calibration workload binding hash mismatch")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CalibrationWorkloadBinding":
        binding = cls(**raw)
        binding.validate()
        return binding

    @classmethod
    def create(
        cls,
        canary: CalibrationCanaryEvidence,
        workload: QuantumExecutionEvidence,
        *,
        max_age_seconds: float | None = None,
        bound_at: float | None = None,
    ) -> "CalibrationWorkloadBinding":
        workload.validate()
        if workload.status != "completed":
            raise CalibrationBindingError("workload evidence must be completed")
        if workload.submitted_at is None:
            raise CalibrationBindingError("workload evidence needs submitted_at")
        if workload.completed_at is None:
            raise CalibrationBindingError("workload evidence needs completed_at")
        effective_max_age = canary.valid_for_seconds
        if max_age_seconds is not None:
            effective_max_age = min(effective_max_age, float(max_age_seconds))
        age = canary.assert_usable(
            provider=workload.provider,
            backend=workload.backend,
            at=workload.submitted_at,
            max_age_seconds=effective_max_age,
        )
        return cls(
            provider=workload.provider,
            backend=workload.backend,
            calibration_execution_id=canary.execution_id,
            calibration_hash=canary.canary_hash,
            workload_execution_id=workload.execution_id,
            workload_evidence_hash=workload.evidence_hash,
            workload_circuit_hash=workload.circuit_hash,
            calibration_completed_at=canary.completed_at,
            workload_submitted_at=workload.submitted_at,
            workload_completed_at=workload.completed_at,
            calibration_age_seconds=round(age, 6),
            max_age_seconds=round(effective_max_age, 6),
            bound_at=time.time() if bound_at is None else float(bound_at),
        ).seal()


def record_calibration_workload_binding(
    armor: "Pramagent",
    canary: CalibrationCanaryEvidence | dict[str, Any],
    workload: QuantumExecutionEvidence | dict[str, Any],
    *,
    tenant_id: str,
    session_id: str,
    max_age_seconds: float | None = None,
) -> CalibrationWorkloadBinding:
    """Validate, seal, and append a canary/workload binding to the audit chain."""
    canary_record = (
        canary
        if isinstance(canary, CalibrationCanaryEvidence)
        else CalibrationCanaryEvidence.from_dict(canary)
    )
    workload_record = (
        workload
        if isinstance(workload, QuantumExecutionEvidence)
        else QuantumExecutionEvidence.from_dict(workload)
    )
    binding = CalibrationWorkloadBinding.create(
        canary_record,
        workload_record,
        max_age_seconds=max_age_seconds,
    )
    armor.audit.append({
        "source": "quantum_calibration",
        "event": "calibration_workload_bound",
        "tenant_id": tenant_id,
        "session_id": session_id,
        "binding": binding.to_dict(),
    })
    return binding
