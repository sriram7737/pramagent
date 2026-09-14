from __future__ import annotations

from dataclasses import replace

import pytest

from pramagent import Pramagent
from pramagent.quantum import (
    CalibrationBindingError,
    CalibrationCanaryEvidence,
    CalibrationWorkloadBinding,
    QuantumExecutionEvidence,
    record_calibration_workload_binding,
)


def _execution(
    *,
    execution_id: str,
    submitted_at: float,
    completed_at: float,
    provider: str = "ibm_quantum_platform",
    backend: str = "ibm_test",
    workload: str = "bell_attestation",
) -> QuantumExecutionEvidence:
    return QuantumExecutionEvidence(
        provider=provider,
        backend=backend,
        execution_id=execution_id,
        workload=workload,
        device_kind="hardware",
        circuit_hash=("a" if workload == "bell_attestation" else "b") * 64,
        shots_requested=100,
        shots_observed=100,
        submitted_at=submitted_at,
        completed_at=completed_at,
        counts={"00": 50, "11": 50},
    ).seal()


def _canary(*, passed: bool = True, valid_for_seconds: float = 300.0):
    execution = _execution(
        execution_id="calibration-1",
        submitted_at=90.0,
        completed_at=100.0,
    )
    return CalibrationCanaryEvidence(
        provider=execution.provider,
        backend=execution.backend,
        execution_id=execution.execution_id,
        execution_evidence_hash=execution.evidence_hash,
        completed_at=execution.completed_at,
        metric_name="same_bit_correlation",
        metric_value=0.95 if passed else 0.40,
        minimum_value=0.60,
        passed=passed,
        valid_for_seconds=valid_for_seconds,
        physical_qubits=(12, 13),
        calibration_snapshot_at=80.0,
    ).seal()


def test_calibration_canary_roundtrips_and_detects_tampering():
    canary = _canary()

    restored = CalibrationCanaryEvidence.from_dict(canary.to_dict())
    payload = canary.to_dict()
    payload["metric_value"] = 0.10

    assert restored.physical_qubits == (12, 13)
    with pytest.raises(CalibrationBindingError):
        CalibrationCanaryEvidence.from_dict(payload)


def test_calibration_canary_rejects_nonfinite_metrics_and_late_snapshot():
    canary = _canary()

    with pytest.raises(CalibrationBindingError, match="finite"):
        replace(canary, metric_value=float("nan"), canary_hash="").seal()
    with pytest.raises(CalibrationBindingError, match="precede"):
        replace(canary, calibration_snapshot_at=101.0, canary_hash="").seal()


def test_canary_rejects_failed_stale_future_and_wrong_backend_use():
    with pytest.raises(CalibrationBindingError, match="did not pass"):
        _canary(passed=False).assert_usable(
            provider="ibm_quantum_platform", backend="ibm_test", at=101.0
        )
    with pytest.raises(CalibrationBindingError, match="stale"):
        _canary(valid_for_seconds=10).assert_usable(
            provider="ibm_quantum_platform", backend="ibm_test", at=111.0
        )
    with pytest.raises(CalibrationBindingError, match="predates"):
        _canary().assert_usable(
            provider="ibm_quantum_platform", backend="ibm_test", at=99.0
        )
    with pytest.raises(CalibrationBindingError, match="does not match"):
        _canary().assert_usable(
            provider="ibm_quantum_platform", backend="another_backend", at=101.0
        )


def test_completed_workload_binds_to_fresh_canary_and_audit_chain():
    armor = Pramagent()
    canary = _canary()
    workload = _execution(
        execution_id="workload-1",
        submitted_at=150.0,
        completed_at=170.0,
        workload="customer_workload",
    )

    binding = record_calibration_workload_binding(
        armor,
        canary,
        workload,
        tenant_id="acme",
        session_id="batch-7",
        max_age_seconds=120.0,
    )

    restored = CalibrationWorkloadBinding.from_dict(binding.to_dict())
    event = armor.audit.records()[-1]["payload"]
    assert restored.calibration_age_seconds == 50.0
    assert restored.max_age_seconds == 120.0
    assert restored.workload_execution_id == "workload-1"
    assert restored.workload_completed_at == 170.0
    assert event["event"] == "calibration_workload_bound"
    assert event["binding"]["binding_hash"] == binding.binding_hash
    assert armor.audit.verify_chain()


def test_workload_binding_rejects_stale_or_cross_provider_evidence():
    stale = _execution(
        execution_id="stale-workload",
        submitted_at=500.0,
        completed_at=510.0,
        workload="customer_workload",
    )
    other_provider = _execution(
        execution_id="other-provider",
        submitted_at=150.0,
        completed_at=160.0,
        provider="aws_braket",
        workload="customer_workload",
    )

    with pytest.raises(CalibrationBindingError, match="stale"):
        CalibrationWorkloadBinding.create(_canary(), stale)
    with pytest.raises(CalibrationBindingError, match="does not match"):
        CalibrationWorkloadBinding.create(_canary(), other_provider)


def test_workload_binding_rejects_inconsistent_or_future_timestamps():
    workload = _execution(
        execution_id="workload-1",
        submitted_at=150.0,
        completed_at=170.0,
        workload="customer_workload",
    )
    binding = CalibrationWorkloadBinding.create(_canary(), workload, bound_at=180.0)

    with pytest.raises(CalibrationBindingError, match="age does not match"):
        replace(binding, calibration_age_seconds=49.0, binding_hash="").seal()
    with pytest.raises(CalibrationBindingError, match="binding predates"):
        CalibrationWorkloadBinding.create(_canary(), workload, bound_at=160.0)
