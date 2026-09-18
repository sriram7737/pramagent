import json
from types import SimpleNamespace

import pytest

from pramagent import Pramagent, Verdict, cli
from pramagent.quantum import ibm_runtime
from pramagent.quantum import qpu_attestation
from pramagent.quantum import (
    CalibrationCanaryEvidence,
    QuantumBudgetLedger,
    QuantumExecutionEvidence,
)
from pramagent.quantum.ibm_runtime import (
    IBM_HARDWARE_TOOL_NAME,
    IBMQuantumRuntime,
    IBMRuntimeConfig,
    QuantumAuditIntegrityError,
    QuantumBudgetExceeded,
    QuantumHardwareConsentRequired,
    QuantumLayoutQualityError,
    make_ibm_hardware_policy,
    quantum_status,
)


class _Backend:
    name = "ibm_test_backend"


class _Service:
    def __init__(self):
        self.backend_value = _Backend()
        self.backend_calls = []
        self.least_busy_calls = 0

    def backend(self, name):
        self.backend_calls.append(name)
        return self.backend_value

    def least_busy(self, **kwargs):
        self.least_busy_calls += 1
        assert kwargs == {"operational": True, "simulator": False, "min_num_qubits": 2}
        return self.backend_value


class _PassManager:
    def run(self, circuit):
        return circuit


class _Measurement:
    def __init__(self, counts):
        self._counts = counts

    def get_counts(self):
        return dict(self._counts)


class _PubData:
    def __init__(self, counts):
        self.meas = _Measurement(counts)


class _PubResult:
    def __init__(self, counts):
        self.data = _PubData(counts)


class _Job:
    def __init__(self, counts, job_id="job-real-shape-123"):
        self._counts = counts
        self._job_id = job_id

    def job_id(self):
        return self._job_id

    def result(self):
        return [_PubResult(self._counts)]

    def usage(self):
        return 0.03125


class _Sampler:
    jobs = []

    def __init__(self, *, mode):
        self.mode = mode

    def run(self, circuits, *, shots):
        assert len(circuits) == 1
        job = _Job({"00": shots // 2, "11": shots - shots // 2})
        self.jobs.append(job)
        return job


def _patch_runtime(monkeypatch):
    qiskit = pytest.importorskip("qiskit")
    monkeypatch.setattr(
        ibm_runtime,
        "_runtime_imports",
        lambda: (qiskit.QuantumCircuit, lambda **_kwargs: _PassManager(), object, _Sampler),
    )


def _armor(max_shots=1024):
    armor = Pramagent()
    armor.tool_guard.register(make_ibm_hardware_policy(max_shots_per_call=max_shots))
    return armor


def _events(armor):
    return [
        record["payload"]
        for record in armor.audit.records()
        if record["payload"].get("source") == "ibm_quantum_runtime"
    ]


def test_runtime_config_reads_supported_environment_names(monkeypatch):
    monkeypatch.setenv("IBM_CLOUD_API_KEY", "secret-token")
    monkeypatch.setenv("IBM_QUANTUM_CRN", "secret-crn")

    config = IBMRuntimeConfig.from_env()

    assert config.configured
    assert config.token_source == "IBM_CLOUD_API_KEY"
    assert config.instance_source == "IBM_QUANTUM_CRN"
    assert "secret-token" not in repr(config)
    assert "secret-crn" not in repr(config)


def test_quantum_status_never_serializes_credentials():
    config = IBMRuntimeConfig(
        token="secret-token",
        instance="secret-crn",
        token_source="test-token",
        instance_source="test-instance",
    )

    payload = quantum_status(config=config)
    serialized = json.dumps(payload)

    assert payload["credentials_configured"] is True
    assert payload["credential_mode"] == "environment"
    assert "secret-token" not in serialized
    assert "secret-crn" not in serialized


def test_quantum_status_connects_without_submitting_a_job():
    captured = {}

    class _StatusService:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def backends(self, **kwargs):
            assert kwargs == {"operational": True, "simulator": False}
            return [_Backend(), _Backend()]

        def instances(self):
            return [{"plan": {"name": "open"}}]

    config = IBMRuntimeConfig(token="token", instance="crn")
    payload = quantum_status(
        connect=True,
        config=config,
        service_factory=_StatusService,
    )

    assert captured["token"] == "token"
    assert payload["connected"] is True
    assert payload["backend_count"] == 2
    assert payload["instance_plans"] == ["open"]


def test_quantum_status_can_use_saved_account_without_exposing_values(monkeypatch):
    captured = {"created": 0}

    class _SavedAccountService:
        @staticmethod
        def saved_accounts():
            return {"workstation": {"token": "secret-token", "instance": "secret-crn"}}

        def __init__(self, **kwargs):
            assert kwargs == {}
            captured["created"] += 1

        def backends(self, **kwargs):
            return [_Backend()]

        def instances(self):
            return [{"plan": "open"}]

    qiskit = pytest.importorskip("qiskit")
    monkeypatch.setattr(
        ibm_runtime,
        "_runtime_imports",
        lambda: (qiskit.QuantumCircuit, object, _SavedAccountService, object),
    )

    payload = quantum_status(connect=True, config=IBMRuntimeConfig())
    serialized = json.dumps(payload)

    assert captured["created"] == 1
    assert payload["credential_mode"] == "saved_account"
    assert payload["saved_account_names"] == ["workstation"]
    assert "secret-token" not in serialized
    assert "secret-crn" not in serialized


def test_hardware_policy_is_strict_and_caps_shots():
    armor = _armor(max_shots=64)
    valid = {
        "provider": "ibm_quantum_platform",
        "backend": "ibm_test",
        "shots": 64,
        "wires": 2,
        "depth": 3,
        "circuit_hash": "a" * 64,
        "pricing_model": "ibm_qpu_time_unpriced",
    }

    allowed = armor.validate_tool(
        IBM_HARDWARE_TOOL_NAME,
        valid,
        action_label="bell_attestation",
    )
    too_many = armor.validate_tool(
        IBM_HARDWARE_TOOL_NAME,
        {**valid, "shots": 65},
        action_label="bell_attestation",
    )
    extra = armor.validate_tool(
        IBM_HARDWARE_TOOL_NAME,
        {**valid, "override": True},
        action_label="bell_attestation",
    )

    assert allowed.verdict == Verdict.ALLOW
    assert too_many.verdict == Verdict.BLOCK
    assert extra.verdict == Verdict.BLOCK


def test_missing_consent_refuses_before_provider_access():
    armor = _armor()
    service = _Service()
    runner = IBMQuantumRuntime(armor, service=service)

    with pytest.raises(QuantumHardwareConsentRequired, match="explicit operator consent"):
        runner.run_hardware_attestation(shots=32)

    assert service.least_busy_calls == 0
    assert _events(armor)[-1]["event"] == "qpu_execution_refused"
    assert armor.audit.verify_chain()


def test_invalid_audit_chain_refuses_before_provider_access(monkeypatch):
    armor = _armor()
    service = _Service()
    runner = IBMQuantumRuntime(armor, service=service)
    monkeypatch.setattr(armor.audit, "verify_chain", lambda: False)

    with pytest.raises(QuantumAuditIntegrityError, match="invalid"):
        runner.run_hardware_attestation(
            shots=32,
            confirm_hardware=True,
            allow_unpriced_hardware=True,
        )

    assert service.least_busy_calls == 0


def test_unpriced_hardware_refuses_before_provider_access():
    armor = _armor()
    service = _Service()
    runner = IBMQuantumRuntime(armor, service=service)

    with pytest.raises(QuantumHardwareConsentRequired, match="cost is not known"):
        runner.run_hardware_attestation(shots=32, confirm_hardware=True)

    assert service.least_busy_calls == 0
    assert armor.audit.verify_chain()


def test_per_call_budget_refuses_before_provider_access():
    armor = _armor(max_shots=16)
    service = _Service()
    runner = IBMQuantumRuntime(
        armor,
        service=service,
        max_shots_per_call=16,
    )

    with pytest.raises(QuantumBudgetExceeded, match="per-call"):
        runner.run_hardware_attestation(
            shots=17,
            confirm_hardware=True,
            allow_unpriced_hardware=True,
        )

    assert service.least_busy_calls == 0
    assert _events(armor)[-1]["event"] == "qpu_budget_blocked"


def test_real_shape_sampler_result_is_audited(monkeypatch):
    _patch_runtime(monkeypatch)
    _Sampler.jobs.clear()
    armor = _armor(max_shots=128)
    runner = IBMQuantumRuntime(
        armor,
        service=_Service(),
        sampler_factory=_Sampler,
        pass_manager_factory=lambda **_kwargs: _PassManager(),
        max_shots_per_call=128,
        max_shots_per_session=256,
        tenant_id="acme",
        session_id="qpu-1",
    )

    result = runner.run_hardware_attestation(
        shots=128,
        confirm_hardware=True,
        allow_unpriced_hardware=True,
    )

    assert result.backend == "ibm_test_backend"
    assert result.job_id == "job-real-shape-123"
    assert result.counts == {"00": 64, "11": 64}
    assert result.shots_observed == 128
    assert result.bell_correlation == 1.0
    assert result.passed is True
    assert result.usage_seconds == 0.03125
    assert result.audit_chain_valid is True
    evidence = QuantumExecutionEvidence.from_dict(result.evidence)
    canary = CalibrationCanaryEvidence.from_dict(result.calibration_canary)
    assert evidence.provider == "ibm_quantum_platform"
    assert evidence.execution_id == result.job_id
    assert evidence.shots_observed == 128
    assert canary.execution_id == result.job_id
    assert canary.execution_evidence_hash == evidence.evidence_hash
    assert canary.metric_value == 1.0
    assert canary.valid_for_seconds == 900.0
    events = _events(armor)
    assert [event["event"] for event in events] == [
        "qpu_execution_authorized",
        "qpu_job_submitted",
        "qpu_job_completed",
    ]
    assert events[-1]["job_id"] == result.job_id
    assert events[-1]["calibration_canary"]["canary_hash"] == canary.canary_hash
    assert armor.audit.verify_chain()


def test_level_three_and_explicit_layout_are_forwarded(monkeypatch):
    _patch_runtime(monkeypatch)
    captured = {}

    def pass_manager_factory(**kwargs):
        captured.update(kwargs)
        return _PassManager()

    runner = IBMQuantumRuntime(
        _armor(max_shots=32),
        service=_Service(),
        sampler_factory=_Sampler,
        pass_manager_factory=pass_manager_factory,
        max_shots_per_call=32,
    )
    result = runner.run_hardware_attestation(
        shots=32,
        confirm_hardware=True,
        allow_unpriced_hardware=True,
        initial_layout=(146, 147),
    )

    assert captured["optimization_level"] == 3
    assert captured["initial_layout"] == [146, 147]
    assert result.optimization_level == 3


def test_noisy_layout_is_blocked_before_sampler_submission(monkeypatch):
    _patch_runtime(monkeypatch)
    _Sampler.jobs.clear()
    monkeypatch.setattr(
        ibm_runtime,
        "_layout_error_profile",
        lambda *_args: {
            "gate_error_proxy": 0.02,
            "readout_error_proxy": 0.05,
            "total_error_proxy": 0.069,
            "gate_terms": 1,
            "readout_terms": 2,
            "unknown_terms": [],
            "complete": True,
        },
    )
    armor = _armor(max_shots=32)
    runner = IBMQuantumRuntime(
        armor,
        service=_Service(),
        sampler_factory=_Sampler,
        pass_manager_factory=lambda **_kwargs: _PassManager(),
        max_shots_per_call=32,
    )

    with pytest.raises(QuantumLayoutQualityError, match="exceeds"):
        runner.run_hardware_attestation(
            shots=32,
            confirm_hardware=True,
            allow_unpriced_hardware=True,
            max_layout_error_proxy=0.05,
        )

    assert _Sampler.jobs == []
    assert _events(armor)[-1]["event"] == "qpu_layout_blocked"


def test_layout_error_profile_combines_isa_gate_and_readout_errors():
    q0, q1 = object(), object()
    circuit = SimpleNamespace(
        data=[
            SimpleNamespace(operation=SimpleNamespace(name="cz"), qubits=(q0, q1)),
            SimpleNamespace(operation=SimpleNamespace(name="measure"), qubits=(q0,)),
            SimpleNamespace(operation=SimpleNamespace(name="measure"), qubits=(q1,)),
        ],
        find_bit=lambda qubit: SimpleNamespace(index=0 if qubit is q0 else 1),
    )
    target = {
        "cz": {(0, 1): SimpleNamespace(error=0.01)},
        "measure": {
            (0,): SimpleNamespace(error=0.02),
            (1,): SimpleNamespace(error=0.03),
        },
    }

    profile = ibm_runtime._layout_error_profile(
        SimpleNamespace(target=target), circuit
    )

    assert profile["complete"] is True
    assert profile["gate_error_proxy"] == pytest.approx(0.01)
    assert profile["readout_error_proxy"] == pytest.approx(0.0494)
    assert profile["total_error_proxy"] == pytest.approx(0.058906)


def test_session_budget_survives_adapter_recreation(monkeypatch):
    _patch_runtime(monkeypatch)
    armor = _armor(max_shots=64)
    common = {
        "service": _Service(),
        "sampler_factory": _Sampler,
        "pass_manager_factory": lambda **_kwargs: _PassManager(),
        "max_shots_per_call": 64,
        "max_shots_per_session": 96,
        "tenant_id": "acme",
        "session_id": "shared",
    }
    first = IBMQuantumRuntime(armor, **common)
    second = IBMQuantumRuntime(armor, **common)

    first.run_hardware_attestation(
        shots=64,
        confirm_hardware=True,
        allow_unpriced_hardware=True,
    )
    with pytest.raises(QuantumBudgetExceeded, match="session shot budget"):
        second.run_hardware_attestation(
            shots=64,
            confirm_hardware=True,
            allow_unpriced_hardware=True,
        )

    assert [event["event"] for event in _events(armor)] == [
        "qpu_execution_authorized",
        "qpu_job_submitted",
        "qpu_job_completed",
        "qpu_budget_blocked",
    ]
    assert armor.audit.verify_chain()


def test_observed_shot_overage_drives_next_session_budget(monkeypatch):
    _patch_runtime(monkeypatch)

    class _OverageSampler(_Sampler):
        def run(self, circuits, *, shots):
            assert len(circuits) == 1
            return _Job({"00": shots, "11": shots})

    armor = _armor(max_shots=64)
    common = {
        "service": _Service(),
        "sampler_factory": _OverageSampler,
        "pass_manager_factory": lambda **_kwargs: _PassManager(),
        "max_shots_per_call": 64,
        "max_shots_per_session": 100,
        "tenant_id": "acme",
        "session_id": "overage",
    }

    first = IBMQuantumRuntime(armor, **common)
    result = first.run_hardware_attestation(
        shots=40,
        confirm_hardware=True,
        allow_unpriced_hardware=True,
    )
    assert result.shots_observed == 80

    second = IBMQuantumRuntime(armor, **common)
    with pytest.raises(QuantumBudgetExceeded, match="session shot budget"):
        second.run_hardware_attestation(
            shots=40,
            confirm_hardware=True,
            allow_unpriced_hardware=True,
        )


def test_ibm_runtime_uses_atomic_budget_ledger(monkeypatch, tmp_path):
    _patch_runtime(monkeypatch)
    ledger = QuantumBudgetLedger(tmp_path / "quantum.db")
    armor = _armor(max_shots=64)
    common = {
        "service": _Service(),
        "sampler_factory": _Sampler,
        "pass_manager_factory": lambda **_kwargs: _PassManager(),
        "max_shots_per_call": 64,
        "max_shots_per_session": 64,
        "tenant_id": "acme",
        "session_id": "atomic",
        "budget_ledger": ledger,
    }

    IBMQuantumRuntime(armor, **common).run_hardware_attestation(
        shots=64,
        confirm_hardware=True,
        allow_unpriced_hardware=True,
    )
    with pytest.raises(QuantumBudgetExceeded, match="session shots"):
        IBMQuantumRuntime(armor, **common).run_hardware_attestation(
            shots=1,
            confirm_hardware=True,
            allow_unpriced_hardware=True,
        )

    assert ledger.snapshot("acme", "atomic").shots == 64
    assert _events(armor)[-1]["event"] == "qpu_budget_blocked"
    ledger.close()


def test_uncertain_submission_is_conservatively_charged(monkeypatch):
    _patch_runtime(monkeypatch)

    class _FailingSampler(_Sampler):
        def run(self, circuits, *, shots):
            raise TimeoutError("provider response lost")

    armor = _armor(max_shots=64)
    runner = IBMQuantumRuntime(
        armor,
        service=_Service(),
        sampler_factory=_FailingSampler,
        pass_manager_factory=lambda **_kwargs: _PassManager(),
        max_shots_per_call=64,
        max_shots_per_session=64,
        tenant_id="acme",
        session_id="uncertain",
    )

    with pytest.raises(TimeoutError):
        runner.run_hardware_attestation(
            shots=64,
            confirm_hardware=True,
            allow_unpriced_hardware=True,
        )
    with pytest.raises(QuantumBudgetExceeded, match="session shot budget"):
        runner.run_hardware_attestation(
            shots=1,
            confirm_hardware=True,
            allow_unpriced_hardware=True,
        )

    assert [event["event"] for event in _events(armor)] == [
        "qpu_execution_authorized",
        "qpu_submission_uncertain",
        "qpu_budget_blocked",
    ]
    assert armor.audit.verify_chain()


def test_bell_circuit_has_expected_ideal_state(monkeypatch):
    _patch_runtime(monkeypatch)
    from qiskit.quantum_info import Statevector

    circuit = ibm_runtime.build_bell_circuit()
    unitary_part = circuit.remove_final_measurements(inplace=False)
    probabilities = Statevector.from_instruction(unitary_part).probabilities_dict()

    assert probabilities["00"] == pytest.approx(0.5)
    assert probabilities["11"] == pytest.approx(0.5)
    assert set(probabilities) == {"00", "11"}


def test_convenience_api_matches_documented_import_shape(monkeypatch):
    _patch_runtime(monkeypatch)
    armor = Pramagent()

    result = qpu_attestation.run_hardware_attestation(
        shots=32,
        confirm_hardware=True,
        allow_unpriced_hardware=True,
        max_shots_per_call=32,
        max_layout_error_proxy=None,
        armor=armor,
        service=_Service(),
        sampler_factory=_Sampler,
        pass_manager_factory=lambda **_kwargs: _PassManager(),
    )

    assert result["backend"] == "ibm_test_backend"
    assert result["job_id"] == "job-real-shape-123"
    assert result["counts"] == {"00": 16, "11": 16}
    assert armor.audit.verify_chain()


def test_quantum_run_cli_persists_audit_chain(monkeypatch, tmp_path, capsys):
    audit_db = tmp_path / "quantum-audit.db"
    monkeypatch.setenv(
        "PRAMAGENT_QUANTUM_SIGNING_KEYS",
        "ibm-live-test-01:quantum-test-signing-key",
    )
    monkeypatch.setenv(
        "PRAMAGENT_QUANTUM_SIGNING_ACTIVE_KID", "ibm-live-test-01"
    )

    class _Runner:
        def __init__(self, armor, **_kwargs):
            self.armor = armor

        def run_hardware_attestation(self, **_kwargs):
            self.armor.audit.append({
                "source": "ibm_quantum_runtime",
                "event": "qpu_job_completed",
                "tenant_id": "test",
                "session_id": "test",
                "job_id": "job-persisted",
            })
            return SimpleNamespace(
                backend="ibm_test",
                job_id="job-persisted",
                shots_observed=8,
                shots_requested=8,
                counts={"00": 4, "11": 4},
                bell_correlation=1.0,
                passed=True,
                audit_chain_valid=self.armor.audit.verify_chain(),
                to_dict=lambda: {"job_id": "job-persisted", "passed": True},
            )

    monkeypatch.setattr("pramagent.quantum.IBMQuantumRuntime", _Runner)
    args = SimpleNamespace(
        audit_db=str(audit_db),
        max_shots_per_call=8,
        max_shots_per_session=8,
        tenant_id="test",
        session_id="test",
        shots=8,
        backend="",
        submit_hardware=True,
        allow_unpriced_hardware=True,
        minimum_correlation=0.6,
        optimization_level=1,
        json=True,
    )

    assert cli.cmd_quantum_run(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["audit_db"] == str(audit_db.resolve())
    assert output["budget_backend"] == "sqlite"

    monkeypatch.setenv("PRAMAGENT_DB", str(audit_db))
    store = cli._store_from_env(verification=True)
    try:
        assert store.verify_chain()
        assert store.records()[-1]["payload"]["job_id"] == "job-persisted"
    finally:
        store.close()
    assert cli.cmd_audit_verify_watch(
        SimpleNamespace(interval_s=0.0, json=True)
    ) == 0


def test_quantum_run_cli_selects_postgres_budget_ledger(
    monkeypatch, tmp_path, capsys
):
    created = []

    class _Ledger:
        def __init__(self, dsn, *, table):
            created.append((dsn, table, self))

        def close(self):
            self.closed = True

    class _Runner:
        def __init__(self, armor, *, budget_ledger, **_kwargs):
            assert budget_ledger is created[0][2]
            self.armor = armor

        def run_hardware_attestation(self, **_kwargs):
            return SimpleNamespace(
                backend="ibm_test",
                job_id="job-postgres-budget",
                shots_observed=8,
                shots_requested=8,
                counts={"00": 4, "11": 4},
                bell_correlation=1.0,
                passed=True,
                audit_chain_valid=True,
                to_dict=lambda: {"job_id": "job-postgres-budget", "passed": True},
            )

    monkeypatch.setattr("pramagent.quantum.PostgresQuantumBudgetLedger", _Ledger)
    monkeypatch.setattr("pramagent.quantum.IBMQuantumRuntime", _Runner)
    args = SimpleNamespace(
        audit_db=str(tmp_path / "quantum-audit.db"),
        budget_postgres_dsn="postgresql://budget-db/pramagent",
        budget_postgres_table="quantum_budget",
        calibration_valid_for_seconds=300.0,
        max_shots_per_call=8,
        max_shots_per_session=8,
        tenant_id="test",
        session_id="test",
        shots=8,
        backend="",
        submit_hardware=True,
        allow_unpriced_hardware=True,
        minimum_correlation=0.6,
        optimization_level=1,
        json=True,
    )

    assert cli.cmd_quantum_run(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["budget_backend"] == "postgres"
    assert created[0][0:2] == (
        "postgresql://budget-db/pramagent",
        "quantum_budget",
    )
    assert created[0][2].closed is True
