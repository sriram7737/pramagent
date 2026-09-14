"""Guarded IBM Quantum Runtime job-mode integration.

The integration submits a small Bell-pair circuit and records provider evidence
in Pramagent's hash chain. It is an operational attestation, not evidence of a
quantum advantage. IBM charges or accounts for QPU usage by execution time, so
the adapter does not invent a per-shot dollar estimate.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from ..core import Pramagent
from ..layers.tool_guard import SideEffect, ToolPolicy
from ..types import Verdict
from .budget import QuantumBudgetLedgerBackend, QuantumBudgetLimits
from .calibration import CalibrationCanaryEvidence
from .evidence import QuantumExecutionEvidence

IBM_HARDWARE_TOOL_NAME = "ibm_quantum_sampler"
DEFAULT_MAX_SHOTS_PER_CALL = 1_024
DEFAULT_MAX_SHOTS_PER_SESSION = 4_096

_SUBMISSION_LOCK = threading.Lock()


class IBMQuantumDependencyError(RuntimeError):
    """Raised when the optional IBM quantum dependencies are unavailable."""


class IBMQuantumConfigurationError(RuntimeError):
    """Raised when IBM credentials or provider configuration are incomplete."""


class QuantumHardwareConsentRequired(PermissionError):
    """Raised when a caller has not explicitly authorized a physical QPU job."""


class QuantumBudgetExceeded(PermissionError):
    """Raised before submission when a configured shot budget would be exceeded."""


class QuantumAuditIntegrityError(PermissionError):
    """Raised before submission when the configured audit chain is invalid."""


class QuantumLayoutQualityError(PermissionError):
    """Raised before submission when the selected hardware layout is too noisy."""


def _first_environment_value(names: tuple[str, ...]) -> tuple[str, str]:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value, name
    return "", ""


@dataclass(frozen=True)
class IBMRuntimeConfig:
    """IBM Runtime credentials loaded without ever serializing secret values."""

    token: str = field(default="", repr=False)
    instance: str = field(default="", repr=False)
    channel: str = "ibm_quantum_platform"
    token_source: str = ""
    instance_source: str = ""

    @classmethod
    def from_env(cls) -> "IBMRuntimeConfig":
        token, token_source = _first_environment_value(
            ("IBM_CLOUD_API_KEY", "IBM_QUANTUM_API_KEY", "QISKIT_IBM_TOKEN")
        )
        instance, instance_source = _first_environment_value(
            ("IBM_QUANTUM_CRN", "IBM_QUANTUM_INSTANCE", "QISKIT_IBM_INSTANCE")
        )
        channel = os.environ.get("QISKIT_IBM_CHANNEL", "ibm_quantum_platform").strip()
        return cls(
            token=token,
            instance=instance,
            channel=channel or "ibm_quantum_platform",
            token_source=token_source,
            instance_source=instance_source,
        )

    @property
    def configured(self) -> bool:
        return bool(self.token and self.instance)

    def require_configured(self) -> None:
        missing = []
        if not self.token:
            missing.append("IBM_CLOUD_API_KEY")
        if not self.instance:
            missing.append("IBM_QUANTUM_CRN")
        if missing:
            raise IBMQuantumConfigurationError(
                "missing IBM Quantum configuration: " + ", ".join(missing)
            )


@dataclass(frozen=True)
class QuantumAttestationResult:
    provider: str
    backend: str
    job_id: str
    shots_requested: int
    shots_observed: int
    counts: dict[str, int]
    bell_correlation: float
    passed: bool
    minimum_correlation: float
    circuit_depth: int
    transpiled_depth: int
    optimization_level: int
    wires: int
    circuit_hash: str
    layout_error_profile: dict[str, Any] = field(default_factory=dict)
    queue_seconds: float | None = None
    usage_seconds: float | None = None
    audit_chain_valid: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)
    calibration_canary: dict[str, Any] = field(default_factory=dict)
    physical_qubits: tuple[int, ...] = ()
    calibration_snapshot_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _runtime_imports():
    try:
        from qiskit import QuantumCircuit
        from qiskit.transpiler import generate_preset_pass_manager
        from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2
    except ImportError as exc:
        raise IBMQuantumDependencyError(
            'IBM hardware support requires `pip install "pramagent[quantum-ibm]"`'
        ) from exc
    return QuantumCircuit, generate_preset_pass_manager, QiskitRuntimeService, SamplerV2


def _saved_account_names(service_class: Any) -> list[str]:
    try:
        accounts = service_class.saved_accounts() or {}
    except Exception:
        return []
    return sorted(str(name) for name in accounts)


def build_bell_circuit():
    """Build the fixed two-qubit circuit used for hardware attestation."""
    QuantumCircuit, _, _, _ = _runtime_imports()
    circuit = QuantumCircuit(2)
    circuit.h(0)
    circuit.cx(0, 1)
    circuit.measure_all()
    return circuit


def _backend_name(backend: Any) -> str:
    name = getattr(backend, "name", "")
    if callable(name):
        name = name()
    return str(name or backend.__class__.__name__)


def _job_id(job: Any) -> str:
    value = getattr(job, "job_id", "")
    if callable(value):
        value = value()
    return str(value or "unknown")


def _circuit_hash(circuit: Any) -> str:
    operations = []
    for instruction in getattr(circuit, "data", ()):
        operation = getattr(instruction, "operation", None)
        qubits = getattr(instruction, "qubits", ())
        operations.append(
            {
                "name": str(getattr(operation, "name", "unknown")),
                "qubits": [int(circuit.find_bit(bit).index) for bit in qubits],
            }
        )
    payload = {
        "num_qubits": int(getattr(circuit, "num_qubits", 0) or 0),
        "operations": operations,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _physical_qubits(circuit: Any, isa_circuit: Any) -> tuple[int, ...]:
    """Return the physical mapping for the original logical circuit."""
    try:
        initial_layout = isa_circuit.layout.initial_layout
        return tuple(int(initial_layout[qubit]) for qubit in circuit.qubits)
    except (AttributeError, KeyError, TypeError):
        return ()


def _calibration_snapshot_at(backend: Any) -> float | None:
    """Read the backend calibration timestamp without making it mandatory."""
    properties = getattr(backend, "properties", None)
    if not callable(properties):
        return None


def _layout_error_profile(backend: Any, isa_circuit: Any) -> dict[str, Any] | None:
    """Estimate circuit failure exposure from current backend target metadata.

    This is a ranking and policy proxy, not a fidelity prediction. It combines
    the reported error probabilities for the ISA gates and measurements that
    appear in the transpiled circuit.
    """
    target = getattr(backend, "target", None)
    if target is None:
        return None
    gate_errors: list[float] = []
    readout_errors: list[float] = []
    unknown_terms: list[str] = []
    ignored_operations = {"barrier", "delay"}
    for instruction in getattr(isa_circuit, "data", ()):
        operation = getattr(instruction, "operation", None)
        name = str(getattr(operation, "name", ""))
        if not name or name in ignored_operations:
            continue
        qargs: tuple[int, ...] = ()
        try:
            qargs = tuple(
                int(isa_circuit.find_bit(qubit).index)
                for qubit in getattr(instruction, "qubits", ())
            )
            properties = target[name].get(qargs)
            error = None if properties is None else properties.error
        except (AttributeError, KeyError, TypeError, ValueError):
            error = None
        if error is None:
            # RZ is virtual on IBM hardware and normally has no reported error.
            if name != "rz":
                unknown_terms.append(f"{name}{qargs}")
            continue
        value = float(error)
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            unknown_terms.append(f"{name}{qargs}")
            continue
        (readout_errors if name.startswith("measure") else gate_errors).append(value)

    def combined(errors: list[float]) -> float:
        success = 1.0
        for error in errors:
            success *= 1.0 - error
        return round(1.0 - success, 9)

    gate_proxy = combined(gate_errors)
    readout_proxy = combined(readout_errors)
    total_proxy = combined(gate_errors + readout_errors)
    return {
        "gate_error_proxy": gate_proxy,
        "readout_error_proxy": readout_proxy,
        "total_error_proxy": total_proxy,
        "gate_terms": len(gate_errors),
        "readout_terms": len(readout_errors),
        "unknown_terms": unknown_terms,
        "complete": not unknown_terms,
    }
    try:
        updated = getattr(properties(), "last_update_date", None)
        if updated is None:
            return None
        timestamp = getattr(updated, "timestamp", None)
        return float(timestamp()) if callable(timestamp) else float(updated)
    except (AttributeError, TypeError, ValueError):
        return None


def _extract_counts(primitive_result: Any) -> dict[str, int]:
    try:
        pub_result = primitive_result[0]
        data = pub_result.data
        measurement = getattr(data, "meas", None)
        if measurement is None:
            fields = [name for name in dir(data) if not name.startswith("_")]
            measurement = next(
                (getattr(data, name) for name in fields
                 if hasattr(getattr(data, name), "get_counts")),
                None,
            )
        counts = measurement.get_counts() if measurement is not None else None
    except (AttributeError, IndexError, TypeError, StopIteration) as exc:
        raise RuntimeError("IBM Sampler result did not contain measurable counts") from exc
    if not isinstance(counts, dict) or not counts:
        raise RuntimeError("IBM Sampler returned no measurement counts")
    normalized: dict[str, int] = {}
    for key, value in counts.items():
        normalized[str(key).replace(" ", "")] = int(value)
    return normalized


def _safe_job_metric(job: Any, method_name: str) -> Any:
    method = getattr(job, method_name, None)
    if not callable(method):
        return None
    try:
        return method()
    except Exception:
        return None


def _float_or_none(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return round(float(value), 6)
    except (TypeError, ValueError):
        return None


def make_ibm_hardware_policy(
    *, max_shots_per_call: int = DEFAULT_MAX_SHOTS_PER_CALL
) -> ToolPolicy:
    """Return the strict ToolGuard policy for the fixed IBM attestation job."""
    if max_shots_per_call < 1:
        raise ValueError("max_shots_per_call must be at least 1")
    return ToolPolicy(
        name=IBM_HARDWARE_TOOL_NAME,
        side_effect=SideEffect.METERED_COMPUTE,
        action=Verdict.ALLOW,
        allowed_actions={"bell_attestation"},
        schema={
            "type": "object",
            "properties": {
                "provider": {"const": "ibm_quantum_platform"},
                "backend": {"type": "string", "minLength": 1, "maxLength": 128},
                "shots": {"type": "integer", "minimum": 1, "maximum": max_shots_per_call},
                "wires": {"const": 2},
                "depth": {"type": "integer", "minimum": 1, "maximum": 10_000},
                "circuit_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "pricing_model": {"const": "ibm_qpu_time_unpriced"},
            },
            "required": [
                "provider", "backend", "shots", "wires", "depth",
                "circuit_hash", "pricing_model",
            ],
            "additionalProperties": False,
        },
        skip_arg_injection_scan=True,
        detail="fixed Bell-pair hardware attestation within the configured shot budget",
    )


def quantum_status(
    *, connect: bool = False, config: IBMRuntimeConfig | None = None,
    service_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Return dependency, credential, and optional provider-connectivity status."""
    cfg = config or IBMRuntimeConfig.from_env()
    saved_accounts: list[str] = []
    service_class = None
    if _package_version("qiskit-ibm-runtime") is not None:
        try:
            _, _, service_class, _ = _runtime_imports()
            saved_accounts = _saved_account_names(service_class)
        except IBMQuantumDependencyError:
            pass
    explicit_credentials = cfg.configured
    status: dict[str, Any] = {
        "qiskit_version": _package_version("qiskit"),
        "qiskit_ibm_runtime_version": _package_version("qiskit-ibm-runtime"),
        "credentials_configured": explicit_credentials or bool(saved_accounts),
        "credential_mode": (
            "environment" if explicit_credentials
            else "saved_account" if saved_accounts
            else "none"
        ),
        "token_source": cfg.token_source or None,
        "instance_source": cfg.instance_source or None,
        "saved_account_names": saved_accounts,
        "channel": cfg.channel,
        "connected": None,
        "backend_count": None,
        "instance_plans": [],
    }
    if not connect:
        return status
    if service_factory is None:
        if service_class is None:
            _, _, service_class, _ = _runtime_imports()
        service_factory = service_class
    if explicit_credentials:
        service = service_factory(channel=cfg.channel, token=cfg.token, instance=cfg.instance)
    elif cfg.token or cfg.instance:
        cfg.require_configured()
    elif saved_accounts:
        service = service_factory()
    else:
        cfg.require_configured()
    backends = service.backends(operational=True, simulator=False)
    plans = []
    for item in service.instances() or ():
        if not isinstance(item, dict):
            continue
        plan = item.get("plan") or item.get("plan_type")
        if isinstance(plan, dict):
            plan = plan.get("name") or plan.get("type")
        if plan:
            plans.append(str(plan))
    status.update(
        connected=True,
        backend_count=len(backends),
        instance_plans=sorted(set(plans)),
    )
    return status


class IBMQuantumRuntime:
    """Submit guarded Bell-pair attestations through IBM Runtime job mode."""

    def __init__(
        self,
        armor: Pramagent,
        *,
        config: IBMRuntimeConfig | None = None,
        tenant_id: str = "default",
        session_id: str = "default",
        max_shots_per_call: int = DEFAULT_MAX_SHOTS_PER_CALL,
        max_shots_per_session: int = DEFAULT_MAX_SHOTS_PER_SESSION,
        service: Any | None = None,
        sampler_factory: Callable[..., Any] | None = None,
        pass_manager_factory: Callable[..., Any] | None = None,
        budget_ledger: QuantumBudgetLedgerBackend | None = None,
    ) -> None:
        if max_shots_per_call < 1 or max_shots_per_session < 1:
            raise ValueError("shot budgets must be at least 1")
        self.armor = armor
        self.config = config or IBMRuntimeConfig.from_env()
        self.tenant_id = tenant_id
        self.session_id = session_id
        self.max_shots_per_call = max_shots_per_call
        self.max_shots_per_session = max_shots_per_session
        self._service = service
        self._sampler_factory = sampler_factory
        self._pass_manager_factory = pass_manager_factory
        self._budget_ledger = budget_ledger
        self._budget_limits = QuantumBudgetLimits(
            max_shots=max_shots_per_session,
            max_cost_usd=0.0,
        )

    def _audit(self, event: str, **fields: Any) -> None:
        self.armor.audit.append({
            "source": "ibm_quantum_runtime",
            "event": event,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            **fields,
        })

    def _session_shots(self) -> int:
        if self._budget_ledger is not None:
            return self._budget_ledger.snapshot(
                self.tenant_id, self.session_id
            ).shots
        shots_by_decision: dict[str, int] = {}
        for record in self.armor.audit.records():
            payload = record.get("payload", record) if isinstance(record, dict) else record
            if not isinstance(payload, dict):
                continue
            if (
                payload.get("source") != "ibm_quantum_runtime"
                or payload.get("tenant_id") != self.tenant_id
                or payload.get("session_id") != self.session_id
                or payload.get("event") not in {
                    "qpu_job_submitted", "qpu_submission_uncertain", "qpu_job_completed"
                }
            ):
                continue
            decision_id = str(payload.get("decision_id") or "")
            if not decision_id:
                continue
            requested = int(payload.get("shots_requested", 0) or 0)
            observed = int(payload.get("shots_observed", 0) or 0)
            shots_by_decision[decision_id] = max(
                shots_by_decision.get(decision_id, 0), requested, observed
            )
        return sum(shots_by_decision.values())

    def _get_service(self):
        if self._service is not None:
            return self._service
        _, _, QiskitRuntimeService, _ = _runtime_imports()
        if self.config.configured:
            self._service = QiskitRuntimeService(
                channel=self.config.channel,
                token=self.config.token,
                instance=self.config.instance,
            )
        elif self.config.token or self.config.instance:
            self.config.require_configured()
        else:
            self._service = QiskitRuntimeService()
        return self._service

    def run_hardware_attestation(
        self,
        *,
        shots: int = 128,
        backend_name: str = "",
        confirm_hardware: bool = False,
        allow_unpriced_hardware: bool = False,
        minimum_correlation: float = 0.60,
        optimization_level: int = 3,
        initial_layout: tuple[int, int] | list[int] | None = None,
        max_layout_error_proxy: float | None = None,
        calibration_valid_for_seconds: float = 900.0,
    ) -> QuantumAttestationResult:
        """Run a Bell-pair circuit on a physical IBM QPU.

        Both consent flags are required. IBM meters QPU execution time rather
        than publishing a universal per-shot dollar rate, so callers must make
        an explicit plan/quota decision outside this adapter.
        """
        if not isinstance(shots, int) or isinstance(shots, bool) or shots < 1:
            raise ValueError("shots must be a positive integer")
        if not 0.0 <= minimum_correlation <= 1.0:
            raise ValueError("minimum_correlation must be between 0 and 1")
        if optimization_level not in {0, 1, 2, 3}:
            raise ValueError("optimization_level must be between 0 and 3")
        layout = None
        if initial_layout is not None:
            layout = tuple(initial_layout)
            if (
                len(layout) != 2
                or any(
                    not isinstance(qubit, int)
                    or isinstance(qubit, bool)
                    or qubit < 0
                    for qubit in layout
                )
                or layout[0] == layout[1]
            ):
                raise ValueError("initial_layout must contain two distinct qubit IDs")
        if max_layout_error_proxy is not None and (
            not math.isfinite(float(max_layout_error_proxy))
            or not 0.0 <= float(max_layout_error_proxy) <= 1.0
        ):
            raise ValueError("max_layout_error_proxy must be between 0 and 1")
        if calibration_valid_for_seconds <= 0:
            raise ValueError("calibration_valid_for_seconds must be positive")
        try:
            audit_chain_valid = bool(self.armor.audit.verify_chain())
        except Exception as exc:
            raise QuantumAuditIntegrityError(
                "quantum audit chain could not be verified before submission"
            ) from exc
        if not audit_chain_valid:
            raise QuantumAuditIntegrityError(
                "quantum audit chain is invalid; refusing hardware submission. "
                "Restore the matching versioned signing-key ring or select a fresh "
                "--audit-db; do not overwrite the existing evidence"
            )
        if shots > self.max_shots_per_call:
            self._audit(
                "qpu_budget_blocked",
                reason="per-call shot budget would be exceeded",
                shots_requested=shots,
                max_shots_per_call=self.max_shots_per_call,
            )
            raise QuantumBudgetExceeded(
                f"per-call shot budget exceeded: {shots} > {self.max_shots_per_call}"
            )
        if not confirm_hardware:
            self._audit(
                "qpu_execution_refused",
                reason="physical QPU execution requires explicit operator consent",
                shots_requested=shots,
            )
            raise QuantumHardwareConsentRequired(
                "physical QPU execution requires explicit operator consent"
            )
        if not allow_unpriced_hardware:
            self._audit(
                "qpu_execution_refused",
                reason="IBM QPU-time cost is not known preflight; explicit acknowledgement required",
                shots_requested=shots,
            )
            raise QuantumHardwareConsentRequired(
                "IBM QPU-time cost is not known preflight; pass explicit acknowledgement only "
                "after checking the selected IBM instance plan and remaining quota"
            )

        _, generate_preset_pass_manager, _, SamplerV2 = _runtime_imports()
        service = self._get_service()
        backend = (
            service.backend(backend_name)
            if backend_name
            else service.least_busy(operational=True, simulator=False, min_num_qubits=2)
        )
        selected_backend = _backend_name(backend)
        circuit = build_bell_circuit()
        pass_manager_factory = self._pass_manager_factory or generate_preset_pass_manager
        pass_manager_options: dict[str, Any] = {
            "backend": backend,
            "optimization_level": optimization_level,
        }
        if layout is not None:
            pass_manager_options["initial_layout"] = list(layout)
        pass_manager = pass_manager_factory(**pass_manager_options)
        isa_circuit = pass_manager.run(circuit)
        circuit_hash = _circuit_hash(circuit)
        physical_qubits = _physical_qubits(circuit, isa_circuit)
        calibration_snapshot_at = _calibration_snapshot_at(backend)
        layout_error_profile = _layout_error_profile(backend, isa_circuit)
        if max_layout_error_proxy is not None:
            profile_complete = bool(
                layout_error_profile and layout_error_profile.get("complete")
            )
            measured_proxy = (
                float(layout_error_profile["total_error_proxy"])
                if profile_complete
                else None
            )
            if measured_proxy is None or measured_proxy > max_layout_error_proxy:
                reason = (
                    "selected layout error metadata is incomplete"
                    if measured_proxy is None
                    else (
                        f"selected layout error proxy {measured_proxy:.6f} exceeds "
                        f"limit {max_layout_error_proxy:.6f}"
                    )
                )
                self._audit(
                    "qpu_layout_blocked",
                    reason=reason,
                    backend=selected_backend,
                    circuit_hash=circuit_hash,
                    optimization_level=optimization_level,
                    physical_qubits=list(physical_qubits),
                    layout_error_profile=layout_error_profile,
                    max_layout_error_proxy=max_layout_error_proxy,
                    calibration_snapshot_at=calibration_snapshot_at,
                )
                raise QuantumLayoutQualityError(reason)
        call_args = {
            "provider": "ibm_quantum_platform",
            "backend": selected_backend,
            "shots": shots,
            "wires": 2,
            "depth": int(isa_circuit.depth()),
            "circuit_hash": circuit_hash,
            "pricing_model": "ibm_qpu_time_unpriced",
        }

        with _SUBMISSION_LOCK:
            spent = self._session_shots()
            reservation_id = None
            if self._budget_ledger is not None:
                reservation = self._budget_ledger.reserve(
                    tenant_id=self.tenant_id,
                    session_id=self.session_id,
                    circuit_name="bell_attestation",
                    estimated_shots=shots,
                    estimated_cost_usd=0.0,
                    limits=self._budget_limits,
                )
                if not reservation.allowed:
                    self._audit(
                        "qpu_budget_blocked",
                        reason=reservation.reason,
                        shots_requested=shots,
                        session_shots_before=reservation.before.shots,
                        max_shots_per_session=self.max_shots_per_session,
                        backend=selected_backend,
                        circuit_hash=circuit_hash,
                    )
                    raise QuantumBudgetExceeded(reservation.reason)
                reservation_id = reservation.reservation_id
                spent = reservation.before.shots
            elif spent + shots > self.max_shots_per_session:
                self._audit(
                    "qpu_budget_blocked",
                    reason="session shot budget would be exceeded",
                    shots_requested=shots,
                    session_shots_before=spent,
                    max_shots_per_session=self.max_shots_per_session,
                    backend=selected_backend,
                    circuit_hash=circuit_hash,
                )
                raise QuantumBudgetExceeded(
                    f"session shot budget exceeded: {spent} + {shots} > "
                    f"{self.max_shots_per_session}"
                )

            try:
                decision = self.armor.validate_tool(
                    IBM_HARDWARE_TOOL_NAME,
                    call_args,
                    tenant_id=self.tenant_id,
                    session_id=self.session_id,
                    action_label="bell_attestation",
                )
            except Exception:
                if self._budget_ledger is not None and reservation_id:
                    self._budget_ledger.release(reservation_id)
                raise
            if decision.verdict != Verdict.ALLOW:
                if self._budget_ledger is not None and reservation_id:
                    self._budget_ledger.release(reservation_id)
                self._audit(
                    "qpu_policy_blocked",
                    decision_id=decision.decision_id,
                    verdict=decision.verdict.value,
                    reason=decision.reason,
                    shots_requested=shots,
                    backend=selected_backend,
                    circuit_hash=circuit_hash,
                )
                if decision.verdict == Verdict.ESCALATE:
                    raise QuantumHardwareConsentRequired(decision.reason)
                raise QuantumBudgetExceeded(decision.reason)

            sampler_factory = self._sampler_factory or SamplerV2
            sampler = sampler_factory(mode=backend)
            submitted_at = time.time()
            self._audit(
                "qpu_execution_authorized",
                decision_id=decision.decision_id,
                shots_requested=shots,
                backend=selected_backend,
                circuit_hash=circuit_hash,
                operator_consent=True,
                unpriced_usage_acknowledged=True,
                reservation_id=reservation_id,
                physical_qubits=list(physical_qubits),
                optimization_level=optimization_level,
                layout_error_profile=layout_error_profile,
                calibration_snapshot_at=calibration_snapshot_at,
            )
            try:
                job = sampler.run([isa_circuit], shots=shots)
            except Exception as exc:
                if self._budget_ledger is not None and reservation_id:
                    self._budget_ledger.mark_uncertain(reservation_id)
                self._audit(
                    "qpu_submission_uncertain",
                    decision_id=decision.decision_id,
                    reason=f"provider submission failed: {exc.__class__.__name__}",
                    shots_requested=shots,
                    session_shots_after=spent + shots,
                    backend=selected_backend,
                    circuit_hash=circuit_hash,
                    reservation_id=reservation_id,
                )
                raise
            job_id = _job_id(job)
            self._audit(
                "qpu_job_submitted",
                decision_id=decision.decision_id,
                job_id=job_id,
                shots_requested=shots,
                session_shots_after=spent + shots,
                backend=selected_backend,
                circuit_hash=circuit_hash,
                transpiled_depth=int(isa_circuit.depth()),
                submitted_at=submitted_at,
                pricing_model="ibm_qpu_time_unpriced",
                operator_consent=True,
                unpriced_usage_acknowledged=True,
                reservation_id=reservation_id,
                physical_qubits=list(physical_qubits),
                optimization_level=optimization_level,
                layout_error_profile=layout_error_profile,
                calibration_snapshot_at=calibration_snapshot_at,
            )

        try:
            primitive_result = job.result()
            counts = _extract_counts(primitive_result)
        except Exception as exc:
            if self._budget_ledger is not None and reservation_id:
                self._budget_ledger.mark_uncertain(reservation_id)
            self._audit(
                "qpu_job_failed",
                decision_id=decision.decision_id,
                job_id=job_id,
                reason=f"provider result failed: {exc.__class__.__name__}",
                shots_requested=shots,
                backend=selected_backend,
                circuit_hash=circuit_hash,
                reservation_id=reservation_id,
            )
            raise

        observed = sum(counts.values())
        if observed < 1:
            raise RuntimeError("IBM Sampler result reported zero observed shots")
        correlated = counts.get("00", 0) + counts.get("11", 0)
        correlation = round(correlated / observed, 6)
        usage_seconds = _float_or_none(_safe_job_metric(job, "usage"))
        passed = correlation >= minimum_correlation
        if self._budget_ledger is not None and reservation_id:
            reconciliation = self._budget_ledger.reconcile(
                reservation_id,
                actual_shots=observed,
                actual_cost_usd=0.0,
                limits=self._budget_limits,
            )
        else:
            reconciliation = None
        completed_at = time.time()
        evidence = QuantumExecutionEvidence(
            provider="ibm_quantum_platform",
            backend=selected_backend,
            execution_id=job_id,
            workload="bell_attestation",
            device_kind="hardware",
            circuit_hash=circuit_hash,
            shots_requested=shots,
            shots_observed=observed,
            pricing_model="ibm_qpu_time_unpriced",
            estimated_cost_usd=None,
            actual_cost_usd=None,
            queue_seconds=None,
            usage_seconds=usage_seconds,
            submitted_at=submitted_at,
            completed_at=completed_at,
            counts=counts,
        ).seal()
        calibration_canary = CalibrationCanaryEvidence(
            provider=evidence.provider,
            backend=evidence.backend,
            execution_id=evidence.execution_id,
            execution_evidence_hash=evidence.evidence_hash,
            completed_at=completed_at,
            metric_name="same_bit_correlation",
            metric_value=correlation,
            minimum_value=minimum_correlation,
            passed=passed,
            valid_for_seconds=float(calibration_valid_for_seconds),
            physical_qubits=physical_qubits,
            calibration_snapshot_at=calibration_snapshot_at,
            layout_error_profile=layout_error_profile,
        ).seal()
        self._audit(
            "qpu_job_completed",
            decision_id=decision.decision_id,
            job_id=job_id,
            backend=selected_backend,
            shots_requested=shots,
            shots_observed=observed,
            counts=counts,
            bell_correlation=correlation,
            minimum_correlation=minimum_correlation,
            passed=passed,
            circuit_hash=circuit_hash,
            usage_seconds=usage_seconds,
            reservation_id=reservation_id,
            budget_overrun=bool(reconciliation and reconciliation.over_limit),
            evidence=evidence.to_dict(),
            calibration_canary=calibration_canary.to_dict(),
            physical_qubits=list(physical_qubits),
            optimization_level=optimization_level,
            layout_error_profile=layout_error_profile,
            calibration_snapshot_at=calibration_snapshot_at,
        )
        return QuantumAttestationResult(
            provider="ibm_quantum_platform",
            backend=selected_backend,
            job_id=job_id,
            shots_requested=shots,
            shots_observed=observed,
            counts=counts,
            bell_correlation=correlation,
            passed=passed,
            minimum_correlation=minimum_correlation,
            circuit_depth=int(circuit.depth()),
            transpiled_depth=int(isa_circuit.depth()),
            optimization_level=optimization_level,
            wires=2,
            circuit_hash=circuit_hash,
            layout_error_profile=layout_error_profile or {},
            queue_seconds=None,
            usage_seconds=usage_seconds,
            audit_chain_valid=self.armor.audit.verify_chain(),
            evidence=evidence.to_dict(),
            calibration_canary=calibration_canary.to_dict(),
            physical_qubits=physical_qubits,
            calibration_snapshot_at=calibration_snapshot_at,
        )
