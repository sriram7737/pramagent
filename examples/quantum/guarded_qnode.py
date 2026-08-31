"""Pramagent guarded PennyLane QNode execution."""
from __future__ import annotations

import hashlib
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pramagent import Pramagent, SideEffect, ToolPolicy, Verdict

TOOL_NAME = "quantum_execute"
HARDWARE_TOOL_NAME = "quantum_execute_hw"

# Dated 2026-08-30. Amazon Braket publishes per-task plus per-shot QPU rates.
# IBM publishes time-based access pricing, so IBM devices stay fail-closed
# unless a caller supplies a project-specific estimator.
BRACKET_TASK_PRICE_USD = 0.30
PRICING_USD_PER_SHOT: dict[str, float | None] = {
    "simulator": 0.0,
    "braket:aqt": 0.02350,
    "braket:ionq": 0.08000,
    "braket:iqm_emerald": 0.00160,
    "braket:iqm_garnet": 0.00145,
    "braket:quera": 0.01000,
    "braket:rigetti": 0.000425,
    "ibm": None,
}

_SIMULATOR_PREFIXES = ("default.", "lightning.", "null.")

# Provider/device tokens that mean "real QPU, real money". Any of these in a
# device name forces a hardware classification even when the name also carries
# a simulator-looking prefix (e.g. a plugin device short-named
# "default.ionq_forte"). Fail-safe: a metering/approval boundary must not be
# defeated by a substring prefix (F3).
_HARDWARE_TOKENS = (
    "braket", "ibm", "rigetti", "cepheus", "ionq", "forte",
    "quera", "aquila", "aqt", "ibex", "iqm", "garnet", "emerald",
)


class QuantumBudgetExceeded(PermissionError):
    """Raised when policy blocks execution or pricing is unknown."""


class ApprovalRequired(PermissionError):
    """Raised on ToolGuard ESCALATE so the app can route to HITL."""

    def __init__(self, decision):
        self.decision = decision
        super().__init__(decision.reason)


class QuantumPolicyViolation(PermissionError):
    """Raised when an input, circuit-structure, or result-sanity guard rejects
    a call. Carries the individual violation strings for the caller/HITL."""

    def __init__(self, message: str, violations: list[str] | None = None):
        self.violations = violations or []
        super().__init__(message)


def _device_name(qnode) -> str:
    dev = getattr(qnode, "device", None)
    return str(getattr(dev, "name", None) or getattr(dev, "short_name", None) or dev or "")


def _device_kind(device_name: str) -> str:
    name = device_name.lower()
    # Hardware tokens win over any simulator-looking prefix (F3): a device
    # named "default.ionq_forte" is an IonQ QPU, not a free simulator.
    if any(tok in name for tok in _HARDWARE_TOKENS):
        return "hardware"
    if name.startswith(_SIMULATOR_PREFIXES) or "simulator" in name:
        return "simulator"
    # Unknown/undiscoverable device: fail safe to hardware so it must be
    # priced (and, when unpriced, fails closed) rather than run free.
    return "hardware"


def _pricing_key(device_name: str, provider_hint: str = "") -> str:
    name = f"{provider_hint} {device_name}".lower()
    if _device_kind(device_name) == "simulator":
        return "simulator"
    if "braket" in name or any(p in name for p in ("rigetti", "ionq", "quera", "aqt", "iqm")):
        if "rigetti" in name or "cepheus" in name:
            return "braket:rigetti"
        if "ionq" in name or "forte" in name:
            return "braket:ionq"
        if "quera" in name or "aquila" in name:
            return "braket:quera"
        if "aqt" in name or "ibex" in name:
            return "braket:aqt"
        if "garnet" in name:
            return "braket:iqm_garnet"
        if "iqm" in name or "emerald" in name:
            return "braket:iqm_emerald"
    if "ibm" in name:
        return "ibm"
    return ""


def _parse_shots(obj: Any) -> int | None:
    """Best-effort integer shot count, or None when the value cannot be
    interpreted. Callers fail closed on None instead of metering an
    unknown-cost call as zero shots (F4). A genuine None/analytic device
    maps to 0 shots (exact simulation runs no samples)."""
    if obj is None:
        return 0
    if isinstance(obj, bool):
        return None
    if isinstance(obj, int):
        return obj
    total = getattr(obj, "total_shots", None)
    if total is not None:
        try:
            return int(total)
        except (TypeError, ValueError):
            return None
    try:
        return int(obj)
    except (TypeError, ValueError):
        return None


def _shots_from(obj: Any) -> int:
    """Backward-compatible wrapper: unparseable/None -> 0. Internal callers
    that must fail closed use _parse_shots directly."""
    return _parse_shots(obj) or 0


def _lookup(obj: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        value = getattr(obj, name, None)
        if value is not None:
            return value
    return default


def _default_specs(qnode, *args, **kwargs) -> Any:
    try:
        import pennylane as qml
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PennyLane is required for guarded QNode inspection") from exc
    return qml.specs(qnode)(*args, **kwargs)


def pennylane_tracker_meter(qnode, *args, **kwargs) -> tuple[Any, dict[str, int]]:
    """Execute a real PennyLane QNode under ``qml.Tracker`` and return
    ``(result, {"shots", "executions", "circuits"})`` with the MEASURED device
    totals.

    A single ``qnode(params)`` under a gradient runs many circuits
    (parameter-shift ≈ 2·num_params + 1), and error mitigation multiplies shots
    again — so a one-circuit ``qml.specs`` estimate can badly undercount real
    spend. Metering the tracker totals captures what actually executed. Pass
    this as ``GuardedQNode(meter_func=pennylane_tracker_meter)``; the adapter
    then emits a ``quantum_cost_reconciled`` audit event and bills subsequent
    budget against the measured shots. Import is deferred so the rest of the
    module works without PennyLane installed."""
    import pennylane as qml  # noqa: PLC0415 - deferred so PennyLane stays optional

    dev = getattr(qnode, "device", None)
    with qml.Tracker(dev) as tracker:
        result = qnode(*args, **kwargs)
    totals = dict(getattr(tracker, "totals", {}) or {})
    return result, {
        "shots": int(totals.get("shots", 0) or 0),
        "executions": int(totals.get("executions", 0) or 0),
        "circuits": int(totals.get("batches", 0) or 0),
    }


# ── input / circuit / result guard policies ───────────────────────────────────
#
# These take the adapter from "metered execution" to "policy-enforced
# execution": what a circuit is allowed to look like and what data is allowed
# to flow through it, not just how much it may cost. All three are opt-in
# (default None on GuardedQNode) so existing budget-only behavior is unchanged.
#
# Field extraction from qml.specs() is best-effort across PennyLane versions
# (see _extract_structure); the guards read a normalized structure dict so the
# same policy works against injected specs in tests and real specs in prod.


@dataclass
class InputPolicy:
    """Bounds on the tensor(s) fed to a QNode, checked BEFORE circuit
    construction so a hostile/NaN/oversized input never reaches qml.specs."""
    require_finite: bool = True          # reject NaN / +-inf
    angle_min: float | None = None       # reject inputs below this (radians)
    angle_max: float | None = None       # reject inputs above this
    max_abs_value: float | None = None   # reject |value| over this
    max_batch_size: int | None = None    # leading-dim cap on the first arg
    max_elements: int | None = None      # total numeric-leaf count cap
    allowed_dtypes: set[str] | None = None  # e.g. {"float32", "float64", "float"}


@dataclass
class CircuitPolicy:
    """Bounds on circuit STRUCTURE, checked on the tape/specs before execution."""
    allowed_gates: set[str] | None = None      # whitelist of gate names
    disallowed_gates: set[str] | None = None   # blacklist of gate names
    max_gates: int | None = None
    max_entanglers: int | None = None          # gates acting on >= 2 wires
    max_measurements: int | None = None
    max_trainable_params: int | None = None
    max_depth: int | None = None
    max_wires: int | None = None
    allow_mid_circuit_measurements: bool = False
    allow_dynamic_wires: bool = True


@dataclass
class ResultPolicy:
    """Post-execution sanity bounds on the returned value(s). For expectation
    values set min_value=-1.0, max_value=1.0."""
    require_finite: bool = True
    min_value: float | None = None
    max_value: float | None = None


def _iter_numeric_leaves(obj: Any):
    """Yield every finite-or-not float leaf reachable from obj: python scalars,
    lists/tuples, dicts (values), and anything array-like with .tolist().
    Non-numeric leaves are skipped. bool is treated as a control value, not
    data, and skipped."""
    if obj is None or isinstance(obj, bool):
        return
    if isinstance(obj, (int, float)):
        yield float(obj)
        return
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_numeric_leaves(v)
        return
    tolist = getattr(obj, "tolist", None)
    if callable(tolist):
        try:
            obj = tolist()
        except Exception:
            return
    if isinstance(obj, (list, tuple)):
        for item in obj:
            yield from _iter_numeric_leaves(item)
        return
    try:
        yield float(obj)
    except (TypeError, ValueError):
        return


def _batch_size(obj: Any) -> int:
    shape = getattr(obj, "shape", None)
    if shape is not None:
        try:
            return int(shape[0]) if len(shape) >= 1 else 0
        except (TypeError, ValueError, IndexError):
            return 0
    if isinstance(obj, (list, tuple)):
        return len(obj)
    return 0


def _dtype_names(args: tuple, kwargs: dict) -> list[str]:
    names: set[str] = set()
    control = {"shots"}
    for obj in list(args) + [v for k, v in kwargs.items() if k not in control]:
        dt = getattr(obj, "dtype", None)
        if dt is not None:
            names.add(str(dt))
        elif isinstance(obj, float):
            names.add("float")
        elif isinstance(obj, int) and not isinstance(obj, bool):
            names.add("int")
        elif isinstance(obj, (list, tuple)):
            names.add("list")
    return sorted(names)


def _summarize_inputs(args: tuple, kwargs: dict) -> dict[str, Any]:
    """Shape/dtype/finiteness/range summary of the call inputs, plus a stable
    content hash usable as an input-and-weights fingerprint (replayable audit)
    and as a parameter-drift signal. The ``shots`` kwarg is a control value,
    not data, and is excluded."""
    control = {"shots"}
    data_kwargs = {k: v for k, v in kwargs.items() if k not in control}
    leaves: list[float] = list(_iter_numeric_leaves(list(args)))
    for k in sorted(data_kwargs):
        leaves.extend(_iter_numeric_leaves(data_kwargs[k]))
    has_nan = any(math.isnan(x) for x in leaves)
    has_inf = any(math.isinf(x) for x in leaves)
    finite = [x for x in leaves if math.isfinite(x)]
    mn = min(finite) if finite else None
    mx = max(finite) if finite else None
    norm = round(math.sqrt(sum(x * x for x in finite)), 9) if finite else 0.0
    digest = hashlib.sha256(
        repr([round(x, 9) for x in leaves]).encode("utf-8")
    ).hexdigest()
    return {
        "n_elements": len(leaves),
        "batch_size": _batch_size(args[0]) if args else 0,
        "min": mn,
        "max": mx,
        "l2_norm": norm,
        "has_nan": has_nan,
        "has_inf": has_inf,
        "all_finite": not (has_nan or has_inf),
        "dtypes": _dtype_names(args, kwargs),
        "hash": digest,
    }


def _check_input(summary: dict, policy: InputPolicy) -> list[str]:
    v: list[str] = []
    if policy.require_finite and not summary["all_finite"]:
        v.append("non-finite input values (" +
                 ("NaN" if summary["has_nan"] else "inf") + ")")
    if policy.max_elements is not None and summary["n_elements"] > policy.max_elements:
        v.append(f"input element count {summary['n_elements']} > max_elements {policy.max_elements}")
    if policy.max_batch_size is not None and summary["batch_size"] > policy.max_batch_size:
        v.append(f"batch size {summary['batch_size']} > max_batch_size {policy.max_batch_size}")
    mn, mx = summary["min"], summary["max"]
    if policy.angle_min is not None and mn is not None and mn < policy.angle_min:
        v.append(f"input min {mn} < angle_min {policy.angle_min}")
    if policy.angle_max is not None and mx is not None and mx > policy.angle_max:
        v.append(f"input max {mx} > angle_max {policy.angle_max}")
    if policy.max_abs_value is not None:
        peak = max(abs(mn) if mn is not None else 0.0, abs(mx) if mx is not None else 0.0)
        if peak > policy.max_abs_value:
            v.append(f"input abs peak {peak} > max_abs_value {policy.max_abs_value}")
    if policy.allowed_dtypes is not None:
        bad = [d for d in summary["dtypes"] if d not in policy.allowed_dtypes]
        if bad:
            v.append(f"disallowed input dtype(s): {sorted(bad)}")
    return v


def _extract_structure(specs: Any, resources: Any) -> dict[str, Any]:
    """Normalize the fields the circuit guard needs out of a qml.specs() result.
    Best-effort: PennyLane's specs shape has shifted across versions, so every
    field is looked up under several names with a safe default and never
    raises. Missing counts read as None (not enforced) rather than 0."""
    gate_types = _lookup(resources, "gate_types", "gate_counts", default={}) or {}
    gate_counts: dict[str, int] = {}
    if hasattr(gate_types, "items"):
        for name, count in gate_types.items():
            try:
                gate_counts[str(name)] = int(count)
            except (TypeError, ValueError):
                continue
    gate_sizes = _lookup(resources, "gate_sizes", default={}) or {}
    entanglers = 0
    if hasattr(gate_sizes, "items"):
        for size, count in gate_sizes.items():
            try:
                if int(size) >= 2:
                    entanglers += int(count)
            except (TypeError, ValueError):
                continue
    fallback_gates = sum(gate_counts.values())
    num_gates = int(_lookup(resources, "num_gates", "num_operations",
                            default=fallback_gates) or 0)
    depth = int(_lookup(resources, "depth", default=0) or 0)
    num_wires = int(_lookup(
        resources, "num_wires", "wires", "num_allocs", default=0
    ) or _lookup(specs, "num_device_wires", default=0) or 0)
    num_trainable = _lookup(specs, "num_trainable_params",
                            "num_trainable_parameters", default=None)
    num_meas = _lookup(specs, "num_observables", "num_measurements", default=None)
    if num_meas is None:
        num_meas = _lookup(resources, "num_measurements", default=None)
    if num_meas is None:
        measurements = _lookup(resources, "measurements", default=None)
        if hasattr(measurements, "values"):
            num_meas = sum(
                int(count) for count in measurements.values()
                if isinstance(count, (int, float))
            )
    mid = int(_lookup(resources, "num_mid_circuit_measurements", default=0)
              or _lookup(specs, "num_mid_circuit_measurements", default=0) or 0)
    dynamic = bool(_lookup(specs, "dynamic_wires", default=False)
                   or _lookup(resources, "dynamic_wires", default=False))
    meas_types = _lookup(specs, "measurement_types", default=None)
    return {
        "gate_counts": gate_counts,
        "num_gates": num_gates,
        "num_entanglers": entanglers,
        "depth": depth,
        "num_wires": num_wires,
        "num_trainable_params": int(num_trainable) if num_trainable is not None else None,
        "num_measurements": int(num_meas) if num_meas is not None else None,
        "num_mid_circuit_measurements": mid,
        "dynamic_wires": dynamic,
        "measurement_types": list(meas_types) if meas_types else [],
    }


def _check_structure(structure: dict, policy: CircuitPolicy) -> list[str]:
    v: list[str] = []
    gates = set(structure["gate_counts"].keys())
    if policy.allowed_gates is not None:
        extra = sorted(g for g in gates if g not in policy.allowed_gates)
        if extra:
            v.append(f"gate(s) not in allow-list: {extra}")
    if policy.disallowed_gates:
        hit = sorted(g for g in gates if g in policy.disallowed_gates)
        if hit:
            v.append(f"disallowed gate(s) present: {hit}")

    def cap(label: str, key: str, limit: int | None) -> None:
        val = structure.get(key)
        if limit is not None and val is not None and val > limit:
            v.append(f"{label} {val} > max {limit}")

    cap("gate count", "num_gates", policy.max_gates)
    cap("entangler count", "num_entanglers", policy.max_entanglers)
    cap("measurement count", "num_measurements", policy.max_measurements)
    cap("trainable params", "num_trainable_params", policy.max_trainable_params)
    cap("circuit depth", "depth", policy.max_depth)
    cap("wire count", "num_wires", policy.max_wires)
    if not policy.allow_mid_circuit_measurements and structure["num_mid_circuit_measurements"] > 0:
        v.append(f"mid-circuit measurements present ({structure['num_mid_circuit_measurements']}) "
                 "but not allowed")
    if not policy.allow_dynamic_wires and structure["dynamic_wires"]:
        v.append("dynamic wires present but not allowed")
    return v


def _check_result(result: Any, policy: ResultPolicy) -> list[str]:
    leaves = list(_iter_numeric_leaves(result))
    v: list[str] = []
    if policy.require_finite and any(not math.isfinite(x) for x in leaves):
        v.append("non-finite value in result")
    finite = [x for x in leaves if math.isfinite(x)]
    if finite:
        if policy.min_value is not None and min(finite) < policy.min_value:
            v.append(f"result min {min(finite)} < min_value {policy.min_value}")
        if policy.max_value is not None and max(finite) > policy.max_value:
            v.append(f"result max {max(finite)} > max_value {policy.max_value}")
    return v


def _circuit_fingerprint(structure: dict, input_summary: dict) -> tuple[str, str]:
    """Replayable fingerprint of a call: a hash over gate list, wires, depth,
    measurement types and trainable-param count (the circuit identity) plus the
    input/weights hash (the data identity). Returns (fingerprint, gate_list_hash)."""
    gate_items = sorted(structure.get("gate_counts", {}).items())
    gate_list_hash = hashlib.sha256(repr(gate_items).encode("utf-8")).hexdigest()
    material = {
        "gate_list_hash": gate_list_hash,
        "num_wires": structure.get("num_wires"),
        "depth": structure.get("depth"),
        "num_measurements": structure.get("num_measurements"),
        "measurement_types": structure.get("measurement_types"),
        "num_trainable_params": structure.get("num_trainable_params"),
        "input_hash": input_summary.get("hash", ""),
    }
    fingerprint = hashlib.sha256(
        repr(sorted(material.items())).encode("utf-8")
    ).hexdigest()
    return fingerprint, gate_list_hash


def _audit_meta_fields(meta: dict | None) -> dict[str, Any]:
    """The replayable-fingerprint fields merged into every quantum audit event."""
    if not meta:
        return {}
    s = meta.get("structure") or {}
    return {
        "fingerprint": meta.get("fingerprint", ""),
        "gate_list_hash": meta.get("gate_list_hash", ""),
        "input_hash": meta.get("input_hash", ""),
        "num_gates": s.get("num_gates"),
        "num_entanglers": s.get("num_entanglers"),
        "num_trainable_params": s.get("num_trainable_params"),
        "num_measurements": s.get("num_measurements"),
        "measurement_types": s.get("measurement_types"),
    }


def make_quantum_policies(
    *,
    max_shots_per_call: int = 1_000,
    max_shots_per_session: int = 10_000,
    max_cost_usd_per_session: float = 0.0,
    max_depth: int | None = None,
    max_calls_per_session: int | None = None,
    hardware_requires_approval: bool = True,
) -> list[ToolPolicy]:
    """Return simulator and hardware policies sharing one budget schema."""
    props: dict[str, Any] = {
        "shots": {"type": "integer", "minimum": 0, "maximum": max_shots_per_call},
        "wires": {"type": "integer", "minimum": 0},
        "depth": {"type": "integer", "minimum": 0},
        "estimated_joules": {"type": "number", "minimum": 0},
        "device": {"type": "string"},
        "device_kind": {"type": "string", "enum": ["simulator", "hardware"]},
        "pricing_key": {"type": "string"},
        "est_cost_usd": {"type": "number", "minimum": 0},
        "session_shots_after": {
            "type": "integer",
            "minimum": 0,
            "maximum": max_shots_per_session,
        },
        "session_cost_after_usd": {
            "type": "number",
            "minimum": 0,
            "maximum": max_cost_usd_per_session,
        },
    }
    if max_depth is not None:
        props["depth"]["maximum"] = max_depth

    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": props,
        "required": [
            "shots",
            "wires",
            "depth",
            "estimated_joules",
            "device",
            "device_kind",
            "pricing_key",
            "est_cost_usd",
            "session_shots_after",
            "session_cost_after_usd",
        ],
    }
    return [
        ToolPolicy(
            name=TOOL_NAME,
            schema=schema,
            side_effect=SideEffect.METERED_COMPUTE,
            max_calls_per_session=max_calls_per_session,
            detail="PennyLane simulator QNode execution under shot and cost budget",
        ),
        ToolPolicy(
            name=HARDWARE_TOOL_NAME,
            schema=schema,
            side_effect=SideEffect.PAYMENT,
            escalate_if_severity_gte=(
                SideEffect.PAYMENT if hardware_requires_approval else None
            ),
            max_calls_per_session=max_calls_per_session,
            detail="PennyLane hardware QNode execution under shot and cost budget",
        ),
    ]


def make_quantum_policy(**kwargs) -> ToolPolicy:
    """Backward-compatible helper returning the simulator policy."""
    return make_quantum_policies(**kwargs)[0]


class GuardedQNode:
    """Wrap a PennyLane QNode and route calls through Pramagent."""

    def __init__(
        self,
        qnode,
        armor: Pramagent,
        *,
        tenant_id: str = "default",
        session_id: str = "default",
        pricing: dict[str, float | None] | None = None,
        provider_hint: str = "",
        specs_func: Callable[..., Any] | None = None,
        joules_per_shot: float = 0.0,
        input_policy: InputPolicy | None = None,
        circuit_policy: CircuitPolicy | None = None,
        result_policy: ResultPolicy | None = None,
        meter_func: Callable[..., tuple[Any, dict]] | None = None,
    ) -> None:
        self._qnode = qnode
        self._armor = armor
        self._tenant_id = tenant_id
        self._session_id = session_id
        self._pricing = {**PRICING_USD_PER_SHOT, **(pricing or {})}
        self._provider_hint = provider_hint
        self._specs_func = specs_func
        self._joules_per_shot = max(float(joules_per_shot), 0.0)
        self._input_policy = input_policy
        self._circuit_policy = circuit_policy
        self._result_policy = result_policy
        # Optional measured-metering seam. When provided, meter_func executes the
        # QNode and returns (result, {"shots": actual, "executions": n}); the
        # ACTUAL shot count (gradient/mitigation multiplicity included) is then
        # reconciled against the pre-execution estimate. Default None keeps the
        # estimate-only behavior unchanged.
        self._meter_func = meter_func
        self.last_event: dict[str, Any] = {}

    def _resolve_shots(self, specs, *args, **kwargs) -> int | None:
        """Effective shot count for THIS call. A call-time ``shots=`` override
        (PennyLane dynamic shots) wins over the device/QNode default because
        the override is what actually executes — metering the device default
        while executing the override is the F1 budget bypass. Returns None
        when the count cannot be determined so the caller fails closed (F4)."""
        if "shots" in kwargs and kwargs["shots"] is not None:
            source = kwargs["shots"]
        else:
            source = (
                _lookup(getattr(self._qnode, "device", None), "shots")
                or _lookup(self._qnode, "shots")
                or _lookup(specs, "shots")
            )
        return _parse_shots(source)

    def _session_spent(self) -> tuple[int, float]:
        """Cumulative shots and USD cost for this (tenant, session), derived from
        the durable audit trail rather than volatile per-instance counters (F2).

        Each call is counted once, keyed by decision_id. When a
        ``quantum_cost_reconciled`` event exists for a call (measured metering),
        its ACTUAL shots/cost supersede the pre-execution estimate — so the
        budget accrues true spend, including gradient/mitigation multiplicity,
        not the single-circuit estimate. With a durable/shared audit backend
        this is consistent across adapter instances, workers, and processes."""
        shots_by_call: dict[str, int] = {}
        cost_by_call: dict[str, float] = {}
        for rec in self._armor.audit.records():
            p = rec.get("payload", rec) if isinstance(rec, dict) else rec
            if not (isinstance(p, dict)
                    and p.get("source") == "quantum_adapter"
                    and p.get("tenant_id") == self._tenant_id
                    and p.get("session_id") == self._session_id):
                continue
            did = p.get("decision_id")
            if did is None:
                continue
            event = p.get("event")
            if event == "quantum_call_executed":
                shots_by_call.setdefault(did, int(p.get("shots", 0) or 0))
                cost_by_call.setdefault(did, float(p.get("est_cost_usd", 0.0) or 0.0))
            elif event == "quantum_cost_reconciled":
                # measured actuals supersede the estimate for this call
                shots_by_call[did] = int(p.get("actual_shots", 0) or 0)
                cost_by_call[did] = float(p.get("actual_cost_usd", 0.0) or 0.0)
        return sum(shots_by_call.values()), round(sum(cost_by_call.values()), 6)

    def _audit_refused(self, event: str, reason: str, *, shots: int, device: str,
                       kind: str, pricing_key: str, wires: int, depth: int,
                       estimated_joules: float, est_cost_usd: float,
                       session_shots_after: int, session_cost_after_usd: float,
                       meta: dict | None = None) -> None:
        payload = {
            "source": "quantum_adapter",
            "event": event,
            "tenant_id": self._tenant_id,
            "session_id": self._session_id,
            "action_label": getattr(getattr(self._qnode, "func", self._qnode), "__name__", "qnode"),
            "verdict": Verdict.BLOCK.value,
            "reason": reason,
            "shots": shots,
            "wires": wires,
            "depth": depth,
            "estimated_joules": estimated_joules,
            "est_cost_usd": est_cost_usd,
            "session_shots_after": session_shots_after,
            "session_cost_after_usd": session_cost_after_usd,
            "device": device,
            "device_kind": kind,
            "pricing_key": pricing_key,
            **_audit_meta_fields(meta),
        }
        self.last_event = dict(payload)
        self._armor.audit.append(payload)

    def _inspect(self, *args, **kwargs) -> tuple[dict[str, Any], dict[str, Any]]:
        device = _device_name(self._qnode)
        kind = _device_kind(device)

        # Input guard: runs BEFORE qml.specs so a hostile/NaN/oversized tensor
        # never reaches circuit construction (item 1).
        input_summary = _summarize_inputs(args, kwargs)
        if self._input_policy is not None:
            violations = _check_input(input_summary, self._input_policy)
            if violations:
                reason = "input guard rejected call: " + "; ".join(violations)
                meta = {
                    "input_summary": input_summary, "structure": {},
                    "fingerprint": "", "gate_list_hash": "",
                    "input_hash": input_summary["hash"],
                }
                self._audit_refused(
                    "quantum_input_rejected", reason,
                    shots=0, device=device, kind=kind, pricing_key="",
                    wires=0, depth=0, estimated_joules=0.0, est_cost_usd=0.0,
                    session_shots_after=0, session_cost_after_usd=0.0, meta=meta,
                )
                raise QuantumPolicyViolation(reason, violations)

        specs = (
            self._specs_func(self._qnode, *args, **kwargs)
            if self._specs_func is not None
            else _default_specs(self._qnode, *args, **kwargs)
        )
        resources = _lookup(specs, "resources", default={})
        structure = _extract_structure(specs, resources)
        fingerprint, gate_list_hash = _circuit_fingerprint(structure, input_summary)
        meta = {
            "input_summary": input_summary, "structure": structure,
            "fingerprint": fingerprint, "gate_list_hash": gate_list_hash,
            "input_hash": input_summary["hash"],
        }

        # Circuit structure guard: allowed gates, entangler/measurement/param
        # caps, mid-circuit-measurement and dynamic-wire policy (item 2).
        if self._circuit_policy is not None:
            violations = _check_structure(structure, self._circuit_policy)
            if violations:
                reason = "circuit guard rejected call: " + "; ".join(violations)
                self._audit_refused(
                    "quantum_structure_rejected", reason,
                    shots=0, device=device, kind=kind,
                    pricing_key=_pricing_key(device, self._provider_hint) or "",
                    wires=structure["num_wires"], depth=structure["depth"],
                    estimated_joules=0.0, est_cost_usd=0.0,
                    session_shots_after=0, session_cost_after_usd=0.0, meta=meta,
                )
                raise QuantumPolicyViolation(reason, violations)

        pricing_key = _pricing_key(device, self._provider_hint)
        shots = self._resolve_shots(specs, *args, **kwargs)
        depth = int(_lookup(resources, "depth", default=0) or 0)
        wires = int(_lookup(resources, "num_wires", "wires", "num_allocs", default=0) or 0)
        spent_shots, spent_cost = self._session_spent()

        # F4: fail closed when the shot count is unknowable rather than
        # metering it as zero and running an unbounded-cost call for free.
        if shots is None:
            reason = (
                f"could not determine shot count for device '{device}'; "
                "refusing to run"
            )
            self._audit_refused(
                "quantum_shots_unparseable", reason,
                shots=0, device=device, kind=kind,
                pricing_key=pricing_key or "unknown", wires=wires, depth=depth,
                estimated_joules=0.0, est_cost_usd=0.0,
                session_shots_after=spent_shots, session_cost_after_usd=spent_cost,
                meta=meta,
            )
            raise QuantumBudgetExceeded(reason)

        estimated_joules = round(shots * self._joules_per_shot, 6)
        rate = self._pricing.get(pricing_key)
        if rate is None:
            reason = (
                f"no price configured for hardware device '{device}' "
                f"(pricing_key={pricing_key or 'unknown'}); refusing to run"
            )
            self._audit_refused(
                "quantum_pricing_refused", reason,
                shots=shots, device=device, kind=kind,
                pricing_key=pricing_key or "unknown", wires=wires, depth=depth,
                estimated_joules=estimated_joules, est_cost_usd=0.0,
                session_shots_after=spent_shots + shots,
                session_cost_after_usd=spent_cost, meta=meta,
            )
            raise QuantumBudgetExceeded(reason)
        per_task = (
            BRACKET_TASK_PRICE_USD
            if kind == "hardware" and pricing_key.startswith("braket:")
            else 0.0
        )
        cost = round((shots * float(rate)) + per_task, 6)
        call_args = {
            "shots": shots,
            "wires": wires,
            "depth": depth,
            "estimated_joules": estimated_joules,
            "device": device,
            "device_kind": kind,
            "pricing_key": pricing_key,
            "est_cost_usd": cost,
            "session_shots_after": spent_shots + shots,
            "session_cost_after_usd": round(spent_cost + cost, 6),
        }
        return call_args, meta

    def _audit_quantum_event(self, decision, call_args: dict[str, Any], event: str,
                             meta: dict | None = None) -> None:
        payload = {
            "source": "quantum_adapter",
            "event": event,
            "decision_id": decision.decision_id,
            "tool_name": decision.tool_name,
            "tenant_id": self._tenant_id,
            "session_id": self._session_id,
            "action_label": decision.action_label,
            "verdict": decision.verdict.value,
            "reason": decision.reason,
            "shots": call_args["shots"],
            "wires": call_args["wires"],
            "depth": call_args["depth"],
            "estimated_joules": call_args["estimated_joules"],
            "est_cost_usd": call_args["est_cost_usd"],
            "session_shots_after": call_args["session_shots_after"],
            "session_cost_after_usd": call_args["session_cost_after_usd"],
            "device": call_args["device"],
            "device_kind": call_args["device_kind"],
            "pricing_key": call_args["pricing_key"],
            **_audit_meta_fields(meta),
        }
        self.last_event = dict(payload)
        self._armor.audit.append(payload)

    def _audit_reconciliation(self, decision, call_args: dict[str, Any],
                              actual: dict, meta: dict | None = None) -> None:
        """Record measured execution against the pre-execution estimate.

        The estimate already gated this call (you cannot un-spend after the
        fact); reconciliation makes the true cost visible and feeds the next
        call's budget via _session_spent. Cost is recomputed from the measured
        shot count using the same rate the estimate used."""
        pricing_key = call_args["pricing_key"]
        rate = self._pricing.get(pricing_key) or 0.0
        per_task = (
            BRACKET_TASK_PRICE_USD
            if call_args["device_kind"] == "hardware" and pricing_key.startswith("braket:")
            else 0.0
        )
        est_shots = int(call_args["shots"])
        est_cost = round(float(call_args["est_cost_usd"]), 6)
        actual_shots = int(actual.get("shots", est_shots) or 0)
        actual_cost = round(actual_shots * float(rate) + per_task, 6)
        overran = actual_shots > est_shots
        payload = {
            "source": "quantum_adapter",
            "event": "quantum_cost_reconciled",
            "decision_id": decision.decision_id,
            "tool_name": decision.tool_name,
            "tenant_id": self._tenant_id,
            "session_id": self._session_id,
            "action_label": decision.action_label,
            "verdict": decision.verdict.value,
            "reason": (
                "measured execution reconciled against pre-execution estimate"
                + ("; actual exceeded estimate (execution multiplicity)" if overran else "")
            ),
            "est_shots": est_shots,
            "actual_shots": actual_shots,
            "actual_executions": int(actual.get("executions", 0) or 0),
            "est_cost_usd": est_cost,
            "actual_cost_usd": actual_cost,
            "shots_variance": actual_shots - est_shots,
            "cost_variance_usd": round(actual_cost - est_cost, 6),
            "over_estimate": overran,
            "device": call_args["device"],
            "device_kind": call_args["device_kind"],
            "pricing_key": pricing_key,
            **_audit_meta_fields(meta),
        }
        self._armor.audit.append(payload)

    def __call__(self, *args, **kwargs):
        call_args, meta = self._inspect(*args, **kwargs)
        tool_name = HARDWARE_TOOL_NAME if call_args["device_kind"] == "hardware" else TOOL_NAME
        qfunc = getattr(self._qnode, "func", self._qnode)
        decision = self._armor.validate_tool(
            tool_name,
            call_args,
            tenant_id=self._tenant_id,
            session_id=self._session_id,
            action_label=getattr(qfunc, "__name__", "qnode"),
        )
        if decision.verdict == Verdict.BLOCK:
            self._audit_quantum_event(decision, call_args, "quantum_call_blocked", meta)
            raise QuantumBudgetExceeded(decision.reason)
        if decision.verdict == Verdict.ESCALATE:
            self._audit_quantum_event(decision, call_args, "quantum_call_escalated", meta)
            raise ApprovalRequired(decision)

        if self._meter_func is not None:
            result, actual = self._meter_func(self._qnode, *args, **kwargs)
        else:
            result, actual = self._qnode(*args, **kwargs), None
        # Session spend is derived from this executed event on the next call
        # (see _session_spent), so there is no volatile per-instance counter
        # to reset by re-wrapping the QNode (F2). The executed event is written
        # BEFORE the result guard so spend stays accurate even when the result
        # is rejected — the shots were already consumed on hardware.
        self._audit_quantum_event(decision, call_args, "quantum_call_executed", meta)
        if actual is not None:
            # Reconcile MEASURED shots/cost against the estimate; the next call's
            # budget then accrues true spend (gradient/mitigation multiplicity).
            self._audit_reconciliation(decision, call_args, actual, meta)
        if self._result_policy is not None:
            violations = _check_result(result, self._result_policy)
            if violations:
                reason = "result guard rejected output: " + "; ".join(violations)
                self._audit_quantum_event(decision, call_args, "quantum_result_rejected", meta)
                raise QuantumPolicyViolation(reason, violations)
        return result


def guard_qnode(armor: Pramagent, **kwargs):
    """Decorator form for wrapping an existing PennyLane QNode."""

    def wrap(qnode):
        return GuardedQNode(qnode, armor, **kwargs)

    return wrap


def _demo_specs(_qnode, *_args, **_kwargs):
    class Resources:
        depth = 2
        num_wires = 2
        gate_types = {"Hadamard": 1, "CNOT": 1}
        gate_sizes = {1: 1, 2: 1}
        num_gates = 2

    return {"resources": Resources(), "num_trainable_params": 1, "num_observables": 1}


def _demo_qnode():
    class Shots:
        total_shots = 500

    class Device:
        name = "default.qubit"
        shots = Shots()

    class QNode:
        device = Device()

        def __init__(self):
            def bell(theta):
                return theta

            self.func = bell

        def __call__(self, theta):
            return {"expval": round(1.0 - theta, 3)}

    return QNode()


if __name__ == "__main__":  # pragma: no cover - exercised manually
    armor = Pramagent()
    for policy in make_quantum_policies(
        max_shots_per_call=500,
        max_shots_per_session=1_000,
    ):
        armor.tool_guard.register(policy)

    # Budget-only guard (metered execution).
    bell = GuardedQNode(_demo_qnode(), armor, session_id="demo", specs_func=_demo_specs)
    print("call 1:", bell(0.3))
    print("call 2:", bell(0.3))
    try:
        bell(0.3)
    except QuantumBudgetExceeded as exc:
        print("call 3 blocked:", exc)

    # Policy-enforced guard: same QNode, now with input + circuit + result
    # policies layered on top of the budget (policy-enforced execution).
    armor2 = Pramagent()
    for policy in make_quantum_policies(max_shots_per_call=500, max_shots_per_session=5_000):
        armor2.tool_guard.register(policy)
    guarded = GuardedQNode(
        _demo_qnode(), armor2, session_id="demo2", specs_func=_demo_specs,
        input_policy=InputPolicy(require_finite=True, angle_min=-6.3, angle_max=6.3),
        circuit_policy=CircuitPolicy(allowed_gates={"Hadamard", "CNOT"}, max_entanglers=4),
        result_policy=ResultPolicy(min_value=-1.0, max_value=1.0),
    )
    print("policy call ok:", guarded(0.3))
    for label, bad in (("NaN input", float("nan")), ("angle out of range", 99.0)):
        try:
            guarded(bad)
        except QuantumPolicyViolation as exc:
            print(f"blocked ({label}):", exc)
    executed = [r["payload"] for r in armor2.audit.records()
                if r["payload"].get("event") == "quantum_call_executed"]
    print("fingerprint:", executed[0]["fingerprint"][:16], "...")

    # Measured metering: estimate gates the call, then a meter reports the ACTUAL
    # shots (here a labeled stub standing in for qml.Tracker, which counts real
    # gradient/mitigation executions) and the adapter reconciles the two.
    def _stub_gradient_meter(qnode, *args, **kwargs):  # placeholder for qml.Tracker
        result = qnode(*args, **kwargs)
        return result, {"shots": qnode.device.shots.total_shots * 3, "executions": 3}

    armor3 = Pramagent()
    for policy in make_quantum_policies(max_shots_per_call=500, max_shots_per_session=5_000):
        armor3.tool_guard.register(policy)
    metered = GuardedQNode(
        _demo_qnode(), armor3, session_id="demo3", specs_func=_demo_specs,
        meter_func=_stub_gradient_meter,
    )
    metered(0.3)
    recon = [r["payload"] for r in armor3.audit.records()
             if r["payload"].get("event") == "quantum_cost_reconciled"][0]
    print(f"reconciled: estimate={recon['est_shots']} shots, "
          f"actual={recon['actual_shots']} shots ({recon['actual_executions']} executions)")
    print("audit chains valid:", armor.audit.verify_chain(),
          armor2.audit.verify_chain(), armor3.audit.verify_chain())
