"""Pramagent guarded PennyLane QNode execution."""
from __future__ import annotations

import sys
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
    ) -> None:
        self._qnode = qnode
        self._armor = armor
        self._tenant_id = tenant_id
        self._session_id = session_id
        self._pricing = {**PRICING_USD_PER_SHOT, **(pricing or {})}
        self._provider_hint = provider_hint
        self._specs_func = specs_func
        self._joules_per_shot = max(float(joules_per_shot), 0.0)

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
        """Cumulative executed shots and USD cost for this (tenant, session),
        derived from the durable audit trail rather than volatile per-instance
        counters (F2). With a durable/shared audit backend this is consistent
        across adapter instances, workers, and processes; with the default
        in-memory backend it is at least consistent across instances in one
        process, closing the re-instantiation reset."""
        shots = 0
        cost = 0.0
        for rec in self._armor.audit.records():
            p = rec.get("payload", rec) if isinstance(rec, dict) else rec
            if (isinstance(p, dict)
                    and p.get("source") == "quantum_adapter"
                    and p.get("event") == "quantum_call_executed"
                    and p.get("tenant_id") == self._tenant_id
                    and p.get("session_id") == self._session_id):
                shots += int(p.get("shots", 0) or 0)
                cost += float(p.get("est_cost_usd", 0.0) or 0.0)
        return shots, round(cost, 6)

    def _audit_refused(self, event: str, reason: str, *, shots: int, device: str,
                       kind: str, pricing_key: str, wires: int, depth: int,
                       estimated_joules: float, est_cost_usd: float,
                       session_shots_after: int, session_cost_after_usd: float) -> None:
        self._armor.audit.append({
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
        })

    def _inspect(self, *args, **kwargs) -> dict[str, Any]:
        specs = (
            self._specs_func(self._qnode, *args, **kwargs)
            if self._specs_func is not None
            else _default_specs(self._qnode, *args, **kwargs)
        )
        resources = _lookup(specs, "resources", default={})
        device = _device_name(self._qnode)
        kind = _device_kind(device)
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
                session_cost_after_usd=spent_cost,
            )
            raise QuantumBudgetExceeded(reason)
        per_task = (
            BRACKET_TASK_PRICE_USD
            if kind == "hardware" and pricing_key.startswith("braket:")
            else 0.0
        )
        cost = round((shots * float(rate)) + per_task, 6)
        return {
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

    def _audit_quantum_event(self, decision, call_args: dict[str, Any], event: str) -> None:
        self._armor.audit.append({
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
        })

    def __call__(self, *args, **kwargs):
        call_args = self._inspect(*args, **kwargs)
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
            self._audit_quantum_event(decision, call_args, "quantum_call_blocked")
            raise QuantumBudgetExceeded(decision.reason)
        if decision.verdict == Verdict.ESCALATE:
            self._audit_quantum_event(decision, call_args, "quantum_call_escalated")
            raise ApprovalRequired(decision)

        result = self._qnode(*args, **kwargs)
        # Session spend is derived from this executed event on the next call
        # (see _session_spent), so there is no volatile per-instance counter
        # to reset by re-wrapping the QNode (F2).
        self._audit_quantum_event(decision, call_args, "quantum_call_executed")
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

    return {"resources": Resources()}


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

    bell = GuardedQNode(_demo_qnode(), armor, session_id="demo", specs_func=_demo_specs)
    print("call 1:", bell(0.3))
    print("call 2:", bell(0.3))
    try:
        bell(0.3)
    except QuantumBudgetExceeded as exc:
        print("call 3 blocked:", exc)
    print("audit chain valid:", armor.audit.verify_chain())
