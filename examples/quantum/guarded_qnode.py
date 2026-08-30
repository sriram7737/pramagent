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
    if name.startswith(_SIMULATOR_PREFIXES) or "simulator" in name:
        return "simulator"
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


def _shots_from(obj: Any) -> int:
    if obj is None or isinstance(obj, bool):
        return 0
    if isinstance(obj, int):
        return obj
    total = getattr(obj, "total_shots", None)
    if total is not None:
        return int(total or 0)
    try:
        return int(obj)
    except (TypeError, ValueError):
        return 0


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
        self._session_shots = 0
        self._session_cost = 0.0

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
        rate = self._pricing.get(pricing_key)
        if rate is None:
            raise QuantumBudgetExceeded(
                f"no price configured for hardware device '{device}' "
                f"(pricing_key={pricing_key or 'unknown'}); refusing to run"
            )

        shots = _shots_from(
            _lookup(getattr(self._qnode, "device", None), "shots")
            or _lookup(self._qnode, "shots")
            or _lookup(specs, "shots")
        )
        depth = int(_lookup(resources, "depth", default=0) or 0)
        wires = int(_lookup(resources, "num_wires", "wires", "num_allocs", default=0) or 0)
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
            "estimated_joules": round(shots * self._joules_per_shot, 6),
            "device": device,
            "device_kind": kind,
            "pricing_key": pricing_key,
            "est_cost_usd": cost,
            "session_shots_after": self._session_shots + shots,
            "session_cost_after_usd": round(self._session_cost + cost, 6),
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
        self._session_shots = call_args["session_shots_after"]
        self._session_cost = call_args["session_cost_after_usd"]
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
