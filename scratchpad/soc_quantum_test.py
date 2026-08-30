"""SOC-style adversarial harness for the quantum QNode guard.

Run from the Pramagent repo root:

    python scratchpad/soc_quantum_test.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from examples.quantum.guarded_qnode import (  # noqa: E402
    ApprovalRequired,
    GuardedQNode,
    QuantumBudgetExceeded,
    make_quantum_policies,
)
from pramagent import Pramagent  # noqa: E402


class Shots:
    def __init__(self, total):
        self.total_shots = total


class Device:
    def __init__(self, name, shots):
        self.name = name
        self.shots = Shots(shots)


class Resources:
    depth = 16
    num_allocs = 4


class QNode:
    def __init__(self, name="default.qubit", shots=500):
        self.device = Device(name, shots)
        self.calls = 0
        self.executed_shots = None

        def circuit(x, shots=None):
            return x

        self.func = circuit

    def __call__(self, x, shots=None):
        self.calls += 1
        self.executed_shots = (
            shots if shots is not None else self.device.shots.total_shots
        )
        return {"ok": True, "x": x}


def specs(_qnode, *_args, **_kwargs):
    return type("Specs", (), {"resources": Resources()})()


def armor(max_call=500, max_session=500, max_cost=10_000.0):
    instance = Pramagent()
    for policy in make_quantum_policies(
        max_shots_per_call=max_call,
        max_shots_per_session=max_session,
        max_cost_usd_per_session=max_cost,
    ):
        instance.tool_guard.register(policy)
    return instance


def quantum_events(instance):
    return [
        rec["payload"] for rec in instance.audit.records()
        if rec["payload"].get("source") == "quantum_adapter"
    ]


def held(name, condition, detail):
    status = "HELD" if condition else "BYPASS"
    print(f"{status} {name}: {detail}")
    return bool(condition)


def run():
    results = []

    a = armor(max_call=100, max_session=10_000)
    q = QNode(shots=100)
    g = GuardedQNode(q, a, tenant_id="soc", session_id="override", specs_func=specs)
    try:
        g("caption", shots=5_000_000)
        results.append(held("A1 call-time shots override", False, "executed"))
    except QuantumBudgetExceeded:
        event = quantum_events(a)[0]
        results.append(held(
            "A1 call-time shots override",
            q.calls == 0 and event["shots"] == 5_000_000,
            f"blocked shots={event['shots']}",
        ))

    a = armor(max_call=500, max_session=150)
    q = QNode(shots=100)
    GuardedQNode(q, a, tenant_id="soc", session_id="rewrap", specs_func=specs)("one")
    try:
        GuardedQNode(q, a, tenant_id="soc", session_id="rewrap", specs_func=specs)("two")
        results.append(held("A2 rewrap session reset", False, "executed"))
    except QuantumBudgetExceeded:
        event = quantum_events(a)[-1]
        results.append(held(
            "A2 rewrap session reset",
            q.calls == 1 and event["session_shots_after"] == 200,
            f"blocked session_shots_after={event['session_shots_after']}",
        ))

    a = armor(max_call=500, max_session=500)
    q = QNode(name="default.ionq_forte", shots=500)
    g = GuardedQNode(q, a, tenant_id="soc", session_id="masked-hw", specs_func=specs)
    try:
        g("caption")
        results.append(held("A3 hardware masked as simulator", False, "executed"))
    except ApprovalRequired:
        event = quantum_events(a)[0]
        results.append(held(
            "A3 hardware masked as simulator",
            q.calls == 0 and event["device_kind"] == "hardware" and event["est_cost_usd"] == 40.3,
            f"escalated cost={event['est_cost_usd']}",
        ))

    a = armor(max_call=500, max_session=500)
    q = QNode(name="braket:ionq:forte", shots=500)
    q.device.shots = object()
    g = GuardedQNode(q, a, tenant_id="soc", session_id="bad-shots", specs_func=specs)
    try:
        g("caption")
        results.append(held("A4 unparseable shots", False, "executed"))
    except QuantumBudgetExceeded:
        event = quantum_events(a)[0]
        results.append(held(
            "A4 unparseable shots",
            q.calls == 0 and event["event"] == "quantum_shots_unparseable",
            f"refused event={event['event']}",
        ))

    a = armor(max_call=500, max_session=500)
    q = QNode(name="ibm_brisbane", shots=500)
    g = GuardedQNode(q, a, tenant_id="soc", session_id="unknown-price", specs_func=specs)
    try:
        g("caption")
        results.append(held("A5 unknown hardware pricing", False, "executed"))
    except QuantumBudgetExceeded:
        event = quantum_events(a)[0]
        results.append(held(
            "A5 unknown hardware pricing",
            q.calls == 0 and event["event"] == "quantum_pricing_refused",
            f"refused event={event['event']}",
        ))

    a = armor(max_call=500, max_session=500)
    q = QNode(shots=500)
    g = GuardedQNode(q, a, tenant_id="soc", session_id="audit-chain", specs_func=specs)
    g("one")
    try:
        g("two")
    except QuantumBudgetExceeded:
        pass
    results.append(held(
        "A6 audit chain validity",
        a.audit.verify_chain() and len(quantum_events(a)) == 2,
        f"chain_valid={a.audit.verify_chain()} events={len(quantum_events(a))}",
    ))

    passed = sum(1 for item in results if item)
    print(f"\n{passed}/{len(results)} HELD")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(run())
