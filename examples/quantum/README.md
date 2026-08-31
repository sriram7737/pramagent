# Quantum Example

This example treats PennyLane QNode execution as a guarded Pramagent tool call.

`guarded_qnode.py` wraps QNode execution with shot, cost, input, circuit, and
result policies. `hybrid_router_demo.py` shows the governance pattern on top:
use the classical path by default, try the guarded quantum path only for
high-difficulty inputs, and fall back to classical when budget or HITL policy
does not allow the quantum call.

## Measured metering (estimate vs. actual)

By default the budget gate uses a pre-execution `qml.specs` estimate. Because a
single QNode call can execute many circuits (parameter-shift gradients run about
`2 * num_params + 1`; error mitigation multiplies shots again), that estimate
can undercount real spend. Pass `meter_func=pennylane_tracker_meter` to
`GuardedQNode` to execute under `qml.Tracker` and record the measured shots:

```python
from guarded_qnode import GuardedQNode, pennylane_tracker_meter

guarded = GuardedQNode(qnode, armor, meter_func=pennylane_tracker_meter)
```

Each call emits a `quantum_cost_reconciled` audit event with estimated vs.
actual shots, cost, executions, and variance. Subsequent calls bill their budget
against the measured spend. The seam is opt-in: omitting `meter_func` keeps the
estimate-only behavior unchanged. `meter_func` is any
`(qnode, *args, **kwargs) -> (result, {"shots", "executions"})` callable, so a
stub can stand in where PennyLane is not installed.

## Run it

```bash
python examples/quantum/guarded_qnode.py
python examples/quantum/hybrid_router_demo.py
python -m pytest tests/test_quantum_guarded_qnode.py tests/test_quantum_hybrid_router_demo.py
```

Verification note, 2026-08-30: PennyLane 0.45.1 `qml.specs` works on the
`QuantumProjection.circuit` torch-interface QNode in
`sriram7737/Quantum-VLM-Adapter` with batched `(1, 4)` circuit inputs.
Finite-shot specs expose depth 16, wire allocations 4, and total shots 500.
