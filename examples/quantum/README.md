# Quantum Example

This example treats PennyLane QNode execution as a guarded Pramagent tool call.

Verification note, 2026-08-30: PennyLane 0.45.1 qml.specs works on the
QuantumProjection.circuit torch-interface QNode in sriram7737/Quantum-VLM-Adapter
with batched (1, 4) circuit inputs. Finite-shot specs expose depth 16,
wire allocations 4, and total shots 500.
