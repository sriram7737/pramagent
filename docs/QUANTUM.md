# Quantum Integration

Pramagent's production quantum surface has two separate purposes:

1. Govern scarce quantum execution with deterministic policy, shot budgets,
   explicit approval, and hash-chained evidence.
2. Protect long-lived evidence with standardized post-quantum cryptography as
   that roadmap phase is implemented.

The IBM integration implements the first purpose. The optional Evidence
Envelope V2 package implements local hybrid Ed25519 plus ML-DSA-65 checkpoint
signing and verification. Independent timestamp/log services, managed signing
keys, and QRNG integration remain deployment work. None of these features is a
quantum-advantage claim.

## IBM Runtime setup

Install the optional provider dependencies:

```powershell
pip install -e ".[quantum-ibm]"
```

Expose an IBM Cloud API key and Quantum service CRN in the same shell that will
run Pramagent:

```powershell
$env:IBM_CLOUD_API_KEY = "..."
$env:IBM_QUANTUM_CRN = "crn:..."
```

The values are read at runtime and are never emitted by the status command or
written to the audit trail.

If those variables exist only in another terminal, save them through Qiskit's
official account store from that same terminal. This avoids putting either
value in chat or in the repository:

```powershell
python -c "import os; from qiskit_ibm_runtime import QiskitRuntimeService as S; S.save_account(token=os.environ['IBM_CLOUD_API_KEY'], instance=os.environ['IBM_QUANTUM_CRN'], set_as_default=True, overwrite=True)"
```

Pramagent will then use the default saved account when explicit environment
credentials are absent. `quantum-status` reports only the saved account name.

Check local readiness, then verify provider connectivity without submitting a
job:

```powershell
pramagent quantum-status
pramagent quantum-status --connect
```

IBM's current client initialization uses `QiskitRuntimeService` with an API key
and, preferably, an instance CRN. See IBM's
[account initialization guide](https://quantum.cloud.ibm.com/docs/en/guides/initialize-account).

## Physical QPU attestation

Review the selected IBM instance's plan and remaining QPU-time quota first.
IBM accounts for hardware usage by QPU execution time; Pramagent therefore
refuses to manufacture a dollar-per-shot estimate. A real submission requires
both explicit flags:

```powershell
pramagent quantum-run --shots 128 `
  --submit-hardware `
  --allow-unpriced-hardware
```

The equivalent Python API is:

```python
from pramagent.quantum import qpu_attestation

attestation = qpu_attestation.run_hardware_attestation(
    shots=128,
    confirm_hardware=True,
    allow_unpriced_hardware=True,
)
print(attestation["backend"], attestation["job_id"], attestation["counts"])
```

Pass your configured `Pramagent` instance as `armor=` in an application so the
events use its durable audit backend. Omitting it creates an in-memory chain for
the one command only.

The command builds a fixed two-qubit Bell circuit, selects the least-busy
physical backend unless `--backend` is supplied, transpiles to that backend's
ISA, and submits with IBM Runtime `SamplerV2` job mode. It reports the provider
job ID, backend, measured counts, observed shots, Bell correlation, circuit
fingerprint, and audit-chain status.

Hardware runs default to optimization level 3 and Qiskit's error-aware automatic
layout. Pramagent independently combines the selected ISA gates' and measured
qubits' current backend error metadata into an audited `total_error_proxy`.
The CLI refuses submission when metadata is incomplete or the proxy exceeds
`0.05`. Use `--initial-layout Q0,Q1` for a controlled layout experiment and
`--max-layout-error-proxy` to set a deployment-specific ceiling. This proxy is
a preflight ranking signal, not a predicted circuit fidelity.

Hardware submission fails closed if the configured audit chain cannot be
verified before the provider call. When rotating audit keys, configure the
versioned `PRAMAGENT_QUANTUM_SIGNING_KEYS` ring so historical quantum rows
remain verifiable; reusing a database with a different unversioned key
correctly invalidates the whole chain. The quantum-specific ring falls back to
`PRAMAGENT_SIGNING_KEYS` when it is unset, preserving existing deployments.

CLI evidence is persisted to `.pramagent/quantum-audit.db` by default. Override
it with `--audit-db` or `PRAMAGENT_QUANTUM_AUDIT_DB`. Configure
`PRAMAGENT_QUANTUM_SIGNING_KEYS` plus
`PRAMAGENT_QUANTUM_SIGNING_ACTIVE_KID` so an attacker with direct database
write access cannot simply recompute an unkeyed chain. If the historical key
is unavailable, preserve the invalid database as evidence and select a fresh
database. Do not rewrite or delete rows to make an old chain appear valid.

IBM documents Open Plan access as up to 10 QPU minutes per rolling 28-day
window, while other instance plans can incur cost. Check the plan attached to
the exact CRN before acknowledging unpriced hardware usage. See IBM's
[plans overview](https://quantum.cloud.ibm.com/docs/en/guides/plans-overview)
and [Sampler examples](https://quantum.cloud.ibm.com/docs/en/guides/sampler-examples).

The default policy caps a call at 1,024 shots and a local session at 4,096
shots. The CLI stores atomic reservations in the same SQLite database as the
audit chain. A reservation is created before submission, reconciled to observed
shots after completion, released when policy refuses before submission, and
left conservatively charged when the provider outcome is uncertain. Separate
workers sharing that database cannot both reserve the same remaining budget.

Direct integrations can pass `QuantumBudgetLedger` to `IBMQuantumRuntime` or
`GuardedQNode`. For multiple hosts, install the PostgreSQL extra and select the
shared ledger:

```powershell
pip install -e ".[quantum-ibm,postgres]"
$env:PRAMAGENT_QUANTUM_BUDGET_POSTGRES_DSN = "postgresql://..."
pramagent quantum-run --shots 128 `
  --submit-hardware `
  --allow-unpriced-hardware
```

`PostgresQuantumBudgetLedger` serializes every tenant/session reservation with
a transaction-scoped advisory lock. This includes the first reservation for a
new session, where locking existing rows would not prevent two workers from
spending the same remaining budget. Use a dedicated database role and restrict
schema permissions in production. The audit chain remains in the configured
audit store; the PostgreSQL ledger is the shared quota authority, not a second
audit log.

The command-line acknowledgement is suitable for a local operator. An agent or
service integration must obtain approval from Pramagent's authenticated HITL
queue before calling `IBMQuantumRuntime.run_hardware_attestation`; a boolean
from model-controlled input is not proof of human approval.

## Calibration canary binding

The Bell attestation can serve as a calibration canary instead of an isolated
demo. A successful IBM run returns `calibration_canary`, a sealed record tied to
the provider execution evidence, backend, physical qubits, completion time,
measured same-bit correlation, and an explicit validity window.

Before submitting a workload, require the canary to be fresh for the selected
provider and backend. After the workload completes, bind the two sealed records
into the same audit chain:

```python
import time

from pramagent.quantum import (
    CalibrationCanaryEvidence,
    QuantumExecutionEvidence,
    record_calibration_workload_binding,
)

canary = CalibrationCanaryEvidence.from_dict(attestation["calibration_canary"])
canary.assert_usable(
    provider="ibm",
    backend=selected_backend,
    at=time.time(),
    max_age_seconds=300,
)

# Submit the application workload only after the preflight check. Its completed
# provider-neutral evidence is then linked to the exact canary used.
workload = QuantumExecutionEvidence.from_dict(workload_event["evidence"])
binding = record_calibration_workload_binding(
    armor,
    canary,
    workload,
    tenant_id="acme",
    session_id="caption-batch-42",
    max_age_seconds=300,
)
```

Binding fails closed for a stale or failed canary, a provider/backend mismatch,
a future-dated workload, an incomplete workload, or altered evidence hashes.
It does not prove that backend calibration stayed unchanged after the canary,
and same-bit correlation alone is not a complete Bell-state fidelity witness.

## Hybrid inference

The PennyLane guard and router are installable APIs:

```python
from pramagent.quantum import GuardedQNode, HybridQuantumRouter
```

`examples/quantum/hybrid_router_demo.py` remains a dependency-light routing
demo with a labeled stub scorer. The separate Quantum-VLM-Adapter now runs the
published classical VLM, a trained finite-shot quantum projection, and a
classical-by-default hybrid route with persistent Pramagent auditing. Its
CLIP-distance scorer is measurable but is not yet validated as a caption-
difficulty oracle.

A local 79-image projection experiment produced no supported advantage: the
quantum point estimate was slightly better, its paired 95% interval included
zero, and simulator projection latency was about 49 times the matched classical
latency. These measurements validate integration only. Hardware attestation
and a four-qubit simulator result do not establish quantum advantage.

## Provider-neutral execution evidence

Completed IBM and PennyLane executions include a sealed
`QuantumExecutionEvidence` record. It normalizes provider, backend, execution
ID, circuit fingerprint, requested and observed shots, timing, pricing model,
and optional measurement counts. Its SHA-256 `evidence_hash` detects accidental
or out-of-band field changes; the surrounding Pramagent audit chain supplies
the keyed, ordered provenance boundary.

```python
from pramagent.quantum import QuantumExecutionEvidence

evidence = QuantumExecutionEvidence.from_dict(event["evidence"])
print(evidence.provider, evidence.execution_id, evidence.evidence_hash)
```

An unknown provider charge is represented as `None`. A simulator run may have
an actual dollar cost of `0.0`; those are intentionally different claims.

## Portable Evidence Envelope V2

The additive V2 evidence protocol provides integer-only RFC 8785
canonicalization, persisted leaf nonces, Merkle inclusion and consistency
proofs, and policy-versioned hybrid Ed25519 plus ML-DSA-65 checkpoint
signatures. Both signatures are mandatory under the initial policy. Existing
V1 records remain readable and are never reserialized.

Install the optional cryptographic implementation with:

```powershell
pip install -e ".[evidence-v2]"
```

V2 verification reports record assurance separately from checkpoint
assurance. A legacy record wrapped by a signed epoch remains `checksum_only`
unless its original HMAC boundary was independently verified; the later epoch
only proves checkpoint-time inclusion. RFC 3161 and transparency-log artifacts
are accepted through explicit verifier callbacks, so unvalidated timestamp
fields can never raise the assurance level.

Install the live external-witness integration with:

```powershell
pip install -e ".[evidence-anchors]"
```

The anchoring worker obtains production service endpoints and trust roots from
Sigstore's TUF configuration. It verifies the TSA response and Rekor inclusion
receipt before persisting either artifact. A SQLite outbox retains partial
success and retries service failures outside the request path.

The complete wire specification and claim boundaries are in
[Evidence Envelope V2](EVIDENCE_ENVELOPE_V2.md).

Verify an envelope against a separately distributed trusted-key registry:

```powershell
pramagent evidence-v2-verify `
  --envelope evidence-envelope.json `
  --keys trusted-evidence-keys.json `
  --require-assurance asymmetric_checkpointed `
  --json
```

Create those external artifacts first:

```powershell
pramagent evidence-v2-anchor `
  --envelope evidence-envelope.json `
  --output evidence-envelope.anchored.json `
  --outbox .pramagent/evidence_anchor_outbox.sqlite3

pramagent evidence-v2-verify `
  --envelope evidence-envelope.anchored.json `
  --keys trusted-evidence-keys.json `
  --anchor-trust sigstore-offline `
  --require-assurance tsa_anchored `
  --json
```

The CLI deliberately does not trust public keys carried beside an envelope.
It also does not trust witness metadata carried by the envelope: Sigstore trust
is loaded independently through TUF. Current anchoring does not capture
contemporaneous revocation responses or perform RFC 4998 archive renewal, so
`tsa_anchored` is a current verification result rather than a seven-year
long-term-validation guarantee.
