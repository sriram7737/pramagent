# Pramagent Conformance Map

This document maps Pramagent to the current agent-security vocabulary used by
Google DeepMind and AWS. It is an engineering self-assessment, not a
certification, penetration test, or claim of production compliance.

Pramagent's lane is the individual-agent control tier: deterministic checks
outside the model, human approval for consequential actions, tamper-evident
evidence, and portable traces that can run on top of any provider or hosting
runtime.

## What Is Implemented

| Framework idea | Pramagent mechanism | Status |
|---|---|---|
| Deterministic controls outside the agent | `ToolGuardLayer`, `SafetyLayer`, `IsolationLayer`, HITL, output validation | Implemented |
| AWS autonomy scope declaration | `Pramagent(agent_scope="scope_1" | "scope_2" | "scope_3")` and `PRAMAGENT_AGENT_SCOPE` for the API | Implemented |
| AWS Scope 1: human-initiated read-only | Non-read tool side effects and registered consequential actions are blocked | Implemented |
| AWS Scope 2: mandatory human approval | Non-read tool side effects require HITL even when a tool policy accidentally says `ALLOW` | Implemented |
| AWS Scope 3: bounded autonomy | Scope is recorded on traces; enforcement comes from configured ToolGuard/HITL/rate-limit policies | Partial |
| DeepMind-style detection tiers | Each trace receives `detection_tier` such as `D2_rule_detection` or `D4_runtime_containment` | Implemented |
| DeepMind-style response tiers | Each trace receives `response_tier` such as `R1_log_and_monitor`, `R2_human_approval`, or `R3_block_or_safe_default` | Implemented |
| Trace-layer coverage metric | Each trace includes required/observed trust layers and a `trace_layer_coverage` value scoped to that single trace | Implemented |
| Time-to-response metric | Each trace includes `time_to_response_ms`, computed to first block/escalation/containment decision | Implemented |
| Seeded recall metric | `run_injection_benchmark()` reports `seeded_recall` over first-party seeded red-team prompts | Implemented for seeded evals |
| MITRE ATT&CK-style tagging | Each trace receives `attack_techniques` derived from side effects, layer decisions, and scrubbed text | Implemented |
| Tamper-evident evidence | Trace payload, conformance fields, and decisions are sealed into the hash chain | Implemented |
| Agent-memory integrity contract | `IntegrityMemoryStore` verifies in-memory/SQLite agent memory chains and supports externally held heads | Implemented for optional memory stores |
| Structured rationale capture | `DecisionRationale` captures scrubbed intent/policy/tool rationale without raw reasoning | Implemented as schema |
| Overreach corpus | 26 human-labeled seeded cases plus `overreach_v0` counts-first evaluator | Implemented as corpus/eval, not runtime enforcement |

## Trace Fields

New traces include:

```json
{
  "aws_scope": "scope_2_human_approved",
  "detection_tier": "D4_runtime_containment",
  "response_tier": "R3_block_or_safe_default",
  "attack_techniques": [
    "ATT&CK:T1059 Command and Scripting Interpreter",
    "ATLAS:AML.T0051 Prompt Injection"
  ],
  "conformance_metrics": {
    "trace_layer_coverage": 1.0,
    "coverage_scope": "single_trace_required_layer_presence",
    "trace_required_layers": ["ComplianceLayer", "IsolationLayer", "SafetyLayer.pre"],
    "trace_observed_layers": ["ComplianceLayer", "IsolationLayer"],
    "monitored": true,
    "time_to_response_ms": 0.7,
    "seeded_recall": null,
    "seeded_recall_source": "not available on runtime traces; use run_injection_benchmark() for first-party seeded recall"
  }
}
```

Runtime traces do not know ground truth labels, so they cannot honestly claim
recall. `trace_layer_coverage` is also not a fleet-level monitoring coverage
claim; it only says whether this one trace passed through the required local
trust layers. First-party seeded recall is reported by red-team runs:

```python
from pramagent.redteam import run_injection_benchmark

report = run_injection_benchmark(force_keyword_only=True)
print(report.seeded_recall)
```

## Configuring AWS Scope

Library:

```python
from pramagent import Pramagent

scope_2_armor = Pramagent(agent_scope="scope_2")
```

API sidecar:

```bash
PRAMAGENT_AGENT_SCOPE=scope_2
uvicorn pramagent.api.app:app --port 8080
```

Supported aliases:

- `scope_1`, `scope1`, `read_only`
- `scope_2`, `scope2`, `human_approved`
- `scope_3`, `scope3`, `bounded_autonomy`
- `undeclared`

## Boundary Of Responsibility

Pramagent intentionally does not provide:

- Firecracker/micro-VM/container compute isolation
- Host sandboxing for arbitrary code execution
- Multi-agent delegation/reputation systems
- Ecosystem-level identity federation
- External certification

Those belong to the hosting platform, cloud control plane, or an enterprise
security program. Pramagent is designed to sit above those controls and produce
portable, inspectable evidence for each individual agent call.

## Remaining Gaps

The rationale for these deferrals is tracked in
[Design decisions](DESIGN_DECISIONS.md).

- Redis/Postgres/vector-store memory backends and automatic framework memory
  routing through `IntegrityMemoryStore`; current memory integrity support is
  limited to optional in-memory/SQLite agent-memory stores
- Automatic trace attachment for `DecisionRationale`
- Progressive autonomy ladder that graduates an agent only after passing
  configured eval gates
- Runtime overtask/overeagerness enforcement for valid-goal overreach
- AI supervisor focused on a narrow high-risk tool class
- External red-team / penetration-test validation
