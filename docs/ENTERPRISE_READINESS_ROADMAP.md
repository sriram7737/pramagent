# Enterprise Readiness Roadmap

This document tracks product gaps that matter for YC-style readiness and
enterprise evaluation. It separates implemented controls from roadmap items so
Pramagent does not let the label outrun the substance.

## Product Wedge

Pramagent's first wedge is financial and other high-impact tool-calling safety:
deterministic policy, HITL, and tamper-evident traces at the boundary between
"the model proposed a tool call" and "the tool actually executes."

Pramagent does not prevent the model from being wrong. It prevents the model
from doing damage when it is wrong.

## Implemented In v0.8.5+

### Shadow rollout mode

`Pramagent(enforcement_mode="observe")` and
`PRAMAGENT_ENFORCEMENT_MODE=observe` let teams trial Safety/ToolGuard/Scope
policy in production-like traffic without blocking the workflow.

Trace fields:

- `enforcement_mode`: `enforce` or `observe`
- `would_block`: whether a policy gate would have blocked
- `would_block_reason`: first would-block reason
- `LayerEvent` entries ending in `.observe`

Limits:

- Consent gates, input/output size caps, and injection isolation still fail
  closed. Observe mode is for policy tuning, not for allowing known data leaks
  or prompt-injection payloads through.

### Classifier verdict visibility

`IsolationLayer` already extracts structured classifier metadata when the
classifier provides it. Core traces now surface that metadata in
`LayerEvent.data`:

- `classifier_flagged`
- `classifier_meta.score`
- `classifier_meta.threshold`
- `classifier_meta.layer`
- `classifier_meta.matched_exemplar`
- `classifier_meta.matched_pattern`
- provenance adjustment metadata for untrusted tool/retrieved content

### Policy-as-code

`pramagent.policies` loads ToolGuard policies from JSON and, when PyYAML is
installed, YAML.

Supported entry points:

- `load_tool_policies(path)`
- `load_tool_guard(path)`
- `tool_policy_from_dict(data)`

YAML remains optional to keep the base install small. Use `pip install pyyaml`
or `pip install "pramagent[policy]"` when YAML policy files are needed.

### Policy backtesting

`pramagent backtest policies.json --cases cases.jsonl` evaluates a proposed
policy file against explicit tool-call cases and exits nonzero on expected
verdict mismatches.

This is v0 explicit case replay, not yet automatic "last 30 days from the trace
store" replay. That distinction matters: stored traces vary by deployment and
do not always contain full tool-call arguments in a replayable shape.

### Drop-in tool decorator

`@guarded_tool(armor, policy="...")` wraps existing sync or async Python tools.
It runs `ToolGuardLayer` before the function body executes.

`BLOCK` and `ESCALATE` both stop execution. Escalation is not consent; approval
must happen through the HITL queue/dashboard path and then the side effect must
be intentionally re-run.

## Partially Implemented

### ChatOps HITL

Slack callbacks exist and are signed with Slack's signing secret. Persistent
SQLite/Postgres HITL queues exist. Teams/ServiceNow/PagerDuty/email/webhook
notifiers exist as notification/escalation surfaces, but Slack is the primary
decision-collecting ChatOps path today.

### Performance framing

Traces separate provider latency, guard-layer events, HITL state, and total
latency. The dashboard uses engine latency rather than human wait time for the
main performance tile.

Missing:

- Published p50/p95/p99 latency by layer under high concurrency
- Separate deterministic, ML-classifier, and LLM-judge latency pages
- Queue-backed async OutputJudge/audit workers for non-blocking strictness

### Conformance vocabulary

Traces carry AWS-style `aws_scope`, response/detection tiers, attack technique
labels, and seeded conformance metrics. Metrics that depend on a small seeded
set are named and documented as seeded, not broad production recall.

Missing:

- Independent conformance review
- Fleet-level coverage measurement from real deployments

## Not Yet Implemented Or Not Yet Proven

### Proof beyond the demo

Current evidence covers local tests, bundled red-team smoke suites, demo traces,
and local load evidence. Enterprise buyers will need stronger proof:

- Nightly scaled red-team runs with dynamic attacks and a published trend page
- Garak/PyRIT-style external runner integration
- 1,000 rps or clearly scoped load evidence against Redis/Postgres backends
- P99 latency, CPU, memory, and queue-depth reporting

### SIEM integrations

The hash chain proves local tamper evidence, but security teams read logs in a
SIEM. Needed integrations:

- Datadog event/log export
- Splunk HEC export
- AWS CloudWatch export
- Clear field allow-list so prompts, outputs, API keys, and plaintext emails do
  not leave the trust boundary by accident

### Data minimization guarantees

Existing controls scrub PII before persisted trace/audit payloads and avoid
storing demo API keys. The next hardening pass should document and test:

- Exact redaction order before Postgres/Redis writes
- Provider key lifetime and drop points
- SIEM export field allow-list
- Regression tests proving no `sk-*`, `nvapi-*`, or dashboard keys are written
  to traces, signals, CSV exports, or logs

### Dynamic thresholds

JSON Schema already supports amount caps such as `maximum: 100`. More expressive
thresholds are still needed:

- Context-aware thresholds such as `payment < 100 and known_destination`
- Policy review diff output
- Backtest summaries grouped by changed threshold

### Stored-trace backtesting

The new CLI backtests explicit cases. A production-grade backtester should also
read the trace store and replay replayable historical tool calls over a time
window:

```bash
pramagent backtest policies.yaml --from-store postgres --days 30
```

That requires a stable replay schema for tool-call arguments and expected
outcomes.

### Ownership and commercial roadmap

Pramagent is Apache-2.0 alpha. A buyer-ready commercial roadmap should include:

- Managed Pramagent Cloud waitlist and terms
- SLA-backed hosted Postgres/Redis/dashboard option
- SOC 2 timeline
- Third-party penetration-test timeline
- Enterprise support boundaries

## Near-Term Build Order

1. Publish benchmark harness and repeatable load-test command.
2. Add SIEM exporters with strict field allow-lists.
3. Add stored-trace backtesting once trace replay schema is stable.
4. Add dynamic threshold policy syntax and reviewer diffs.
5. Add managed-pilot request flow tied to the admin signals page.

The priority is evidence over breadth: a narrower control that is measured and
honestly scoped is more valuable than a wide feature list with unproven claims.
