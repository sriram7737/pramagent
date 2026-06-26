# Pramagent Design Decisions

This file records security and product decisions where Pramagent deliberately
does less than a checklist might ask for. The goal is to keep implementation
claims tied to real controls, not green checkmarks.

## ADR-001: Do Not Ship Partial Memory Integrity As Full Integrity

**Decision:** Defer persistent agent memory/state integrity until Pramagent has
a defined memory-store contract.

**Why:** Pramagent already hash-chains traces, but arbitrary agent memory can
live in vector stores, SQL rows, files, browser state, or framework-specific
checkpointers. Adding integrity to one path would create a misleading claim
that "memory integrity" is solved while other paths remain uncovered.

**Current control:** Trace inputs, decisions, outputs, and conformance labels
are tamper-evident through the audit chain.

**Future gate:** Define a memory-store interface with append, read, erase,
checksum, and tenant/session boundaries; then apply integrity checks to every
supported backend through that contract.

## ADR-002: Do Not Capture Raw Hidden Reasoning

**Decision:** Defer reasoning/plan capture as a first-class trace field.

**Why:** Raw reasoning can expose private prompts, sensitive business logic, or
chain-of-thought-like content. Capturing it without a safe schema would improve
audit appearance while increasing data-retention and disclosure risk.

**Current control:** Traces capture policy decisions, layer events, rule names,
latency, HITL state, and hash-chain evidence.

**Future gate:** Capture bounded rationale fields such as intent, policy reason,
tool rationale, and cited evidence, not raw hidden reasoning.

## ADR-003: Do Not Hardcode An Autonomy Ladder

**Decision:** Defer progressive autonomy graduation.

**Why:** A real autonomy ladder needs persisted agent maturity state, eval
gates, rollback rules, and operator review. A hardcoded ladder would be theater:
it would make the table green without proving an agent earned more autonomy.

**Current control:** `AgentScope` enforces Scope 1 read-only blocking and Scope
2 human approval for non-read side effects.

**Future gate:** Add configured eval suites and promotion/rollback criteria
before any automatic scope upgrade.

## ADR-004: Treat Overtask Detection As A Measured Classifier Problem

**Decision:** Defer overeagerness and overtask heuristics.

**Why:** "Doing too much" depends on user intent, tool permissions, tenant
policy, and task context. Broad rules can block useful work or miss subtle
overreach. It needs a corpus and false-positive budget before release.

**Current control:** ToolGuard side effects, scope enforcement, HITL, quotas,
and rate limits bound what an agent can actually do.

**Future gate:** Build a labeled overtask corpus, track false positives, and
emit a separate `overtask_verdict` rather than folding it into injection or
safety.

## ADR-005: Keep AI Supervision Narrow And Opt-In

**Decision:** Defer a general AI supervisor.

**Why:** A second model introduces latency, cost, provider failure modes, and a
new prompt-injection surface. It should supervise narrow high-risk tool classes,
not every request by default.

**Current control:** Deterministic pre-provider checks and optional output judge
support for selected deployments.

**Future gate:** Add a supervisor only for explicit high-risk tools, with
fail-closed behavior, audit fields, and cost controls.

## ADR-006: Do Not Claim Runtime Sandboxing From Middleware

**Decision:** Defer compute sandboxing and micro-VM isolation to the hosting
layer.

**Why:** A Python middleware cannot honestly provide Firecracker, container,
kernel, or network isolation by itself. That belongs to the platform running the
agent and tools.

**Current control:** Pramagent validates, blocks, escalates, and traces tool
requests before execution.

**Future gate:** Provide deployment guides and integration hooks for sandboxed
tool runners, but label the isolation boundary as platform-provided.

## ADR-007: Do Not Treat Self-Assessment As Certification

**Decision:** Keep conformance maps as engineering self-assessments until an
external party validates them.

**Why:** SOC 2, HIPAA assessments, ISO 42001, penetration tests, and red-team
reports require external scope, evidence review, and remediation tracking.
Project-owned tests are useful evidence but not certification.

**Current control:** Security scans, unit/regression tests, red-team harnesses,
load evidence, conformance labels, and hash-chain traces are documented.

**Future gate:** Commission an external API/security assessment and publish a
remediation summary before making production compliance claims.
