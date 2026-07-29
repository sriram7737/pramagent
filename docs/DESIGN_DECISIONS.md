# Pramagent Design Decisions

This file records security and product decisions where Pramagent deliberately
does less than a checklist might ask for. The goal is to keep implementation
claims tied to real controls, not green checkmarks.

## ADR-001: Ship Memory Integrity Through A Contract

**Decision:** Implement agent-memory integrity through a small
`AgentMemoryStore` contract plus an `IntegrityMemoryStore` wrapper, instead of
claiming arbitrary framework memory is protected.

**Why:** Pramagent already hash-chains traces, but arbitrary agent memory can
live in vector stores, SQL rows, files, browser state, or framework-specific
checkpointers. Integrity has to be a property of the memory contract, not a
single backend.

**Current control:** `IntegrityMemoryStore` ships with in-memory and SQLite
backends. It detects point mutation on read and supports `expected_head` so a
caller can catch full-chain rewrites when the genuine head is held outside the
store.

**Honest limit:** It detects integrity failures, not authenticity failures. A
bad value written through the legitimate API chains cleanly. Without an
externally held head, a store owner can rewrite the whole chain
self-consistently.

**Future gate:** Add Redis/Postgres backends, tenant/session erasure semantics,
and framework adapters that force agent memory through this contract.

## ADR-002: Capture Structured Rationale, Not Raw Reasoning

**Decision:** Ship a bounded `DecisionRationale` schema and continue refusing
raw hidden reasoning capture.

**Why:** Raw reasoning can expose private prompts, sensitive business logic, or
chain-of-thought-like content. Capturing it would improve audit appearance while
increasing data-retention and disclosure risk.

**Current control:** `DecisionRationale` has only `intent`, `policy_reason`,
and `tool_rationale`; there is no `raw_reasoning` field. Free-text fields are
scrubbed through the compliance layer and fail closed on scrubber errors or bad
return shapes.

**Future gate:** Attach scrubbed rationale summaries to selected trace events
and add cited evidence fields without creating a raw reasoning slot.

## ADR-003: Do Not Hardcode An Autonomy Ladder

**Decision:** Defer progressive autonomy graduation.

**Why:** A real autonomy ladder needs persisted agent maturity state, eval
gates, rollback rules, and operator review. A hardcoded ladder would be theater:
it would make the table green without proving an agent earned more autonomy.

**Current control:** `AgentScope` enforces Scope 1 read-only blocking and Scope
2 human approval for non-read side effects.

**Future gate:** Add configured eval suites and promotion/rollback criteria
before any automatic scope upgrade.

## ADR-004: Build The Overreach Corpus Before The Runtime Heuristic

**Decision:** Ship the labeled corpus and a disposable v0 baseline before
turning overreach detection into runtime enforcement.

**Why:** "Doing too much" depends on user intent, tool permissions, tenant
policy, and task context. Broad rules can block useful work or miss subtle
overreach. A corpus with human labels is the durable asset; a rule without that
corpus is just another brittle heuristic.

**Current control:** `corpus/overreach` contains 26 human-labeled seeded cases
with labeling guidelines, edge cases, and counts-first reporting. `overreach_v0`
scores TP=6, FP=2, FN=4, TN=14; the failures show the intended finding: v0's
authorization model is lexical, not semantic.

**Future gate:** Grow the corpus from real traces, then add a separate runtime
`overreach_verdict` only after a v1 beats the baseline without overfitting.

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
load evidence, trace-local self-assessment indicators, and hash-chain traces
are documented.

**Future gate:** Commission an external API/security assessment and publish a
remediation summary before making production compliance claims.
