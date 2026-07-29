# Pramagent

[![PyPI version](https://img.shields.io/pypi/v/pramagent.svg)](https://pypi.org/project/pramagent/)
[![Python versions](https://img.shields.io/pypi/pyversions/pramagent.svg)](https://pypi.org/project/pramagent/)
[![License](https://img.shields.io/pypi/l/pramagent.svg)](https://github.com/sriram7737/pramagent/blob/main/LICENSE)
[![CI](https://github.com/sriram7737/pramagent/actions/workflows/tests.yml/badge.svg)](https://github.com/sriram7737/pramagent/actions/workflows/tests.yml)

Trust middleware for LLM agents: deterministic tool policy, HITL approvals,
and tamper-evident audit traces. **Alpha** - read the
[implementation status](https://github.com/sriram7737/pramagent/blob/main/docs/IMPLEMENTATION_STATUS.md)
before customer-facing pilots.

The wedge is narrow by design: Pramagent does not prevent your model from being
wrong; it prevents your model from doing damage when it is wrong.

![Pramagent trust stack](https://raw.githubusercontent.com/sriram7737/pramagent/main/docs/stack.png)

Pramagent wraps OpenAI, Anthropic, Gemini, Ollama, local, and
OpenAI-compatible providers with guardrails that run outside the model. The
most differentiated layer is ToolGuard: deterministic tool validation with JSON
Schema, tenant/action allow-lists, side-effect taxonomy, dangerous-chain
detection, output scanning, and HITL escalation. The current package also
ships curated safety rule corpora, persistent HITL queues, thin adapters for
popular agent frameworks, compliance evidence generation, and trace-local
self-assessed control indicators mapped to DeepMind/AWS-style vocabulary. It also includes an
optional agent-memory integrity contract, structured decision-rationale schema,
and a human-labeled overreach corpus for measuring valid-goal overreach.

## What it's ready for (and what it isn't)

Pramagent is an honest alpha. The core trust pipeline is real and tested; the
gaps are around it. Use this to decide whether it fits your use case.

**Ready for today:**

- Developer evaluation and integration against the SDK and FastAPI sidecar
- Single-tenant or trusted-network pilots **with a persistent store configured**
  (`PRAMAGENT_POSTGRES_DSN` or `PRAMAGENT_DB`) — the API refuses to boot on
  volatile memory unless you explicitly opt in
- Design-partner deployments where you control the network boundary
- Generating compliance *evidence* (control mappings, not certifications)

**Not ready for yet — do not claim:**

- Production banking / healthcare or other regulated environments
- Multi-tenant SaaS at scale (no published HA/soak evidence, no backup/DR runbook,
  no SLA)
- Prompt-injection *immunity*, *certified* GDPR/SOC 2/HIPAA compliance, or
  third-party-validated safety — none of these have been externally assessed

**What backs this:** 720 passing integration-first tests across Python
3.10–3.13, CI security scanning (Bandit, Semgrep, authenticated OWASP ZAP), and
three prior engineering audits whose release-blocking findings are remediated
and verified in the current source. Those audit reports are kept in the repo
**with remediation banners** so you can read both the original findings and
their fixes — see
[Full audit](https://github.com/sriram7737/pramagent/blob/main/pramagent_full_audit.md)
and [Enterprise review](https://github.com/sriram7737/pramagent/blob/main/pramagent_enterprise_audit.md).

## Alpha Maturity Notice

Pramagent is published as **Alpha software**. It has live smoke-test evidence
for Sepolia anchoring, S3 cold archive, local load testing, real OpenAI/Ollama
provider calls, and bundled red-team runs, but it has **not** passed an
external penetration test, SOC 2 audit, HIPAA assessment, or
regulated-production certification.

Do not treat Pramagent as bank-grade or healthcare-grade security
infrastructure. Do not claim prompt-injection immunity, production compliance,
or third-party-validated safety from the bundled benchmarks alone. Read
[Implementation status](https://github.com/sriram7737/pramagent/blob/main/docs/IMPLEMENTATION_STATUS.md),
[Live test results](https://github.com/sriram7737/pramagent/blob/main/docs/LIVE_TEST_RESULTS.md), and
[Hardening guide](https://github.com/sriram7737/pramagent/blob/main/docs/HARDENING_GUIDE.md)
before using it in a customer-facing pilot.
The June 11 active security prompt results are tracked in
[Security test results](https://github.com/sriram7737/pramagent/blob/main/pramagent_security_test_results.md).
The self-assessed DeepMind/AWS agent-security mapping is tracked in
[Conformance map](https://github.com/sriram7737/pramagent/blob/main/docs/CONFORMANCE.md).
Deferred controls and the reasoning behind them are tracked in
[Design decisions](https://github.com/sriram7737/pramagent/blob/main/docs/DESIGN_DECISIONS.md).
The YC/product-readiness gap list and commercial hardening roadmap are tracked
in [Enterprise readiness roadmap](https://github.com/sriram7737/pramagent/blob/main/docs/ENTERPRISE_READINESS_ROADMAP.md).

**Start here:** [Getting Started With Pramagent](https://github.com/sriram7737/pramagent/blob/main/docs/GETTING_STARTED.md)
walks from install to provider setup, agent wrapping, ToolGuard, HITL, trace
storage, dashboard/API, and real workflow demos.

**Try the public demo:** run the API and open `/demo`. The front-door scenario
is financial tool-calling safety: a payment-like action is held for HITL before
any provider call and sealed into a verifiable trace. No provider key is needed
for that zero-config path. Visitors can optionally enter an NVIDIA NIM
`nvapi-*` key, OpenAI `sk-*` key, or Gemini API Studio key for live model
answers; keys are used for that request only and never persisted.

One-command local demo:

```bash
pip install "pramagent[api]"
pramagent demo
# open http://127.0.0.1:8080/demo
```

## Bare Install Quickstart

This works with the base package only. No Docker, API server, or provider key is
required.

```bash
pip install pramagent
```

```python
import asyncio
from pramagent import Pramagent

async def main():
    resp = await Pramagent().run("Summarize this request", tenant_id="demo", session_id="s1")
    print(resp.output)
print(resp.trace.this_hash)
print(resp.trace.detection_tier, resp.trace.response_tier)  # trace-local indicators

asyncio.run(main())
```

![Pramagent bare-install terminal quickstart](https://raw.githubusercontent.com/sriram7737/pramagent/main/docs/quickstart-terminal.png)

That creates a tamper-evident trace using the deterministic mock provider.

Swap to a real OpenAI model by setting `OPENAI_API_KEY`:

```python
from pramagent import Pramagent
from pramagent.providers import OpenAIProvider

armor = Pramagent(provider=OpenAIProvider(model="gpt-4o-mini"))
```

Run against NVIDIA NIM with an `nvapi-*` key:

```python
from pramagent import Pramagent
from pramagent.providers import NvidiaProvider

armor = Pramagent(provider=NvidiaProvider(model="meta/llama-3.3-70b-instruct"))
```

## Frequently Asked Questions

**How do I add safety guardrails to an LLM agent?**  
Install Pramagent and wrap your agent call with the trust stack. Pramagent
enforces deterministic policy outside the model, so the LLM cannot override the
tool policy, HITL gate, or audit chain by changing its own text output.

**How do I audit AI agent decisions in production?**  
Every Pramagent call produces a hash-chained `TraceEvent` with layer decisions,
verdicts, provider metadata, PII redactions, HITL status, and `this_hash` /
`prev_hash`. New traces also include `aws_scope`, `detection_tier`,
`response_tier`, `attack_techniques`, and `conformance_metrics` so the same
evidence can be read through DeepMind/AWS-style agent-security vocabulary. These
fields are trace-local self-assessment metadata, not system-level conformance
or certification claims. The local chain can be verified and optionally anchored
externally.

**How do I declare AWS agent autonomy scope?**
Pass `agent_scope="scope_1"`, `"scope_2"`, or `"scope_3"` to `Pramagent`, or
set `PRAMAGENT_AGENT_SCOPE` for the API sidecar. Scope 1 blocks non-read side
effects. Scope 2 requires human approval for non-read tools even if a policy
was accidentally configured as `ALLOW`. Scope 3 records bounded-autonomy intent
and relies on your configured ToolGuard/HITL/rate-limit policies.

**How do I prevent prompt injection in a Python LLM agent?**  
`IsolationLayer` is a content-boundary layer: it scans inputs before the model
sees them, enforces size caps, and scopes optional memory by tenant/session. It
does not sandbox processes, networks, credentials, tools, or files. It covers known
instruction overrides, chat-template wrapper attacks, authority framing,
base64/hex/unicode-escape encoded payloads, and targeted multilingual override
phrases. v0.8.0 adds structured classifier verdicts, held-out PINT/TensorTrust
style fixtures, provenance-aware stricter scanning for tool output and
retrieved content, and optional `pramagent[ml]` embedding/DeBERTa layers. This
is defense-in-depth, not proof of prompt-injection immunity.

**How do I stop unsafe model output from reaching users?**  
`OutputJudgeLayer` runs an LLM-as-judge on every output before it returns — the
"is the OUTPUT safe?" check that regex cannot give. It catches semantic failures
deterministic rules miss (working malware, bypass walkthroughs, confirmed
destructive actions, leaked internals). On by default in the public demo, opt-in
for `/v1/run` (`PRAMAGENT_OUTPUT_JUDGE=1`). It is fail-closed, but it is itself a
model — strong defense-in-depth, not a guarantee.

**How do I stop unsafe tool calls from an AI agent?**  
Use `ToolGuardLayer` with `ToolPolicy`. Pramagent validates JSON Schema,
tenant/action allow-lists, side-effect class, call frequency, argument
injection, and dangerous chains before any side effect can execute.

**Can I trial policies without breaking production workflows?**
Yes. Construct `Pramagent(enforcement_mode="observe")` or set
`PRAMAGENT_ENFORCEMENT_MODE=observe` for the API sidecar. Observe mode records
`trace.would_block=True`, `trace.would_block_reason`, and a `*.observe`
LayerEvent, but lets Safety/ToolGuard/Scope policy decisions continue so teams
can tune policies. Consent, size caps, and injection isolation still fail
closed.

**Can security teams review policies without editing Python?**
Yes. `pramagent.policies.load_tool_guard("policies.json")` loads ToolPolicy
definitions from JSON, and YAML is supported with `pip install pyyaml` or
`pramagent[policy]`. `pramagent backtest policies.json --cases cases.jsonl`
runs proposed policy changes against explicit tool-call cases and exits
nonzero on expected-verdict mismatches.

**How do I add human approval to AI agent actions?**  
Use `HITLLayer` or a ToolGuard policy with `Verdict.ESCALATE`. Silence is never
consent: if approval does not arrive, the action remains unexecuted.

**Does Pramagent work with OpenAI, Anthropic, Gemini, Ollama, and local models?**  
Yes. Pramagent ships provider adapters for OpenAI, Anthropic, Gemini, Ollama,
NVIDIA NIM, and OpenAI-compatible local endpoints, plus a deterministic mock
provider for tests.

**Is Pramagent compliant with SOC 2, HIPAA, or the EU AI Act?**  
No. Pramagent includes compliance evidence mapping and tamper-evident logging
features that can support an assessment, but it has not passed SOC 2, HIPAA, EU
AI Act conformity assessment, or an external penetration test.

## API And Dashboard Install

```bash
pip install "pramagent[api,dashboard,redis,postgres]"
```

From source:

```bash
git clone git@github.com:sriram7737/pramagent.git
cd Pramagent
pip install -e ".[dev,api,redis,postgres,dashboard]"
```

## CLI And Docker Quickstart

```bash
pramagent init
pramagent validate
```

Run the local stack:

```bash
cp .env.example .env
docker compose up -d
```

Open:

- API docs: `http://localhost:8080/docs`
- Dashboard: `http://localhost:8501`

## Public Live Demo

The API serves a single-page product demo at `/demo`. It is enabled by default
so a new evaluator reaches the trust-stack proof immediately; set
`PRAMAGENT_DEMO_ENABLED=false` for API-only deployments.

```bash
pip install "pramagent[api]"
pramagent demo
```

`pramagent demo` sets demo-safe local defaults in that process:
`PRAMAGENT_DEMO_ENABLED=true`, `PRAMAGENT_ALLOW_MEMORY_STORE=1`, and
`PRAMAGENT_PROVIDER=mock`.

The first scenario needs no provider key: it routes a financial transfer
request through deterministic policy, pauses it at HITL, and returns the trace
plus `this_hash` / `prev_hash`. This is the five-minute wedge: financial
side-effect safety before the model is trusted.

Visitors can optionally bring a provider key on each run: `nvapi-*` for NVIDIA
NIM models, `sk-*` / `sk-proj-*` for OpenAI `gpt-4o-mini`, or an AI Studio
Gemini key for `gemini-2.5-flash`. Pramagent uses that key only for the current
provider call; it is not written to traces, logs, stores, usage records, or the
hash-chain payload. Each demo run uses an isolated in-memory trace store and
returns the output, trust-layer events, redactions, HITL state, latency,
self-assessed trace-control fields, `this_hash`, `prev_hash`, and local chain
verification.

The demo also includes optional product signals. If a visitor checks the
anonymous usage box, Pramagent records only a process-salted hashed visitor ID,
provider kind, verdict, HITL state, and trace-control indicators. It never records
prompts, outputs, provider keys, IP addresses, or plaintext email. The
managed-pilot form stores salted contact hashes plus a short use-case label
with obvious email/phone values redacted, so demand can show up as data without
turning the demo into a tracking surface.

Set `PRAMAGENT_DEMO_ADMIN_KEY` to enable the protected operator view at
`/demo/admin/signals`. The browser page asks for that key and then calls
`/demo/admin/signals.json` with an `Authorization: Bearer ...` header; the key
is never placed in a URL. By default these signals are process-local memory.
Set `PRAMAGENT_DEMO_SIGNALS_POSTGRES_DSN` to persist them to Postgres, and set
`PRAMAGENT_DEMO_SIGNAL_SALT` when you want hashed visitor/contact identifiers
to remain stable across restarts. The persisted schema still stores only
hashed/scrubbed fields, not prompts, outputs, provider keys, IPs, or plaintext
contacts.

The public throttle is keyed by client IP plus a short in-memory SHA-256 hash
of the visitor's provider key. The no-key deterministic path is throttled by
IP. If a visitor switches to a different key, they get a fresh demo bucket
without Pramagent storing the plaintext key.
A `DEGRADED` demo result means the upstream model call failed and Pramagent
returned its safe default with a trace. NVIDIA HTTP 403 usually means the
NVIDIA organization lacks hosted Public API Endpoints access; changing models
usually will not fix that entitlement issue.

Dashboard evidence from the authenticated June 21 smoke run is captured in
[Demo evidence](https://github.com/sriram7737/pramagent/blob/main/docs/DEMO_EVIDENCE_2026-06-21.md).
It includes screenshots for safe output, PII scrubbing, prompt-injection
blocking, destructive database-operation blocking, HITL-held financial action,
trace hashes, and the dashboard metric fix that reports engine latency
separately from human approval wait time. The evidence set also includes the
current console redesign preview: single-brand navigation, dense trace detail
with raw/scrubbed payloads, terminal `EXPIRED` approval states, and a
favicon-size proof for the Pramagent mark. The packaged dashboard serves the
new Pramagent SVG mark from `/static` across authenticated and pre-auth key
flows.

Run the release sanity checks:

```bash
python -m pytest -q --tb=no
python -m pramagent.cli redteam --json --attacks 100
python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999
```

Current local result: `684 passed, 2 skipped`. The latest targeted prompt
suite also passed with `0` failures across emergency override, output override,
margin/liquidation, IBAN/SWIFT, ambiguous escalation, PHI, false-positive,
base64, hex, unicode-escape, multilingual override-token, and
chat-template-wrapper cases.

## ToolGuard Example

```python
import asyncio

from pramagent import Pramagent, Verdict
from pramagent.layers import ToolGuardLayer, ToolPolicy
from pramagent.layers.tool_guard import SideEffect

guard = ToolGuardLayer(policies=[
    ToolPolicy(
        name="send_payment",
        side_effect=SideEffect.PAYMENT,
        action=Verdict.ESCALATE,
        allowed_tenants={"finance_team"},
        schema={
            "type": "object",
            "required": ["amount_usd", "destination"],
            "properties": {
                "amount_usd": {"type": "number", "minimum": 0.01, "maximum": 5000},
                "destination": {"type": "string", "pattern": r"acct-\d{6,}"},
            },
            "additionalProperties": False,
        },
    )
])

armor = Pramagent(tool_guard=guard)

async def main():
    decision = armor.validate_tool(
        "send_payment",
        {"amount_usd": 250.00, "destination": "acct-123456"},
        tenant_id="finance_team",
        session_id="demo",
    )
    print(decision.verdict)  # ESCALATE

    too_large = armor.validate_tool(
        "send_payment",
        {"amount_usd": 9000.00, "destination": "acct-123456"},
        tenant_id="finance_team",
        session_id="demo",
    )
    print(too_large.verdict, too_large.reason)  # BLOCK: schema violation

    wrong_tenant = armor.validate_tool(
        "send_payment",
        {"amount_usd": 250.00, "destination": "acct-123456"},
        tenant_id="marketing_team",
        session_id="demo",
    )
    print(wrong_tenant.verdict, wrong_tenant.reason)  # BLOCK: tenant mismatch

    response = await armor.run(
        "Summarize this payment request",
        tenant_id="finance_team",
        session_id="demo",
        action="send_payment",
    )
    print(response.hitl)
    print(response.trace.this_hash)

asyncio.run(main())
```

## Policy-As-Code And Backtesting

Security teams can review ToolGuard definitions as JSON/YAML files instead of
hardcoding them in application code.

`policies.json`:

```json
{
  "policies": [
    {
      "name": "send_payment",
      "side_effect": "payment",
      "action": "escalate",
      "allowed_tenants": ["finance_team"],
      "schema": {
        "type": "object",
        "required": ["amount_usd", "destination"],
        "properties": {
          "amount_usd": {"type": "number", "minimum": 0.01, "maximum": 5000},
          "destination": {"type": "string", "pattern": "acct-\\d{6,}"}
        },
        "additionalProperties": false
      }
    }
  ]
}
```

```python
from pramagent import Pramagent
from pramagent.policies import load_tool_guard

armor = Pramagent(tool_guard=load_tool_guard("policies.json"))
```

Backtest before merging a policy PR:

```bash
pramagent backtest policies.json --cases cases.jsonl
```

`cases.jsonl` uses one JSON object per historical/proposed tool call:

```json
{"case_id":"pay-001","tool_name":"send_payment","arguments":{"amount_usd":250,"destination":"acct-123456"},"tenant_id":"finance_team","expected":"escalate"}
```

This v0 backtest contract is explicit case replay. Stored-trace replay over the
last 30 days is on the roadmap once deployments have a stable tool-call export
shape.

## Drop-In Tool Decorator

For custom Python agents, wrap existing tools without rewriting the execution
loop:

```python
from pramagent.adapters import guarded_tool

@guarded_tool(armor, policy="send_payment")
def send_payment(amount_usd: float, destination: str):
    ...
```

`BLOCK` and `ESCALATE` both stop the function before the side effect runs.
Use the persistent HITL queue/dashboard path to approve and then re-run the
side effect intentionally; the decorator never treats escalation as consent.

## Built-In Rule Corpora

Pramagent now includes deterministic, importable rule bundles. They are plain
Python `Rule` objects, so a reviewer can inspect exactly what is enforced.

```python
from pramagent import Pramagent
from pramagent.layers import SafetyLayer
from pramagent.rules import ALL_RULES, JAILBREAK_PATTERNS, OWASP_LLM_TOP10

armor = Pramagent(
    safety=SafetyLayer(rules=[*JAILBREAK_PATTERNS, *OWASP_LLM_TOP10])
)

strict_armor = Pramagent(safety=SafetyLayer(rules=ALL_RULES))
```

Included corpora:

- `JAILBREAK_PATTERNS`
- `OWASP_LLM_TOP10`
- `INJECTION_CORPUS`
- `FICTIONAL_WRAPPER`
- `PHI_PATTERNS`
- `FINANCIAL_PII`

## Escalation Policy

`Verdict.ESCALATE` means "suspicious, but not certain enough to block." What
the pipeline does with it is configurable per stage — `pre` (the input pass,
before the model runs) and `post` (the output pass, after) — with one of
`"log"` (record and continue), `"hitl"` (route to the human-in-the-loop gate,
idle-on-silence), or `"block"` (hard stop). The default is `"log"` so adding an
ESCALATE rule never silently starts gating traffic; the ESCALATE verdict is
always recorded in the trace either way.

```python
# Healthcare / finance — maximum caution
Pramagent(safety=SafetyLayer(rules=[...]),
          escalate_policy={"pre": "hitl", "post": "block"})

# Developer tool — minimal interruption (default)
Pramagent(safety=SafetyLayer(rules=[...]),
          escalate_policy="log")

# Internal enterprise — gate suspicious input, log suspicious output
Pramagent(safety=SafetyLayer(rules=[...]),
          escalate_policy={"pre": "hitl", "post": "log"})
```

A string applies to both stages; a dict sets them independently. Invalid values
raise at construction, not at request time.

## Persistent HITL Queue

For approval flows that must survive process restarts, use the persistent
queue backends:

```python
from pramagent.layers import HITLLayer
from pramagent.queue import SQLiteHITLQueue

hitl = HITLLayer(
    require_approval_for=["send_email", "wire_transfer"],
    store=SQLiteHITLQueue("hitl.db"),
    timeout_s=None,  # wait until another process approves or denies
)
```

`InMemoryHITLQueue`, `SQLiteHITLQueue`, and `PostgresHITLQueue` are available
under `pramagent.queue`.

## Framework Adapters

Pramagent is meant to sit under existing agent frameworks, not replace them.

```python
from pramagent.adapters import PramagentNode, PramagentHook, PramagentGuard

# LangGraph
guard_node = PramagentNode(armor=armor)

# AutoGen
PramagentHook(armor=armor).attach(agent)

# CrewAI
safe_tool = PramagentGuard(armor=armor).wrap_tool(send_email)
```

Generic helpers are also available:

```python
from pramagent.adapters import protect, protect_tool
```

## Coding-Agent Hooks

Pramagent also ships a publishable hook plugin for coding agents:

- Claude Code `PreToolUse`
- Codex plugin hooks
- Grok Build / xAI plugin hooks
- any host that can emit Claude-style pre-tool-call JSON on stdin

The plugin lives in `plugins/pramagent-guard/`, with publishing notes in
[`docs/AGENT_HOOK_PUBLISHING.md`](docs/AGENT_HOOK_PUBLISHING.md). It is not an
MCP server/client/proxy; it is a host-agent lifecycle hook that evaluates
proposed tool calls before execution.

## Compliance Evidence

`ComplianceReporter.generate()` can produce point-in-time evidence packages
from Pramagent traces and mappings:

```python
from pramagent.compliance import ComplianceReporter

ComplianceReporter(store=store, audit=audit).generate(
    framework="SOC2",
    period_start="2026-01-01",
    period_end="2026-06-30",
    tenant_id="demo",
    output="evidence.json",
)
```

Supported mapping targets include SOC2, HIPAA, GDPR, NIST AI RMF, EU AI Act,
and PCI DSS. This is engineering evidence, not a certification.

## When To Use Pramagent

- You are wrapping LLM calls or agent workflows and need audit trails, policy
  checks, HITL approvals, PII scrubbing, and provider fallback in one place.
- You want deterministic tool policy outside the model, especially for actions
  like payments, data export, account changes, or admin operations.
- You are building an internal tool or pilot where honest safety evidence
  matters more than marketing claims.
- You need tamper-evident traces with optional Sepolia anchoring and encrypted
  S3 cold archive support.
- You already use LangGraph, AutoGen, CrewAI, or a custom loop and want a thin
  trust layer around prompts, tool calls, and approvals.

## When Not To Use Pramagent Yet

- You need certified bank-grade, healthcare-grade, or SOC2-audited production
  infrastructure today.
- You need proven jailbreak resistance against a serious red team; the bundled
  benchmark is only a deterministic smoke test, not third-party assurance.
- You need mature enterprise dashboard auth such as SSO/OIDC/RBAC. Optional
  generated dashboard keys and SQL users exist, but this is not an enterprise
  IAM plane yet.
- You need production-grade scale evidence, chaos engineering, or SLA-backed
  capacity numbers beyond the published local Docker Compose load run.
- You need billing-grade Stripe/Chargebee metering rather than the local usage
  ledger and event hooks.

## What Works Today

| Capability | Status | Notes |
|---|---|---|
| Provider adapters | Implemented | Mock, OpenAI, Anthropic, Gemini, Ollama, OpenAI-compatible/local |
| Rule corpora | MVP | 129 deterministic rules across jailbreaks, OWASP LLM risks, injection, fictional-wrapper bypasses, PHI, and financial PII |
| ToolGuard | Strong MVP | Draft 2020-12 JSON Schema, allow-lists, side-effect taxonomy, output scanning, Redis-backed chain state |
| HITL | Beta | Slack callbacks, persistent SQLite/Postgres queues, quorum/escalation primitives, ServiceNow/PagerDuty/email/webhook notifiers |
| Audit trail | Strong MVP | SHA-256 hash chain; optional real Sepolia anchoring |
| PII redaction | Strong MVP | Context-aware patterns for common regulated data; bounded email scrubbing avoids long-input regex DoS |
| Auth/rate limits/quotas | Beta | JWT/API keys, token buckets, per-tenant quotas |
| Framework adapters | MVP | LangGraph node, AutoGen hook, CrewAI guard, generic protect/protect_tool helpers |
| Dashboard | Prototype | Shared-key fallback, optional SQL users with generated keys, tenant scoping, traces, approvals, metrics, usage page, CSRF |
| Redis/Postgres backends | Beta | Wired and tested locally; needs scale/load testing |
| OpenTelemetry | Partial | Per-layer spans exist; dashboards and alerting need hardening |
| Red-team benchmark | MVP | Static and dynamic mutation modes; includes base64, translation-wrapper, and authority-framing regressions |
| Billing hooks | MVP | In-memory hash-chain usage ledger plus fail-open webhook; no Stripe/Chargebee provider yet |
| S3 cold archive | MVP | Gzip + encrypted trace archive wrapper; metadata sink hook |
| Compliance evidence | MVP | `ComplianceReporter.generate()` for JSON/text/PDF-style evidence packages |

## Integration Safety Contract

Pramagent should not replace human workflows that already work. Treat it as a
policy and evidence layer around risky agent actions, not as a mandate to put AI
into every decision path.

Before integrating a new feature or agent workflow, require three gates:

1. **Isolation contract:** declare which trust layers the feature touches. HITL
   features need a negative test proving the action cannot proceed without an
   authenticated approval. Isolation features need tenant/session boundary tests.
2. **Regression baseline:** run the full suite plus the new feature tests. Zero
   regressions are allowed for previously passing safety, trace, auth, and store
   behavior.
3. **Consequence traceability:** every approved or triggered action must leave a
   trace that explains why it was allowed, who/what approved it, what policy
   applied, and which downstream side effect was attempted.

The reusable reviewer prompt for this is in
[Security audit prompt](https://github.com/sriram7737/pramagent/blob/main/docs/SECURITY_AUDIT_PROMPT.md).

## Honest Limits

- Prompt-injection defense is not complete. The bundled static corpus and
  seeded dynamic mutation smoke tests now include base64, translation-wrapper,
  and authority-framing regressions. v0.8.0 adds structured verdicts,
  provenance-aware stricter scanning, held-out PINT/TensorTrust-style fixtures,
  and optional `pramagent[ml]` embedding/DeBERTa layers, but the project still
  needs larger third-party red-team sets and external assessment.
- ToolGuard is a hard policy gate outside the model, but it is not a sandbox.
- ToolGuard chain detection and per-session call limits are per-process unless
  a shared Redis backend is configured (`PRAMAGENT_TOOL_GUARD_REDIS_URL` or
  `PRAMAGENT_REDIS_URL`). When running multiple uvicorn workers, a dangerous
  tool chain whose steps land on different workers is only detected with a
  shared Redis backend; the Redis path uses an atomic Lua append so concurrent
  same-session calls never lose history.
- Slack is the main decision-collecting HITL adapter today. ServiceNow,
  PagerDuty, email, and generic webhooks are useful notification/escalation
  adapters. Persistent SQLite/Postgres approval queues exist, but broader
  enterprise approval workflows are still in development.
- Dashboard auth has tenant-scoped shared-key fallback plus optional SQL-backed
  users with generated dashboard keys and key regeneration. It is still not
  SSO/OIDC/RBAC-grade.
- Ethereum anchoring is Sepolia/testnet-oriented; no mainnet runbook, verifier
  contract, HSM/KMS key-management story, or enterprise anchoring operating
  model is included yet.
- The usage ledger is local audit evidence for pilots, not an invoice-grade
  billing system.
- Redis/Postgres support exists, but the stack has not been chaos-tested or
  load-tested for high-stakes deployments.
- No external penetration test or formal compliance certification has been run.
- QuantumLayer is future research only. It is not implemented, advertised as a
  feature, or exposed as a production API.

## Optional Anchoring And Archive

```bash
pip install "pramagent[ethereum,s3]"
```

Ethereum/Sepolia anchoring submits the audit head as transaction calldata and
stores the tx hash plus block number on the trace when configured. S3 cold
archive wraps a primary store and archives pruned/erased traces as encrypted
gzip JSON while keeping metadata available for compliance reporting.

## Demo Flow

```bash
pramagent init
docker compose up -d
python -m pytest -q --tb=no
python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999
```

Then use the dashboard to inspect traces, pending HITL approvals, audit status,
metrics, and per-tenant usage.

## Docs

- [Getting started](https://github.com/sriram7737/pramagent/blob/main/docs/GETTING_STARTED.md)
- [Implementation status](https://github.com/sriram7737/pramagent/blob/main/docs/IMPLEMENTATION_STATUS.md)
- [Conformance map](https://github.com/sriram7737/pramagent/blob/main/docs/CONFORMANCE.md)
- [Design decisions](https://github.com/sriram7737/pramagent/blob/main/docs/DESIGN_DECISIONS.md)
- [Overreach corpus](https://github.com/sriram7737/pramagent/tree/main/corpus/overreach)
- [Live test results](https://github.com/sriram7737/pramagent/blob/main/docs/LIVE_TEST_RESULTS.md)
- [Hardening guide](https://github.com/sriram7737/pramagent/blob/main/docs/HARDENING_GUIDE.md)
- [Incident-response runbook](https://github.com/sriram7737/pramagent/blob/main/docs/INCIDENT_RESPONSE_RUNBOOK.md) — key/credential compromise, audit-chain tamper response, and the security CLI: `pramagent auth-revoke` (revoke a leaked API key), `pramagent audit-verify-watch` (automated tamper detection), `pramagent audit-export` (export a tenant's trace rows)
- [Google Dev Library submission draft](https://github.com/sriram7737/pramagent/blob/main/docs/GOOGLE_DEV_LIBRARY_SUBMISSION.md)
- [Cookbook submission plan](https://github.com/sriram7737/pramagent/blob/main/docs/COOKBOOK_SUBMISSIONS.md)
- [Security test results](https://github.com/sriram7737/pramagent/blob/main/pramagent_security_test_results.md)
- [More documentation](https://github.com/sriram7737/pramagent/tree/main/docs)

## Author

- [Sriram Rampelli](https://sriram7737.github.io)

## License

Apache-2.0.
