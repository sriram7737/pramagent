# Technical Marketing Post Drafts

Use these drafts for Medium, dev.to, LinkedIn, GitHub Discussions, Hacker News,
Reddit, launch emails, and recruiter outreach. The tone is technical and
honest: Pramagent is Alpha trust middleware, not certified production
infrastructure.

Canonical links:

- PyPI: https://pypi.org/project/pramagent/
- GitHub: https://github.com/sriram7737/pramagent
- Implementation status: https://github.com/sriram7737/pramagent/blob/main/docs/IMPLEMENTATION_STATUS.md
- Live workflow demo: https://github.com/sriram7737/pramagent/blob/main/docs/LIVE_WORKFLOW_DEMO.md

Core wedge:

> Pramagent gives LLM agents deterministic tool policy and tamper-evident
> receipts for consequential actions. When money, data, or decisions move, "the
> model said so" is not enough.

Best one-line pitch:

> Trust middleware for LLM agents: deterministic tool policy, HITL approvals,
> and tamper-evident audit traces. Alpha, with public implementation status.

## Launch Sequence

Do not post everything at once. Sequence the launch so each post has a different
job.

Day 0:

- Update GitHub README and PyPI.
- Pin a short rename/migration note if any audience remembers the old package
  name.

Day 1:

- Publish the LinkedIn Builder Story with the live OpenAI payment-agent
  screenshot.
- Target recruiters, hiring managers, platform engineers, and AI infra teams.
- Primary visual: terminal screenshot, not architecture diagram.

Day 3:

- Submit the Hacker News / Reddit version.
- Goal: raw technical stress-testing and code feedback.
- Lead with ToolGuard's deterministic side-effect policy, not the full feature
  inventory.

Day 7:

- Publish the long-form Medium/dev.to post.
- Include the stack diagram and one terminal screenshot.
- Goal: engineering leads and technical buyers who want the architecture.

## Primary Visual

Use a real terminal screenshot as the main launch visual:

```powershell
python examples\live_payment_agent.py --provider openai --env-file .env.live --reset-db
```

What the screenshot should prove:

```text
provider: openai
guard  : allow - all checks passed
guard  : escalate - payment tools require human approval
guard  : block - tenant 'marketing_team' not in allowed_tenants for 'send_payment'
guard  : block - argument schema violation: $.amount_usd: 9000 > maximum 5000
hitl   : idle
tool   : not executed
chain_valid: True
```

Secondary visuals:

- `docs/stack.png` for architecture
- `docs/dataflow.png` for "the model is not the final authority"
- `docs/rca.png` for audit/replay posts
- dashboard screenshot for a follow-up post

## Long-Form Post

# The LLM Should Not Be The Final Authority

When an AI agent can call tools, move data, modify records, or trigger
workflows, model refusals are no longer sufficient.

You need deterministic control outside the model.

That is why I built Pramagent: Alpha trust middleware for LLM agents.

The principle is simple:

> The model can propose. Deterministic code must dispose.

I learned this the hard way while building bounded escalation and operational
controls around AI workflows in a HIPAA-sensitive eldercare environment. The
lesson generalized cleanly: once an LLM is connected to tools, the control
boundary cannot live only inside the prompt.

A chatbot giving a bad answer is a quality problem. An agent calling the wrong
tool with the wrong arguments is an operational problem. An agent exporting the
wrong data, modifying an account, or triggering a payment-like workflow is a
control problem.

Pramagent treats that as an engineering problem, not a vibes problem.

## The Core Layer: ToolGuard

Most LLM firewalls focus on text: prompts, outputs, jailbreaks, and refusals.
That work matters, but tool execution needs a different boundary.

ToolGuard treats tool execution as deterministic access control and schema
validation outside the model environment.

The model can hallucinate all it wants. If the generated tool name is not
registered, the arguments violate JSON Schema, the tenant is not allowed, or the
action crosses a side-effect policy, the execution layer blocks or escalates.

Example:

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
                "amount_usd": {
                    "type": "number",
                    "minimum": 0.01,
                    "maximum": 5000,
                },
                "destination": {
                    "type": "string",
                    "pattern": r"acct-\d{6,}",
                },
            },
            "additionalProperties": False,
        },
    )
])

armor = Pramagent(tool_guard=guard)

async def main():
    ok = armor.validate_tool(
        "send_payment",
        {"amount_usd": 250.00, "destination": "acct-123456"},
        tenant_id="finance_team",
        session_id="demo",
    )
    print(ok.verdict)  # ESCALATE: payment requires human approval

    too_large = armor.validate_tool(
        "send_payment",
        {"amount_usd": 9000.00, "destination": "acct-123456"},
        tenant_id="finance_team",
        session_id="demo",
    )
    print(too_large.verdict, too_large.reason)

    wrong_tenant = armor.validate_tool(
        "send_payment",
        {"amount_usd": 250.00, "destination": "acct-123456"},
        tenant_id="marketing_team",
        session_id="demo",
    )
    print(wrong_tenant.verdict, wrong_tenant.reason)

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

That is the important permission dynamic: not "please behave", but "this path is
not executable unless policy allows it."

## Install

```bash
pip install pramagent
```

Minimal run:

```python
import asyncio
from pramagent import Pramagent

async def main():
    resp = await Pramagent().run(
        "Summarize this request",
        tenant_id="demo",
        session_id="s1",
    )
    print(resp.output)
    print("trace:", resp.trace.this_hash)

asyncio.run(main())
```

The base package works without API keys because it defaults to a deterministic
mock provider.

## What Pramagent Does Today

Pramagent wraps model calls and agent workflows with:

- ToolGuard: JSON Schema validation, side-effect classification,
  tenant/action policies, argument scanning, output scanning, and HITL
  escalation
- tamper-evident SHA-256 hash-chain traces
- optional Sepolia anchoring as a decentralized, verifiable timestamp authority
  for audit heads
- PII scrubbing, prompt-injection heuristics, rate limiting, and quotas
- Slack HITL approvals
- adapters for OpenAI, Anthropic, Gemini, Ollama, local models, and
  OpenAI-compatible endpoints
- curated rule corpora, persistent HITL queues, and framework adapters
- FastAPI sidecar, dashboard, Redis/Postgres support, S3 archive
  support, and OpenTelemetry spans
- compliance evidence generation
- RCA helpers for replay, causality, and counterfactual inspection
- static and dynamic red-team benchmark CLI

Release evidence:

- 623 passing tests, one optional-environment skip
- Python 3.10, 3.11, 3.12, and 3.13 CI matrix
- live OpenAI smoke test
- real OpenAI job-agent stress run: 216 calls, five tenants, concurrency 10,
  18 real read-only public-page fetches, 0 provider errors, 0 circuit-breaker
  trips, 0 post-safety false positives, `$0.00674850` total model cost
  (`~$0.031` per 1,000 calls under this workload)
- real Slack HITL approve/deny clicks with trace hashes and hash-chain
  verification
- local Ollama smoke test
- live Sepolia anchoring smoke test
- S3 archive/restore smoke test
- Bandit, Semgrep, and authenticated OWASP ZAP scan evidence
- local Docker Compose load-test documentation
- public implementation-status and hardening docs

That evidence matters, but it has a limit.

## What It Is Not

Pramagent is Alpha software.

It is not certified bank-grade infrastructure. It is not HIPAA-certified. It has
not passed an external penetration test. It does not prove prompt-injection
immunity. It does not yet provide enterprise SSO/OIDC/RBAC. It is not a
complete billing system, compliance platform, or sandbox.

It is a strong Alpha for internal tools, pilots, interviews, and engineering
teams that want deterministic controls around LLM agents without pretending the
problem is solved.

AI infrastructure has too much marketing language and not enough implementation
status. I would rather say exactly what works, what is partial, and what is
missing than oversell a safety tool.

The implementation status is public:

https://github.com/sriram7737/pramagent/blob/main/docs/IMPLEMENTATION_STATUS.md

## Three Design Choices

The architecture is not interesting because it has many layers. It is
interesting because of where the boundaries sit.

First, ToolGuard makes tool execution a policy problem. Prompts can still be
attacked, and classifiers can still miss novel phrasing. A schema boundary and
side-effect policy are different: the generated arguments either satisfy the
contract or they do not.

Second, the audit trail is a hash chain over trace evidence. Every call records
the relevant inputs, verdicts, approvals, provider metadata, and hash pointers.
Optional Sepolia anchoring is used as a timestamping backstop for audit heads,
not as crypto theater or token infrastructure.

Third, PII scrubbing is context-guarded instead of blindly replacing every
number-like string. That matters because safety middleware still has to preserve
enough information for debugging, audit, and incident review.

The model can be useful, creative, and fast. It can also be wrong, manipulated,
or ambiguous. Pramagent assumes that ambiguity and wraps it with deterministic
software boundaries.

## Try It

Install:

```bash
pip install pramagent
```

Run the benchmark:

```bash
python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999
```

Open the repo:

https://github.com/sriram7737/pramagent

Read the implementation status:

https://github.com/sriram7737/pramagent/blob/main/docs/IMPLEMENTATION_STATUS.md

If you are building agents that touch real systems in finance, healthcare,
operations, compliance, or internal platforms, I want your feedback on ToolGuard
policy design and production hardening.

## Medium / Dev.to Metadata

Suggested title options:

- The LLM Should Not Be The Final Authority
- Building Pramagent: Deterministic Tool Policy For LLM Agents
- Why AI Agent Permissions Need Policy Outside The Model
- From Model Refusals To Enforceable Tool Policy
- Tamper-Evident Receipts For AI Agent Actions

Suggested subtitle:

> Pramagent is Alpha trust middleware for LLM agents: deterministic tool policy,
> HITL approvals, tamper-evident traces, and honest implementation status.

Suggested tags:

- ai
- llm
- agents
- ai-safety
- python
- devtools
- security
- observability
- compliance

Suggested canonical CTA:

> Try it on PyPI: `pip install pramagent`
>
> GitHub: https://github.com/sriram7737/pramagent

## LinkedIn Post: Builder Story Version

I have been thinking a lot about the difference between model behavior and
system control.

Most LLM safety work starts with the model: better prompts, better refusals,
better instruction following. That matters. But once an agent can call tools,
the control boundary cannot live only inside the model.

That is why I built Pramagent.

Pramagent wraps LLM agent calls with deterministic controls outside the model:
ToolGuard policy, HITL approvals, PII scrubbing, provider adapters, audit
traces, and replayable decisions.

The most important layer is ToolGuard:

- validate arguments with JSON Schema
- classify side effects
- enforce tenant/action allow-lists
- escalate risky tools to human approval
- record decisions in a tamper-evident trace

The release has 623 passing tests, one optional-environment skip, and a Python
3.10 through 3.13 CI matrix, plus live smoke evidence for OpenAI, Ollama,
Sepolia anchoring, S3 archive/restore, Slack HITL, multi-tenant load,
enterprise-audit remediation, and security scans. That does not make it
production-certified, but it does mean the release is more than a README.

It is published as Alpha software, with an honest implementation-status doc. No
fake "prompt-injection-proof" claims. No pretending it is certified enterprise
infrastructure. Just a strong guardrail/audit middleware foundation that can be
tested and improved.

PyPI:
https://pypi.org/project/pramagent/

GitHub:
https://github.com/sriram7737/pramagent

Implementation status:
https://github.com/sriram7737/pramagent/blob/main/docs/IMPLEMENTATION_STATUS.md

If you work on LLM agents, platform engineering, AI safety, compliance, or
production workflows, I want your feedback on ToolGuard and the hardening
roadmap.

## LinkedIn Post: Launch Version

I shipped Pramagent as an Alpha PyPI package.

It is trust middleware for LLM agents: deterministic tool policy, HITL
approvals, PII scrubbing, provider adapters, and tamper-evident audit traces.

The core idea:

> The LLM should never be the final authority.

Model-level refusals are useful, but they are not the same thing as control
boundaries. If an agent can call tools, move data, trigger workflows, or take
actions with side effects, policy needs to live outside the model too.

Pramagent currently includes:

- ToolGuard with JSON Schema validation, tenant/action allow-lists, side-effect
  taxonomy, output scanning, and HITL escalation
- curated deterministic safety rule corpora
- persistent HITL queues for longer-running approvals
- LangGraph, AutoGen, CrewAI, and generic framework adapters
- adapters for OpenAI, Anthropic, Gemini, Ollama, and local/OpenAI-compatible
  endpoints
- Slack HITL approval callbacks
- tamper-evident SHA-256 trace chains
- optional Sepolia timestamp anchoring and S3 cold archive support
- FastAPI sidecar, dashboard, Redis/Postgres support, OTel spans
- compliance evidence generation
- red-team benchmark CLI
- 623 passing tests across Python 3.10 through 3.13, with one optional skip

Important: it is Alpha software. It is not bank-grade, healthcare-grade,
externally audited, or prompt-injection-proof. I documented the current status
and gaps publicly because AI safety tooling should not hide behind marketing.

PyPI:
https://pypi.org/project/pramagent/

GitHub:
https://github.com/sriram7737/pramagent

Implementation status:
https://github.com/sriram7737/pramagent/blob/main/docs/IMPLEMENTATION_STATUS.md

If you are building LLM agents with tools, approvals, audit trails, or regulated
workflows, I want technical feedback.

## LinkedIn Post: Short Version

I shipped Pramagent as an Alpha PyPI package.

It is trust middleware for LLM agents: deterministic tool policy, HITL
approvals, provider adapters, PII scrubbing, and tamper-evident traces.

The premise is simple:

> The LLM should never be the final authority.

If an agent can call tools or trigger side effects, model refusals are not
enough. You need policy outside the model.

What is included today:

- ToolGuard for schema, tenant/action, and side-effect policy
- curated deterministic safety rule corpora
- persistent HITL queues for longer approval workflows
- LangGraph, AutoGen, CrewAI, and generic framework adapters
- OpenAI, Anthropic, Gemini, Ollama, local provider support
- Slack HITL approvals
- hash-chain audit traces
- optional Sepolia timestamp anchoring and S3 archive support
- compliance evidence generation for auditor-facing packages
- FastAPI sidecar, dashboard, Redis/Postgres, OTel
- 623 passing tests, 1 optional-environment skip

It is Alpha and not externally certified. The implementation status is public
and intentionally blunt.

PyPI: https://pypi.org/project/pramagent/
GitHub: https://github.com/sriram7737/pramagent

Feedback welcome from people building production AI agents.

## Rename Bridge Post

Use this once, before the main launch, only for people who saw the old package
name.

Quick note: the project I previously published as `veritrace` is now
**Pramagent**.

The new package is:

```bash
pip install pramagent
```

The old `veritrace` PyPI package has a migration shim that depends on
`pramagent>=0.5.0` and warns users to migrate.

New repo:
https://github.com/sriram7737/pramagent

New PyPI:
https://pypi.org/project/pramagent/

The name changed. The technical direction is the same: deterministic policy,
HITL, and tamper-evident traces for LLM agents.

## X / Twitter Thread

1. The LLM should never be the final authority.

If an AI agent can call tools, move data, or trigger side effects, model
refusals are not enough.

You need deterministic policy outside the model.

2. I shipped Pramagent as an Alpha PyPI package.

It is trust middleware for LLM agents: deterministic tool policy, HITL
approvals, provider adapters, PII scrubbing, and tamper-evident traces.

3. The core layer is ToolGuard.

It validates tool calls with JSON Schema, tenant/action allow-lists,
side-effect taxonomy, output scanning, and HITL escalation.

4. The model can hallucinate tool arguments.

ToolGuard does not care. If the args violate schema, tenant policy, or
side-effect rules, execution gets blocked or escalated before the workflow
proceeds.

5. Pramagent also includes OpenAI, Anthropic, Gemini, Ollama, and local provider
support, plus Slack HITL, hash-chain traces, optional Sepolia timestamp
anchoring, S3 archive support, Redis/Postgres, OTel, and a FastAPI sidecar.

6. Current release evidence:

- 623 passing tests, 1 optional-environment skip
- Python 3.10 to 3.13 CI
- OpenAI and Ollama smoke tests
- Sepolia anchoring smoke
- S3 archive/restore smoke
- Bandit, Semgrep, and authenticated OWASP ZAP scan evidence
- red-team benchmark CLI

7. Important: it is Alpha.

Not bank-grade. Not healthcare-grade. Not externally audited. Not
prompt-injection-proof.

The implementation status is public and intentionally blunt.

8. Try it:

`pip install pramagent`

GitHub:
https://github.com/sriram7737/pramagent

PyPI:
https://pypi.org/project/pramagent/

## Hacker News / Reddit Submission

Title:

Show HN: Pramagent, deterministic tool policy for LLM agents

Post:

I built Pramagent, an Alpha Python middleware layer for LLM agents.

The main technical idea is ToolGuard: tool execution is gated outside the model
with JSON Schema validation, side-effect classification, tenant/action
allow-lists, output scanning, and HITL escalation. This sidesteps a common
failure mode of tool-using agents: even if the model is manipulated into
generating a bad tool call, the execution layer can still reject arguments that
violate policy.

Pramagent also includes provider adapters for OpenAI, Anthropic, Gemini, Ollama,
and local/OpenAI-compatible models, plus PII scrubbing, Slack HITL, hash-chain
audit traces, optional Sepolia timestamp anchoring, S3 archive support,
Redis/Postgres, OpenTelemetry, a FastAPI sidecar, and a small dashboard.

It is explicitly Alpha. Not certified, not prompt-injection-proof, not
bank-grade. I included an implementation-status doc with the honest gaps.

PyPI: https://pypi.org/project/pramagent/
GitHub: https://github.com/sriram7737/pramagent

I would appreciate technical feedback, especially on ToolGuard policy design,
red-team benchmarking, and production hardening.

## Launch Email

Subject options:

- Why your LLM should never be the final authority
- Deterministic policy outside the LLM
- I shipped Pramagent, trust middleware for LLM agents

Body:

Hi,

I just published Pramagent, an Alpha Python package for wrapping LLM agents with
deterministic safety and audit controls.

It is built around a simple idea:

> The LLM should never be the final authority.

Pramagent includes provider adapters, PII scrubbing, prompt-injection checks,
ToolGuard policy validation, HITL approvals, tamper-evident trace chains,
optional Sepolia timestamp anchoring, S3 archive support, a FastAPI sidecar, and
a dashboard.

The most important piece is ToolGuard: JSON Schema validation, tenant/action
allow-lists, side-effect taxonomy, output scanning, and HITL escalation for
agent tools.

It is Alpha software, and I am being explicit about the limits: it is not
externally audited, not certified for regulated production, and not
prompt-injection-proof. The implementation status is public.

PyPI:
https://pypi.org/project/pramagent/

GitHub:
https://github.com/sriram7737/pramagent

Implementation status:
https://github.com/sriram7737/pramagent/blob/main/docs/IMPLEMENTATION_STATUS.md

If you are building AI agents with tools, approvals, audit trails, or compliance
requirements, I want your feedback.

Thanks,
Sriram

## Interview Pitch

Use this when someone asks what makes Pramagent different from prompt filters or
generic guardrails:

> Everyone else is trying to build a better prompt filter. Pramagent's ToolGuard
> treats tool execution as a deterministic access-control and schema-validation
> problem outside the model environment. The model can hallucinate all it wants,
> but if the generated arguments violate JSON Schema, side-effect policy, or
> tenant boundaries, the execution layer blocks or escalates before the tool
> runs.

## Technical Audit Checklist Before Posting

Run this before launch posts, release notes, or demo videos:

```powershell
cd path\to\pramagent

# Legacy-name scan. Expected hits: only migration docs or intentional mentions.
rg -n "veritrace|Veritrace|VERITRACE" `
  -g "!dist/**" `
  -g "!build/**" `
  -g "!*.egg-info/**" `
  -g "!docs/*.png" `
  -g "!docs/*.docx"

python -m compileall -q pramagent tests
python -m pytest -q --tb=no
python -m twine check dist\pramagent-*.whl dist\pramagent-*.tar.gz
```

## Follow-Up Post Ideas

1. ToolGuard deep dive: why tool safety needs schemas plus side-effect policy.
2. HITL design: why idle-on-silence is safer than auto-approve.
3. Audit traces: hash chains, Sepolia timestamp anchoring, and what
   "tamper-evident" does and does not mean.
4. Honest safety marketing: why Alpha AI infrastructure should publish its
   limitations.
5. Local agents: running Pramagent with Ollama and OpenAI-compatible endpoints.

