# Getting Started With Pramagent

This guide shows how to install Pramagent, connect it to an LLM provider, wrap a
small agent loop, add deterministic tool policy, and verify the audit trace.

Pramagent is Alpha software. Use it as a trust middleware layer for prototypes,
internal pilots, and security review, not as certified production security.

## 1. Install

Base install:

```bash
pip install pramagent
```

Install API, dashboard, Redis, and Postgres extras:

```bash
pip install "pramagent[api,dashboard,redis,postgres]"
```

Install from source:

```bash
git clone git@github.com:sriram7737/pramagent.git
cd pramagent
pip install -e ".[dev,api,dashboard,redis,postgres]"
```

Optional ML prompt-injection classifier extras:

```bash
pip install "pramagent[ml]"
```

## 2. Run The Smallest Check

This uses the deterministic mock provider, so it does not need an API key.

```python
import asyncio
from pramagent import Pramagent


async def main():
    armor = Pramagent()
    response = await armor.run(
        "Summarize the value of audit logs for AI agents.",
        tenant_id="demo",
        session_id="quickstart-1",
    )
    print(response.output)
    print("blocked:", response.blocked)
    print("trace:", response.trace.this_hash)
    print("chain valid:", armor.audit.verify_chain())


asyncio.run(main())
```

Expected result:

- `blocked: False`
- a non-empty `trace` hash
- `chain valid: True`

## 3. Choose An LLM Provider

Pramagent ships provider adapters for OpenAI, Anthropic, Gemini, NVIDIA NIM,
Ollama, local OpenAI-compatible endpoints, and the mock provider.

### OpenAI

PowerShell:

```powershell
$env:OPENAI_API_KEY="sk-..."
```

Python:

```python
from pramagent import Pramagent
from pramagent.providers import OpenAIProvider

armor = Pramagent(provider=OpenAIProvider(model="gpt-4o-mini"))
```

### Gemini

PowerShell:

```powershell
$env:GEMINI_API_KEY="..."
$env:GEMINI_MODEL="gemini-1.5-flash"
```

Python:

```python
from pramagent import Pramagent
from pramagent.providers import GeminiProvider

armor = Pramagent(provider=GeminiProvider(model="gemini-1.5-flash"))
```

Runnable example:

```bash
python examples/gemini_trust_layer.py
```

### Anthropic

PowerShell:

```powershell
$env:ANTHROPIC_API_KEY="sk-ant-..."
```

Python:

```python
from pramagent import Pramagent
from pramagent.providers import AnthropicProvider

armor = Pramagent(provider=AnthropicProvider(model="claude-3-5-haiku-latest"))
```

### Ollama

Start Ollama locally, then:

```bash
ollama pull qwen2.5:1.5b
```

```python
from pramagent import Pramagent
from pramagent.providers import OllamaProvider

armor = Pramagent(provider=OllamaProvider(model="qwen2.5:1.5b"))
```

## 4. Wrap A Simple Agent Step

Your agent can keep its own planning logic. The key rule is: run model input
through Pramagent, then validate any tool call before executing side effects.

```python
import asyncio
import json

from pramagent import Pramagent, Verdict
from pramagent.layers import ToolGuardLayer, ToolPolicy
from pramagent.layers.tool_guard import SideEffect
from pramagent.providers import OpenAIProvider


def send_email(to: str, subject: str, body: str) -> dict:
    # Real code would call your email provider here.
    return {"sent": True, "to": to, "subject": subject}


tool_guard = ToolGuardLayer(
    policies=[
        ToolPolicy(
            name="send_email",
            side_effect=SideEffect.EXTERNAL_MESSAGE,
            action=Verdict.ESCALATE,
            schema={
                "type": "object",
                "required": ["to", "subject", "body"],
                "properties": {
                    "to": {"type": "string", "format": "email"},
                    "subject": {"type": "string", "maxLength": 120},
                    "body": {"type": "string", "maxLength": 5000},
                },
                "additionalProperties": False,
            },
            detail="external email requires human approval",
        )
    ]
)

armor = Pramagent(
    provider=OpenAIProvider(model="gpt-4o-mini"),
    tool_guard=tool_guard,
)


async def agent_step(prompt: str):
    response = await armor.run(
        prompt,
        tenant_id="demo_company",
        session_id="agent-session-1",
        action="draft_email",
    )
    if response.blocked:
        return {"status": "blocked", "reason": response.block_reason}

    # Example: your agent parsed a proposed tool call from the model output.
    proposed_tool = {
        "name": "send_email",
        "args": {
            "to": "manager@example.com",
            "subject": "Follow up",
            "body": "Hello from the agent.",
        },
    }

    decision = await armor.validate_tool(
        proposed_tool["name"],
        proposed_tool["args"],
        tenant_id="demo_company",
        session_id="agent-session-1",
    )

    if decision.verdict == Verdict.ALLOW:
        return send_email(**proposed_tool["args"])
    if decision.verdict == Verdict.ESCALATE:
        return {"status": "held", "reason": "awaiting human approval"}
    return {"status": "blocked", "reason": decision.reason}


print(asyncio.run(agent_step("Draft a follow-up email to the hiring manager.")))
```

What this proves:

- The model can suggest actions.
- Pramagent validates tool arguments outside the model.
- Consequential tools can be held for human approval.
- Every call creates a trace.

## 5. Add HITL Approval

The simplest HITL behavior is fail-closed: if nobody approves, the action does
not execute.

```python
from pramagent.layers import HITLLayer

armor = Pramagent(
    provider=OpenAIProvider(model="gpt-4o-mini"),
    tool_guard=tool_guard,
    hitl=HITLLayer(require_approval_for=["send_email"], timeout_s=30),
)
```

For persistent approvals, use a queue store:

```python
from pramagent.layers import HITLLayer
from pramagent.queue import SQLiteHITLQueue

hitl = HITLLayer(
    require_approval_for=["send_email"],
    timeout_s=None,
    store=SQLiteHITLQueue("hitl_queue.db"),
)
```

Slack approval is available through the HITL Slack adapter when your deployment
has a public callback URL and Slack app credentials configured.

## 6. Store And Verify Traces

Use SQLite locally:

```python
from pramagent import Pramagent
from pramagent.providers import OpenAIProvider
from pramagent.store import SQLiteStore

store = SQLiteStore("pramagent_traces.db")

armor = Pramagent(
    provider=OpenAIProvider(model="gpt-4o-mini"),
    store=store,
    audit=store,
)
```

Verify the audit chain:

```python
print(store.verify_chain())
```

Every trace has:

- tenant and session scope
- provider/model metadata
- pre/post safety verdicts
- HITL status
- latency
- `prev_hash` and `this_hash`

## 7. Run The API And Dashboard

Install extras:

```bash
pip install "pramagent[api,dashboard,redis,postgres]"
```

Create an environment file from the template:

```bash
cp .env.example .env
```

Run the API:

```bash
uvicorn pramagent.api.app:app --host 0.0.0.0 --port 8080
```

Run the dashboard stack with Docker:

```bash
docker compose up -d
```

Open:

- API docs: `http://localhost:8080/docs`
- Dashboard: `http://localhost:8501`

## 8. Run A Real Workflow Demo

Mock run:

```bash
python examples/live_payment_agent.py --provider mock --reset-db
```

OpenAI run:

```powershell
$env:OPENAI_API_KEY="sk-..."
python examples/live_payment_agent.py --provider openai --reset-db
```

Gemini run:

```powershell
$env:GEMINI_API_KEY="..."
python examples/gemini_trust_layer.py
```

Job-search agent integration example:

```bash
python examples/job_search_agent.py --provider mock
```

## 9. Production Checklist Before A Pilot

Do this before a customer-facing pilot:

- Use a persistent trace store, not in-memory storage.
- Set strong `PRAMAGENT_JWT_SECRET` and dashboard/API keys.
- Configure per-tenant API keys or JWTs.
- Set explicit CORS origins.
- Use per-request `tenant_id` and `session_id`.
- Keep HITL approvals persistent if actions can wait across restarts.
- Run red-team checks:

```bash
python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999
```

- Read `docs/IMPLEMENTATION_STATUS.md`, `docs/HARDENING_GUIDE.md`, and
  `docs/audits/pramagent_security_test_results.md`.

## 10. What To Build Next

For a first integration, start with one consequential tool:

- `send_email`
- `refund_customer`
- `send_payment`
- `update_database_record`
- `scrape_company_site`

Wrap that tool with `ToolGuardLayer`, give it a strict JSON Schema, decide
whether it should `ALLOW`, `BLOCK`, or `ESCALATE`, and verify the audit chain
after each run.

That is the core Pramagent pattern: the model can propose, but deterministic
policy outside the model decides what can actually happen.
