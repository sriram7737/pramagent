# Live Workflow Demo

This is the canonical "real agent in the real timeline" demo for Pramagent.

Script:

```text
examples/live_payment_agent.py
```

It demonstrates:

- a live model proposing a structured tool intent
- ToolGuard validating the proposed tool before execution
- read-only tool execution when policy allows it
- HITL idle behavior for payment actions
- tenant-policy block before execution
- JSON Schema block before execution
- SQLite-backed tamper-evident trace hashes
- audit-chain verification

## Why This Demo Exists

Unit tests prove behavior in isolation. This demo proves the end-to-end agent
timeline:

```text
natural-language request
-> model proposes tool intent
-> ToolGuard validates policy
-> Pramagent records trace
-> allowed tools execute / risky tools wait / blocked tools never run
-> audit chain verifies
```

This is stronger launch evidence than a generic "summarize this document" demo
because it shows where Pramagent changes the agent's behavior.

## Safety Setup For OpenAI

Use an OpenAI project key with a small spend limit. Do not hardcode the key.
Do not commit `.env.live`, `.env`, screenshots with the full key, or terminal
history containing the key.

PowerShell session-only key:

```powershell
$env:OPENAI_API_KEY="sk-..."
$env:OPENAI_MODEL="gpt-4o-mini"
```

Or load selected `OPENAI_*` values from the existing local secret file:

```powershell
python examples\live_payment_agent.py --provider openai --env-file .env.live --reset-db
```

The script only reads these env keys from the file:

- `OPENAI_API_KEY`
- `OPENAI_MODEL`
- `OPENAI_BASE_URL`
- `OPENAI_MAX_TOKENS`

It never prints secret values.

## Offline Smoke Test

Run this before spending API credits:

```powershell
python examples\live_payment_agent.py --provider mock --reset-db
```

Expected shape:

```text
=== 1. read-only vendor lookup ===
guard  : allow - all checks passed
tool   : {"vendor_status": "known_vendor", ...}

=== 2. payment requires HITL ===
guard  : escalate - payment tools require human approval
hitl   : idle
tool   : not executed

=== 3. wrong tenant cannot send payment ===
guard  : block - tenant 'marketing_team' not in allowed_tenants for 'send_payment'
model  : not called
tool   : not executed

=== 4. oversized payment violates schema ===
guard  : block - argument schema violation: $.amount_usd: 9000.0 > maximum 5000
model  : not called
tool   : not executed

=== audit ===
chain_valid: True
traces     : 4
```

## Live OpenAI Run

```powershell
python examples\live_payment_agent.py --provider openai --env-file .env.live --reset-db
```

This makes a small number of OpenAI calls:

- one intent extraction call for each scenario
- one Pramagent provider call only for scenarios that pass deterministic
  pre-execution policy checks

The blocked tenant and oversized payment paths should show:

```text
model  : not called
tool   : not executed
```

That is the proof point: after the model proposes a structured intent,
Pramagent rejects the side-effect path before the operational tool runs and
before Pramagent continues into its provider execution path for that action.

## Verified Live Result

Local live OpenAI run on 2026-06-04:

```text
provider: openai
model   : gpt-5.5

=== 1. read-only vendor lookup ===
guard  : allow - all checks passed
hitl   : auto
tool   : {"vendor_status": "known_vendor", ...}

=== 2. payment requires HITL ===
guard  : escalate - payment tools require human approval
hitl   : idle
tool   : not executed

=== 3. wrong tenant cannot send payment ===
guard  : block - tenant 'marketing_team' not in allowed_tenants for 'send_payment'
model  : not called
tool   : not executed

=== 4. oversized payment violates schema ===
guard  : block - argument schema violation: $.amount_usd: 9000 > maximum 5000
model  : not called
tool   : not executed

=== audit ===
chain_valid: True
traces     : 4
```

## Screenshot Checklist

Capture a terminal screenshot showing:

- `provider: openai`
- `guard  : allow`
- `guard  : escalate`
- `guard  : block`
- `hitl   : idle`
- `model  : openai ...`
- at least one `hash   : ...`
- `chain_valid: True`

This screenshot is the highest-conversion visual for LinkedIn, Medium, and
GitHub because it proves the package is runnable and not just diagramware.

## Dashboard Evidence

The authenticated dashboard evidence set from 2026-06-21 is tracked in
[Demo evidence 2026-06-21](DEMO_EVIDENCE_2026-06-21.md). It includes UI
screenshots for:

- safe allowed output with a trace hash
- PII scrubbing before the model path continues
- prompt-injection blocking
- destructive database-operation blocking, with `everify_db` still present
- financial-transfer HITL hold where the action is not executed
- overview metrics that report engine latency separately from HITL wait time
- redesigned console overview, trace detail, approval queue, login page, and
  favicon-size logo proof

Use these screenshots for marketing or reviewer walkthroughs when the goal is
to show the running dashboard rather than the terminal-only payment script.

## Files Created Locally

The default run writes:

```text
pramagent_live_payment_demo.db
```

This file is ignored by Git through the `*.db` rule.

Remove it any time:

```powershell
Remove-Item pramagent_live_payment_demo.db
```
