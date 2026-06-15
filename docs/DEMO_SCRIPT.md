# Two-minute Demo Script

Use this for a Loom or interview walkthrough.

## 0:00 - Bootstrap

```bash
pramagent init
cp .env.example .env
docker compose up -d --build
```

Show:

- API docs at `http://localhost:8080/docs`
- Dashboard at `http://localhost:8501`

## 0:30 - Consequential Action

Run a payment-like action:

```powershell
Invoke-RestMethod `
  -Method POST `
  -Uri "http://localhost:8080/v1/run" `
  -ContentType "application/json" `
  -Body '{"prompt":"Please execute the transfer","tenant_id":"bank","session_id":"demo","action":"wire_transfer"}'
```

Show the HITL request in Slack or the dashboard approvals view.

## 1:10 - Trace And Audit

Open dashboard traces. Show:

- tenant/session
- verdicts
- HITL status
- trace hash
- provider/model

Then verify audit:

```powershell
Invoke-RestMethod http://localhost:8080/v1/audit/verify | ConvertTo-Json
```

## 1:40 - Honesty Check

Run:

```bash
python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999
```

Say plainly: this is a guardrail/audit MVP. It adds deterministic policy gates
outside the model, but prompt injection is not solved and the project still
needs bigger red-team coverage, load tests, and external security review.
