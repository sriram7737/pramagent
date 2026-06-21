# Pramagent Dashboard Evidence - 2026-06-21

This is local authenticated dashboard evidence from the Pramagent demo stack.
It is not a third-party assessment, certification, or production uptime report.
It records what the UI showed after running representative safe, sensitive,
blocked, and HITL-held prompts.

## Screenshot Set

| Step | Evidence |
|---|---|
| Login page | ![Login page](assets/demo-evidence/01-login-page.png) |
| Overview with reconciled block rate and engine latency | ![Overview](assets/demo-evidence/02-overview-engine-latency.png) |
| Trace browser | ![Trace list](assets/demo-evidence/03-traces-list.png) |
| Safe request trace | ![Safe summary trace](assets/demo-evidence/04-safe-summary-trace.png) |
| PII scrubbing trace | ![PII scrubbing trace](assets/demo-evidence/05-pii-scrub-trace.png) |
| Prompt-injection block trace | ![Injection block trace](assets/demo-evidence/06-injection-block-trace.png) |
| Destructive DB operation block trace | ![DB delete block trace](assets/demo-evidence/07-db-delete-blocked-trace.png) |
| Financial transfer held for HITL | ![Financial HITL trace](assets/demo-evidence/08-financial-hitl-held-trace.png) |
| Latest DB delete attempt, blocked | ![Latest DB delete block trace](assets/demo-evidence/09-db-delete-blocked-latest.png) |

## Run Summary

The run used dynamic prompts through the dashboard/API stack and verified that
the audit trace hash was generated for each path.

| Scenario | Verdict | Evidence hash |
|---|---|---|
| Safe production-agent risk summary | `ALLOWED` | `1275c64de3b9d9b089332e79ff1d7a0509f3837d66e24c9ad7fd0077b3226a4e` |
| PII health-care prompt | `ALLOWED`, PII scrubbed | `f4fcbef7ae1c7818c82226bd2abbdcb1716373dddc16a4e0b3a632b9f18006fa` |
| Prompt-injection attempt | `BLOCKED` | `b15af27f74da460202f1cfa4d02193b343eb4a8e16a7567fd19ebe8591e18d8a` |
| Destructive `everify_db` deletion attempt | `BLOCKED` | `800e4acc79ecc7cceaac1759d57de3c9b8bebdf61e559efe8433967a8408d831` |
| Financial transfer prompt | `HELD`, `hitl_status=idle`, action not executed | `7c65d3d05f94d8e319bbb8b6846139f7fc3e1031ae1705ba7bd3172169d28788` |
| Latest destructive `everify_db` deletion attempt | `BLOCKED` | `7e1cfb4d526879528253eaa8c0aabbd36156920eebcf95f2d5b498c3bcaccb64` |

The destructive database prompt was blocked by the input safety rule. The local
MySQL check after the run confirmed `everify_db_exists=True`; no database
deletion side effect was executed.

## Dashboard Fixes Captured By This Evidence

- The overview block-rate card is reconciled from persisted trace rows, so
  blocked traces no longer appear below a misleading `0.0%` block rate.
- The latency cards now show engine latency. Human waiting time from HITL idle
  holds is tracked separately so a 120-second approval timeout does not make the
  Pramagent engine look like it took 120 seconds to process the request.
- The trace browser links by `call_id` while still displaying trace hashes,
  which keeps copied dashboard URLs stable even for stored traces.
- HITL idle decisions are shown as `HELD` / action not executed, distinct from
  hard `BLOCKED` requests.

## Validation

Focused validation after the dashboard/evidence update:

```powershell
python -m pytest tests\test_dashboard_security.py::test_dashboard_overview_reconciles_metrics_from_trace_rows tests\test_dashboard_usage_page_is_tenant_scoped tests\test_api.py::test_dashboard_trace_routes_derive_blocked_status -q --tb=short
# 3 passed

python -m compileall -q deploy\dashboard tests\test_dashboard_security.py
# passed
```
