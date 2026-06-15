# Pramagent — Current Implementation Status

_Last updated after the 2026-06-15 v0.7.5 demo and red-team hardening pass._

This document is deliberately blunt. Pramagent is **strong trust middleware for
AI agents** — deterministic guardrails, HITL, tool policy, and tamper-evident
traces. It is **not** "bank-grade production infrastructure" yet. Use the table
below to know exactly what you are getting.

Package status: **Alpha**. PyPI metadata, README, and release notes should keep
this maturity label until external security review and real pilot evidence
exist.

## Test status

`python -m pytest -q --tb=no` -> **598 passing, 1 skipped**. The skip is
the Postgres optional-driver negative test when `psycopg2` is installed
locally; there are no expected failures hiding classifier misses in the bundled
suite.

Additional release harnesses:

- `python test_agent_v2.py --mock --api-url http://127.0.0.1:8010 --report test-results/test_agent_v2_full.json`
  -> **57/57 passing** across load, multi-tenant isolation, API/HTTP, and
  regression suites.
- `python examples/dynamic_feed_agent.py --provider mock --reset-db` ->
  **8/8 dynamic feed cases passing**, hash chain valid.
- `python examples/dynamic_feed_agent.py --provider ollama --ollama-model qwen2.5:1.5b --reset-db`
  -> **8/8 dynamic feed cases passing**, hash chain valid.
- Real Slack HITL UI approve/deny against the job-agent integration -> **passed**.
  Approve produced `hitl=approved` and a simulated email side effect; deny
  produced `hitl=denied` and no side effect. Both traces preserved a valid
  hash chain.
- Real OpenAI job-agent stress harness with `gpt-4o-mini`, five tenants,
  concurrency 10, per-request sessions, quota tracking, and real read-only
  public-page fetches -> **216/216 completed**, 0 provider errors, 0 circuit
  breaker trips, 0 post-safety false positives, 18 real fetches executed,
  hash chain valid.

The local pre-PyPI clean-environment check was run on Python 3.13.13. GitHub
Actions is configured to run the same suite on Python 3.10, 3.11, 3.12, and
3.13 with upgraded pip, setuptools, and wheel.

## Status table

### Implemented (works today, covered by tests)
- Provider adapters (Mock, OpenAI, Anthropic, Gemini, Ollama, NVIDIA NIM,
  OpenAI-compatible) + fallback chain
- Curated deterministic rule corpora under `pramagent.rules`: jailbreaks,
  OWASP LLM risks, injection payloads, fictional-wrapper bypasses, PHI, and
  financial PII. Current total: 129 importable `Rule` objects.
- Framework adapters under `pramagent.adapters`: LangGraph node, AutoGen hook,
  CrewAI guard, and generic `protect` / `protect_tool` helpers.
- PII scrubbing (context-guarded patterns, bounded email handler, and
  pre-scrub input-size cap)
- Deterministic safety rule engine (pre/post, precedence veto)
- Isolation heuristics + size caps + tenant/session-scoped memory, including
  decoded-base64 scanning, authority-framing patterns, and indirection-wrapper
  patterns
- **ToolGuardLayer** — Draft 2020-12 JSON Schema validation via `jsonschema`,
  arg-injection scan, output exfil scan, side-effect taxonomy, dangerous-chain
  detection, Redis/back-end-backed side-effect history and session call counters,
  per-tenant/action allow-lists, decision recorded in the trace,
  **LLM-as-judge** tightening hook
- Slack HITL (approve/deny, signed callbacks) **+ persistent in-memory,
  SQLite, and Postgres HITL queues, escalation chains, N-of-M quorum, full
  approval audit log, ServiceNow/PagerDuty/email/webhook adapters**
- Tamper-evident hash chain (SHA-256), optional real Ethereum/Sepolia anchoring
  with tx hash + block metadata, and Hyperledger fallback anchoring. Live
  Sepolia validation passed on tx
  `0x8d0d7bd15c377224acee00f397272bab1007c757080f19523cfc66c8461b5d99`.
- RCA: replay, causality, counterfactual **+ tool-call graphs, multi-rule
  counterfactuals, critical-path** for complex agents
- JWT / API-key auth, Postgres-backed persistent API-key registry, optional
  SQL-backed dashboard users with generated keys/key regeneration, per-tenant
  rate limiting, usage quotas, cross-tenant trace guard
- JWT `kid`-based signing-key rotation (`PRAMAGENT_JWT_SECRETS` +
  `PRAMAGENT_JWT_ACTIVE_KID`) with legacy single-secret compatibility
- Usage-event hooks for billing/analytics (in-memory hash-chain usage ledger,
  in-memory sink, fail-open webhook, fail-closed mode when explicitly enabled)
- SQLite + encrypted SQLite; **Postgres** store; **Redis** distributed backend
  for rate limits, memory, HITL signals, and ToolGuard side-effect history
- S3 cold archive wrapper for pruned/erased traces (gzip + encrypted JSON,
  metadata sink hook for Postgres/compliance tables). Live AWS S3
  archive/restore validation passed with a tiny fake trace.
- **Migration runner** (stdlib, SQLite + Postgres)
- **Compliance reporter** - consent registry, purpose limitation, retention
  policy with legal floor, JSON/text/PDF auditor reports, plus
  `ComplianceReporter.generate()` for SOC2, HIPAA, GDPR, NIST AI RMF, EU AI Act,
  and PCI DSS evidence packages
- OpenTelemetry per-layer spans (Compliance, Isolation, Safety, ToolGuard,
  Provider, HITL) + W3C trace-context propagation
- FastAPI sidecar (auth, CORS, security headers, structured logging, RCA +
  retention + GDPR-erasure endpoints, `/v1/usage` quota snapshots,
  `/v1/usage/ledger` ledger evidence, and a gated public `/demo` page for
  NVIDIA NIM smoke demos)
- Dashboard usage page, Redis-backed dashboard rate limiting with local
  fallback, no-store security headers, session revocation, optional SQL users
  with generated high-entropy dashboard keys, bcrypt key hashes, phone/email
  identities, hashed reset tokens, and signed CSRF protection for both pre-auth
  and session-authenticated browser forms
- Built-in red-team benchmark CLI with static and dynamic mutation modes
  (`python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999`)
- Public red-team result/methodology doc and load-test runbook
- Syntax-health test that compiles every Python source file before release
- Small concurrency smoke test for trace uniqueness and hash-chain integrity
- CI security scanning with Bandit, Semgrep, and authenticated OWASP ZAP
  OpenAPI scan
- Public NVIDIA NIM demo mode is disabled by default, rate-limited per IP, and
  uses a visitor-supplied `nvapi-*` key only for the current request. Demo
  traces are isolated in memory and are not persisted.

### MVP / needs hardening
- Usage quotas: enforced before expensive routes and integrated with rate
  limiting; ledger/webhook events exist, but there is no Stripe/Chargebee
  provider, invoice reconciliation, or billing-grade metering backend
- Ethereum anchoring: Sepolia live smoke test passed; no mainnet runbook, no
  deployed verifier contract, and no production key-management story yet
- S3 cold archive: live AWS S3 archive/restore smoke test passed; needs real
  lifecycle policies, KMS/envelope encryption, and restore runbooks before
  compliance use
- Dashboard auth: tenant-scoped config, shared-key fallback, optional
  SQLite/Postgres users, generated dashboard keys, bcrypt key hashes, key
  regeneration tokens, secure-cookie support, CSRF protection, Redis-backed
  throttling, and explicit all-tenant opt-in exist; still not SSO/OIDC/RBAC-grade
  and no email/SMS delivery provider is wired yet
- HITL adapters: Slack collects approve/deny decisions and persistent
  in-memory/SQLite/Postgres queues survive worker restarts. ServiceNow,
  PagerDuty, email, and generic webhooks are notification/escalation adapters;
  broader enterprise approval workflows, admin queue UX, and owner rotation are
  not complete.
- Prompt-injection defense: the bundled deterministic corpora and seeded
  dynamic mutation smoke tests now include base64, translation-wrapper, and
  authority-framing regressions, but the embedding classifier is optional
  (needs `sentence-transformers`); third-party and novel red-team sets are
  still required before high-stakes claims
- Multi-process scaling — Redis backend exists and ToolGuard chain state can be
  shared across workers; still not load-tested at 50+ tenant / 10k+ daily-call
  scale
- Load testing — authenticated local Docker Compose/Postgres/Redis 10-minute
  run passed with 12,000 requests, 0 errors, 0 HTTP 5xx; still not chaos/SLA
  testing
- RCA for complex branching agents — graph support added; heuristic, not a solver
- OTel tracing — spans emitted; Grafana dashboards are provided as config, not battle-tested

### Not implemented / out of scope for the current alpha
- SSO/OIDC/RBAC dashboard auth and email-verification delivery
- QuantumLayer (future research only; intentionally not built or exposed)
- Real external penetration test (must be run by a third party)
- 200-500 call run with full production side effects such as real email sends
  or third-party scraper providers. Current heavy run executes real read-only
  fetches only.
- Hosted public demo traffic at meaningful scale. The `/demo` flow has route
  tests and local smoke coverage, but no published Railway uptime/load evidence
  yet.
- Pilot-user production deployments

## Latest Workflow Evidence

2026-06-15 v0.7.5 red-team and public-demo hardening:

- Fixed the SE-2 emergency-override miss at input and output layers:
  `emergency_override` / `disable_safety_controls` heuristics block the prompt,
  and a demo post-rule withholds model completions that claim filters were
  disabled.
- Fixed F-4/F-2 demo financial-intent misses: margin-call/liquidation prompts
  and IBAN/SWIFT transfers now route to `wire_transfer` and idle at HITL with
  action not executed.
- Added `EscalatePolicy` and `Pramagent(escalate_policy=...)` so a
  `SafetyLayer` `ESCALATE` verdict can be logged, blocked, or routed to HITL
  per stage. The reference `/v1/run` deployment uses
  `escalate_policy={"pre": "hitl"}`.
- Fixed H-1 strict-healthcare redaction gap for MRN and contextual insurance
  member IDs.
- Fixed four dynamic benchmark misses in the fallback classifier: padded
  base64 tokens are decoded correctly, and indirect `exfiltrate credentials` /
  inline developer-message wrappers are caught.
- Red-team validation:
  `python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999`
  API run -> **200/200 caught, 0 false positives**.
- Local verification: **598 passed, 1 skipped**; Bandit returned no findings.

2026-06-15 public demo hardening after live NVIDIA checks:

- Fixed payment-like prompts that were only receiving `SafetyLayer.pre =
  escalate` but not visibly reaching HITL. The demo now detects payment intent,
  runs the provider, then idles at HITL with `[action not executed -
  awaiting/declined human approval]`.
- Removed broad post-output classifier use from the demo path; benign answers
  about LLM-agent risks no longer get silently replaced by
  `[output withheld by safety rule]`.
- Added deterministic pre- and post-safety coverage for file-exfiltration code
  generation requests.
- Confirmed contextual routing-number behavior: `021000021` is redacted when
  nearby text contains `routing`, while bare 9-digit values remain unredacted.
- Regression coverage added for these exact demo failure classes. Local
  verification at the time: **572 passed, 1 skipped**; later v0.7.5 hardening
  raised the suite to **598 passed, 1 skipped**.

2026-06-15 public NVIDIA NIM live-demo build:

- Added `NvidiaProvider` for NVIDIA NIM's OpenAI-compatible endpoint.
- Added gated `/demo`, `/demo/run`, and `/demo/verify` routes. The demo is
  disabled by default with `PRAMAGENT_DEMO_ENABLED=false`, throttled by
  `PRAMAGENT_DEMO_RATE_LIMIT`, and uses isolated in-memory traces per run.
- Demo model allow-list excludes deprecated NVIDIA Build free-endpoint IDs that
  return provider `404` safe defaults on otherwise-benign prompts.
- The browser demo asks visitors for their own `nvapi-*` key. Route tests
  verify invalid keys are not echoed, PII is scrubbed before the provider sees
  the prompt, injection/HITL cases do not call the provider, and the per-IP
  demo throttle returns `429`.
- Local verification: **568 passed, 1 skipped**; Bandit returned no findings.

2026-06-11 v0.7.3 security remediation:

- Active security prompt found two Medium issues and no Critical/High auth,
  tenant-isolation, HITL, or audit-chain bypasses.
- `SEC-2026-06-11-01` fixed: the isolation input-size cap now runs before
  compliance scrubbing, and email redaction uses bounded `@`-window scanning
  instead of running a regex across long no-match text. The 262 KiB no-match
  scrub regression is covered by `test_scrub_long_no_match_completes_fast`.
- `SEC-2026-06-11-02` fixed: isolation now decodes printable base64-looking
  tokens before heuristic scanning and adds authority-framing plus indirection
  wrapper patterns. Regression tests cover base64, developer/admin/tester
  framing, and translation wrappers.
- Release-gate validation caught additional dynamic red-team bypasses in the
  zero-dependency benchmark path. The red-team runner now combines injection
  and safety classifiers for its broader corpus, while the API pipeline keeps
  weapon-construction blocking in `SafetyLayer` rather than `IsolationLayer`.
- Local verification after remediation: **558 passed, 1 skipped**.
- Full evidence is in `pramagent_security_test_results.md`.

2026-06-11 v0.7.2 CI/dependency cleanup:

- Carries the v0.7.1 enterprise-audit remediation.
- Fixes GitHub Actions `pip-audit` invocation and authenticated ZAP CI sidecar
  startup after the persistent-store startup refusal hardening.
- Raises dependency floors to `aiohttp>=3.14.0` and
  `python-multipart>=0.0.27` to avoid newly published parser advisories in the
  default resolver path.
- Local verification before release: **547 passed, 1 skipped**, Bandit 0
  findings, Semgrep 0 findings, dynamic red-team 200/200 caught.

2026-06-11 v0.7.1 enterprise-audit remediation:

- Baseline suite before the final audit remediation series: **505 passed,
  1 skipped**.
- Final suite after five remediation phases: **547 passed, 1 skipped**.
- Closed the release-blocking API/dashboard issues from the June 9 full-spectrum
  audit and the June 10 enterprise pre-production review, including
  authenticated unversioned dashboard proxy routes, replay reproducibility,
  scrubbed persisted traces, erasure parity, persistent store startup refusal,
  weak-secret startup denial, Postgres chain integrity, chain-head race
  handling, blocking I/O off the async hot path, and deployment hardening.
- Added regression coverage for threaded chain writers, Postgres tamper
  detection, fallback providers, weak-secret startup refusal, tenant-scoped
  traces, and remediation-specific deployment/security behavior.
- Remaining deferred items are documented in `pramagent_full_audit.md`:
  keyset pagination, Redis quota Lua, chain verification watermark,
  Prometheus-specific metrics, `jti` denylist, dependency lockfile/SBOM, CI SHA
  pinning, and organizational artifacts such as breach runbook, DPA, and VDP.

2026-06-07 v0.5.20 package verification:

- Test suite: 449 passed, 1 skipped
- Rule corpus import smoke: 129 total rules
- Package build: wheel and sdist include `pramagent.rules`,
  `pramagent.queue`, and `pramagent.adapters`
- PyPI: `pramagent==0.5.20` published through GitHub Trusted Publishing

2026-06-05 job-agent stress harness with real OpenAI:

- Model: `gpt-4o-mini`
- Calls: 216 across five tenants, concurrency 10, per-request sessions
- Real tools: 18 read-only `fetch_public_page` calls executed against
  `https://example.com`; SSRF variants were blocked before any network call
- Quotas: per-tenant call/cost tracking enabled; 0 quota blocks at the configured limits
- Provider health: 0 provider errors, 0 circuit-breaker trips
- Safety quality: 0 post-safety false positives, 0 sentinel outputs in non-blocked responses
- Cost: `$0.00674850` total, approximately `$0.031` per 1,000 calls
  under this workload, with 2,142 prompt tokens and 10,712 completion tokens
- Latency: avg 1261.19 ms, p50 1180.77 ms, p95 3104.49 ms, p99 4207.98 ms, max 4293.46 ms
- Audit: hash chain valid

2026-06-05 real Slack HITL UI test:

- Approve path: `hitl=approved`, simulated email side effect recorded, trace hash
  `ff70c2adb3ed15b434bb6c63f8bb23b634b9840815d2b6e49e2bfa237681d08c`
- Deny path: `hitl=denied`, no side effect executed, trace hash
  `d9bd6d07070b6391401a0ac24dcd24cae760435a206d5b3425038ff37e395064`

These runs are strong beta evidence for the middleware. They are still not a
formal pen-test, a third-party red-team, or a production SLA/load guarantee.

## Honest one-line

> Trust middleware for AI agents with deterministic guardrails, HITL, tool
> policy, and tamper-evident traces. Genuinely strong for interviews and early
> users; not yet certified bank-grade infrastructure.
