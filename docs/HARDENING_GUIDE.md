# Pramagent Hardening Guide

This guide is intentionally blunt. Pramagent is useful guardrail and audit
middleware today, but regulated production use needs more proof, stronger
controls, and third-party validation.

## What This Pass Added

- v0.7.3 security remediation for the active security prompt:
  - The isolation input-size cap now runs before compliance regex scrubbing.
  - Email redaction uses bounded `@`-window scanning to avoid long-input regex
    CPU DoS.
  - Isolation decodes printable base64-looking tokens before heuristic scans.
  - Authority-framing and translation/indirection wrapper probes are now in the
    deterministic isolation coverage and red-team corpus.
  - Evidence is tracked in `pramagent_security_test_results.md`.
- Curated deterministic rule corpora under `pramagent.rules` for jailbreaks,
  OWASP LLM risks, injection payloads, fictional-wrapper bypasses, PHI, and
  financial PII.
- Persistent HITL queue backends under `pramagent.queue`: in-memory, SQLite,
  and Postgres.
- Thin framework adapters under `pramagent.adapters` for LangGraph, AutoGen,
  CrewAI, and generic custom loops/tools.
- `ComplianceReporter.generate()` for JSON/text/PDF-style evidence packages
  across SOC2, HIPAA, GDPR, NIST AI RMF, EU AI Act, and PCI DSS.
- In-memory hash-chain usage ledger for pilot metering evidence.
- `/v1/usage/ledger` API endpoint for tenant-scoped ledger inspection.
- Explicit fail-open/fail-closed behavior for usage event sinks.
- ServiceNow notify-only HITL adapter for ITSM/on-call escalation.
- JWT `kid` support for signing-key rotation through
  `PRAMAGENT_JWT_SECRETS` and `PRAMAGENT_JWT_ACTIVE_KID`.
- Dashboard CSRF protection for cookie-authenticated logout and approval
  decisions, while keeping API-key automation usable.
- Optional dashboard SQL users with generated high-entropy dashboard keys,
  bcrypt key hashes, tenant-scoped roles, signup routes, and one-time key
  regeneration tokens stored as hashes.
- Postgres-backed persistent API-key registry via `PRAMAGENT_API_KEY_DSN`.
- Redis/back-end-backed ToolGuard side-effect history and per-session tool call
  counters for multi-worker dangerous-chain detection.
- Draft 2020-12 JSON Schema validation through `jsonschema` instead of relying
  on the handwritten validator path.
- Updated docs that distinguish MVP evidence from billing-grade or
  compliance-grade guarantees.

## Release Gates Before Public Claims

Run these before any public release announcement:

```bash
python -m pytest -q --tb=no
python -m compileall pramagent tests
python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999
```

Then validate the optional systems you plan to claim:

- Sepolia anchoring with a burner wallet and testnet ETH.
- S3 archive/restore with a tiny fake trace and a scoped test bucket.
- Docker Compose stack with Postgres, Redis, API, and dashboard.

Publish the exact tx hash, S3 archive smoke result, red-team numbers, and test
count in `docs/LIVE_TEST_RESULTS.md`.

## Safety Hardening

Current state:

- Injection defense is layered: `IsolationLayer`/`classifier.py` pre-scan
  input before it ever reaches a prompt (provenance-aware — tool
  output/retrieved content gets stricter thresholds than direct user input),
  and the LLM-judge prompts themselves (`pramagent/layers/llm_judge.py`) now
  fence untrusted content (tool arguments, prior model output) in
  `<untrusted_...>` tags with explicit instruction-hierarchy language,
  escaping any attacker-supplied text that tries to forge a fake closing tag.
  This is defense-in-depth, not a replacement for the pre-scan: a fenced
  prompt still relies on the judge model actually respecting the fence.
- **Classifier default tier is a deliberate choice, not an oversight**:
  keyword-only pattern matching is the default and the supported baseline —
  zero extra dependencies, works everywhere `pramagent` installs. The
  embedding (`sentence-transformers`) and DeBERTa fine-tuned classifiers are
  a real, higher-assurance upgrade, but pull in `torch` (gigabytes, slow cold
  start), which is why they stay behind the separate `pramagent[ml]` extra
  instead of being bundled into `all`. Set `PRAMAGENT_CLASSIFIER=embedding`
  (or `PRAMAGENT_DEMO_CLASSIFIER=embedding` for the demo) to opt in — this is
  the recommended upgrade for deployments handling PHI or high-value tool
  calls. Whichever tier is actually active is logged at startup
  (`build_classifier()` in `pramagent/classifier.py`), so this is visible in
  logs, not just inferred from config.

Do next:

- Expand the red-team corpus with third-party jailbreak sets, indirect prompt
  injection, tool-output poisoning, delimiter attacks, and multi-step tool
  chains. The bundled corpus now includes base64, authority-framing, and
  translation-wrapper regressions, but this is still first-party coverage.
- Track bypass rate and false-positive rate per release in
  `docs/REDTEAM_RESULTS.md`.
- Add an optional stronger semantic judge for high-risk deployments.
- Keep ToolGuard as the deterministic gate: schema validation, side-effect
  taxonomy, tenant/action allow-lists, and HITL escalation should remain outside
  the model.

Do not claim:

- "Unbreakable" prompt defense.
- Bank/healthcare-grade safety without an external assessment.
- Production semantic safety from the bundled smoke benchmark alone.

## Billing And Usage

Current state:

- Quotas are enforced before expensive calls and tool validations.
- Usage events can be sent to a webhook.
- The local usage ledger is hash-chained evidence, not invoice reconciliation.
- API keys can be persisted in Postgres, with hashed keys and revocation
  timestamps. This is auth persistence, not billing-grade metering.
- `PRAMAGENT_QUOTA_FAIL_OPEN` defaults to fail-open (quota backend outage ->
  calls proceed unmetered), which is the intentional opposite of
  `RedisBackend`'s rate limiter (fail-closed by default). This is a
  reasoned asymmetry, not an inconsistency: the rate limiter guards against
  unbounded external abuse during an outage (a security concern), while the
  quota tracker only risks a tenant's own spend/call budget overrunning its
  cap during that outage (a self-inflicted billing trade-off). Set
  `PRAMAGENT_QUOTA_FAIL_OPEN=0` for deployments where strict cost control
  outweighs availability during a quota-backend outage.

Next:

- Add a persistent Postgres usage ledger.
- Add Stripe/Chargebee webhook ingestion and idempotency keys.
- Add reconciliation jobs that compare local usage events to billing-provider
  usage records.
- Add dashboard views for usage by tenant, model, action, and billing period.

## HITL And ITSM

Current state:

- Slack can collect decisions.
- ServiceNow, PagerDuty, email, and webhooks can notify humans.
- Quorum/escalation primitives exist.
- Persistent in-memory, SQLite, and Postgres approval queues exist for HITL
  gates that need to survive process restarts or wait indefinitely.
- Dashboard approval actions require session-bound CSRF tokens for browser
  cookie sessions.
- Dashboard users can be stored in SQLite/Postgres with generated keys and
  bcrypt key hashes, but the enterprise identity target remains SSO/OIDC/RBAC.

Next:

- Battle-test persistent approval queues under multi-worker load and add admin
  queue UX for search, reassignment, and manual expiry.
- Add escalation policies with owner rotation and timeout handoff.
- Add approval evidence exports: who approved, when, context hash, and final
  action.
- Add SSO/OIDC/RBAC for dashboard and approval admin workflows.
- Add verified email/SMS delivery for account activation and key regeneration.

## Multi-Tenancy And Data Isolation

Current state:

- `pramagent_traces` has row-level security (`ENABLE`/`FORCE ROW LEVEL
  SECURITY` + a tenant-scoped policy) applied by `PostgresStore`'s own DDL on
  every startup — not an opt-in migration. It only has teeth when the DSN
  connects as a non-superuser role: Postgres superusers and `BYPASSRLS`
  roles bypass RLS unconditionally, `FORCE` included. `deploy/postgres/init.sh`
  provisions a dedicated `pramagent_app` role for exactly this reason, and
  `PostgresStore` logs a startup warning if the connected role can't actually
  enforce the policy.
- `pramagent_chain` (the audit hash chain) is **deliberately not** RLS-scoped.
  Its rows aren't tenant-partitioned — a GDPR erasure tombstones a tenant's
  fields in place (see `redact_chain_payload`) rather than deleting rows,
  because the hash chain needs every row to still exist for `verify()` to
  walk it. Row-level tenant isolation doesn't apply to a table where "which
  tenant does this row belong to" isn't how access is gated in the first
  place; the isolation guarantee for chain data is that `redact_for_tenant()`
  only rewrites rows matching the target tenant, verified by the redaction
  test suite, not a DB-level RLS policy.
- `pramagent_chain` does have DB-level append-only enforcement: a trigger
  rejects all `DELETE`s and any `UPDATE` that doesn't come through the GDPR
  redaction path. This is a real, verified control (works regardless of
  table ownership), not just a `GRANT` omission — but it does not stop a
  fully privileged Postgres credential holder who reads the trigger logic
  and replicates its marker; that residual risk is what external chain
  anchoring (`EthereumBackend`/`HyperledgerBackend` in `pramagent/audit`)
  exists for.
- `deploy/postgres/hardening_rls.sql` remains as an *additional*, optional
  lockdown step (tighter migration-vs-runtime role split) for deployments
  that want it — it is no longer what makes tenant isolation or append-only
  semantics work at all.

Next:

- Add a stricter two-role deployment mode (separate migration/owner role
  from the runtime role) as a documented, tested path, not just the
  `hardening_rls.sql` GRANT/REVOKE sketch.
- Extend RLS-style tenant scoping to any future tenant-partitioned tables
  before they ship, not as a follow-up migration.

## Observability And Operations

Current state:

- Per-layer OpenTelemetry spans exist.
- Docker Compose, Redis, Postgres, and basic Grafana config exist.
- Load-test runbook exists.
- JWT signing keys can be rotated with `kid` headers, but this is still not a
  full enterprise identity plane.
- API key age is tracked (`AuthRecord.created_at`) and rotation is
  enforceable, not just documented: `PRAMAGENT_API_KEY_MAX_AGE_DAYS` rejects
  keys past the configured age (off by default). A dedicated
  `AuthFailureGuard` locks out repeated invalid-credential attempts per peer
  with an escalating cooldown, separate from the request-rate limiter.
- Audit-chain tamper detection is automated: `pramagent audit-verify-watch`
  (or the opt-in `docker compose --profile audit-watch` service) runs
  `verify()` on a loop and POSTs to `PRAMAGENT_AUDIT_ALERT_WEBHOOK_URL` on any
  broken link. Everything else (auth-failure spikes, unusual traffic
  patterns) is still manual/log-review based.

Next:

- Publish repeatable 10-minute and 60-minute load results.
- Add SSO/OIDC/RBAC and a full admin workflow for API-key/session
  administration.
- Add alert thresholds for block-rate spikes, HITL timeout spikes, quota-store
  failures, provider fallback rate, and auth-failure spikes (audit-chain
  tamper alerting itself is done — see Current state).
- Add chaos tests for Redis/Postgres outages and provider timeouts.
- Keep the operational runbooks current:
  `docs/INCIDENT_RESPONSE_RUNBOOK.md`, `docs/BACKUP_DR_RUNBOOK.md`, and
  `docs/SUPPLY_CHAIN.md`.

## Secrets Management

Current state:

- No hardcoded secrets repo-wide; a shared weak-secret denylist
  (`pramagent/security.py`) refuses every published placeholder spelling at
  startup, in both the API and dashboard.
- `pramagent/secrets.py` adds optional AWS Secrets Manager / HashiCorp Vault
  backing for `PRAMAGENT_JWT_SECRET`, `PRAMAGENT_ENCRYPTION_KEY`,
  `PRAMAGENT_API_KEY`, and `PRAMAGENT_DASHBOARD_KEY` — set
  `<NAME>_AWS_SECRET_ID` or `<NAME>_VAULT_PATH` and leave the plain env var
  empty. A secret found directly in the environment still always wins
  (unchanged default path); this was previously env-var-only with no
  secret-manager integration at all.
- API keys track issuance time (`AuthRecord.created_at`); rotation can be
  enforced, not just documented, via `PRAMAGENT_API_KEY_MAX_AGE_DAYS`.
- JWT signing keys rotate via `kid` (`PRAMAGENT_JWT_SECRETS` /
  `PRAMAGENT_JWT_ACTIVE_KID`) — that multi-key format is not yet wired into
  the secret-manager resolver, only the singular `PRAMAGENT_JWT_SECRET` path
  is.

Next:

- Extend secret-manager resolution to the `PRAMAGENT_JWT_SECRETS` multi-kid
  format and to `POSTGRES_PASSWORD`/`PRAMAGENT_POSTGRES_DSN`'s embedded
  credential.
- Automate rotation (a scheduled job that issues a new key and revokes the
  old one after a grace period), rather than requiring an operator to run
  `auth-issue`/`auth-revoke` by hand.
- Add GCP Secret Manager as a third backend alongside AWS/Vault.

## Compliance Evidence

Current state:

- Compliance mapping docs exist.
- Retention, erasure, consent, purpose limitation, S3 archive, and audit export
  primitives exist.
- Erasure has two granularities: `DELETE /v1/tenant/{tenant_id}/traces` (whole
  tenant) and `DELETE /v1/tenant/{tenant_id}/sessions/{session_id}/traces`
  (one end user within a multi-user tenant), across all three store backends
  (Postgres, SQLite, encrypted SQLite). Previously only tenant-wide erasure
  existed, so a single end user's request within a shared tenant required
  hand-written SQL.
- GDPR tombstoning covers more than input_text/output_text: rule and layer
  event `detail` strings and `layer_events[*].data` are redacted too, since a
  rule can echo the offending content back into its own explanation.
- `pramagent audit-verify-watch` can run on a scheduled interval, but
  retention pruning (`pramagent retention-prune`) is still invoked manually
  or via an external cron/scheduler, not run on a loop by the app itself.

Next:

- Extend generated evidence packages to ISO 42001 and customer-specific control
  mappings.
- Add field-level redaction policies by tenant.
- Add tiered retention by tenant, data class, and legal hold.
- Use immutable external storage for audit exports where required.
- Get an external pen test before claiming regulated production readiness.

### Audit Chain Threat Model — What It Does and Does Not Protect Against

The hash chain (`pramagent.audit.HashChainBackend` and the chain columns in
every store backend) is tamper-**evident** for the threats it's designed for:
an application bug, a compromised API credential, or SQL injection that edits
a record through the app's normal write path. `verify_chain()` recomputes
every link and any retroactive edit breaks the chain from that point forward.

It is explicitly **not** tamper-evident against an actor with raw database
write access, unless `PRAMAGENT_SIGNING_KEY` is set:

- Without a signing key, `canonical_hash()` is unkeyed SHA-256 over public
  data (the payload and the previous hash). Anyone who can write directly to
  the `audit_chain` / `pramagent_chain` table can edit a payload and
  recompute every hash after it — `verify_chain()` will report `True`
  because the algorithm and its inputs are both public.
- With `PRAMAGENT_SIGNING_KEY` set, `canonical_hash()` becomes HMAC-SHA256
  keyed with that secret. Recomputing a valid chain then requires the key,
  not just the payload — a DB-only attacker without the key cannot forge a
  self-consistent chain. This closes the gap for that specific threat, but
  the guarantee is only as strong as the key's secrecy and storage (a
  secrets manager, not an env var checked into source control) and still
  does not defend against an attacker who also has the key (e.g. anyone with
  access to the application's own runtime secrets).
- For a threat model that must also cover an attacker who compromises both
  the database and the application's secrets, the signing key alone is not
  enough — the chain head must be anchored outside the database entirely.
  `EthereumBackend` and `HyperledgerBackend` (`pramagent/audit/__init__.py`)
  exist for exactly this: they anchor the chain head to an external ledger,
  so even a from-scratch chain rewrite would not match the previously
  published anchors.

**Any deployment claiming tamper-evidence against a database-write-access
threat model must configure `PRAMAGENT_SIGNING_KEY` at minimum, and use
`EthereumBackend`/`HyperledgerBackend` (not `HashChainBackend`/plain
`SQLiteStore`/`PostgresStore`) if the threat model includes an attacker who
also has that key.** Treat external anchoring as required, not optional, for
that threat model — the local chain alone, keyed or not, is still evidence
recomputed from data that lives in the same trust boundary as the attacker.

## External Security Assessment Scope

Start this before GA. Typical scheduling lead time is measured in weeks, not
days.

Recommended scope:

- FastAPI sidecar: auth, JWT/API-key handling, tenant isolation, retention,
  GDPR erase, trace fetch, metrics, usage, and Slack callback routes.
- Dashboard: login/logout, cache-control, tenant scoping, export endpoints,
  rate limiting, and session invalidation.
- ToolGuard: schema validation bypasses, tenant/action allow-list bypasses,
  SSRF patterns, argument injection, output exfiltration, and dangerous-chain
  detection.
- HITL: Slack signature verification, replay resistance, approval evidence,
  button replacement, timeout semantics, and approval queue behavior.
- Audit: hash-chain tamper detection, trace canonicalization, Sepolia anchor
  verification, S3 cold archive restore integrity, and erasure-with-chain
  semantics.
- Operations: Redis/Postgres failure behavior, quota fail-open/fail-closed
  paths, provider timeout/circuit breaker behavior, and log/trace leakage of
  secrets or PII.

Evidence package to provide:

- `docs/IMPLEMENTATION_STATUS.md`
- `docs/LIVE_TEST_RESULTS.md`
- `docs/REDTEAM_RESULTS.md`
- `docs/COMPLIANCE_MAPPING.md`
- latest pytest output
- latest real workflow/load JSON reports
- architecture/dataflow diagrams

Claims blocked until this is complete:

- bank-grade, healthcare-grade, SOC 2-ready, HIPAA-ready, prompt-injection
  proof, or production-certified.

## Honest Positioning

Use this:

> Trust middleware for AI agents with deterministic guardrails, HITL, tool
> policy, and tamper-evident traces.

Avoid this until externally proven:

> Certified production trust infrastructure for banks and hospitals.
