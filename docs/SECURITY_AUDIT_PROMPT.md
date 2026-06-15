# Pramagent Security Audit Prompt

Use this prompt with a senior AI code reviewer or security-focused model when
you want a hard, evidence-based review of Pramagent or a Pramagent integration.
It is designed around three product-owner concerns:

- do not replace working human workflows just because an agent can act;
- do not approve actions whose downstream consequences are invisible;
- do not integrate a new feature unless it proves it will not create regressions.

Copy the prompt below and attach the repository, audit reports, and current test
results.

```text
You are a principal security engineer reviewing Pramagent, an alpha Python trust
middleware package for LLM agents. Be blunt and evidence-driven. Do not write
marketing copy. Your job is to find contradictions between what the product
claims and what the code actually enforces.

Context:
- Pramagent's core promise is deterministic policy outside the model: ToolGuard,
  HITL approvals, tenant/session isolation, PII scrubbing, tamper-evident traces,
  replay/RCA, persistence, and deployment hardening.
- Treat the LLM as untrusted. Treat user prompts, tool outputs, emails, web
  pages, callbacks, dashboards, and stored traces as untrusted.
- A feature is not safe merely because tests pass; it must have an integration
  contract, negative tests, and consequence traceability.

Primary product-owner concerns to evaluate:
1. Human workflow preservation:
   - Does the code replace or bypass existing human approval/procurement/security
     workflows?
   - Are ESCALATE decisions actually wired to authenticated HITL approval?
   - Can a risky action proceed on timeout, missing approval, fake approval,
     replayed callback, stale request, or unauthenticated route?

2. Downstream consequence traceability:
   - For every approved/triggered side effect, can we reconstruct why it was
     allowed, which policy applied, who/what approved it, which tenant/session it
     belonged to, what input/output was used, and what side effect was attempted?
   - Does replay independently re-derive verdicts, or merely restate stored
     decisions?
   - Are trace records scrubbed, hash-chained, tenant-scoped, and resilient to
     deletion/reordering/payload tamper?

3. Regression safety:
   - For any new feature, identify which trust layers it touches.
   - Require a negative test for each touched security boundary.
   - Verify the full suite plus new tests stays green.
   - Identify untested load-bearing paths such as fallback providers, stores,
     migrations, auth, HITL queues, Redis/Postgres paths, dashboard routes, and
     deployment defaults.

Review lenses:
1. Architecture and trust boundaries:
   - Confirm the ten-layer design is actually wired in the runtime path.
   - Find dead abstractions, duplicated routes, bypass routes, optional security
     paths that silently fail open, and model-controlled decisions that should
     be deterministic.

2. Authentication, authorization, and tenant isolation:
   - Test API-key/JWT auth, dashboard sessions, cookies, CSRF, CORS, callback
     signatures, logout/back-button behavior, all-tenant access, tenant-derived
     store access, and unversioned/dashboard proxy routes.
   - Look for any endpoint that reads, lists, decides, deletes, exports, prunes,
     or approves without authenticated tenant context.

3. HITL and ToolGuard:
   - Verify BLOCK, ALLOW, REDACT, and ESCALATE semantics.
   - Prove ESCALATE cannot proceed without authenticated approval.
   - Test approval expiry, duplicate click, denial, stale request, invalid
     signature, replayed signature, wrong tenant, wrong session, and callback
     route exposure.
   - Test tool input schema bypass, output exfiltration, dangerous-chain
     detection, per-session call limits, Redis-backed state, and multi-worker
     behavior.

4. Persistence and audit integrity:
   - Test MemoryStore refusal in production, SQLite, encrypted SQLite,
     Postgres, S3 archive, migrations, chain head race, concurrent writers,
     verify_chain, erase/prune/redaction parity, JSONB handling, and trace
     retrieval by tenant.
   - Attempt row deletion, row reorder, payload mutation, stale-head append,
     cross-tenant read, cross-tenant erase, and chain replay mismatch.

5. PII/PHI and data minimization:
   - Verify model input, persisted trace, audit-chain payload, dashboard export,
     CSV export, usage ledger, logs, exceptions, and S3 archive do not retain raw
     sensitive data unless explicitly documented.
   - Test SSNs, emails, phone numbers, API keys, private keys, JWTs, bank
     accounts, credit cards, and medical identifiers.

6. Runtime safety and concurrency:
   - Test event-loop blocking, sync I/O in async paths, semaphore saturation,
     circuit breaker open/half-open/close, provider fallback, timeout behavior,
     Redis/Postgres outages, quota fail-open/fail-closed behavior, bounded
     memory structures, and 8+ threaded writers.

7. Deployment and supply chain:
   - Review Docker Compose, Helm, Dockerfiles, env defaults, secret validation,
     ports, non-root users, image tags, dependency floors/caps, optional extras,
     CI workflows, publishing, SBOM/lockfile status, Bandit/Semgrep/ZAP scans,
     and known CVEs.

8. Tests and proof:
   - For every finding, provide a failing test or a precise reproduction.
   - Do not accept "covered" unless you can name the test file and assertion.
   - Mark gaps as one of: release blocker, fix before beta, fix before scale,
     hygiene, or intentionally deferred.

Required output:
- Start with a severity-ranked table: ID, severity, affected guarantee,
  files/lines, exploit or failure mode, and recommended fix.
- Then provide detailed findings with exact code references and reproduction
  steps or tests.
- Separate true vulnerabilities from documentation drift, false positives, and
  product limitations.
- Include a "new feature safety contract" section: what a proposed integration
  must declare, which negative tests it needs, and what trace evidence it must
  produce before merge.
- End with a release verdict:
  - safe to publish now,
  - publish only as alpha with caveats,
  - block release until fixes land,
  - or needs external pen-test before customer use.

Be brutal but fair. If something is strong, say why. If something is weak, prove
it with code, tests, or a reproduction.
```

Minimum local commands to ask the reviewer to run:

```powershell
python -m compileall -q pramagent tests deploy\dashboard
python -m pytest -q --tb=short
python -m bandit -r pramagent deploy\dashboard
docker run --rm -v "${PWD}:/src" -w /src semgrep/semgrep:latest `
  semgrep scan --metrics=off --config p/security-audit --config p/python `
  --error pramagent deploy/dashboard
python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999
```

For API-facing reviews, also run authenticated OWASP ZAP against the OpenAPI
schema and include both the raw report and remediation notes.
