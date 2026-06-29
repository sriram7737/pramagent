# Pramagent SDK — Full-Spectrum Engineering Audit

**Auditor:** Principal Engineer (independent review)
**Date:** 2026-06-09
**Repo:** `pramagent` (working tree `.../veritrace`), branch `main`, original audit version `0.5.20`
**Current package note:** v0.7.3 includes the v0.7.1 enterprise remediation,
the v0.7.2 CI/dependency cleanup, and the v0.7.3 security-prompt remediation.
Current local suite: **558 passed, 1 skipped**.

> **REMEDIATION STATUS — added 2026-06-29 (current package v0.8.5).**
> This is a historical, point-in-time audit of v0.5.20, retained as the
> permanent finding record. **All ten findings below were remediated in the
> v0.7.1 enterprise-audit remediation series**, and the fixes are verified
> present in the current v0.8.5 source. Read the findings below as *what was
> fixed*, not as open issues. For the living, per-fix status see
> [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md). Items
> genuinely still deferred (none of them release-blocking) are tracked there:
> keyset pagination, Redis quota Lua atomicity, chain-verification watermark,
> Prometheus-specific metrics, `jti` denylist, dependency lockfile/SBOM, CI SHA
> pinning, and organizational artifacts (breach runbook, DPA, VDP).
**Ground truth:** `docs/Pramagent-Design-Document.docx` (the "ten-layer trust stack" design)
**Method:** Full read of every Python module in `pramagent/`, `deploy/`, and `tests/`; the
design document read in full first; runtime verification of the highest-severity findings
with a live `fastapi.testclient`, a live `SQLiteStore`, and a live `RCAEngine`.

> **Scope note.** This is an engineering audit, not a marketing review. The design document's own
> "Current Implementation Status" section is admirably blunt about what is and isn't hardened, and
> several findings below echo caveats the author already documented. Where that is the case I say so.
> The findings that matter most are the ones where the *code's behavior contradicts a guarantee the
> system actively makes to a caller* — those are not caveated anywhere and are the ones a senior team
> will catch.

---

## Executive Summary — Top 10 Findings by Severity

| # | Sev | Finding | Domains | Evidence |
|---|-----|---------|---------|----------|
| 1 | **CRITICAL** | The FastAPI sidecar registers a second, **unauthenticated** copy of its data routes (`/traces`, `/traces/{id}`, `/metrics`, `/usage`, `/usage/ledger`, `/hitl/pending`, `/hitl/{id}/decide`). With API-key auth *enabled*, `/v1/trace/{id}` correctly returns 401 but `/traces/{id}` returns **200 with full, unredacted trace content**, and `POST /hitl/{id}/decide` lets **any unauthenticated caller approve a consequential action**. This defeats Layer 3 (Isolation) and Layer 5 (HITL) outright. | 4, 3, 5, 2 | Live test below |
| 2 | **HIGH** | `RCAEngine.replay()` returns `"reproducible": True` as a **hardcoded constant** — it never compares the re-derived verdict to the stored verdict. The design doc's central forensic guarantee ("replay re-derives the verdict independently… if the derived verdict disagrees with the stored one, the trace has been tampered with") is **not implemented**. | 2, 5, 8 | Live test below |
| 3 | **HIGH** | Raw, **unredacted** PII is stored in `TraceEvent.input_text`/`output_text` and copied verbatim into the tamper-evident `audit_chain` payload. PII scrubbing only protects the *model* copy (`clean`), never the persisted trace. | 2, 5 | `core.py:134`, live test |
| 4 | **HIGH** | GDPR right-to-erasure is **incomplete**: `delete_for_tenant()` removes trace rows but **leaves the full trace payload — including PII — in `audit_chain` permanently**. The "redact instead" alternative named in the docstring is never implemented. | 5, 2 | `store.py:197`, live test |
| 5 | **HIGH** | In unauthenticated mode the resolved tenant is `""` (falsy), which **disables the ownership guard** in `DELETE /v1/tenant/{id}/traces` and `POST /v1/retention/prune`. Any caller can erase or prune **any** tenant's data. | 4, 2 | `api/app.py:645`, `:626` |
| 6 | **MED-HIGH** | The admin dashboard falls back to the literal JWT secret `change-me-in-production` with **no production guard** (unlike `config.validate()` for the API). A known default secret means **forgeable super-admin (`tenant:"*"`) session cookies**. | 4, 8 | `deploy/dashboard/app.py:57` |
| 7 | **MEDIUM** | The flagship Layer-1 **failover (`FallbackProvider`) has zero tests**, and the entire 436-line `PostgresStore` (the recommended production backend + its hash chain) has **zero tests**. Two load-bearing components are unverified. | 6, 1, 7 | `tests/` grep |
| 8 | **MEDIUM** | `ToolGuardLayer`'s `ESCALATE` verdict and its `validate_output()` exfiltration scan are **not wired into the core pipeline or HITL**. A tool that should require human approval proceeds unless the caller separately maps it to a HITL action label; tool *output* is never scanned by `run()`. | 1, 2 | `core.py:206-230` |
| 9 | **MEDIUM** | Dependencies are pinned **lower-bound-only** with no upper caps and no lockfile. Floors permit versions with **published advisories** (`python-multipart`, `aiohttp`); `psycopg2-binary` is shipped for production; `sentence-transformers` (the "semantic" injection classifier) is **in no extra at all**, so the embedding defense is never installed. | 7, 8 | `pyproject.toml` |
| 10 | **MEDIUM** | Concurrency: `ToolGuardLayer` side-effect history / call counters and `ObservabilityLayer` latency list are mutated **without locks**, and without a Redis backend they are **per-worker**. Under multi-worker load, tool-chain detection and metrics/percentiles are unreliable; cross-worker dangerous chains are missed entirely. | 3 | `tool_guard.py:608`, `observability.py:37` |

**Bottom line.** The architecture is genuinely good and the breadth is real (449 passing tests, ten
well-separated modules, careful hand-rolled JWT/Slack-signature verification, a real Sepolia anchor).
But three of the system's *headline* guarantees — tenant isolation, human-in-the-loop, and
replayable tamper-evidence — are each undermined by a concrete, demonstrable defect. Finding #1 alone
is a release blocker for any deployment where the API port is reachable by an untrusted party.

---

## Verification Evidence (reproduced live during this audit)

**Finding #1 — unauthenticated routes (API-key auth *enabled*):**
```
authed /v1/run            -> 200  call_id dc42643e
/v1/trace/{id} no-auth    -> 401                         # correct
/traces/{id}   no-auth    -> 200  leaks input_text: 'my email is bob@x.com'
/traces list   no-auth    -> 200  count 1
/hitl/{id}/decide no-auth -> 200  {'decision': 'approved'}   # anyone can approve
/metrics       no-auth    -> 200
```

**Finding #2 — replay never checks reproducibility:**
```
stored pre_verdict : allow
derived_from_rules : block          # stored and derived DISAGREE
reproducible       : True           # …yet replay reports True unconditionally
```

**Findings #3/#4 — PII persists through erasure:**
```
before erase: traces = 1
after  erase: traces = 0
audit_chain still holds raw PII: True   # 'SSN 123-45-6789' present in chain payload
```

---

## AUDIT DOMAIN 1 — Architecture & Design Integrity

**Verdict: Strong design, faithfully implemented for Layers 1–8, with two real coupling gaps.**

### Ten-layer stack: implemented vs. designed

The design doc is explicit that the reference ships Layers 1–8 plus the sidecar; Layers 9–10 are
roadmap. The code matches that honestly:

| # | Layer | State in code | Notes |
|---|-------|---------------|-------|
| 1 | ProviderAdapter | **Built** | `providers/__init__.py`: Mock, Anthropic, OpenAI(-compat), Gemini, Ollama, Fallback. Failover untested (see Domain 6). |
| 2 | ComplianceLayer | **Built** | Context-guarded PII scrub. *But scrubs only the model copy — raw PII persists (Domain 2/5).* |
| 3 | IsolationLayer | **Built** | Tenant/session scoping, injection heuristics, size caps. Honestly labeled "not a hardened sandbox." |
| 4 | SafetyLayer (+ ToolGuard) | **Built** | Deterministic rule engine + optional classifier + ToolGuard. Precedence correct. |
| 5 | HITLLayer | **Built** | Propose-and-wait; idle-on-silence invariant correct. Persistent queue + Slack present. |
| 6 | ReliabilityLayer | **Built** | Semaphore + `wait_for` timeout + circuit breaker. Breaker counters unsynchronized (Domain 3). |
| 7 | TraceLayer / Audit | **Built** | SHA-256 hash chain; `verify_chain()` correct. |
| 8 | RCAEngine | **Partially built** | replay/causality/counterfactual present, **but `replay()` reproducibility check is fake** (Domain 2). |
| 9 | ObservabilityLayer | **Minimal** | Counts + p50/p95/p99 only. Doc's "anomaly detection, behavioral baselines" not present. Honestly scoped as "basic." |
| 10 | QuantumLayer | **Not built** | No module exists. Correctly positioned as research-only; no false claim in code. |

### Three-tier topology (FastAPI → LLM runtime → MySQL)

The audit brief names **MySQL**; the system uses **SQLite/Postgres** (and Redis, S3, Ethereum). This is
a brief/implementation mismatch, not a code defect — there is no MySQL anywhere, and the persistence
abstraction is clean. Separation between tiers is good: `core.py` is the only orchestration point, layers
depend only on `types.py`, and providers are normalized behind `BaseProvider`. **No circular imports**
were found; optional backends are import-guarded (`try/except ImportError`) so the core has one hard
dependency (`jsonschema`).

### Trust boundaries between agent roles

Tenant/session scope is threaded through every layer as `(tenant_id, session_id)` and the store
enforces it on `get()` via `PermissionError`. This is **enforced in code**, not assumed — *except* where
Finding #1 and #5 bypass it at the HTTP edge. So the boundary is sound in the library and broken in the
sidecar.

### Coupling / fragility gaps (real)

1. **ToolGuard ↔ HITL is not wired (Finding #8).** `core.run()` consults ToolGuard only to short-circuit
   on `BLOCK`; an `ESCALATE` verdict is recorded in the trace and then **ignored** (`core.py:230`,
   comment: *"ESCALATE: recorded in trace; caller decides on human approval"*). HITL gating keys off the
   string `action` label, not the tool decision. So the "dangerous tool chain → escalate → human
   confirms" story in `tool_guard.py` only works if the integrator manually maps the tool to a HITL
   action. The two layers the doc presents as a pipeline are actually decoupled.
2. **`validate_output()` has no pipeline caller.** The output exfiltration scan (AWS keys, private keys,
   JWTs) is a `ToolGuardLayer` method that `core.run()` never calls. Tool *output* validation is opt-in
   and easy to forget — exactly the "silent failure" class the design warns against.
3. **Dead abstraction — `errors.py`.** A full structured-error taxonomy (`PramagentError`, `Errors.*`,
   HTTP-status mapping) exists and is imported **only by its own test** (`test_new_modules.py`). The API
   raises bare `HTTPException`s instead. Either wire it in or delete it; today it's maintenance weight
   that implies a consistency that doesn't exist.

---

## AUDIT DOMAIN 2 — Code Correctness & Logic Flaws

### Trust-scoring / verdict propagation

- **Precedence is correct and centralized.** `BLOCK(3) > ESCALATE(2) > REDACT(1) > ALLOW(0)` in
  `SafetyLayer._combine`, `RCAEngine`, and the LLM-judge "tighten-only" merge. Rules sit outside the
  model and cannot be overridden by model output — the architectural guarantee holds.
- **The LLM judge can only tighten, never loosen** (`tool_guard.py:828`), and judge failures default to
  the deterministic verdict. Good fail-safe design.
- **Can trust be inflated/bypassed?** Not through scoring logic. The bypasses are at the *transport*
  edge (Findings #1, #5), not the verdict math.

### `RCAEngine.replay()` — the headline correctness bug (HIGH)

`rca.py:38-55` re-derives `derived` from the fired rules, returns it, and then sets
`"reproducible": True` **unconditionally**. It never compares `derived` to `stored_pre_verdict` /
`stored_post_verdict`. Proven live: a trace with `pre_verdict="allow"` but a fired `BLOCK` rule still
reports `reproducible: True`. Consequences:

- The audit's tamper-detection-by-replay claim is false. Hash-chain tamper-evidence still works
  (that's `verify_chain()`), but the *semantic* replay check that the doc sells as a distinct guarantee
  does nothing.
- `replay()` also derives a single verdict from `rules_evaluated`, which **mixes pre- and post-rules**
  (both are appended in `core.py:194,276`). Even a correct comparison would then be comparing a
  pre+post max against `pre_verdict` alone — a category error. The fix must both (a) actually compare and
  (b) separate pre/post derivation.

### Input/output handling

- **Inputs:** `RunRequest.prompt` has `min_length=1`; isolation enforces a 64 KiB byte cap and injection
  heuristics before the provider call. Reasonable.
- **Outputs:** post-safety `BLOCK` withholds output, `REDACT` re-scrubs, and `truncate_output` caps size.
  Good. **But** `block_reason=f"provider error: {e}"` (`core.py:264`) propagates the raw provider
  exception string into the HTTP response body — a minor internal-detail leak (Domain 4).
- **PII stored unredacted (HIGH, Finding #3).** `core.py:134` sets `tr.input_text = prompt` (the original),
  and only `clean` (the scrubbed copy) goes downstream. The persisted trace, the CSV export, and the
  audit chain therefore contain raw PII. The doc's plain-language promise ("personal data is stripped out
  before the AI ever sees it") is true for the *model* but the reader will reasonably assume it applies to
  the *record* too. It does not.

### Pipeline trace as a first-class field

- The trace **is** returned as `AgentResponse.trace` (never a side channel) — good, matches design.
- **Can it be overwritten/omitted/corrupted?** Within `run()` it is append-only and always finalized;
  `_finalize` correctly pops the hash fields before hashing to avoid self-reference. One soft spot:
  `mark("IsolationLayer.cap_output", …, time.perf_counter())` (`core.py:288`) passes *now* as the start
  time, so that event's `latency_ms` is meaningless (~0). Cosmetic, but it's a trace-integrity smell in
  the one field the system treats as sacred.

### Silent-failure paths

- `EthereumBackend.append` and the Hyperledger/Slack/usage webhooks **fail open by design** and log a
  warning. Defensible (a billing or anchor outage must not break the pipeline) and documented — but the
  fail-open anchor means `anchor_tx_id` can silently degrade to a local pseudo-anchor with only a log
  line. For a "regulation-ready" audit anchor, that degradation should also be a first-class trace field,
  not just a log.
- `UsageTracker._reserve` catches all exceptions and returns "allowed" when `fail_open=True` (default).
  A quota-store outage therefore silently disables quota enforcement. Documented, but worth a metric.

---

## AUDIT DOMAIN 3 — Concurrency & Runtime Safety

**Verdict: Correct for single-process asyncio; unsafe assumptions under multi-worker / multi-thread.**

### Semaphore / bounded queue

`ReliabilityLayer` uses `asyncio.Semaphore(max_concurrent)` + `asyncio.wait_for`. This is a correct
bounded-concurrency + hard-timeout implementation. The provider call is passed as a zero-arg factory so
the layer controls execution — good. The circuit breaker opens at `breaker_threshold` consecutive
failures and half-opens after cooldown.

**Race (LOW-MED):** `_consecutive_failures` and `_opened_at` are mutated inside `guard()` with no lock.
Within one event loop the `await` points make this benign; across OS threads (uvicorn `--workers` sharing
nothing, or a threaded host) the counter can under/over-count, so the breaker may trip late or reset
early. Not corrupting, but the breaker's threshold is not honored precisely under true parallelism.

### ToolGuard shared state (MEDIUM, Finding #10)

`_side_effect_history` and `_call_counts` are plain `defaultdict`s mutated in `evaluate()`:
- **No lock.** Single event loop is fine (sync section, no `await`); multiple threads race.
- **Per-worker without Redis.** Each uvicorn worker gets its own dict, so a dangerous chain whose steps
  land on different workers is **never detected**. The Redis path exists but its load→append→store is
  **not atomic** (no Lua/transaction), so concurrent same-session tool calls can lose history updates.
- **Session call limits** have the same split-brain: `max_calls_per_session` is enforced per worker, so
  the real limit is `N × workers`.

### Observability list (LOW-MED)

`record_result` does `self._latencies.pop(0)` + `insort` with no lock. Concurrent calls from multiple
tasks/threads can corrupt the sorted invariant and skew percentiles. Single-loop safe; threaded unsafe.

### FastAPI session bleed

No request-scoped mutable state is shared incorrectly: `require_tenant` derives tenant per request, and
trace objects are created fresh per call. `app.state.*` singletons (armor, registry, buckets) are
read-mostly and safe. **No state bleed between sessions was found** in the request path — the concurrency
risks are all in the *layer* singletons above, not in FastAPI wiring.

### High-parallel behavior

`test_load_smoke.py` (1 test) fires concurrent `run()`s and asserts trace-id uniqueness + chain
validity — a good smoke test, but it does **not** exercise saturation (semaphore back-pressure),
timeout-under-load, breaker half-open recovery, or starvation. The design's own status section concedes
"chaos recovery not proven"; the test suite confirms that gap.

---

## AUDIT DOMAIN 4 — FastAPI Sidecar Surface

### Authentication coverage (CRITICAL — Finding #1)

The `/v1/*` surface is correctly guarded by `Depends(require_tenant)` and derives the tenant from the
key, ignoring body-asserted tenants. **However**, a parallel set of *unversioned* routes was added for
the dashboard and shipped with **no auth dependency**:

| Route | Auth? | Impact |
|-------|-------|--------|
| `GET /traces` | **none** | Lists all traces (cross-tenant) |
| `GET /traces/{id}` | **none** | Returns any trace incl. **unredacted `input_text`/`output_text`** |
| `GET /metrics`, `/usage`, `/usage/ledger` | **none** | Operational + per-tenant usage disclosure |
| `GET /hitl/pending` | **none** | Lists pending approvals + context |
| `POST /hitl/{id}/decide` | **none** | **Approve/deny any consequential action** |

The comment at `api/app.py:660` ("no auth required for internal use") assumes these are reachable only
from the dashroad's private network. But `docker-compose.yml` publishes the API on `:8080` to the host,
so they are reachable by anyone who can reach the API. This **defeats Layer 5 (HITL)** — an attacker
approves their own `wire_transfer` — and **defeats Layer 3 (Isolation)** — cross-tenant trace and PII
disclosure. The dashboard adds the API key as an *upstream* header, but the endpoints don't require it,
so the credential is decorative.

**Also (MEDIUM):** `GET /health` is registered twice (`:435` and `:655`); FastAPI keeps the first and the
second is dead. Harmless but sloppy in a security-sensitive file.

### Input validation / typing

`/v1/run`, `/v1/tools/validate`, `/v1/auth/token` use Pydantic models with constraints (`min_length`,
`ge/le`). Good. The unversioned routes take raw query params / `body: dict` with no schema —
`POST /hitl/{id}/decide` reads `body.get("approved", False)` untyped. Combined with no auth, that route
is the worst of both.

### Error responses

The custom middleware logs `request_id`/path/error and re-raises; FastAPI returns a generic
`{"detail":"Internal Server Error"}` (no stack traces to clients). Security headers
(`X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, HSTS on HTTPS) are set globally.
**Minor leak:** provider-exception text flows into `block_reason` in the 200 body (`core.py:264`), and
`_raise_quota` echoes `decision.reason`. Low severity.

### SSRF

**Well-guarded.** Every outbound URL (OpenAI-compatible/Gemini base URLs, Ollama host, billing webhook,
Slack API) flows through `security.validate_http_url`, which blocks private/link-local/metadata IPs and
non-loopback HTTP. Crucially, these URLs come from **operator config/env, not the request body**, so
there is **no per-request SSRF surface** on `/v1/run`. `allow_http_localhost=True` is an operator opt-in,
not a user-reachable vector. This is one of the stronger parts of the codebase.

### Timeouts / retries

`ReliabilityLayer` enforces a per-call timeout; the dashboard's `httpx` client uses `timeout=10.0`;
providers set explicit timeouts; the OpenAI-compatible adapter retries with a bounded loop on specific
400s. CORS defaults to an empty allow-list with a warning if `*` is configured — safe by default.
Rate limiting (token bucket per tenant/IP, tighter bucket for RCA) is present. **Gap:** in unauthenticated
mode the rate key is the client IP, which collapses to the proxy IP behind a load balancer (all callers
share one bucket).

---

## AUDIT DOMAIN 5 — Compliance & Governance

**Verdict: The framework *mapping* is thorough and auditor-friendly; the *enforcement* has two real holes
and several "documented control" rows that are claims rather than mechanisms.**

### EU AI Act Article 9 / 12 / 14 / 15

- **Art. 14 (human oversight):** HITL "idle-on-silence" invariant is correctly implemented — *but*
  Finding #1's unauthenticated `/hitl/{id}/decide` lets an unauthenticated party satisfy the oversight
  step, which is worse than having no oversight (it produces an *audit record of approval* that didn't
  come from an authorized human).
- **Art. 12 (record-keeping, ≥6 months):** `RetentionPolicy.legal_floor_days >= 180` is enforced in the
  constructor and the `/v1/retention/prune` endpoint rejects windows < 180 days. Good.
- **Art. 15 (accuracy/robustness):** undermined by the fake `replay()` reproducibility (Finding #2) —
  the system cannot actually demonstrate decision reproducibility on demand.

### GDPR

- **Data minimization (Art. 5(1)(c)) — VIOLATED in storage (Finding #3).** Raw PII is persisted in
  `input_text`/`output_text` and in the audit chain. The `ComplianceLayer` scrubs the model copy only.
- **Right to erasure (Art. 17) — INCOMPLETE (Finding #4).** `delete_for_tenant()` deletes trace rows but
  leaves the full PII-bearing payload in `audit_chain` forever (proven live). The code comment proposes
  "redact `input_text`/`output_text` instead" but **no redaction routine exists**. A regulator asking
  "show me this subject is erased" would find their SSN still in the chain.
- **Consent / purpose limitation (Art. 5(1)(b), 7):** `ConsentRegistry` exists and is well-modeled, but
  **nothing in `core.run()` checks consent before processing** — it's a side library, not a gate. The
  compliance report can attest "consent on file," but the pipeline never enforces it.

### Are compliance hooks implemented or just described?

Mixed. **Implemented:** hash-chain audit, retention floor, PII scrub (model side), HITL, tenant scoping,
evidence-package PDF/JSON generator (`ComplianceReporter.generate`). **Described-only / claim-rows:** the
`CONTROL_MAP` asserts `in_place: True` for every control unconditionally (`compliance.py:282`,
`collect_evidence` sets `"in_place": True` for all rows) — the report does not actually *test* whether a
control is live, it asserts it. An auditor who probes one row (e.g., "show erasure") will find the gap in
#4. That erodes trust in the whole evidence package.

### Tamper-evident & complete audit trail

The hash chain is genuinely tamper-evident for **edits** (`verify_chain` recomputes every link; proven by
`test_pipeline::test_tamper_breaks_chain`). Two caveats: (a) deletion of trace rows is *by design* not
reflected in the chain (erasure keeps the chain intact), so "complete" and "erasable" are in tension and
the system currently resolves it by keeping PII; (b) the replay-based semantic check is non-functional.

---

## AUDIT DOMAIN 6 — Test Coverage & Quality

**Reality check:** the suite has **449 passed, 1 skipped** (run live this session) — far above the design
doc's stale "25" and "356" counts and the brief's "72+". Breadth is a genuine strength. The problem is
*where* the gaps are: they sit on the highest-value paths.

### Coverage map (layer → level → gaps)

| Layer / Area | Coverage | Key gaps |
|---|---|---|
| 1 ProviderAdapter | **Moderate** | Mock/OpenAI/Gemini/Ollama covered (`test_providers`, `test_api` matrix). **`FallbackProvider` failover: ZERO tests** — the headline Layer-1 guarantee is unverified. Cost-estimation table untested. |
| 2 ComplianceLayer | **Good (scrub)** | Scrub + contextual patterns well tested. **No test asserts the data-minimization risk** (raw PII in trace) — the gap is invisible because nothing checks for it. |
| 3 IsolationLayer | **Good** | 27 tests; injection heuristics, size caps, scope. Multi-worker Redis-backed memory isolation only lightly exercised. |
| 4 SafetyLayer + ToolGuard | **Good (rules)** | 70 classifier + 19 rules + 10 tool-guard tests. **`validate_output()` not tested via pipeline; ESCALATE→HITL wiring untested (because it doesn't exist).** |
| 5 HITLLayer | **Moderate** | Slack signing, idle-on-silence covered. **`HITLWorkflowLayer` (chain/quorum/SLA): no dedicated test.** Persistent `_gate_persistent` poll loop lightly covered. |
| 6 ReliabilityLayer | **Low-Moderate** | One breaker test. **No saturation/starvation/timeout-under-load/half-open-recovery tests.** |
| 7 TraceLayer / Audit | **Good (SQLite/Memory)** | Tamper + persistence + anchoring covered. **`PostgresStore` (436 LOC, the recommended prod backend): ZERO tests.** |
| 8 RCAEngine | **Misleading** | `test_pipeline::test_rca_replay_reproducible` passes — but it asserts the **hardcoded** `reproducible: True`, so it green-lights the bug (Finding #2). counterfactual/graph tested. |
| 9 ObservabilityLayer | **Low** | One metrics-increment test. Percentile math and concurrent recording untested. |
| 10 QuantumLayer | **N/A** | Unbuilt by design. |
| Auth (key + JWT) | **Good** | 17 tests; rotation, expiry, tenant binding. |
| Usage / quota / ratelimit | **Good** | 12 + 4 tests, fail-open paths covered. |
| Dashboard security | **Good** | 25 tests (CSRF, session revocation). **But SQLite store only — `PostgresDashboardUserStore`: ZERO tests.** |
| Encryption / S3 / retention / migrations | **Moderate** | Present and passing; S3 covered, retention covered. |

### Edge cases

Covered: empty/blocked inputs, malformed Slack payloads, quota-then-ratelimit interaction, tenant
mismatch on `store.get`. **Missing:** concurrent same-session tool-chain detection, agent-role mismatch on
the unauthenticated routes, malformed `/hitl/{id}/decide` bodies, fallback-provider exhaustion.

### Integration vs. unit

`test_pipeline.py` (7) and `test_api.py` (26) are real input→trace integration tests — good. But the
**unauthenticated-route exposure (Finding #1) has no negative test** asserting that `/traces/{id}`
*requires* auth, which is precisely why it shipped.

### Zero-coverage critical paths (verified by direct grep)

- `FallbackProvider` — **0** test files (Layer-1 failover).
- `PostgresStore` — **0** test files (production persistence + Postgres hash chain).
- `PostgresDashboardUserStore` — **0** (only SQLite variant tested).
- `HITLWorkflowLayer` / `ApproverChain` / `QuorumApprover` — no dedicated test file.

---

## AUDIT DOMAIN 7 — Dependency & Supply-Chain Health

**Verdict: Lean core (one hard dep), but pinning policy permits known-vulnerable versions and the
"semantic" classifier dependency is missing entirely.**

### Pinning policy

Every dependency is **lower-bound-only (`>=`) with no upper cap and no lockfile / hashes**. This invites
silent major-version breakage (`web3>=7.0`, `fastapi>=0.110`, `bcrypt>=4.1` could resolve to a future
breaking major) and means the *minimum* resolvable version — often the one CI doesn't test — can carry
published advisories.

### Dependency health table

| Package | Pin | Concern |
|---|---|---|
| `jsonschema` | `>=4.23` | Only hard dep. Current, maintained. **OK.** |
| `fastapi` | `>=0.110` | Floor ~early-2024; fine current, but unbounded major. |
| `python-multipart` | `>=0.0.9` | **Floor permits the pre-`0.0.18` DoS advisory (CVE-2024-53981).** Used by dashboard form parsing. Raise floor to `>=0.0.18`. |
| `aiohttp` | `>=3.9` | **Floor permits pre-`3.9.4`/`3.10.11` advisories** (request smuggling / parser issues). Raise floor. |
| `psycopg2-binary` | `>=2.9` | `-binary` is explicitly **not recommended for production** by the maintainers (use `psycopg2` from source or `psycopg[binary]` v3). Shipped as the prod Postgres driver. |
| `web3` | `>=7.0` | Heavy, fast-moving; unbounded major is risky for an "optional anchor." |
| `cryptography` | `>=42` | Good floor; keep current for OpenSSL CVEs. |
| `redis`, `boto3`, `uvicorn`, `httpx`, `bcrypt`, `jinja2`, `opentelemetry-*` | `>=` | Current, maintained; no specific concern beyond unbounded majors. |
| `anthropic` | `>=0.39` | Fine; lazy-imported. |
| **`sentence-transformers`** | **absent** | `classifier.py` documents `pip install sentence-transformers` for the `EmbeddingInjectionClassifier`, **but it is in no extra (not even `all`)**. The "semantic, embedding-based" injection defense is therefore **never installed** by the package; the runtime always uses the keyword fallback. This is both a packaging gap and a docs-vs-code gap. |

No package is abandoned; the concern is **version floors and reproducibility**, not unmaintained code.
There is no `pip-audit`/`safety` step in `.github/workflows/tests.yml` (though a separate
`security.yml` + ZAP scans exist per `test-results/`).

---

## AUDIT DOMAIN 8 — Documentation & Maintainability

**Verdict: Documentation is unusually good for a solo project and an engineer could onboard from it —
but it over-claims in three specific places the code contradicts.**

### Does the code match the 19-page design doc?

Mostly yes, and the doc's own "Current Implementation Status" pre-empts most over-claims honestly.
The contradictions that remain:

1. **RCA replay** — doc: "replay re-derives the verdict independently and confirms reproducibility… if
   the derived verdict disagrees with the stored one, the trace has been tampered with." Code: hardcoded
   `True`. (Finding #2)
2. **PII** — doc/Part-1: "personal data… is stripped out before the AI ever sees it." True for the model;
   the *record* keeps raw PII. A reader will conflate the two. (Finding #3)
3. **Embedding classifier** — `classifier.py` presents the embedding model as the primary defense; it
   ships in no extra and never loads by default. (Domain 7)
4. **Test counts** — doc says "25 passing tests" (Part 3) and "356 passing" (status header); actual is
   **449**. Harmless drift, but a reviewer who diffs the number loses trust in the rest.

### Undocumented / dead modules

- `errors.py` — full taxonomy, used only by its own test (dead in production paths).
- `ConsentRegistry` / `RetentionPolicy` enforcement — documented as governance, not invoked by the
  pipeline.
- A stale **`veritrace/` package directory and `veritrace.egg-info`** sit in the working tree (untracked
  by git — confirmed `git ls-files veritrace/` → 0). Legacy from the prior project name; it's confusing
  next to `pramagent/` and should be deleted to avoid import ambiguity for new contributors.

### Repo hygiene (positive)

`.gitignore` correctly excludes `.env*` (except `.env.example`), all `*.db`, keys, and `test-results/`.
Confirmed **no secrets or databases are git-tracked** — only `.env.example` (placeholders). Local working
files (`.env`, `.env.live`, several `*.db`) exist on disk but are untracked. This is good discipline.
The untracked marketing artifacts in the root (`*.png`, `*.docx`, `pramagent_review.md`) are clutter but
not a risk.

### Onboarding

`README.md`, `docs/IMPLEMENTATION_STATUS.md`, `docs/DEPLOYMENT.md`, `HARDENING_GUIDE.md`, and inline
module docstrings are thorough; `core.py` really is the single legible orchestration point the doc
promises. A new engineer could stand the system up. They would, however, hit the dead `errors.py` and the
missing embedding dep without guidance.

---

## Design Doc vs. Code — Gap Table

| Design-doc claim | Code reality | Gap severity |
|---|---|---|
| "Replay re-derives the verdict… disagreement ⇒ tampering detected" | `replay()` returns `reproducible: True` hardcoded; no comparison | **HIGH** |
| "Personal data is stripped before the AI ever sees it" | Model copy scrubbed; `input_text`/`output_text` persist **raw PII** in trace + chain | **HIGH** |
| Right-to-erasure: `store.delete_for_tenant(tenant_id)` | Deletes trace rows; **PII remains in `audit_chain`**; redaction not implemented | **HIGH** |
| "Every `/v1` endpoint requires `Authorization`" | True for `/v1/*`; **duplicate unversioned routes need no auth** | **CRITICAL** |
| Layer 5: "No consequential action without human approval" | True via `HITLLayer`; **but `/hitl/{id}/decide` is unauthenticated** | **CRITICAL** |
| ToolGuard "escalates rather than blindly blocks — humans confirm" | ESCALATE recorded but **not routed to HITL** by the pipeline | **MEDIUM** |
| Embedding injection classifier as primary defense | `sentence-transformers` in no extra; keyword fallback always used | **MEDIUM** |
| Provider "automatic failover… recorded in the trace" | `FallbackProvider` exists; `used_fallback` via fragile substring match; **zero tests** | **MEDIUM** |
| "QuantumLayer" (Layer 10) | Not built — **correctly** scoped as research; no false code claim | None (honest) |
| "25 / 356 passing tests" | **449 passed, 1 skipped** | Low (stale) |
| Three-tier "FastAPI → LLM → MySQL" (brief) | SQLite/Postgres/Redis; **no MySQL** | Low (brief mismatch) |

---

## Test Coverage Map (consolidated)

| Trust Layer | Coverage Level | Primary test files | Critical gap |
|---|---|---|---|
| 1 ProviderAdapter | Moderate | `test_providers`, `test_api` | **FallbackProvider failover untested** |
| 2 ComplianceLayer | Good (scrub only) | `test_compliance`, `test_persistence` | No test for raw-PII-in-trace risk |
| 3 IsolationLayer | Good | `test_isolation` (27) | Multi-worker memory isolation light |
| 4 SafetyLayer/ToolGuard | Good (rules) | `test_classifier`, `test_rules_and_extensions`, `test_tool_guard` | Output-validation + ESCALATE→HITL path |
| 5 HITLLayer | Moderate | `test_slack_hitl`, `test_adversarial` | Workflow chain/quorum untested |
| 6 ReliabilityLayer | Low-Moderate | `test_adversarial` | Saturation/timeout/recovery untested |
| 7 Trace/Audit | Good (SQLite) | `test_persistence`, `test_pipeline`, `test_anchoring` | **PostgresStore untested** |
| 8 RCAEngine | Misleading-pass | `test_pipeline`, `test_rca_graph` | Test asserts the broken `reproducible` |
| 9 ObservabilityLayer | Low | `test_api` | Percentiles + concurrency untested |
| 10 QuantumLayer | N/A | — | Unbuilt by design |

---

## Dependency Health Table (action view)

| Package | Current pin | Recommended | Why |
|---|---|---|---|
| `python-multipart` | `>=0.0.9` | `>=0.0.18` | Excludes published DoS advisory |
| `aiohttp` | `>=3.9` | `>=3.10.11` | Excludes parser/smuggling advisories |
| `psycopg2-binary` | `>=2.9` | `psycopg[binary]>=3.1` (or source `psycopg2`) | `-binary` unsupported for prod |
| `sentence-transformers` | *(missing)* | add to a `classifier`/`ml` extra | Embedding defense never installed today |
| `fastapi`,`web3`,`bcrypt`,`redis`,`boto3` | `>=` only | add upper caps + lockfile | Prevent silent breaking majors |
| `jsonschema`,`cryptography`,`httpx`,`uvicorn` | `>=` | keep, but lock | Healthy; reproducibility only |
| CI | no `pip-audit` | add `pip-audit`/`safety` job | Catch advisory regressions automatically |

---

## Recommended Fix Priority Order

### CRITICAL — before any externally reachable deployment
1. **Remove or authenticate the unversioned routes (Finding #1).** Either delete `/traces`, `/traces/{id}`,
   `/metrics`, `/usage`, `/usage/ledger`, `/hitl/pending`, `/hitl/{id}/decide` and have the dashboard call
   the `/v1/*` equivalents with its key, or put `Depends(require_tenant)` (and tenant-scoping) on every
   one. Add a negative test asserting each requires auth and enforces tenant ownership.
2. **Fix the unauthenticated-mode ownership bypass (Finding #5).** Treat empty tenant as "no implicit
   ownership": require an explicit tenant for erase/prune, or refuse those mutating endpoints when auth is
   disabled.

### HIGH — before any compliance/audit claim is made
3. **Make `replay()` actually verify reproducibility (Finding #2).** Derive pre and post verdicts
   separately, compare to stored, and return `reproducible = (derived == stored)`. Update the test to
   assert a *mismatch* yields `False`.
4. **Stop persisting raw PII / implement real erasure (Findings #3, #4).** Store scrubbed text (or an
   encrypted, separately-erasable field) in `input_text`/`output_text`; implement the chain-payload
   redaction the docstring promises so Art. 17 erasure removes PII while preserving chain links (e.g.,
   replace payload PII with a hash and re-anchor, or keep PII only in the encrypted store).
5. **Guard the dashboard's default JWT secret (Finding #6).** Refuse to start (or refuse cookie auth) when
   `PRAMAGENT_JWT_SECRET == "change-me-in-production"`, mirroring `config.validate()` for the API.

### MEDIUM — before "production-ready" positioning
6. **Wire ToolGuard `ESCALATE` → HITL and call `validate_output()` in the pipeline (Finding #8).**
7. **Add tests for `FallbackProvider` failover and `PostgresStore` (Finding #7);** make `used_fallback`
   a structured result field, not a substring check.
8. **Make ToolGuard chain state and counters concurrency-safe (Finding #10):** lock the in-memory path,
   make the Redis load→modify→store atomic (Lua/`WATCH`), and document that chain detection requires a
   shared backend for multi-worker correctness.
9. **Fix dependency floors + add a lockfile and `pip-audit` CI job (Domain 7);** add
   `sentence-transformers` to an extra or stop advertising the embedding classifier as primary.

### LOW — hygiene / polish
10. Delete the stale `veritrace/` package + egg-info; remove the duplicate `/health` route; either wire in
    `errors.py` or delete it; stop the API leaking provider-exception text via `block_reason`; correct the
    `cap_output` latency marker; reconcile the doc's test counts (25/356 → 449) and the MySQL reference.

---

## Remediation Status

**Initial remediation:** 2026-06-10, v0.7.0 remediation draft, branch `main`.
This block records the first pass over the June 9 audit; the final v0.7.1 enterprise-remediation status appears below.
**Verification:** full suite green after every sprint - intermediate state **505 passed, 1 skipped**
(449 baseline + 66 new tests, − 10 removed with the deleted `errors.py`).

| # | Finding | Status | Fixed in | Commit |
|---|---------|--------|----------|--------|
| 1 | Unauthenticated unversioned routes (`/traces`, `/traces/{id}`, `/metrics`, `/usage`, `/usage/ledger`, `/hitl/pending`, `/hitl/{id}/decide`) | **RESOLVED** | `pramagent/api/app.py` — every unversioned route now carries `Depends(require_tenant)` and is hard-scoped to the caller's tenant; `/traces/{id}` enforces ownership (cross-tenant → 404); `/hitl/{id}/decide` is typed (Pydantic) and ownership-checked; negative tests assert 401 on all seven routes | `f50cfc4` |
| 2 | `RCAEngine.replay()` hardcoded `reproducible: True` | **RESOLVED** | `pramagent/rca.py` — pre and post verdicts derived separately (`RuleResult.phase` tag added in `pramagent/types.py`; classifier verdicts recorded as rule results in `pramagent/layers/__init__.py`), compared to stored verdicts; `reproducible = (derived == stored)`; counterfactuals scoped to pre-phase; `test_rca_replay_reproducible` asserts a tampered verdict returns `False` | `85dacf5` |
| 3 | Raw PII persisted in `input_text`/`output_text` and the audit chain | **RESOLVED** | `pramagent/core.py` — `tr.input_text` is the scrubbed copy; `_finalize` scrubs `output_text` before the trace and chain payload are written; `input_hash` still covers the original bytes; test asserts no PII in trace or chain | `85dacf5` |
| 4 | GDPR erasure left PII in `audit_chain` forever | **RESOLVED** | `pramagent/store.py` + `pramagent/audit/__init__.py` — `delete_for_tenant()` tombstones the tenant's chain payloads (SHA-256 markers, idempotent) and re-anchors the chain (links re-hashed, head updated, `verify_chain()` still passes); `redact_for_tenant()` added to `HashChainBackend`/`EthereumBackend`/`HyperledgerBackend`/`SQLiteStore`/`PostgresStore`; the erase endpoint coordinates store deletion with chain redaction | `85dacf5` |
| 5 | Empty tenant ("" in unauthenticated mode) disabled the ownership guard on erase/prune | **RESOLVED** | `pramagent/api/app.py` — `DELETE /v1/tenant/{id}/traces` and `POST /v1/retention/prune` refuse (403) when no authenticated tenant exists; prune is always tenant-scoped (unscoped fallback removed); tests assert unauthenticated and cross-tenant attempts are refused | `f50cfc4` |
| 6 | Dashboard default JWT secret `change-me-in-production` with no guard | **RESOLVED** | `deploy/dashboard/app.py` — startup validation (`validate_dashboard_config()`) raises `RuntimeError` when the secret is unset or the default, mirroring `config.validate()`; tests assert startup refuses the default/empty secret and accepts a strong one | `f50cfc4` |
| 7 | Zero tests for `FallbackProvider`, `PostgresStore`, HITL workflow primitives | **RESOLVED** | `tests/test_fallback_provider.py` (failover, exhaustion, structured flag), `tests/test_postgres_store.py` (hash chain, tenant isolation, erasure + chain redaction, restart head recovery, tamper detection — fake driver returning JSONB as dict, swappable for a live DSN/testcontainers), `tests/test_hitl_workflow.py` (`ApproverChain`, `QuorumApprover`, `HITLWorkflowLayer`); `used_fallback` is a structured `ProviderResult` field, not a substring match (also fixed a latent `json.loads`-on-dict bug in `PostgresStore.get/verify` that the new tests exposed) | `2065e2a` |
| 8 | ToolGuard `ESCALATE` not routed to HITL; `validate_output()` never called by the pipeline | **RESOLVED** | `pramagent/core.py` + `pramagent/layers/__init__.py` — ESCALATE now invokes `HITLLayer.propose()` (new method; approval required regardless of action label); DENIED/IDLE short-circuits before any side effect with the approval decision recorded in the trace; `validate_output()` runs on every provider output (exfil scan; schema/size for registered tools) and withholds failing output; integration tests cover idle/denied/approved and exfil withholding | `2065e2a` |
| 9 | Dependency floors permit published advisories; `psycopg2-binary` in prod; `sentence-transformers` in no extra; no CI audit | **RESOLVED** | `pyproject.toml` — `python-multipart>=0.0.18`, `aiohttp>=3.10.11`, `psycopg[binary]>=3.1` (new `pramagent/_pg.py` shim prefers psycopg 3, falls back to psycopg2), caps `fastapi<1.0` and `web3<8`, new `ml` extra for `sentence-transformers`; `.github/workflows/tests.yml` gains a `pip-audit` job | `2065e2a` |
| 10 | ToolGuard / Observability shared state mutated without locks; Redis history not atomic | **RESOLVED** | `pramagent/layers/tool_guard.py` — in-memory history and call counters mutated under `threading.Lock`; `pramagent/backends/redis_backend.py` — atomic Lua `RPUSH+LTRIM+EXPIRE` (`history_append`) replaces load→append→store; `pramagent/layers/observability.py` — counters and the sorted latency list are lock-guarded; README documents the shared-Redis requirement for multi-worker chain detection; thread-safety tests added | `2065e2a` |

**Low-severity / hygiene items (audit "LOW" list):**

| Item | Status | Notes | Commit |
|---|---|---|---|
| Stale `veritrace/` package + `veritrace.egg-info` | **RESOLVED** | egg-info deleted; package contents deleted (the empty directory handle is held by OneDrive and clears on sync — no modules remain, so no import ambiguity) | `f17ee1a` |
| Duplicate `GET /health` route | **RESOLVED** | dead second registration removed | `f50cfc4` |
| `errors.py` dead abstraction | **RESOLVED (deleted)** | imported only by its own test; wiring it in would have changed the public error-response contract for every endpoint with no consumer — deletion chosen per the audit's "wire it in or delete it" | `f17ee1a` |
| `block_reason` leaks provider exception text | **RESOLVED** | response carries generic `provider error`; detail stays in logs and the tenant-scoped trace | `f17ee1a` |
| `ConsentRegistry` not enforced by the pipeline | **RESOLVED** | `core.run()` consent gate: with a configured registry, processing is refused and traced unless active consent covers the tenant/subject/purpose; revocation honored immediately | `f17ee1a` |
| Design-doc drift (test counts, MySQL, embedding classifier) | **RESOLVED** | counts corrected to 505 passing / 1 skipped; persistence stated as SQLite/Postgres (no MySQL); embedding classifier documented as the optional `pramagent[ml]` extra with keyword fallback | `f17ee1a` |

**Known residuals (documented, not regressions):** the `cap_output` latency-marker cosmetic
issue remains; `CONTROL_MAP` evidence rows still assert `in_place: True` unconditionally;
reliability saturation/chaos tests and the `PostgresDashboardUserStore` test gap remain open
items from Domain 6 beyond the four findings scoped above.

---

## Closing Assessment

Pramagent is a **well-architected, broadly-tested middleware** with a clear thesis ("the LLM is never the
last line of defense") that the code mostly honors: deterministic rules sit outside the model, the hash
chain is real and verifiable, the JWT and Slack-signature verification are hand-rolled but careful, and
SSRF is genuinely well-contained. For a solo portfolio project, the breadth and the candor of the status
section are impressive.

What will draw senior scrutiny is that **three of the marquee guarantees leak at the seams**: tenant
isolation and human oversight are bypassable through a forgotten set of unauthenticated routes, and the
"replayable, tamper-evident audit" cannot actually prove reproducibility because that check was stubbed to
`True`. None of these are architectural dead-ends — they are concrete, individually fixable defects, and
the fixes are scoped in the priority list above. Close findings #1–#5 and the project moves from "great
demo with sharp edges" to "defensibly pilot-ready," which is exactly where the design document aspires to
position it.

---

## v0.7.1 Remediation Status

**Date:** 2026-06-10 · **Baseline:** the 2026-06-10 enterprise pre-production code
review (2 P0 / 10 P1 / 18 P2 / 20 P3) and the 2026-06-10 formal security assessment
(T1/T2/T3 tracks). Remediation landed as five sequential commits (Phases 1–4 + final),
each gated on the full test suite. **Suite: 547 passed / 1 skipped** (505 at baseline;
42 tests added). The threaded chain-writer test was verified to FAIL against the
pre-fix code and PASS after it.

Where a code-review finding and a security finding describe the same defect they were
fixed in one change and are listed together.

### P0 / Critical — Phase 1 (commit `4356521`)

| Finding | Status | Fix | Where |
|---|---|---|---|
| P0-1 + T1-12 (reference deploy persists nothing) | **RESOLVED** | `build_default_armor()` store priority chain `PRAMAGENT_POSTGRES_DSN` > `PRAMAGENT_DB` > explicit `PRAMAGENT_ALLOW_MEMORY_STORE=1`; RuntimeError otherwise; compose/Helm DSN contract documented; tests opt in via `tests/conftest.py` | `pramagent/api/app.py`, `pramagent/config.py`, `docker-compose.yml`, `deploy/helm/pramagent/values.yaml` |
| P0-2 + T1-1 (published placeholder secrets pass startup) | **RESOLVED** | shared `assert_strong_secret()` + `WEAK_SECRET_DENYLIST` (all 8 spellings incl. underscored + CI variants) enforced at startup by API `create_app()` AND the dashboard; `.env.example` regenerated with empty required secrets + generation instructions; negative tests parametrized over the full denylist in both services | `pramagent/security.py`, `pramagent/api/app.py`, `deploy/dashboard/app.py`, `.env.example` |
| T2-3 + P1-6 (Postgres chain not chained; protocol mismatch) | **RESOLVED** | `PostgresStore.append()` hashes `canonical_hash(payload, prev)` with prev derived inside the transaction under `SELECT … FOR UPDATE`; `verify_chain()` checks hash AND prev-linkage in id order (deletion/reorder now detected — tests prove it); `get(call_id, tenant_id)` returns `TraceEvent` raising `KeyError`/`PermissionError`; rows keyed by `call_id`; `list_all`/`list_by_tenant`/tenant-scoped `prune_older_than`/`ping` added; `MIGRATIONS_PG` incl. call_id re-keying for pre-0.7.1 rows | `pramagent/store_postgres.py`, `pramagent/backends/migrations.py`, `tests/test_postgres_store.py` |

### P1 / High — Phase 2 (commit `311ce7d`)

| Finding | Status | Fix | Where |
|---|---|---|---|
| P1-5 + T2-4 (chain head race forks the chain) | **RESOLVED** | append derives prev inside a serialized critical section everywhere: SQLite/Encrypted stores use `threading.RLock` + `BEGIN IMMEDIATE` + DB re-read (passed prev ignored); `HashChainBackend` locked; Postgres uses FOR UPDATE (Phase 1); `core._finalize` no longer passes a pre-read head (`last_prev_hash` recorded post-append); `test_chain_survives_threaded_writers` (8 threads × 64 runs) fails pre-fix, passes post-fix | `pramagent/store.py`, `pramagent/store_encrypted.py`, `pramagent/audit/__init__.py`, `pramagent/core.py`, `tests/test_load_smoke.py` |
| P1-1 + P1-8 + T1-7 (blocking I/O on the event loop; 300 s receipt wait) | **RESOLVED** | `_finalize` is async; `audit.append`/`store.save` via `asyncio.to_thread` (8 call sites awaited); SafetyLayer pre/post (embedding inference) off-loop; usage `reserve_call`/`reserve_tool_validation`/`record_cost` (and therefore the sync urllib billing webhook) off-loop; `EthereumAnchor.anchor()` submits and returns immediately with `status=-1` (unconfirmed) unless `wait_for_receipt=True`; nonce read→sign→send serialized under a lock | `pramagent/core.py`, `pramagent/api/app.py`, `pramagent/anchoring/ethereum.py`, `pramagent/usage.py` |
| P1-2 + T3-1 (encrypted store erasure leaves PII in chain) | **RESOLVED** | `redact_for_tenant()` with canonical re-anchoring (tombstone + rehash every later link); `delete_for_tenant()` invokes it; protocol parity: `list_all(limit)`, `prune_older_than(tenant_id)`, `ping()`; parity test mirroring the SQLite erasure test incl. restart survival | `pramagent/store_encrypted.py`, `tests/test_encryption.py` |
| P1-7 + T3-2 (S3 erasure archives instead of destroying) | **RESOLVED** | `delete_for_tenant()` never archives; deletes all previously archived objects under `tenant={id}/` (paginated `list_objects_v2` + `delete_objects`) and drops their metadata; `prune_older_than` keeps the archive path (retention); tests assert no-archive-on-erase and archive-on-prune | `pramagent/store_s3.py`, `tests/test_store_s3.py` |
| P1-3 + T1-5 + P2-18 + T1-9 (O(n) unauthenticated readiness + info disclosure) | **RESOLVED** | `/health/ready` is O(1): store `ping()` + redis `ping()` only, returns `{status, checks}` with 503 on degraded; chain verification stays in authenticated rate-limited `/v1/audit/verify`; `auth_enabled`/`slack_last_error`/counts/`tool_guard_distributed` removed from the unauthenticated surface | `pramagent/api/app.py`, `pramagent/store.py` |
| P1-4 + T1-6 (RCA loads the whole store per request) | **RESOLVED** | all three handlers build `RCAEngine([_fetch_trace(call_id, tenant)])` | `pramagent/api/app.py` |
| P1-9 (/traces filters after the limit) | **RESOLVED** | tenant filter pushed into SQL via `list_by_tenant` (indexed); `limit` capped `Query(50, ge=1, le=500)`; dead `MemoryStore._traces` branch deleted | `pramagent/api/app.py` |
| P1-10 + T2-9 (datastores published to host; root dashboard image) | **RESOLVED** | compose Postgres/Redis `expose:`-only; Redis healthcheck `--no-auth-warning -a "$$REDIS_PASSWORD"` via container env (no `docker inspect` leak); mem/cpu limits on all four services (also closes P3-14); dashboard image `USER 1001`, all deps pinned with upper caps, `psycopg[binary]>=3.1,<4` replaces psycopg2-binary | `docker-compose.yml`, `deploy/dashboard/Dockerfile` |
| T1-2 (token endpoint unthrottled) + P2-12/T2-6 (per-process random JWT fallback) | **RESOLVED** | `/v1/auth/token` carries an IP-keyed bucket (429 + Retry-After, test included); refuses issuance with 503 when auth is on and no shared `PRAMAGENT_JWT_SECRET(S)` is configured (test included) | `pramagent/api/app.py`, `tests/test_auth.py` |
| T2-1 + P2-8 (dashboard XSS + CSV formula injection) | **RESOLVED** | `html.escape()` on the approve/deny error badges; `csv_value()` prefixes `=`/`+`/`-`/`@`/tab strings with `'` | `deploy/dashboard/app.py` |
| T2-7 + P2-6 (Gemini key in URL) + P3-7 (Ollama host unvalidated) | **RESOLVED** | key moved to `x-goog-api-key` header (test asserts no `key=` in URL); Ollama host through `validate_http_url(allow_http_localhost=True, allow_private=True)` + 60 s `ClientTimeout` | `pramagent/providers/__init__.py` |
| P2-7 + T2-9 (Redis URL password logged) | **RESOLVED** | credentials redacted (`url.split("@")[-1]`) in both the INFO log and the unreachable-error message | `pramagent/backends/redis_backend.py` |

### P2 / Medium — Phase 3 (commit `e315bf0`)

| Finding | Status | Fix | Where |
|---|---|---|---|
| P2-2 + T1-8 (unbounded in-process growth) | **RESOLVED** | ToolGuard `_provenance_log`/`audit_log` and LLM-judge `audit_log` → `deque(maxlen=10_000)`; `_call_counts` stores `(count, window_started)` resetting on `chain_ttl_s`; usage ledger growth documented + one-time warning at 100k entries (silent truncation would break chain verification from genesis — see docstring) | `pramagent/layers/tool_guard.py`, `pramagent/layers/llm_judge.py`, `pramagent/usage.py` |
| P2-3 (validator rebuilt per call) | **RESOLVED** | `compile_schema_validator()`; argument AND output validators compiled once per policy in `register()`; `validate_schema(validator=…)` skips per-call check_schema+constructor | `pramagent/layers/tool_guard.py` |
| P2-4 + T1-8 (unbounded request body) | **RESOLVED** | `prompt` `max_length=262_144` (422 before the pipeline, test included); reverse-proxy `client_max_body_size` documented | `pramagent/api/app.py`, `docs/DEPLOYMENT.md` |
| P3-4 + T1-3 (JWT aud/alg) | **RESOLVED** | `aud="pramagent-api"` issued and strictly verified (forged no-aud token test); explicit HS256 allow-list comment naming the none-algorithm/key-confusion defense. *Residual:* per-token `jti` revocation list deferred (short TTLs ≤ 1 h; dashboard sessions already revocable) | `pramagent/auth.py`, `tests/test_auth.py` |
| P2-10 (untyped responses) | **RESOLVED** | `TraceModel` on `GET /v1/trace/{id}`, `EraseResponse` on `DELETE /v1/tenant/{id}/traces`, `PruneResponse` on `POST /v1/retention/prune` | `pramagent/api/app.py` |
| P3-9 (CLI .env umask) | **RESOLVED** | written via `os.open(..., 0o600)` | `pramagent/cli.py` |
| P2-15 + P3-3 (no graceful shutdown; deprecated on_event) | **RESOLVED** | lifespan context managers in API + dashboard; shutdown closes store/audit with error handling; `--timeout-graceful-shutdown 30` in the image CMD | `pramagent/api/app.py`, `deploy/dashboard/app.py`, `Dockerfile` |
| P2-14 (compliance attests instead of measuring) | **RESOLVED** | live probes: audit row = actual `verify_chain()` result, consent rows = active-consent registry check, retention = real policy comparison; `CONTROL_MAP` evidence rows probed via `_control_in_place()`; `store.count(tenant_id)` (SQL COUNT) on SQLite/Postgres/Encrypted/Memory replaces `len(list_all())` | `pramagent/compliance.py`, `pramagent/store*.py` |
| P3-13 + T2-9 (Helm drift, no securityContext/PDB) | **RESOLVED** | image tag 0.7.1; `runAsNonRoot` + `readOnlyRootFilesystem` + `allowPrivilegeEscalation: false` + drop ALL caps + seccomp RuntimeDefault; PodDisruptionBudget (minAvailable 2); /tmp emptyDir for the read-only root | `deploy/helm/pramagent/` |
| P2-13 (judge exception leak; 3.10 timeout class) | **RESOLVED** | `except (TimeoutError, asyncio.TimeoutError)`; generic reason to callers, `repr(exc)[:500]` kept in audit-log `raw_response` only | `pramagent/layers/llm_judge.py` |

### P3 hygiene — Phase 4 (commit `f030e63`)

| Finding | Status | Note |
|---|---|---|
| P3-1 | **RESOLVED** | `require_tenant(request: Request)` — required, non-Optional. (The review's literal `Optional[Request] = None` suggestion is rejected by FastAPI's Request special-casing; FastAPI always injects the request for dependencies, so the truthful signature drops the default.) |
| P3-2 | **RESOLVED** | `uvicorn pramagent.api.app:create_app --factory`; module-level `app` kept behind `PRAMAGENT_EAGER_APP` (default on); `pramagent.api.__init__` tolerates factory-only mode |
| P3-3 | **RESOLVED** | in Phase 3.7 (lifespan, both services) |
| P3-5 | **RESOLVED** | cap_output marker passes the pre-truncate `t0` |
| P3-6 | **RESOLVED** | duplicate env-var names removed across the 6 `_env_*_optional` call sites |
| P3-7 | **RESOLVED** | host validation + request timeout (Phase 2.11 / final). *Residual:* per-call `ClientSession` retained (cheap for a local daemon) |
| P3-8 | **RESOLVED** | PostgresHITLQueue thread-local connection cache with commit/rollback + eviction; dead `_connect` branch deleted |
| P3-9 | **RESOLVED** | in Phase 3.6 |
| P3-10 | **RESOLVED** | `decide()` reports found only for ids known in-process or in the shared backend — the Slack "expired" reply path is reachable |
| P3-11 | **RESOLVED** | `HITLLayer.enqueue_notify_failures` counter incremented in the except branch |
| P3-12 | **RESOLVED** | compliance reports stamp `store_error` instead of silently asserting zero traces |
| P3-13 | **RESOLVED** | in Phase 3.9 |
| P3-14 | **RESOLVED** | in Phase 2.8 (compose mem/cpu limits) |
| P3-15 | **RESOLVED** | `COPY docs/` dropped; psycopg comment corrected |
| P3-16 | **RESOLVED** | HITL outcome-assert timeouts raised to ≥ 1 s |
| P3-17 | **RESOLVED** | asserts through `GET /hitl/pending` |
| P3-18 | **RESOLVED** | `rules_fired=` precedence fixed |
| P3-19 | **RESOLVED** | regenerated in Phase 1.2 with required/optional/type annotations; verified complete |
| P3-20 | **RESOLVED** | marketing assets moved to `assets/`; `.gitignore` extended (root-scoped so tracked docs/ images are unaffected) |

### Intentionally deferred (with reason)

| Finding | Reason |
|---|---|
| P2-1 (keyset pagination + streaming CSV export) | Mitigated by the 500-row cap on `/traces` (P1-9) and SQL-side tenant filtering; full cursor pagination is an API-shape change scheduled for 0.8 so dashboard and SDK clients migrate together |
| P2-5 (atomic Redis quota Lua script) | Quota accounting races only across multi-worker Redis deployments and fails open by design; needs the same Lua treatment as `history_append` — scheduled with the 0.8 multi-worker hardening batch |
| P2-9 + T2-2 (proxy-aware rate-limit key) | Resolved by documentation: `--proxy-headers --forwarded-allow-ips` + "unauthenticated mode must not face the internet" in DEPLOYMENT.md; the LB CIDR is deployment-specific and cannot be hardcoded |
| P2-11 (incremental chain verification watermark) | Readiness no longer verifies the chain (the DoS vector is closed); full verification remains in the authenticated, rate-limited endpoint; watermarked incremental verify scheduled with the 1 M-trace soak work |
| P2-16 (Prometheus exposition + correlation-ID logging) | Observability-stack work, no security impact; OTel spans already carry call/tenant context — scheduled for 0.8 |
| P2-17 (classifier lazy-load + pre-baked model) | Partially mitigated: the app factory (P3-2) removes import-time builds when using `--factory`; moving `SentenceTransformer` load out of `__init__` touches the ml extra's startup contract — scheduled with the image pre-bake |
| T1-3 residual (API JWT `jti` revocation list) | `aud` + explicit alg landed; tokens are ≤ 1 h TTL and the dashboard (long-lived sessions) already has Redis-backed revocation — denylist scheduled for 0.8 |
| T1-4 (heuristic injection ceiling) | Accepted residual by design and documented: the load-bearing guarantee is deterministic rules + HITL outside the model; the `[ml]` classifier remains the recommended upgrade for regulated deployments |
| T2-10 (CI actions pinned to SHAs; scanner image digests) | CI-pipeline change outside the five remediation phases; tracked for the next CI pass together with Dependabot for github-actions |
| Appendix B residuals (lockfile, upper caps on remaining deps, pip-audit extras gap, SBOM) | Dependency-management batch tracked for the 0.8 release pipeline; no currently-known advisory in the shipped floors |
| GDPR Art. 33/34 breach-notification runbook, DPA/RoPA templates, SECURITY.md/VDP, SOC 2 scoping | Organizational/documentation artefacts from the security assessment's 46–90-day roadmap, not code defects — tracked in the go-to-market hardening plan |

**Supersedes the "Known residuals" note above:** the `cap_output` latency marker (P3-5)
and the unconditional `CONTROL_MAP` attestations (P2-14) named there as open residuals
are both closed in v0.7.1.

---

## v0.7.3 Security Prompt Remediation Status

Date: 2026-06-11

The active security prompt recorded in `pramagent_security_test_results.md`
found no Critical or High auth, tenant-isolation, HITL, or audit-chain bypasses.
It did find two Medium issues, both now closed:

| Finding | Status | Fix | Verification |
|---|---|---|---|
| `SEC-2026-06-11-01` ComplianceLayer long-input regex CPU DoS | **RESOLVED** | `core.py` runs the isolation input-size cap before compliance scrubbing; `ComplianceLayer` redacts email through bounded `@`-window scanning instead of applying the email regex over long no-match text | `tests/test_compliance.py`, full suite `558 passed, 1 skipped` |
| `SEC-2026-06-11-02` deterministic injection coverage gaps | **RESOLVED** | `IsolationLayer` decodes printable base64-looking tokens before scanning and adds authority-framing plus indirection-wrapper patterns; red-team corpus includes base64, translation-wrapper, and authority-framing variants; the release red-team benchmark now combines injection and safety classifiers for the broader first-party corpus | `tests/test_isolation.py`, `tests/test_classifier.py`, full suite `558 passed, 1 skipped` |

This does not change the product maturity claim: Pramagent remains Alpha /
pilot-ready middleware, not externally certified production infrastructure.
