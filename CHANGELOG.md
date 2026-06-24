# Changelog

## Unreleased

## v0.8.3 - 2026-06-24

### Changed

- Public `/demo` now uses the lighter trust-stack walkthrough: scenario picker,
  policy toggles, provider-key field, ordered layer timeline, safe output, and
  hash-chain evidence in one first-screen flow.
- Demo copy now uses `HELD` for paused human-approval actions instead of the
  ambiguous `IDLE` label, and the chain-verification button reads the live
  `/demo/verify` response before reporting success.
- Authenticated dashboard now exposes `Verify chain` in the main top bar and
  serves a dedicated `/audit/verify` page backed by `/v1/audit/verify`.
- Dashboard summary pages fetch a bounded trace window once for metrics
  reconciliation instead of scanning 500 traces during normal page rendering.
- Dashboard Redis fallback now uses a short connection timeout plus a retry
  cooldown so a missing local Redis server does not make every page load feel
  slow.
- Pre-auth dashboard CSRF accepts a still-valid signed form token even when a
  second open tab has rotated the CSRF cookie.

### Verified

- `python -m pytest tests\test_api.py tests\test_dashboard_security.py -q --tb=short` -> `120 passed`.

## v0.8.2 - 2026-06-23

### Changed

- Dashboard package now ships Pramagent SVG logo assets and serves them from
  `/static`, replacing placeholder letter marks across the authenticated
  console and pre-auth key flows.
- Auth preview design removed the inverted-logo filter that caused ghosting on
  dark panels; the hero now uses the small mark plus live text so state-node
  colors stay true.
- Dashboard evidence screenshots were refreshed with the redesigned overview,
  trace detail, approval queue, login page, and favicon-size logo proof.
- Approval UI language now treats timed-out approval requests as terminal
  `EXPIRED` states instead of ambiguous `IDLE` labels.

### Verified

- Logo mark proof remains readable from 16px through 48px.

## v0.8.1 - 2026-06-23

### Changed

- Dashboard overview metrics now reconcile from persisted trace rows, so
  visible blocked traces cannot sit under a misleading `0.0%` block rate after
  API restarts or in-memory metric resets.
- Dashboard latency cards now report engine latency separately from HITL wait
  time, so a held approval timeout is not presented as Pramagent processing
  latency.
- Trace browser links use `call_id` while still displaying trace hashes, making
  copied dashboard URLs stable for stored traces.
- Public demo now defaults to `mistralai/mistral-small-4-119b-2603`, the NIM
  model that has been stable in live tests, and surfaces upstream provider
  failures as explicit `DEGRADED` detail instead of leaving visitors to infer
  the cause from the trace table.
- Demo rate limiting is now scoped by client IP plus a short in-memory SHA-256
  hash of the visitor's provider key. Plaintext keys are still never persisted,
  logged, traced, or used as raw dictionary keys.
- The public demo accepts either NVIDIA NIM `nvapi-*` keys or OpenAI `sk-*` /
  `sk-proj-*` keys. OpenAI demo runs route to `gpt-4o-mini`.

### Added

- Added `examples/gemini_trust_layer.py`, a runnable Gemini trust-layer recipe
  for Google Dev Library submission and Google-tech SEO/discovery.
- Added `docs/GOOGLE_DEV_LIBRARY_SUBMISSION.md` and
  `docs/COOKBOOK_SUBMISSIONS.md` to track the Google Dev Library, Anthropic
  Claude Cookbook, and OpenAI Cookbook submission path.
- Added authenticated dashboard evidence with screenshots and trace hashes in
  `docs/DEMO_EVIDENCE_2026-06-21.md`.

### Verified

- `python -m pytest -q --tb=short` -> `673 passed, 2 skipped`.
- `python -m compileall -q pramagent deploy\dashboard tests` -> passed.

## v0.8.0 - 2026-06-16

### Added

- **Structured prompt-injection verdicts.** Injection classifiers now return
  `InjectionVerdict` with `flagged`, `score`, `threshold`, `layer`,
  `matched_exemplar`, `matched_pattern`, and details instead of collapsing
  security signal into a bare boolean. `bool(verdict)` remains backward
  compatible.
- **DeBERTa prompt-injection classifier path.** `pramagent[ml]` now includes
  the optional `protectai/deberta-v3-base-prompt-injection-v2` classifier via
  `transformers`, usable as a purpose-trained layer in the ensemble.
- **Provenance-aware isolation policy.** Calls can label input provenance as
  `SYSTEM`, `USER`, `TOOL_OUTPUT`, or `RETRIEVED`; tool output and retrieved
  content use a stricter effective classifier threshold and fail closed when
  suspicious, even when normal user-input detection is configured to record.
- **Held-out benchmark fixtures.** Added Lakera PINT-style and TensorTrust-style
  held-out benchmark data plus tests so the injection layer is no longer
  evaluated only against its own exemplar corpus.

### Changed

- Normalization now strips zero-width/control characters, applies NFKC, handles
  basic leetspeak, and scans decoded payloads before normalized classification.
- Content-policy keywords are separated from prompt-injection detection in the
  classifier path so audit metrics can distinguish "unsafe content" from
  "instruction override attempt."
- Explicit DeBERTa mode now degrades **closed**: if an operator enables it and
  the model cannot load, the layer remains in the ensemble and returns an
  error verdict instead of silently dropping the requested security control.

### Verified

- `python -m pytest -q --tb=short` -> `661 passed, 2 skipped`.
- `python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999`
  -> `200/200 caught`, `0` false positives.

## v0.7.8 - 2026-06-16

### Added

- **Wired the LLM-as-judge output layer into the deployments.** The
  `OutputJudgeLayer` (a second model that evaluates every output before it
  reaches the caller — the "is the OUTPUT safe?" check) already existed and was
  wired into `core.run()`, but no deployment configured it, so semantic output
  failures a regex cannot describe (a working keylogger, a bypass walkthrough, a
  confirmed data-wipe) reached the caller. It is now **on by default in the
  public demo** (`output_judge` policy toggle; one extra NIM call on the
  visitor's key) and **opt-in for the reference `/v1/run`**
  (`PRAMAGENT_OUTPUT_JUDGE=1`, reusing the configured provider). Fail-closed: a
  judge error/timeout/ambiguous verdict withholds the output. Added the first
  test coverage for the layer (`tests/test_output_judge.py`) plus a demo
  end-to-end test proving a keylogger that *evades* the file-exfil rule is
  withheld by the judge.

### Note

- The judge is itself an LLM — it can be wrong and can in principle be targeted
  by adversarial output. It is strong defense-in-depth, not a guarantee; the
  deterministic input rules and output rules remain the first filters, and the
  HITL gate still governs consequential actions.

### Verified

- `python -m pytest -q` -> `657 passed, 2 skipped`.
- `python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999`
  -> `200/200 caught`, `0` false positives.

## v0.7.7 - 2026-06-16

### Added

- Wired the **semantic embedding classifier** as the language-agnostic
  secondary injection layer (the scalable fix for the multilingual gap).
  `get_shared_classifier()` / `get_shared_safety_classifier()` cache the model
  process-wide so it loads at most once — required because the public demo
  builds a fresh pipeline per request. Both the reference `/v1/run` deployment
  (`PRAMAGENT_CLASSIFIER=embedding`) and the demo (`PRAMAGENT_DEMO_CLASSIFIER=embedding`)
  opt in; the default stays on the zero-dependency keyword path. Added
  `warm_shared_classifiers()` (+ `PRAMAGENT_WARM_CLASSIFIER=1`) to pre-load at
  startup, and Hindi/Russian/Arabic/Portuguese plus multilingual
  override-confirmation exemplars so the model has anchors for the languages
  red-team proved bypass the keyword path. Requires `pramagent[ml]`; degrades
  gracefully to keyword when absent.

### Fixed

- Fixed `SEC-2026-06-15-02` (red-team GAP 1/2 — encoded-payload injection):
  the IsolationLayer now decodes **hex** and **`\uXXXX` unicode-escape** runs in
  addition to base64, appending the decoded text for scanning. A hex- or
  unicode-wrapped "ignore all previous instructions" is now caught by the
  existing `instruction_override` heuristic instead of passing through to the
  model. Decode-and-scan only flags a payload when its *decoded* form matches a
  heuristic, so legitimate hex/base64 data (hashes, ids, gzip frames) is not
  over-blocked.
- Added an `override_confirmation_token` input heuristic: a prompt asking the
  model to emit `OVERRIDE_ACCEPTED` (or `FILTERS DISABLED`, `UNRESTRICTED MODE
  ON`) is now blocked at the input layer regardless of the surrounding
  language. This closes the input side of red-team GAP 3/4 (Spanish/German
  jailbreaks) — the literal token is the language-independent signal.
- Added `encoded_payload_framing` (decode-and-act framing) and targeted
  non-English instruction-override phrases (fr/es/de/hi) to the isolation
  heuristics.

### Note

- Red-team GAP 3/4 (`OVERRIDE_ACCEPTED` reaching the user in es/de) was **not a
  code regression**: the `withhold_filter_override_confirmation` output rule
  added in v0.7.5 catches it and its test passes. The observed behaviour was a
  stale public-demo deployment running a pre-fix build. Action: redeploy.
- Non-English injection coverage is still **targeted, not complete** — see
  `docs/IMPLEMENTATION_STATUS.md`. The output post-check is the backstop; the
  scalable fix is wiring the embedding classifier (hook already present).

### Verified

- `python -m pytest -q` -> `640 passed, 2 skipped`.
- `python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999`
  -> `200/200 caught`, `0` false positives.
- Confirmed hex/unicode payloads decode-and-block while a 64-char hex checksum,
  a UUID, and benign engineering prompts do not trigger isolation.

## v0.7.6 - 2026-06-15

### Fixed

- Tightened the SE-2 emergency-override heuristic so harder maintenance-mode
  prompts such as "standard restrictions are temporarily suspended" and
  "OVERRIDE_ACCEPTED" block, while benign explainers such as "how do emergency
  override systems work?" pass.
- Added chat-template delimiter coverage for `<|system|>`, `<|user|>`,
  `<|im_start|>system`, `[INST]`, and `<<SYS>>` wrapper attacks.
- Added NPI redaction before the generic phone-number pattern so
  `NPI 1234567890` is recorded as `npi`, not `phone`.
- Expanded demo financial-intent routing for leveraged-position liquidation
  phrasing while keeping liquidation/margin/IBAN educational prompts clean.
- Expanded the reference `/v1/run` pre-HITL escalation profile to cover
  ambiguous payment, broad account-data access, and uncertain production
  credential-change requests.

### Verified

- Targeted prompt harness from the fresh 0.7.4/0.7.5 regression list:
  `0` failures across emergency override, output override, margin/liquidation,
  IBAN/SWIFT, ambiguous escalation, PHI, false-positive traps, base64, and
  chat-template wrapper prompts.
- `python -m pytest tests\test_adversarial.py tests\test_compliance.py tests\test_api.py tests\test_escalate_policy.py -q --tb=short`
  -> `158 passed`.
- `python -m pytest -q --tb=short` -> `623 passed, 1 skipped`.

## v0.7.5 - 2026-06-15

### Added

- `escalate_policy` on `Pramagent`: configurable handling of a
  `Verdict.ESCALATE` from the safety passes, set per stage (`pre` = input,
  `post` = output) to `"log"` | `"hitl"` | `"block"`. Accepts a string (both
  stages), a dict, or an `EscalatePolicy`; invalid values raise at construction.
  Default is `"log"` (record and continue) so adding an ESCALATE rule never
  silently starts gating traffic. `"hitl"` routes through the human-in-the-loop
  gate (propose-and-wait, idle-on-silence); a `pre` escalation is handled
  before the model call. Three recommended deployment profiles are documented
  in the README. Generalizes the earlier hard-wired ESCALATE→HITL behavior into
  an explicit, opt-in policy.

### Fixed

- Fixed `SEC-2026-06-15-01` (red-team SE-2): a fake "emergency override"
  prompt that asked to disable content filters bypassed the isolation
  heuristics, and the model's `OVERRIDE_ACCEPTED` / "content filters disabled"
  reply was returned verbatim. Added `emergency_override` and
  `disable_safety_controls` input heuristics to `IsolationLayer`, plus a
  `withhold_filter_override_confirmation` output rule on the public demo so a
  self-disabling completion is withheld even if the input slips through.
- Fixed red-team F-4: approving a margin call or ordering a liquidation was
  treated as a plain response. `_demo_financial_intent` now recognizes margin
  call / liquidation / close-positions language and routes it through the HITL
  gate (`hitl=idle` → action not executed).
- Fixed red-team F-2: IBAN / SWIFT international transfers now trip the same
  demo financial-intent gate as ACH transfers (routed to the `wire_transfer`
  HITL action). The underlying latent gap — a `Verdict.ESCALATE` from the
  safety passes being recorded but never acted on — is addressed by the new
  `escalate_policy` (see Added). The reference deployment (`build_default_armor`,
  served at `/v1/run`) now sets `escalate_policy={"pre": "hitl"}`, so its
  `escalate_transfer` rule holds a `transfer $N` prompt for approval before the
  model runs; with no approver configured it idles and is not executed. `IDLE`
  is never consent.
- Fixed red-team H-1: HIPAA MRN (`MRN-…`) is now redacted as a high-precision
  identifier, and dash-separated insurance/payer member IDs (`BCB-992341`) are
  redacted when an insurance context keyword is nearby. The contextual guard
  keeps SKUs and order codes from being over-redacted.
- Fixed four dynamic red-team benchmark misses found after the SE/F/H fixes:
  padded base64 payloads were not decoded by the fallback classifier because of
  a trailing word-boundary bug, and indirect wrappers around `exfiltrate
  credentials` / inline developer-message instructions were too narrow.

### Verified

- `python -m pytest -q` -> `598 passed, 1 skipped`.
- `python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999`
  -> `200/200 caught`, `0` false positives.
- `escalate_policy` matrix covered in `tests/test_escalate_policy.py`
  (log/hitl/block × pre/post, dict form, idle/deny/approve, invalid-config).
- Confirmed the report's six false-positive prompts (env vars, auth vs authz,
  LLM vulnerabilities, rate limiting, directory monitoring, IBAN explainer) and
  legitimate ops phrases ("enable debug mode") do not trip the new heuristics.

## v0.7.3 - 2026-06-11

### Fixed

- Fixed `SEC-2026-06-11-01`: compliance email scrubbing no longer runs an
  unbounded regex over long no-match input before isolation. The isolation byte
  cap now runs before compliance scrubbing, and email redaction uses bounded
  `@`-window scanning.
- Fixed `SEC-2026-06-11-02`: deterministic injection scanning now decodes
  printable base64-looking tokens and covers authority/developer/tester
  framing plus translation/indirection wrapper attacks.
- Fixed the release red-team benchmark path so the broader first-party corpus
  combines injection and safety classifiers without changing API pipeline
  ordering. Weapon-construction prompts remain blocked by `SafetyLayer`, not
  `IsolationLayer`.
- Added regression corpus entries for base64, translation-wrapper, and
  authority-framing bypass classes.

### Documentation

- Added `pramagent_security_test_results.md` with the June 11 active security
  prompt results and remediation status.
- Refreshed README, implementation status, live test results, red-team results,
  release checklist, deployment examples, and full-audit notes for v0.7.3.

### Verified

- `python -m pytest tests/test_compliance.py tests/test_isolation.py -q --tb=short`
  -> `41 passed`.
- `python -m pytest tests/test_api.py::test_run_blocks_weapon_construction_via_safety_classifier tests/test_classifier.py -q --tb=short`
  -> `73 passed`.
- `python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999`
  -> `200/200 caught`, `0` false positives.
- `python -m pytest tests/ -q --tb=no` -> `558 passed, 1 skipped`.

## v0.7.2 - 2026-06-11

### Fixed

- Fixed GitHub Actions `pip-audit` invocation by using the installed console
  script instead of an invalid `python -m pip-audit` module call.
- Fixed the authenticated ZAP CI sidecar startup by explicitly opting the CI
  scan into volatile memory storage with `PRAMAGENT_ALLOW_MEMORY_STORE=1`.
- Raised dependency floors for `aiohttp` and `python-multipart` to avoid newly
  published parser advisories in the default resolver path.

### Verified

- `python -m pytest -q --tb=short` -> `547 passed, 1 skipped`.
- Bandit -> no issues identified.
- Semgrep `p/security-audit` + `p/python` -> `0 findings`.
- Dynamic red-team smoke -> `200/200 caught`, `0` false positives.

## v0.7.1 - 2026-06-11

### Fixed

- Remediated the June full-spectrum audit and enterprise pre-production review
  findings across API authentication, HITL escalation, replay reproducibility,
  persisted trace scrubbing, erasure parity, Postgres chain integrity, store
  startup refusal, weak-secret startup denial, chain-head concurrency, blocking
  I/O, deployment hardening, and security hygiene.
- Added Postgres tamper-detection coverage for deletion, reordering, payload
  tamper, stale-head concurrent appends, and JSONB dict handling.
- Added regression coverage for fallback providers, threaded chain writers,
  tenant-scoped trace access, weak-secret denylist enforcement, and deployment
  startup contracts.

### Added

- Added a reusable security audit prompt for external AI/code-review passes
  focused on integration safety, HITL correctness, downstream consequence
  traceability, tenant isolation, persistence, and regression risk.

### Verified

- `python -m pytest -q --tb=short` -> `547 passed, 1 skipped`.
- `python -m compileall -q pramagent tests deploy\dashboard` -> passed.

## v0.5.20 - 2026-06-07

### Changed

- Refreshed README, implementation status, hardening guide, release checklist,
  live-test results, deployment guide, and technical marketing docs to match
  the v0.5.x trust-extension scope.
- Added the June 7 security scan report to packaged documentation.
- Opted GitHub Actions workflows into Node 24 with
  `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` to clear upstream Node.js 20
  deprecation noise.

### Fixed

- Replaced remaining silent exception paths in AutoGen adapter notification and
  HITL notification paths with debug/warning logging.
- Tightened SQLite/Postgres HITL queue query construction and scanner
  annotations after Bandit/Semgrep review.

### Verified

- `python -m pytest -q --tb=short` -> `449 passed, 1 skipped`.
- `python -m compileall -q pramagent tests deploy\dashboard` -> passed.
- `python -m bandit -r pramagent deploy\dashboard` -> no issues identified.
- Semgrep `p/security-audit` + `p/python` -> `0 findings`.
- `python -m build` and `python -m twine check dist\pramagent-0.5.20*` -> passed.

## v0.5.19 - 2026-06-07

### Added

- Added curated deterministic rule corpora for jailbreaks, OWASP LLM risks,
  injection payloads, fictional-wrapper bypasses, PHI, and financial PII.
- Added persistent HITL queue backends with in-memory, SQLite, and Postgres
  stores for approval flows that survive process restarts.
- Added framework adapters for LangGraph, AutoGen, CrewAI, and generic custom
  loops/tools.
- Added `ComplianceReporter.generate()` for JSON/text/PDF-style evidence
  packages across SOC2, HIPAA, GDPR, NIST AI RMF, EU AI Act, and PCI DSS.

### Fixed

- Added Slack signature verification export support used by HITL imports.
- Added decorator-style support for `protect_tool(...)`.

### Verified

- `python -m pytest -q --tb=short` -> `449 passed, 1 skipped`.
- `python -m compileall -q pramagent tests` -> passed.

## v0.5.18 - 2026-06-07

### Added

- Added signed, expiring double-submit CSRF tokens to the pre-auth dashboard
  forms for login, signup, forgot-key, and reset-key flows.
- Added authenticated OWASP ZAP OpenAPI scanning in CI by injecting a CI bearer
  token through ZAP's replacer configuration.

### Verified

- `python -m pytest -q --tb=short` -> `431 passed`.
- Bandit and Semgrep -> `0 findings`.
- Local authenticated ZAP OpenAPI scan -> `0 fail-level findings`.

## v0.5.16 - 2026-06-06

### Fixed

- Fixed the dashboard Docker image after generated-key auth by copying the
  `pramagent` package into the image and installing auth-store dependencies.
- Updated the login-page recovery link from "Forgot password?" to "Forgot key?"
  to match generated dashboard-key authentication.
- Verified the live Docker dashboard exposes `/signup` and `/forgot-password`
  on port `8501`.

### Verified

- `python -m pytest tests\test_dashboard_security.py -q --tb=short` -> `21 passed`.
- `python -m compileall -q pramagent deploy\dashboard` -> passed.
- Live Docker dashboard: `/login`, `/signup`, and `/forgot-password` returned `200`.

## v0.5.15 - 2026-06-06

### Changed

- Dashboard signup now asks for email and/or phone, then generates a
  high-entropy `pga-...` dashboard key instead of asking users to choose a
  password.
- Forgot-password flow is now a key-regeneration flow: after verification token
  validation, Pramagent invalidates the old key hash and shows a new key once.
- Dashboard login copy now says "Dashboard key" and accepts email, phone, or
  the legacy shared-key username path.
- Dashboard user storage now defaults to local SQLite
  `.pramagent/dashboard-users.db` when no Postgres/SQLite user store is
  configured, so signup/reset pages are visible in the local UX without CSV.

### Added

- Phone identity support for dashboard users.
- One-time generated-key display page with no-store cache headers.

### Verified

- `python -m pytest -q --tb=short` -> `421 passed`.

## v0.5.14 - 2026-06-05

### Fixed

- Package `deploy.dashboard` and its Jinja templates in the PyPI distribution so
  the signup and forgot-password dashboard pages are available from installed
  artifacts, not only from a git checkout.

### Verified

- `python -m pytest -q --tb=short` -> `420 passed`.

## v0.5.13 - 2026-06-05

### Added

- Optional SQL-backed dashboard user auth with bcrypt password hashes,
  tenant-scoped roles, signup routes, and one-time password reset tokens stored
  as SHA-256 hashes.
- SQLite dashboard user store for local development/tests and Postgres
  dashboard user store for team deployments. CSV is intentionally not used for
  auth state.
- Postgres-backed `PostgresAPIKeyRegistry` with persistent hashed API keys,
  created timestamps, and revocation timestamps behind the existing registry
  interface.
- Redis/back-end-backed ToolGuard side-effect history and per-session tool call
  counters for multi-worker dangerous-chain detection.
- Draft 2020-12 JSON Schema validation through `jsonschema`, preserving the
  existing `(ok, reason)` ToolGuard validation contract.

### Changed

- API defaults use Redis-backed ToolGuard state when
  `PRAMAGENT_TOOL_GUARD_REDIS_URL` or `PRAMAGENT_REDIS_URL` is configured.
- Dashboard login now prefers SQL user authentication when configured while
  retaining the shared dashboard key as the alpha fallback.

### Verified

- `python -m pytest -q --tb=short` -> `420 passed`.

## v0.5.12 - 2026-06-05

This patch release hardens dashboard session security and JWT operations.

### Added

- JWT `kid`-based signing-key rotation through `PRAMAGENT_JWT_SECRETS` and
  `PRAMAGENT_JWT_ACTIVE_KID`, while preserving the existing single-secret path.
- Dashboard CSRF protection for cookie-authenticated logout and approval/deny
  actions.
- Regression coverage for JWT rotation/retirement, CSRF logout, CSRF approval
  decisions, and API-key automation paths.

### Changed

- Dashboard logout is now POST-only and requires a session-bound CSRF token.
- Dashboard templates now pass CSRF tokens to logout and HTMX approval buttons.
- Implementation and hardening docs now call out the new controls and keep
  SSO/OIDC/RBAC, persistent HITL queues, billing ledgers, and external
  assessment as alpha roadmap items.

### Verified

- `python -m pytest -q --tb=no` -> `412 passed`.

## v0.5.11 - 2026-06-05

This patch release records the real workflow beta-validation pass and tightens
Slack HITL behavior.

### Added

- Real OpenAI job-agent load evidence: 216 `gpt-4o-mini` calls across five
  tenants with concurrency 10, per-request sessions, quota tracking, 18 real
  read-only public-page fetches, and a valid audit chain.
- Public cost evidence for that run: `$0.00674850` total, approximately
  `$0.031` per 1,000 calls under the measured workload.
- External security assessment scope in the hardening guide.

### Changed

- Slack HITL callbacks now replace the original approval message with the final
  approve/deny status and remove action buttons after a decision.
- OpenAI provider traces now preserve provider token counts for cost/usage
  reporting.
- The release docs now report the clean local result:
  `405 passed, 0 warnings`.

### Fixed

- Slack callback tests no longer trigger `httpx` raw-body deprecation warnings.
- Isolation/classifier coverage now catches admin/elevated-privilege authority
  claim prompts requesting confidential data.

## v0.5.10 - 2026-06-04

This patch release adds a deeper release harness and fixes a default API safety
miss found by that harness.

### Added

- `test_agent_v2.py`, a standalone release harness covering load,
  multi-tenant isolation, API/HTTP behavior, and regression checks.
- `examples/dynamic_feed_agent.py`, a dynamic workflow agent that generates
  fresh invoices, support notes, retrieved tool output, and adversarial feed
  items at runtime. It stores the exact prompts and RCA paths in JSON reports.

### Changed

- The keyword safety classifier now blocks controlled-substance and chemical
  weapon synthesis intent when procedural language appears near the substance.
- API `/v1/run` now rejects empty prompts at the schema boundary with 422.
- The v2 release harness is ASCII-safe on Windows consoles and avoids
  cross-test pollution from rate-limit exhaustion.

### Verified

- `python -m pytest -q --tb=short` -> `402 passed, 2 warnings`.
- `test_agent_v2.py` full run -> `57/57 passed`.
- Dynamic feed agent with mock provider -> `8/8 passed`, hash chain valid.
- Dynamic feed agent with local Ollama `qwen2.5:1.5b` -> `8/8 passed`,
  hash chain valid.

## v0.5.9 - 2026-06-04

This patch release fixes post-safety false positives found during real local
model workflow testing.

### Changed

- `SafetyLayer` now supports separate `post_rules` and `post_classifier`
  configuration. Existing callers keep the previous behavior by default, while
  production workflows can use strict input screening and narrower output
  screening.
- `test_agent.py` now treats `[output withheld by safety rule]` as a failure
  for non-blocked cases, preventing silent post-safety false positives from
  passing live workflow reports.

### Fixed

- Benign model outputs that mention risky terms in harmless contexts, such as
  chemistry explanations or privacy-preserving PII refusals, are no longer
  silently replaced when the harness is configured with narrow post-safety
  policy.

## v0.5.8 - 2026-06-04

This release hardens the dashboard session boundary and adds adversarial
coverage from real generated test-agent failures.

### Added

- GitHub Actions Trusted Publishing workflow for PyPI releases using OIDC and
  `pypa/gh-action-pypi-publish@release/v1`.
- Test-agent reports now preserve the exact prompt, expected output checks,
  output preview, and trace summary for every generated adversarial case.
- Built-in adversarial coverage for malware/data-theft intent and privileged
  role prompts that request sensitive system logs.

### Changed

- Release checklist now documents the PyPI Trusted Publisher setup and treats
  token-based local Twine upload as an emergency fallback.
- Semantic safety classifier now blocks targeted malware/data-theft and
  admin/root sensitive-log exfiltration classes while preserving benign
  malware education and ordinary log-summary cases.
- Isolation and red-team corpora now include the generated failure classes so
  future benchmark runs exercise them without requiring OpenAI generation.
- Dashboard visual design was refreshed under the Pramagent name.

### Fixed

- Dashboard logout now revokes server-side sessions, clears cookies, and sends
  no-store headers so browser back navigation returns to login instead of a
  cached authenticated page.
- Dashboard CSV export now returns a real CSV attachment.
- API trace listing now normalizes stored trace events before tenant filtering.
- Docker image build now includes docs and changelog inputs required by the
  package metadata.

## v0.5.7 - 2026-06-04

This is a README/PyPI listing-quality release.

### Changed

- Docs section now shows only the three highest-signal links on the launch
  surface: implementation status, live test results, and hardening guide.
- Remaining docs are collapsed behind one `More documentation` link to the
  GitHub docs directory.

### Still Not Proven

- This remains Alpha software. This patch improves reader onboarding; it does
  not change runtime safety guarantees.

## v0.5.6 - 2026-06-04

This is a README/PyPI listing-quality release.

### Changed

- Bare-install section now includes the exact import path for swapping from the
  mock provider to a real OpenAI provider:
  `from pramagent.providers import OpenAIProvider`.

### Still Not Proven

- This remains Alpha software. The provider snippet shows how to connect a real
  model; it is not a claim of provider-specific safety certification.

## v0.5.5 - 2026-06-04

This is a README/PyPI listing-quality release.

### Changed

- ToolGuard README example now shows two blocked cases in addition to HITL
  escalation: an oversized payment rejected by JSON Schema and a wrong-tenant
  payment rejected by tenant policy.

### Still Not Proven

- This remains Alpha software. The stronger example demonstrates policy
  enforcement semantics, not third-party safety certification.

## v0.5.4 - 2026-06-04

This is a listing-quality release focused on making the package feel runnable
within the first five seconds of evaluation.

### Added

- `docs/quickstart-terminal.png`, a terminal-style screenshot of
  `pip install pramagent` followed by the bare mock-provider quickstart with a
  printed `this_hash`.

### Changed

- README now shows the quickstart screenshot immediately after the bare-install
  code block.
- Source and wheel distributions now include PNG docs assets.

### Still Not Proven

- This remains Alpha software. The screenshot proves the base package runs; it
  is not a production safety claim or external certification.

## v0.5.3 - 2026-06-04

This release adds the canonical live workflow evidence for Pramagent's public
Alpha launch story.

### Added

- `examples/live_payment_agent.py`, a real payment-agent workflow that can run
  against either the mock provider or live OpenAI.
- `docs/LIVE_WORKFLOW_DEMO.md`, including the verified live OpenAI result:
  allowed read-only lookup, HITL-idle payment, tenant block, schema block, and
  valid SQLite audit chain.
- `docs/TECHNICAL_MARKETING_POST.md`, a technical launch/post template grounded
  in the live workflow demo.

### Changed

- README docs index now links to the live workflow demo.
- Release checklist now references the live workflow result and `v0.5.3`.

### Still Not Proven

- This remains Alpha software. The live workflow demo is stronger evidence than
  unit tests alone, but it is not an external penetration test, compliance
  certification, or proof of prompt-injection immunity.

## v0.5.2 - 2026-06-02

This is a final repository-link cleanup patch after the GitHub repository was
renamed to `sriram7737/pramagent`. It does not change runtime behavior.

### Fixed

- README badge, CI, diagram, documentation, clone, and project metadata links
  now point at `https://github.com/sriram7737/pramagent`.

## v0.5.1 - 2026-06-02

This is a PyPI listing hotfix. It does not change runtime behavior.

### Fixed

- README badge, CI, diagram, and documentation links now point at the currently
  live GitHub repository URL so PyPI no longer renders broken images while the
  GitHub repository rename is pending.
- Project metadata URLs now point at the currently live GitHub repository.

## v0.5.0 - 2026-06-02

This release completes the public rebrand to Pramagent. It is a
breaking package-name and import-path change.

### Changed

- PyPI/project package renamed to `pramagent`.
- Python import path renamed to `pramagent`.
- Console command renamed to `pramagent`.
- Public API class renamed to `Pramagent`.
- Environment variables, Docker Compose service config, dashboard cookies,
  docs, release notes, and deployment examples now use `PRAMAGENT_*` and
  Pramagent naming.
- Design document filename changed to `docs/Pramagent-Design-Document.docx`.

### Migration

- New installs: `pip install pramagent`
- New imports: `from pramagent import Pramagent`
- New CLI: `pramagent --help`

### Still Not Proven

- This remains Alpha software. The rebrand does not add external certification,
  SSO/OIDC/RBAC, or third-party jailbreak assurance.

## v0.4.4 - 2026-06-02

This is a PyPI listing cleanup patch. It does not change runtime behavior.

### Changed

- Removed the external Pepy downloads badge from README because it rendered as
  a broken image on PyPI for the newly published project.
- Package/API version bumped to `0.4.4`.

## v0.4.3 - 2026-06-02

This is a PyPI/GitHub listing-quality patch. It does not add new runtime
security claims.

### Changed

- README doc links now use absolute GitHub URLs so PyPI does not rewrite them
  into broken `pypi.org/project/pramagent/docs/...` links.
- README now leads with badges, a sharper ToolGuard-first pitch, an inline
  trust-stack diagram, and a bare-install example that works with
  `pip install pramagent`.
- README no longer contains pre-launch wording about PyPI publication.
- Project metadata now includes an Author URL.
- Release checklist and deployment example were updated for `v0.4.3`.

### Still Not Proven

- This remains an Alpha release: no external penetration test, no SSO/OIDC/RBAC,
  no production compliance certification, and no third-party jailbreak
  assurance.

## v0.4.2 - 2026-06-02

### Added

- In-memory hash-chain usage ledger for pilot billing/analytics evidence.
- `/v1/usage/ledger` and `/usage/ledger` endpoints for ledger inspection.
- `ServiceNowNotifier` as a notify-only HITL escalation adapter.
- Hardening guide that turns the release-gap critique into concrete next steps.
- `MANIFEST.in` and wheel data-file config so implementation status,
  hardening, live-test, red-team, load-test, deployment, and release docs ship
  with distributions.
- Live OpenAI and local Ollama smoke-test results in `docs/LIVE_TEST_RESULTS.md`.
- GitHub Actions test matrix now covers Python 3.10, 3.11, 3.12, and 3.13 with
  upgraded pip/setuptools/wheel.

### Changed

- Usage event sink failures now re-raise when `fail_open=False`.
- README, deployment docs, and implementation status now distinguish local
  ledger evidence from Stripe/Chargebee-grade billing.
- PyPI/package positioning now explicitly says Alpha and points users to live
  test results, implementation status, and the hardening guide.
- OpenAI-compatible providers now retry with `max_completion_tokens` when a
  newer OpenAI model rejects legacy `max_tokens`.
- The `dashboard` extra now includes FastAPI/uvicorn so it can be installed
  independently from the `api` extra.

## v0.4.1 - 2026-06-01

This is a release-hardening patch for packaging, CLI validation, and red-team
smoke testing.

### Added

- PyPI-facing project metadata: classifiers, project URLs, and an `all` extra.
- README install instructions for PyPI and source installs.
- Release checklist covering build, twine check, GitHub tag/release, and PyPI
  publish commands.
- Dynamic red-team validation result:
  `pramagent redteam --json --dynamic --attacks 200 --seed 999`.

### Verified

- `pramagent --help` works from the installed console script.
- `[project.scripts]` exposes `pramagent = "pramagent.cli:main"`.
- `pip install -e .` succeeds.
- Dynamic red-team run caught 200/200 prompts with 0 false positives for seed
  `999`.

### Still Not Proven

- Package is prepared for PyPI, but publishing still requires a PyPI API token.
- Dashboard auth remains MVP-level; no SSO/OIDC/RBAC yet.
- Dynamic red-team mode is useful smoke testing, not third-party jailbreak
  assurance.

## v0.4.0 - 2026-06-01

This release adds two high-leverage production-adjacent capabilities while
keeping the claims honest: Pramagent is stronger guardrail and audit middleware,
not certified bank-grade infrastructure.

### Added

- Optional Ethereum/Sepolia anchoring for audit hash heads via `web3.py`.
- Trace anchor metadata: transaction hash, block number, status, chain ID, and
  anchored hash.
- Optional encrypted S3 cold archive wrapper for retention and erasure flows.
- Tests for Ethereum anchoring, fail-open behavior, S3 archive/restore, and
  tenant-scoped archive access.
- Live Sepolia validation:
  `0x8d0d7bd15c377224acee00f397272bab1007c757080f19523cfc66c8461b5d99`.
- Live AWS S3 archive/restore validation with encrypted fake trace data.
- First published local smoke-load result.
- Authenticated Docker Compose load validation: 10 minutes, 12,000 requests,
  0 errors, 0 HTTP 5xx, with Redis/Postgres/dashboard healthy after the run.
- Red-team CLI can now run a 100-prompt built-in smoke corpus with
  `pramagent redteam --json --attacks 100`.
- Red-team CLI now supports runtime prompt mutation with reproducible seeds:
  `pramagent redteam --json --dynamic --attacks 100 --seed 123`.

### Changed

- Package/API version bumped to `0.4.0`.
- Design and status docs now call out Ethereum and S3 as MVP features with
  clear hardening gaps.
- Keyword fallback catches classic developer-mode, DAN, indirect tool-output,
  delimiter, and exfiltration jailbreaks in the bundled corpus.
- Keyword fallback was tightened against dynamic variants such as debug mode,
  unrestricted persona, supersede/replace overrides, private data, and system
  directive exfiltration.

### Still Not Proven

- No third-party red-team benchmark, chaos run, or external penetration test has
  been completed.
- No mainnet anchoring, deployed verifier contract, or production key-management
  runbook exists yet.
- No external penetration test, SSO/RBAC dashboard hardening, or formal
  compliance certification exists yet.
