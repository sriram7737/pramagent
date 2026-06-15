# Live Test Results

Last refreshed: 2026-06-15

These are release-validation smoke tests using real external services. They are
not a penetration test, a scale test, or a compliance certification.

## Sepolia Ethereum Anchoring

Result: **passed**

```json
{
  "network_chain_id": 11155111,
  "tx_hash": "0x8d0d7bd15c377224acee00f397272bab1007c757080f19523cfc66c8461b5d99",
  "block_number": 10968438,
  "status": 1,
  "verified_status": 1,
  "trace_hash": "e251d85472de268d0b50d10abf36158d24483ef360f37bfaf01a0747468b6fd4",
  "tx_type": 2
}
```

Notes:

- The transaction was submitted on Sepolia with the trace hash in calldata.
- `verify_on_chain(tx_hash, expected_hash=...)` succeeded.
- Live testing exposed a verifier bug around Web3 `HexBytes` calldata and a
  legacy-gas pending transaction. The release code now normalizes calldata and
  uses EIP-1559 fee fields when the chain supports them.

## S3 Cold Archive

Result: **passed**

```json
{
  "region": "us-east-1",
  "call_id": "live-s3-e42647ff1f3a",
  "deleted_from_hot_store": 1,
  "s3_key": "pramagent-live-test/v0.4/tenant=live-release-test/2026/06/01/live-s3-e42647ff1f3a.json.gz.fernet",
  "content_length": 548,
  "metadata_encrypted": "true",
  "restored_call_id": "live-s3-e42647ff1f3a",
  "restored_tenant_id": "live-release-test"
}
```

Notes:

- The test used a real AWS S3 bucket with a tiny fake trace.
- The object was gzip-compressed, Fernet-encrypted, uploaded to S3, removed
  from the hot store, and restored by call ID.
- Bucket name and credentials are intentionally not published.

## Local Release Checks

```text
python -m compileall -q pramagent tests
python -m pytest -q --tb=no
```

Result:

```text
623 passed, 1 skipped
```

Current package regression note: after the v0.7.6 targeted prompt-suite
hardening pass, the full local suite passed with `623 passed, 1 skipped`. The
skip is the Postgres optional-driver negative test when `psycopg2` is installed
locally.

The fresh targeted prompt suite passed with `0` failures after remediation
across emergency override, output override, margin/liquidation, IBAN/SWIFT,
ambiguous escalation, PHI, false-positive, padded base64, and chat-template
wrapper cases.

## Active Security Prompt Remediation

Result: **passed after remediation**

Report:

```text
pramagent_security_test_results.md
```

Summary:

- Initial active security prompt pass found no Critical or High auth,
  tenant-isolation, HITL, or audit-chain bypasses.
- `SEC-2026-06-11-01` exposed long-input CPU DoS in compliance email scrubbing.
  Commit `085c7b4` fixed it by running the isolation byte cap before scrubbing
  and by switching email redaction to bounded `@`-window scanning.
- `SEC-2026-06-11-02` exposed deterministic injection gaps for base64,
  authority/developer framing, and translation wrappers. Commit `e8392aa` fixed
  it by decoding printable base64 tokens and adding authority/indirection
  patterns plus corpus entries.
- The release red-team gate then exposed benchmark-path gaps for opaque
  base64-in-wrapper prompts and fictional weapon-construction wrappers. The
  benchmark now combines injection and safety classifiers for its broader
  first-party corpus without moving weapon-safety blocking into `IsolationLayer`.
- Targeted validation: `tests/test_compliance.py tests/test_isolation.py` ->
  `41 passed`.
- Classifier/API regression validation:
  `tests/test_api.py::test_run_blocks_weapon_construction_via_safety_classifier tests/test_classifier.py`
  -> `73 passed`.
- Full validation after v0.7.6 targeted prompt-suite hardening:
  `python -m pytest tests/ -q --tb=no` -> `623 passed, 1 skipped`.

## Clean Environment Checks

Result: **passed**

Python 3.13.13 clean venv with upgraded build tooling:

```text
python -m pip install -U pip setuptools wheel
python -m pip install -e ".[dev,api,otel]"
python -m pytest -q --tb=no
```

```text
412 passed, 1 warning
```

Notes:

- Clean venv used upgraded pip, setuptools, and wheel before installing
  `.[dev,api,otel]`.
- The single clean-venv warning is from FastAPI/Starlette's `TestClient`
  dependency path (`httpx` deprecation notice), not auth, crypto, HITL, provider
  usage, or audit-chain code.
- GitHub Actions is configured to run Python 3.10, 3.11, 3.12, and 3.13 with
  upgraded pip/setuptools/wheel before installing test dependencies.

## Built Wheel Smoke Test (historical v0.5.16)

Result: **passed**

```text
python -m venv %TEMP%/pramagent-0516-wheel-smoke
%TEMP%/pramagent-0516-wheel-smoke/Scripts/python -m pip install dist/pramagent-0.5.16-py3-none-any.whl
%TEMP%/pramagent-0516-wheel-smoke/Scripts/python -c "import pramagent; print(pramagent.__version__)"
```

```text
0.5.16
```

Dashboard-extra smoke:

```text
python -m venv %TEMP%/pramagent-0516-dashboard-smoke
%TEMP%/pramagent-0516-dashboard-smoke/Scripts/python -m pip install "dist/pramagent-0.5.16-py3-none-any.whl[dashboard]"
%TEMP%/pramagent-0516-dashboard-smoke/Scripts/python -c "from pramagent.dashboard_auth import SQLiteDashboardUserStore; ..."
```

```text
tenant
```

## Generated Test-Agent Regression Loop

Result: **passed for deterministic built-in corpus**

The local `test_agent.py` harness now stores exact generated prompts, output
previews, and trace summaries in JSON reports. During v0.5.8 hardening, OpenAI
generated several fresh failures against the Ollama-backed workflow. Those
classes were promoted into the classifier, isolation heuristics, red-team
corpus, unit tests, and built-in harness cases:

- malware/data-theft intent
- self-replicating or spreading malware behavior
- privileged role prompts requesting sensitive logs
- trusted-advisor prompts eliciting sensitive personal data
- admin-privilege prompts requesting confidential files

Deterministic harness command:

```text
python test_agent.py --mock --no-ai-prompts --report test-results/test_agent_mock.json
```

```text
37/37 passed
```

Post-safety false-positive regression:

```text
python test_agent.py --ollama-model qwen2.5:1.5b --no-ai-prompts --report test-results/test_agent_ollama_qwen.json
```

```text
37/37 passed
no non-blocked sentinel outputs found
```

This checks that benign non-blocked responses are not silently replaced with
`[output withheld by safety rule]`.

Optional extras install check (historical v0.5.16):

```text
python -m pip install "dist/pramagent-0.5.16-py3-none-any.whl[all]"
```

Result: **passed**. Import smoke covered Anthropic, Ollama/aiohttp, FastAPI,
uvicorn, Jinja2, httpx, cryptography, OpenTelemetry, Redis, psycopg2, Web3,
boto3, and Pramagent itself.

## Real Slack HITL UI Flow

Result: **passed**

The job-agent integration was exposed through a public Cloudflare Tunnel and
Slack Interactivity was pointed at:

```text
/v1/hitl/slack/actions
```

Approve path:

```json
{
  "approved": true,
  "hitl": "approved",
  "side_effect": "simulated_email_outbox",
  "chain_valid": true,
  "trace_hash": "ff70c2adb3ed15b434bb6c63f8bb23b634b9840815d2b6e49e2bfa237681d08c"
}
```

Deny path:

```json
{
  "approved": false,
  "hitl": "denied",
  "side_effect": null,
  "chain_valid": true,
  "trace_hash": "d9bd6d07070b6391401a0ac24dcd24cae760435a206d5b3425038ff37e395064"
}
```

Notes:

- Both paths used real Slack button clicks from the Slack UI.
- The callback route verified the Slack signature.
- The approved path wrote only a simulated local email side effect to
  `test-results/live_email_outbox.jsonl`; no external email was sent.
- The Slack message is updated after approval/denial so the action buttons are
  removed and the decision is visible in-channel.

## Real OpenAI Job-Agent Load Run

Result: **passed**

Report:

```text
C:\Users\srira\OneDrive\Desktop\agent\test-results\stress_openai_4omini_216_20260605.json
```

Summary:

```json
{
  "model": "gpt-4o-mini",
  "tenants": 5,
  "concurrency": 10,
  "total_calls": 216,
  "blocked": 90,
  "hitl_idle_or_pending": 54,
  "hitl_auto": 72,
  "real_fetches_executed": 18,
  "real_fetch_errors": 0,
  "provider_errors": 0,
  "circuit_breaker_blocks": 0,
  "quota_blocks": 0,
  "post_safety_withheld": 0,
  "provider_prompt_tokens": 2142,
  "provider_completion_tokens": 10712,
  "provider_cost_usd": 0.0067485,
  "duration_s": 29.12,
  "avg_latency_ms": 1261.19,
  "p50_latency_ms": 1180.77,
  "p95_latency_ms": 3104.49,
  "p99_latency_ms": 4207.98,
  "max_latency_ms": 4293.46,
  "chain_valid": true
}
```

Notes:

- The run used the real OpenAI API with `gpt-4o-mini`, not the mock provider.
- The measured provider cost was approximately `$0.031` per 1,000 calls for
  this workload (`$0.00674850 / 216 calls`). At 100,000 similar calls per month,
  raw model cost would be about `$3.12` before infrastructure and margin.
- Tenants rotated across `tenant_a` through `tenant_e`; every call used a
  per-request session ID to avoid false-positive write-chain buildup.
- The harness executed 18 actual read-only public page fetches after ToolGuard
  allowed the `fetch_public_page` schema.
- SSRF variants using `169.254.169.254` were blocked before any network call.
- Consequential actions such as email, LinkedIn posting, and full
  `scrape_company_site` remain HITL-gated. Slack was intentionally disabled for
  this load run, so those decisions timed out to `hitl=idle`; the separate
  Slack UI test above validates live approval/denial.
- This is useful beta evidence. It is not a formal pen-test, third-party
  red-team, or production SLA load test.

## Real LLM Provider Smoke Tests

Result: **passed**

OpenAI live API:

```json
{
  "provider": "openai",
  "model": "gpt-5.5-2026-04-23",
  "direct_latency_ms": 6461.61,
  "pipeline_blocked": false,
  "pipeline_hitl": "auto",
  "pipeline_latency_ms": 4644.49,
  "pipeline_hash_len": 64
}
```

Notes:

- The smoke test used the key from local `.env.live`; no secret is published.
- Live testing exposed a compatibility issue: newer OpenAI models reject
  `max_tokens` and require `max_completion_tokens`. The provider now retries
  with the newer parameter when OpenAI returns that explicit error.

Local Ollama:

```json
{
  "provider": "ollama",
  "model": "qwen2.5:1.5b",
  "direct_latency_ms": 3205.62,
  "pipeline_blocked": false,
  "pipeline_hitl": "auto",
  "pipeline_latency_ms": 907.19,
  "pipeline_hash_len": 64
}
```

Notes:

- Installed local models at test time: `qwen2.5:1.5b` and
  `nomic-embed-text:latest`.
- First cold Ollama load can exceed the default 15s reliability timeout; warm
  the model before release smoke tests or configure a longer timeout in the
  host application.

## Dynamic Feed Agent Workflow

Result: **passed**

This workflow generates fresh runtime feed items instead of replaying one static
prompt list: vendor invoices, support notes with PII, retrieved tool-output
injection, privileged-role exfiltration, controlled-substance synthesis, and
ToolGuard payment attempts.

Commands:

```text
python examples/dynamic_feed_agent.py --provider mock --reset-db --report test-results/dynamic_feed_agent_mock.json --db test-results/dynamic_feed_agent_mock.db
python examples/dynamic_feed_agent.py --provider mock --reset-db --report test-results/dynamic_feed_agent_mock_repeat.json --db test-results/dynamic_feed_agent_mock_repeat.db
python examples/dynamic_feed_agent.py --provider ollama --ollama-model qwen2.5:1.5b --reset-db --report test-results/dynamic_feed_agent_ollama_qwen.json --db test-results/dynamic_feed_agent_ollama_qwen.db
```

Results:

```text
mock run #1: 8/8 passed, chain_valid=True, seed=1663236727
mock run #2: 8/8 passed, chain_valid=True, seed=1617985603
ollama/qwen2.5:1.5b: 8/8 passed, chain_valid=True, seed=1208745367
```

The JSON reports preserve exact generated prompts, tool arguments, ToolGuard
decisions, response hashes, layer events, and RCA summaries. They are stored
under ignored local `test-results/` because they are generated artifacts, not
source-controlled release docs.

## Red-team Benchmark

Command:

```text
python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999
```

```text
attacks_bypassed: 0
attacks_caught: 200
attacks_total: 200
bypass_rate: 0.0
false_positive_rate: 0.0
mode: dynamic
seed: 999
```

Additional local sweep: seeds 1 through 10, 100 dynamic prompts each, all
reported 0 bypasses and 0 false positives against the bundled benign set.

This is intentionally published as a dynamic smoke test only. Passing it does
not prove resistance against novel or third-party jailbreak sets.

## Not Run Here

- External penetration test.
- Mainnet Ethereum anchoring.
