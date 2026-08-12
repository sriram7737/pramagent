# Release Checklist

Use this checklist for public releases.

## Preflight

```bash
python -m pip install -U build twine
python -m pip install -e ".[dev,api,redis,postgres,dashboard]"
pramagent --help
python -m compileall -q pramagent tests
python -m pytest -q --tb=no
python scripts/test_agent_v2.py --mock --suite load tenant regression --report test-results/test_agent_v2_mock.json
python examples/dynamic_feed_agent.py --provider mock --reset-db --report test-results/dynamic_feed_agent_mock.json
python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999
```

Clean-environment check:

```bash
python -m venv %TEMP%/pramagent-release-venv
%TEMP%/pramagent-release-venv/Scripts/python -m pip install -U pip setuptools wheel
%TEMP%/pramagent-release-venv/Scripts/python -m pip install -e ".[dev,api,otel]"
%TEMP%/pramagent-release-venv/Scripts/python -m pytest -q --tb=no
```

Optional extras install check:

```bash
python -m pip install "dist/pramagent-0.8.7-py3-none-any.whl[all]"
python - <<'PY'
import anthropic, aiohttp, fastapi, uvicorn, jinja2, httpx, cryptography
import opentelemetry, redis, psycopg, web3, boto3
print("all extras import smoke passed")
PY
```

Confirm the version matches in:

- `pyproject.toml`
- `pramagent/__init__.py`
- `pramagent/api/app.py`

Confirm the release positioning:

- PyPI classifier is `Development Status :: 3 - Alpha`.
- README/PyPI long description contains the Alpha maturity notice.
- README and implementation status call out known limits: Slack-first HITL
  decisions, no SSO/OIDC/RBAC, Sepolia/testnet anchoring maturity, scale/load
  gaps, and incomplete third-party prompt-injection assurance.
- Release notes reference `docs/LIVE_TEST_RESULTS.md`.
- `docs/IMPLEMENTATION_STATUS.md` and `docs/HARDENING_GUIDE.md` are included
  in the built artifacts.
- QuantumLayer is described only as future research, not as an exposed feature.

## Trusted Publishing Setup

Pramagent is configured for PyPI Trusted Publishing through
`.github/workflows/publish.yml`. This removes the need to store or paste a PyPI
API token during normal releases.

One-time PyPI project setup:

- Go to the `pramagent` project on PyPI.
- Add a GitHub Trusted Publisher with:
  - Owner: `sriram7737`
  - Repository name: `pramagent`
  - Workflow filename: `publish.yml`
  - Environment name: `pypi`
- In GitHub repository settings, create an environment named `pypi`.
- Recommended: require a manual reviewer on the `pypi` environment so a
  compromised push cannot publish without approval.

The publish workflow uses OIDC through `pypa/gh-action-pypi-publish@release/v1`
with `id-token: write`. It runs on GitHub Release publish, manual dispatch, or
`v*` tag push. Do not add `TWINE_PASSWORD`, `PYPI_API_TOKEN`, or other PyPI
credentials to this workflow.

## Branch Protection

`.github/CODEOWNERS` is checked in (`* @sriram7737`), but a CODEOWNERS file
by itself does not require review — GitHub still allows a direct push or an
unreviewed merge to `main` unless branch protection is turned on. This is a
GitHub repository setting, not something a commit to this repo can enable
(ISSUE-13). One-time setup, done outside this repo:

- GitHub -> repository Settings -> Branches -> add a branch protection rule
  for `main`.
- Enable "Require a pull request before merging."
- Enable "Require review from Code Owners."
- Enable "Require approvals" (at least 1).
- Consider "Do not allow bypassing the above settings" so it also applies
  to admins, not just external contributors.

Until this is enabled, treat `main` as protected by convention/discipline
only, not by an enforced control — do not cite required-review as a
control in a compliance mapping or audit response until it is actually
configured.

## Build

```bash
python -m build
python -m twine check dist/*
```

## GitHub

```bash
git status --short
git tag -a v0.8.7 -m "v0.8.7"
git push origin main
git push origin v0.8.7
```

Create a GitHub Release from tag `v0.8.7` and include:

- Test result: `975 passed, 6 skipped`
- Public-demo output-judge result: `OutputJudgeLayer` on by default, visible
  policy toggle in `/demo`, keylogger/bypass/destructive-output class withheld,
  reference `/v1/run` opt-in via `PRAMAGENT_OUTPUT_JUDGE=1`
- Security prompt remediation result: `SEC-2026-06-11-01` and
  `SEC-2026-06-11-02` closed in commits `085c7b4` and `e8392aa`; evidence in
  `docs/audits/pramagent_security_test_results.md`
- Enterprise audit remediation result: 2 P0, 10 P1, 18 P2, and 20 P3 findings
  closed or explicitly deferred with reasons in `docs/audits/pramagent_full_audit.md`
- Rule corpus result: 129 importable deterministic rules
- Persistent HITL queue result: in-memory/SQLite/Postgres backends packaged
- Framework adapters result: LangGraph, AutoGen, CrewAI, and generic helpers packaged
- ComplianceReporter.generate result: JSON/text/PDF-style evidence generation packaged
- Test-agent v2 result: `57/57 passed`
- Dynamic feed agent result: mock `8/8 passed`, Ollama `qwen2.5:1.5b` `8/8 passed`
- Dynamic red-team result: `200/200 caught`, seed `999`
- Encoded-payload and multilingual hardening result: hex/unicode-escape
  injection blocked; targeted fr/es/de/hi override phrases and
  override-confirmation tokens blocked; public demo must be redeployed to pick
  up the v0.8.7 runtime.
- Dashboard evidence result: screenshots for allowed, PII-scrubbed, injection
  blocked, destructive-DB blocked, and HITL-held paths, plus engine-latency
  metrics separated from HITL wait time.
- Live OpenAI payment-agent workflow result from `docs/LIVE_WORKFLOW_DEMO.md`
- Real OpenAI + local Ollama smoke-test results from `docs/LIVE_TEST_RESULTS.md`
- Real OpenAI job-agent load result: 216 calls, five tenants, concurrency 10,
  18 real read-only fetches, `$0.031` per 1,000 calls under the measured workload
- Live Sepolia transaction hash from `docs/LIVE_TEST_RESULTS.md`
- S3 archive/restore smoke result from `docs/LIVE_TEST_RESULTS.md`
- Links to `docs/IMPLEMENTATION_STATUS.md` and `docs/HARDENING_GUIDE.md`
- Honest limits: Alpha maturity, no external pen test, no SSO/OIDC/RBAC, no
  regulated-production certification
- Confirm GitHub Actions no longer emits the Node.js 20 deprecation warning.
  Workflows opt in with `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true`.

## PyPI

Publishing should happen through the GitHub Actions Trusted Publishing
workflow, not local Twine upload.

Normal release path:

1. Complete the preflight checks above.
2. Push the release commit and tag. The `v*` tag starts Trusted Publishing.
3. Create and publish the GitHub Release for release notes and provenance.
4. Confirm `.github/workflows/publish.yml` completes successfully.
5. Verify the PyPI release page and run the post-release smoke check below.

The PyPI page uses `README.md` as the long description. Do not publish if the
Alpha maturity notice or honest-limits section has been removed.

Token-based local upload is now an emergency fallback only. If used, rotate the
token afterward and document why Trusted Publishing was bypassed.

Use TestPyPI first when validating any new publishing setup:

```bash
python -m twine upload --repository testpypi dist/*
```

## Post-release Smoke

```bash
pip install "pramagent[api,dashboard,redis,postgres]"
pramagent --help
python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999
```
