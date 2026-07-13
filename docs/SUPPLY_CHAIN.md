# Supply Chain Security

Pramagent uses lower-bound package metadata for library compatibility, so each
deployment must produce its own lockfile/SBOM from the exact extras it uses.

## Automated in CI

The `pip-audit` job in `.github/workflows/security.yml` runs on every push,
every PR, and weekly on the same schedule as Bandit/Semgrep/ZAP. It installs
`.[all,dev]` constrained by `requirements-security.txt`, runs `pip-audit`
against that resolved environment, and **fails the build on any known
vulnerability** — this is a real CI gate, not just the manual step described
below. It also generates a CycloneDX SBOM as a build artifact on every run.
The commands below remain the source of truth for what CI runs and for
auditing a specific deployment's exact extras/lockfile outside of CI.

## Required For Production

1. Install through `requirements-security.txt` constraints.
2. Generate a lockfile with the deployment toolchain (`uv lock`,
   `pip-compile --generate-hashes`, Poetry, or equivalent).
3. Generate an SBOM from the deployed environment.
4. Run `pip-audit` on the locked dependency set.
5. Block deployment on known high/critical vulnerabilities unless a written
   risk acceptance exists.

## Commands

```bash
python -m pip install -c requirements-security.txt ".[api,postgres,encrypted]"
python -m pip_audit
python -m cyclonedx_py environment -o sbom.cdx.json
```

Store `sbom.cdx.json`, the lockfile, and the `pip-audit` output with release
evidence. Do not claim a dependency scan is clean based only on `pyproject.toml`;
scan the resolved environment.
