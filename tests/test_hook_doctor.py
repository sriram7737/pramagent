from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from pramagent.hook_doctor import inspect_hooks


_RUNTIME_FILES = (
    "pramagent/hook_scan.py",
    "pramagent/hook_state.py",
    "scripts/hook_bootstrap.py",
    "scripts/claude_code_hook.py",
    "scripts/gemini_cli_hook.py",
    "scripts/codex_tool_hook.py",
    "plugins/pramagent-guard/hooks/hooks.json",
    "plugins/pramagent-guard/hooks/codex_hooks.json",
    "plugins/pramagent-guard/hooks/scripts/pramagent_guard.py",
    "plugins/pramagent-guard/policies.json",
)


def _tree(root: Path) -> Path:
    hashes = {}
    for relative in _RUNTIME_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"runtime:{relative}\n", encoding="utf-8")
        hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = root / "pramagent" / "hook_integrity.json"
    manifest.write_text(json.dumps({"algorithm": "sha256", "files": hashes}))
    return manifest


def test_doctor_detects_runtime_tampering(tmp_path):
    manifest = _tree(tmp_path)
    target = tmp_path / "scripts" / "claude_code_hook.py"
    target.write_text("print('{}')\n", encoding="utf-8")

    report = inspect_hooks(
        repo_root=tmp_path,
        home=tmp_path / "home",
        manifest_path=manifest,
    )

    check = next(c for c in report.checks if c.name.endswith("claude_code_hook.py"))
    assert check.status == "fail"
    assert report.healthy is False


def test_doctor_recognizes_fail_closed_host_wiring(tmp_path):
    manifest = _tree(tmp_path)
    config = tmp_path / ".claude" / "settings.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({
        "hooks": {
            "PreToolUse": [{
                "matcher": ".*",
                "hooks": [{
                    "args": [
                        "scripts/hook_bootstrap.py",
                        "--script",
                        "scripts/claude_code_hook.py",
                    ]
                }],
            }]
        }
    }), encoding="utf-8")

    report = inspect_hooks(
        repo_root=tmp_path,
        home=tmp_path / "home",
        manifest_path=manifest,
    )

    check = next(c for c in report.checks if c.name == "claude.configuration")
    assert check.status == "ok"
    assert check.path == str(config)


def test_doctor_marks_malformed_host_config_as_failure(tmp_path):
    manifest = _tree(tmp_path)
    config = tmp_path / ".gemini" / "settings.json"
    config.parent.mkdir(parents=True)
    config.write_text("{broken", encoding="utf-8")

    report = inspect_hooks(
        repo_root=tmp_path,
        home=tmp_path / "home",
        manifest_path=manifest,
    )

    check = next(c for c in report.checks if c.name == "gemini.configuration")
    assert check.status == "fail"


def test_hooks_doctor_cli_emits_machine_readable_report(tmp_path):
    env = {
        **os.environ,
        "PRAMAGENT_HOOK_STATE_PATH": str(tmp_path / "state.json"),
        "PRAMAGENT_HOOK_ADMIN_AUDIT_DB": str(tmp_path / "audit.db"),
    }
    result = subprocess.run(
        [sys.executable, "-m", "pramagent.cli", "hooks-doctor", "--json"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["healthy"] is True
    assert any(check["name"] == "runtime.manifest" for check in payload["checks"])
