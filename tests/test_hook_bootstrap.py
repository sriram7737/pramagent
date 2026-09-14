import json
import subprocess
import sys
from pathlib import Path


_BOOTSTRAP = Path(__file__).resolve().parents[1] / "scripts" / "hook_bootstrap.py"


def _run(host: str, script: Path, payload: str = "{}") -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(_BOOTSTRAP),
            "--host",
            host,
            "--script",
            str(script),
            "--timeout",
            "5",
        ],
        input=payload,
        capture_output=True,
        text=True,
    )


def test_missing_child_fails_closed_for_pretool(tmp_path):
    result = _run("pretool", tmp_path / "missing.py")
    output = json.loads(result.stdout)
    assert result.returncode == 0
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_broken_child_fails_closed_for_gemini(tmp_path):
    child = tmp_path / "broken.py"
    child.write_text("this is invalid python !!!", encoding="utf-8")
    result = _run("gemini", child)
    output = json.loads(result.stdout)
    assert result.returncode == 0
    assert output["decision"] == "deny"


def test_unlisted_child_fails_closed(tmp_path):
    child = tmp_path / "ok.py"
    child.write_text("print('{}')", encoding="utf-8")
    result = _run("pretool", child)
    output = json.loads(result.stdout)
    assert result.returncode == 0
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_manifest_verified_child_output_passes_through():
    child = _BOOTSTRAP.parent / "claude_code_hook.py"
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "README.md"},
        "session_id": "bootstrap-test",
    })

    result = _run("pretool", child, payload)

    assert result.returncode == 0
    assert json.loads(result.stdout) == {}
