"""Contract checks for the GitHub-installable Gemini CLI extension."""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_gemini_extension_manifest_uses_the_hook_bundle_version():
    manifest = json.loads((ROOT / "gemini-extension.json").read_text(encoding="utf-8"))
    assert manifest["name"] == "pramagent"
    assert manifest["version"] == "0.1.3"


def test_gemini_extension_registers_the_fail_closed_bootstrap():
    config = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    hook = config["hooks"]["BeforeTool"][0]["hooks"][0]
    assert hook["type"] == "command"
    assert "hook_bootstrap.py" in hook["command"]
    assert "--host gemini" in hook["command"]
    assert "--script" in hook["command"]
    assert "args" not in hook
