"""Contract checks for the GitHub-hosted Claude Code marketplace."""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_marketplace_references_the_guard_plugin_inside_the_repository():
    marketplace = json.loads(
        (ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8")
    )
    assert marketplace["name"] == "pramagent"
    entry = marketplace["plugins"][0]
    assert entry["name"] == "pramagent-guard"
    assert entry["source"] == "./plugins/pramagent-guard"
    assert entry["version"] == "0.1.4"

    plugin = json.loads(
        (ROOT / "plugins" / "pramagent-guard" / ".claude-plugin" / "plugin.json").read_text(
            encoding="utf-8"
        )
    )
    assert plugin["version"] == entry["version"]
    assert not (ROOT / "plugins" / "pramagent-guard" / ".claude-plugin" / "marketplace.json").exists()
