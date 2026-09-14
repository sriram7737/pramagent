"""Contract checks for the GitHub-installable Codex marketplace."""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_codex_marketplace_exposes_the_guard_plugin_from_the_repo_root():
    marketplace = json.loads(
        (ROOT / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8")
    )
    assert marketplace["name"] == "pramagent"
    entry = marketplace["plugins"][0]
    assert entry["name"] == "pramagent-guard"
    assert entry["source"] == {"source": "local", "path": "./plugins/pramagent-guard"}
