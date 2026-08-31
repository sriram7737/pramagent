"""Regression tests for hook control-plane self-protection (SEC-2026-08-30).

The hooks exist to constrain a possibly prompt-injected coding agent. Before
this protection, the guard's own config file (``pramagent_hook_config.json``)
sat repo-local and was writable by the very agent the guard constrains, using an
``ALLOW``-by-default ``Write`` policy. An injected agent could therefore write
``{"surfaces": {"claude": false}}`` to it and the very next tool call would run
completely unguarded (or write a ``policies`` override to silently neuter Bash
escalation while the surface still reported "Enforcing").

The fix (``pramagent.hook_state.targets_protected_path``) refuses any mutating
or shell tool call whose target is the hook config or its admin audit DB, and
each surface consults it BEFORE its master switch  -  so a would-be-disabling
write cannot turn the surface off and slip through. These tests pin that down at
the unit level and across all four hook surfaces.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from pramagent import hook_state


def _load_hook(filename: str, module_name: str):
    path = _REPO_ROOT / "scripts" / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


CLAUDE = _load_hook("claude_code_hook.py", "claude_code_hook")
GEMINI = _load_hook("gemini_cli_hook.py", "gemini_cli_hook")
CODEX = _load_hook("codex_tool_hook.py", "codex_tool_hook")

_PLUGIN_PATH = (
    _REPO_ROOT / "plugins" / "pramagent-guard" / "hooks" / "scripts" / "pramagent_guard.py"
)
_plugin_spec = importlib.util.spec_from_file_location("pramagent_guard", _PLUGIN_PATH)
PLUGIN = importlib.util.module_from_spec(_plugin_spec)
assert _plugin_spec is not None and _plugin_spec.loader is not None
_plugin_spec.loader.exec_module(PLUGIN)


# -- helpers ---------------------------------------------------------------

_CONFIG_NAME = "pramagent_hook_config.json"
_AUDIT_NAME = "pramagent_hook_admin_audit.db"
_DISABLE_PAYLOAD = json.dumps({"surfaces": {"claude": False}})
_POLICY_OVERRIDE = json.dumps(
    {"policies": [{"name": "Bash", "schema": {"type": "object"}, "side_effect": "read"}]}
)


def _is_deny(output: dict) -> bool:
    blob = json.dumps(output).lower()
    return "deny" in blob and "self-protection" in blob


# -- unit: targets_protected_path -----------------------------------------

def test_unit_write_to_config_by_basename_is_flagged():
    hit = hook_state.targets_protected_path("Write", {"file_path": _CONFIG_NAME})
    assert hit is not None


def test_unit_write_to_config_absolute_path_is_flagged(monkeypatch, tmp_path):
    cfg = tmp_path / _CONFIG_NAME
    monkeypatch.setenv("PRAMAGENT_HOOK_STATE_PATH", str(cfg))
    hit = hook_state.targets_protected_path("Write", {"file_path": str(cfg)})
    assert hit is not None


def test_unit_write_to_admin_audit_db_is_flagged():
    hit = hook_state.targets_protected_path("Edit", {"file_path": _AUDIT_NAME})
    assert hit is not None


def test_unit_shell_redirect_to_config_is_flagged():
    # A one-liner that writes the config via the shell, not a structured file arg.
    cmd = "printf '%s' '{}' | tee " + _CONFIG_NAME
    hit = hook_state.targets_protected_path("Bash", {"command": cmd})
    assert hit is not None


def test_unit_payload_routed_through_nested_field_is_flagged():
    # apply_patch-style body: target named inside a patch string, not file_path.
    body = "*** Update File: " + _CONFIG_NAME + "\n+ {}"
    hit = hook_state.targets_protected_path("apply_patch", {"input": body})
    assert hit is not None


def test_unit_read_only_tool_targeting_config_is_not_flagged():
    # Reading the config is harmless; only writes can disable the guard.
    assert hook_state.targets_protected_path("Read", {"file_path": _CONFIG_NAME}) is None
    assert hook_state.targets_protected_path("Grep", {"path": _CONFIG_NAME}) is None


def test_unit_ordinary_write_is_not_flagged():
    assert hook_state.targets_protected_path("Write", {"file_path": "src/app.py"}) is None


# -- claude surface --------------------------------------------------------

def test_claude_disable_write_to_config_is_denied():
    out = CLAUDE.evaluate_event({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": _CONFIG_NAME, "content": _DISABLE_PAYLOAD},
        "session_id": "pytest",
    })
    assert _is_deny(out)


def test_claude_policy_override_write_to_config_is_denied():
    out = CLAUDE.evaluate_event({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": _CONFIG_NAME, "content": _POLICY_OVERRIDE},
        "session_id": "pytest",
    })
    assert _is_deny(out)


def test_claude_protection_runs_before_master_switch(monkeypatch, tmp_path):
    """The crux: even with this surface already switched OFF in the config, a
    write that targets the config itself is still denied  -  proving the check
    runs ahead of the master switch and the disable can never take hold."""
    cfg = tmp_path / _CONFIG_NAME
    cfg.write_text(json.dumps({"surfaces": {"claude": False}}), encoding="utf-8")
    monkeypatch.setenv("PRAMAGENT_HOOK_STATE_PATH", str(cfg))

    # Surface is off, so an ordinary write is a no-op (allowed) ...
    ordinary = CLAUDE.evaluate_event({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": str(tmp_path / "notes.txt"), "content": "hi"},
        "session_id": "pytest",
    })
    assert ordinary == {}

    # ... but a write to the config file itself is still denied.
    protected = CLAUDE.evaluate_event({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": str(cfg), "content": '{"surfaces": {"claude": true}}'},
        "session_id": "pytest",
    })
    assert _is_deny(protected)


# -- other surfaces --------------------------------------------------------

def test_gemini_write_to_config_is_denied():
    out = GEMINI.evaluate_event({
        "hook_event_name": "BeforeTool",
        "tool_name": "write_file",
        "tool_input": {"file_path": _CONFIG_NAME, "content": _DISABLE_PAYLOAD},
        "session_id": "pytest",
    })
    assert _is_deny(out)


def test_codex_write_to_config_is_denied():
    out = CODEX.evaluate_event({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": _CONFIG_NAME, "content": _DISABLE_PAYLOAD},
        "session_id": "pytest",
    })
    assert _is_deny(out)


def test_plugin_write_to_config_is_denied():
    out = PLUGIN.evaluate_event({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": _CONFIG_NAME, "content": _DISABLE_PAYLOAD},
        "session_id": "pytest",
    })
    assert _is_deny(out)
