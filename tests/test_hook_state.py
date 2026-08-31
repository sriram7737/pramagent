"""Tests for the central hook config (pramagent.hook_state) and that the hooks
honor it — with emphasis on the fail-safe property: a missing, corrupt, or
partial config must never silently drop enforcement.
"""
import importlib.util
from pathlib import Path

import pytest

from pramagent import hook_admin, hook_state

_CLAUDE_HOOK = Path(__file__).resolve().parents[1] / "scripts" / "claude_code_hook.py"


@pytest.fixture(autouse=True)
def _temp_config(monkeypatch, tmp_path):
    monkeypatch.setenv("PRAMAGENT_HOOK_STATE_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.setenv("PRAMAGENT_HOOK_ADMIN_AUDIT_DB", str(tmp_path / "audit.db"))
    yield


def _load_claude_hook():
    spec = importlib.util.spec_from_file_location("cch_state", _CLAUDE_HOOK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _event(tool_name, tool_input):
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "session_id": "pytest",
    }


def test_missing_config_is_enforcement_on():
    assert hook_state.is_enabled("claude") is True
    assert hook_state.tool_enabled("Bash") is True
    assert hook_state.get_policies() is None


def test_corrupt_config_fails_safe(tmp_path, monkeypatch):
    path = Path(hook_state.state_path())
    path.write_text("{ this is not json", encoding="utf-8")
    assert hook_state.is_enabled("claude") is True   # corrupt -> enabled
    assert hook_state.tool_enabled("Write") is True


def test_only_explicit_false_disables():
    # An unrelated/garbled value must not disable a surface.
    hook_admin.set_surface_enabled("claude", True, actor="t")
    assert hook_state.is_enabled("claude") is True
    hook_admin.set_surface_enabled("claude", False, actor="t")
    assert hook_state.is_enabled("claude") is False


def test_hook_noops_when_surface_disabled():
    hook = _load_claude_hook()
    # unknown tool normally denies; when the surface is disabled it allows
    hook_admin.set_surface_enabled("claude", False, actor="t")
    assert hook.evaluate_event(_event("UnknownMCP", {})) == {}


def test_hook_denies_disabled_tool():
    hook = _load_claude_hook()
    hook_admin.set_tool_enabled("Bash", False, actor="t")
    out = hook.evaluate_event(_event("Bash", {"command": "ls -la"}))
    decision = out.get("hookSpecificOutput", {}).get("permissionDecision")
    assert decision == "deny"
    assert "disabled" in out.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")


def test_central_policy_override_is_applied():
    # Register a brand-new tool via the console; a freshly-loaded hook process
    # must recognize it instead of fail-closed "not registered".
    hook_admin.upsert_policy(
        {"name": "MyCustomTool", "side_effect": "read", "schema": {"type": "object"}},
        actor="t",
    )
    hook = _load_claude_hook()  # fresh load picks up central policies
    out = hook.evaluate_event(_event("MyCustomTool", {}))
    # read side-effect, no findings -> clean allow ({}), NOT "not registered" deny
    assert out == {}


def test_unknown_surface_toggle_rejected():
    with pytest.raises(ValueError):
        hook_admin.set_surface_enabled("nonexistent", False, actor="t")


# ── tenant permissions ──────────────────────────────────────────────────────

def test_unmanaged_tenant_is_unrestricted():
    assert hook_state.tenant_tool_allowed("never-configured", "Bash") is True


def test_tenant_allow_list_limits_tools():
    hook_admin.upsert_tenant("acme", allowed_tools=["Read", "Grep"], actor="t")
    assert hook_state.tenant_tool_allowed("acme", "Read") is True
    assert hook_state.tenant_tool_allowed("acme", "Bash") is False


def test_tenant_deny_list_blocks_tool():
    hook_admin.upsert_tenant("beta", allowed_tools=None, denied_tools=["Bash"], actor="t")
    assert hook_state.tenant_tool_allowed("beta", "Write") is True   # all minus denied
    assert hook_state.tenant_tool_allowed("beta", "Bash") is False


def test_disabled_tenant_denied_everything():
    hook_admin.set_tenant_enabled("gamma", False, actor="t")
    assert hook_state.tenant_tool_allowed("gamma", "Read") is False


def test_upsert_tenant_rejects_unknown_tool():
    with pytest.raises(ValueError):
        hook_admin.upsert_tenant("delta", allowed_tools=["NotARealTool"], actor="t")


def test_hook_enforces_tenant_permission(monkeypatch):
    # A hook running as tenant 'acme' that is restricted to Read/Grep must deny Bash.
    hook_admin.upsert_tenant("acme", allowed_tools=["Read", "Grep"], actor="t")
    monkeypatch.setenv("PRAMAGENT_TENANT_ID", "acme")
    hook = _load_claude_hook()  # reads PRAMAGENT_TENANT_ID at import
    out = hook.evaluate_event(_event("Bash", {"command": "ls -la"}))
    decision = out.get("hookSpecificOutput", {}).get("permissionDecision")
    assert decision == "deny"
    assert "not permitted" in out.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")
    # a permitted tool for that tenant still flows normally (Read -> clean allow)
    assert hook.evaluate_event(_event("Read", {"file_path": "a.py"})) == {}


def test_tenant_change_is_audited():
    hook_admin.upsert_tenant("acme", allowed_tools=["Read"], actor="admin@x")
    actions = [a["action"] for a in hook_admin.read_audit(20)]
    assert "upsert_tenant" in actions
    assert hook_admin.verify_chain() is True
