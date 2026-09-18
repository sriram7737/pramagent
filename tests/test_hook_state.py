"""Tests for the central hook config (pramagent.hook_state) and that the hooks
honor it — with emphasis on the fail-safe property: a missing, corrupt, or
partial config must never silently drop enforcement.
"""
import importlib.util
import json
from pathlib import Path

import pytest

from pramagent import hook_admin, hook_state

_CLAUDE_HOOK = Path(__file__).resolve().parents[1] / "scripts" / "claude_code_hook.py"
_CODEX_HOOK = Path(__file__).resolve().parents[1] / "scripts" / "codex_tool_hook.py"
_GEMINI_HOOK = Path(__file__).resolve().parents[1] / "scripts" / "gemini_cli_hook.py"
_PLUGIN_HOOK = (
    Path(__file__).resolve().parents[1]
    / "plugins" / "pramagent-guard" / "hooks" / "scripts" / "pramagent_guard.py"
)


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


def _load_hook(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
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
    policies = hook_state.get_policies()
    assert policies
    assert {policy["name"] for policy in policies} >= {"Bash", "Read", "Agent"}


def test_default_policies_are_closed_and_valid():
    from pramagent.policies import tool_policy_from_dict

    policies = hook_state.get_default_policies()
    assert len(policies) == len({policy["name"] for policy in policies})
    assert all(policy["schema"]["additionalProperties"] is False for policy in policies)
    assert all(tool_policy_from_dict(policy) for policy in policies)


def test_user_policy_overrides_default_by_name():
    hook_admin.upsert_policy(
        {
            "name": "Read",
            "side_effect": "read",
            "action": "block",
            "schema": {"type": "object", "additionalProperties": False},
        },
        actor="t",
    )
    policies = {policy["name"]: policy for policy in hook_state.get_policies()}
    assert policies["Read"]["action"] == "block"
    assert len([policy for policy in hook_state.get_policies() if policy["name"] == "Read"]) == 1


def test_new_user_policy_extends_defaults_and_delete_restores_default():
    default_bash = {
        policy["name"]: policy for policy in hook_state.get_default_policies()
    }["Bash"]
    hook_admin.upsert_policy(
        {
            "name": "MyCustomTool",
            "side_effect": "read",
            "schema": {"type": "object", "additionalProperties": False},
        },
        actor="t",
    )
    hook_admin.upsert_policy(
        {
            "name": "Bash",
            "side_effect": "destructive",
            "action": "block",
            "schema": {"type": "object", "additionalProperties": False},
        },
        actor="t",
    )
    assert {policy["name"] for policy in hook_state.get_policies()} >= {
        "Bash",
        "MyCustomTool",
    }

    hook_admin.delete_policy("Bash", actor="t")
    effective = {policy["name"]: policy for policy in hook_state.get_policies()}
    assert effective["Bash"] == default_bash
    assert {policy["name"] for policy in hook_state.get_policy_overrides()} == {
        "MyCustomTool"
    }


def test_missing_custom_default_file_keeps_adapter_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "PRAMAGENT_HOOK_DEFAULT_CONFIG", str(tmp_path / "missing-default.json")
    )
    assert hook_state.get_default_policies() == []
    assert hook_state.get_policies() == []


def test_replace_mode_uses_only_user_policies_across_all_hooks(monkeypatch, tmp_path):
    custom = {
        "name": "MyCustomTool",
        "side_effect": "read",
        "schema": {"type": "object", "additionalProperties": False},
    }
    hook_admin.upsert_policy(custom, actor="t")
    hook_admin.set_policy_mode("replace", actor="t")
    monkeypatch.setenv("PRAMAGENT_GEMINI_HOOK_AUDIT_DB", str(tmp_path / "gemini.db"))

    hooks = [
        (_load_claude_hook(), "PreToolUse", "Read"),
        (_load_hook(_CODEX_HOOK, "codex_replace"), "PreToolUse", "Read"),
        (_load_hook(_GEMINI_HOOK, "gemini_replace"), "BeforeTool", "read_file"),
        (_load_hook(_PLUGIN_HOOK, "plugin_replace"), "PreToolUse", "Read"),
    ]
    for hook, event_name, built_in_name in hooks:
        allowed = hook.evaluate_event({
            "hook_event_name": event_name,
            "tool_name": "MyCustomTool",
            "tool_input": {},
            "session_id": "pytest",
        })
        denied = hook.evaluate_event({
            "hook_event_name": event_name,
            "tool_name": built_in_name,
            "tool_input": {"file_path": "README.md"},
            "session_id": "pytest",
        })
        assert allowed == {}
        assert denied.get("decision") == "deny" or (
            denied.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
        )
        assert "not registered" in str(denied)


def test_invalid_policy_mode_is_rejected():
    with pytest.raises(ValueError, match="policy mode"):
        hook_admin.set_policy_mode("merge-ish", actor="t")


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


# tenant permissions
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


def test_out_of_band_config_edit_fails_closed():
    hook_admin.set_surface_enabled("claude", True, actor="dashboard:admin")
    path = Path(hook_state.state_path())
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["surfaces"]["claude"] = False
    path.write_text(json.dumps(raw), encoding="utf-8")

    valid, reason = hook_state.integrity_status()
    assert valid is False
    assert "latest audited state" in reason
    assert hook_state.is_enabled("claude") is True
    with pytest.raises(RuntimeError, match="integrity check failed"):
        hook_admin.set_tool_enabled("Bash", False, actor="dashboard:admin")


def test_admin_change_records_matching_state_hash():
    result = hook_admin.set_tool_enabled("Bash", False, actor="dashboard:admin")
    latest = hook_admin.read_audit(1)[0]

    assert latest["detail"]["state_hash"] == hook_state.state_digest(result["state"])
    assert hook_state.integrity_status() == (True, "verified")


def test_deleted_audit_history_makes_config_fail_closed():
    hook_admin.set_surface_enabled("claude", False, actor="dashboard:admin")
    Path(hook_state.audit_path()).unlink()

    valid, reason = hook_state.integrity_status()
    assert valid is False
    assert "no audit history" in reason
    assert hook_state.is_enabled("claude") is True


def test_unsigned_hook_admin_mutation_is_refused(monkeypatch):
    monkeypatch.delenv("PRAMAGENT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("PRAMAGENT_SIGNING_KEYS", raising=False)

    with pytest.raises(RuntimeError, match="PRAMAGENT_SIGNING_KEY"):
        hook_admin.set_surface_enabled("claude", False, actor="dashboard:admin")
    assert not Path(hook_state.state_path()).exists()


def test_legacy_config_requires_deliberate_binding():
    path = Path(hook_state.state_path())
    path.write_text(json.dumps({"surfaces": {"claude": False}}), encoding="utf-8")

    assert hook_state.is_enabled("claude") is True
    hook_admin.bind_legacy_state(actor="dashboard:admin")
    assert hook_state.integrity_status() == (True, "verified")
    assert hook_state.is_enabled("claude") is False


def test_empty_audit_actor_is_refused():
    with pytest.raises(ValueError, match="authenticated actor"):
        hook_admin.set_surface_enabled("claude", False, actor="")


def test_rollback_restores_snapshot_without_rewriting_history():
    hook_admin.set_surface_enabled("claude", False, actor="alice")
    target = hook_admin.read_audit(1)[0]
    hook_admin.set_surface_enabled("claude", True, actor="bob")

    result = hook_admin.rollback_config(target["this_hash"], actor="carol")

    assert result["state"]["surfaces"]["claude"] is False
    latest = hook_admin.read_audit(1)[0]
    assert latest["action"] == "rollback_config"
    assert latest["actor"] == "carol"
    assert latest["detail"]["target_chain_hash"] == target["this_hash"]
    assert hook_admin.verify_chain() is True
    assert len(hook_admin.read_audit(10)) == 3


def test_rollback_rejects_unknown_target():
    hook_admin.set_surface_enabled("claude", False, actor="alice")
    with pytest.raises(ValueError, match="restorable state"):
        hook_admin.rollback_config("not-a-real-hash", actor="carol")


def test_stale_control_plane_update_is_rejected():
    first = hook_state._state_for_update()
    stale = hook_state._state_for_update()
    first["surfaces"]["claude"] = False
    hook_admin._commit(first, action="test", actor="alice", detail={})
    stale["surfaces"]["gemini"] = False

    with pytest.raises(RuntimeError, match="changed during this update"):
        hook_admin._commit(stale, action="test", actor="bob", detail={})
