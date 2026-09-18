"""Tests for the admin hook-control console (deploy/dashboard/app.py + the
pramagent.hook_admin backend it drives).

Covers: admin-only access, surface + tool toggles persisting through the
SHA-256 hash-chained audit, policy upsert/validation, and CSRF enforcement.
"""
import pytest

dashboard = pytest.importorskip("deploy.dashboard.app")
from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(autouse=True)
def _temp_hook_config(monkeypatch, tmp_path):
    monkeypatch.setenv("PRAMAGENT_HOOK_STATE_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.setenv("PRAMAGENT_HOOK_ADMIN_AUDIT_DB", str(tmp_path / "audit.db"))
    yield


def _login_admin(monkeypatch, tenant="tenant_a"):
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_KEY", "secret")
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_TENANT", tenant)
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_SECURE_COOKIE", False)
    monkeypatch.setattr(dashboard, "PRAMAGENT_DASHBOARD_ALLOW_SHARED_KEY_LOGIN", True)
    dashboard._revoked_sessions.clear()
    client = TestClient(dashboard.app)
    page = client.get("/login")
    csrf = page.text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    login = client.post(
        "/login",
        data={"username": "alice", "password": "secret", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert login.status_code == 302
    payload = dashboard._verify(login.cookies["pramagent_session"])
    return client, payload["csrf"]


def test_admin_role_required_for_console():
    for role in ("viewer", "auditor", "approver"):
        ctx = dashboard.AuthContext("alice", "tenant_a", role=role)
        with pytest.raises(HTTPException) as exc:
            dashboard._require_admin_role(ctx)
        assert exc.value.status_code == 403
    dashboard._require_admin_role(dashboard.AuthContext("alice", "tenant_a", role="admin"))


def test_console_page_lists_surfaces(monkeypatch):
    client, _ = _login_admin(monkeypatch)
    page = client.get("/hooks")
    assert page.status_code == 200
    assert "Hook control console" in page.text
    for surface in ("claude", "gemini", "codex", "plugin"):
        assert surface in page.text
    assert "Default" in page.text
    assert "Agent" in page.text


def test_toggle_surface_persists_and_audits(monkeypatch):
    from pramagent import hook_admin, hook_state

    client, csrf = _login_admin(monkeypatch)
    resp = client.post(
        "/hooks/surface/claude",
        data={"enabled": "false", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert hook_state.is_enabled("claude") is False
    assert hook_state.is_enabled("gemini") is True  # isolated
    # audit chain recorded the change and still verifies
    audit = hook_admin.read_audit(5)
    assert any(a["action"] == "set_surface_enabled" for a in audit)
    assert audit[0]["actor"] == "dashboard:alice"
    assert hook_admin.verify_chain() is True


def test_toggle_tool_blocks_it(monkeypatch):
    from pramagent import hook_state

    client, csrf = _login_admin(monkeypatch)
    resp = client.post(
        "/hooks/tool",
        data={"tool": "Bash", "enabled": "false", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert hook_state.tool_enabled("Bash") is False


def test_upsert_policy_and_reject_invalid(monkeypatch):
    from pramagent import hook_state

    client, csrf = _login_admin(monkeypatch)
    # valid policy
    ok = client.post(
        "/hooks/policy",
        data={
            "policy_json": '{"name": "CustomTool", "side_effect": "write", "schema": {"type": "object"}}',
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert ok.status_code == 303
    assert "error" not in (ok.headers.get("location", ""))
    assert any(p["name"] == "CustomTool" for p in hook_state.get_policies() or [])

    # invalid policy (missing schema) -> redirected back with an error, not saved
    bad = client.post(
        "/hooks/policy",
        data={"policy_json": '{"name": "Bad"}', "csrf_token": csrf},
        follow_redirects=False,
    )
    assert bad.status_code == 303
    assert "error" in bad.headers.get("location", "")
    assert not any(p["name"] == "Bad" for p in hook_state.get_policies() or [])


def test_delete_policy(monkeypatch):
    from pramagent import hook_admin, hook_state

    client, csrf = _login_admin(monkeypatch)
    hook_admin.upsert_policy(
        {"name": "Temp", "side_effect": "read", "schema": {"type": "object"}}, actor="seed")
    resp = client.post(
        "/hooks/policy/Temp/delete",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert not any(p["name"] == "Temp" for p in hook_state.get_policies() or [])


def test_delete_default_override_restores_shipped_policy(monkeypatch):
    from pramagent import hook_admin, hook_state

    default = {
        policy["name"]: policy for policy in hook_state.get_default_policies()
    }["Read"]
    hook_admin.upsert_policy(
        {
            "name": "Read",
            "action": "block",
            "side_effect": "read",
            "schema": {"type": "object", "additionalProperties": False},
        },
        actor="seed",
    )
    client, csrf = _login_admin(monkeypatch)
    response = client.post(
        "/hooks/policy/Read/delete",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    effective = {policy["name"]: policy for policy in hook_state.get_policies()}
    assert response.status_code == 303
    assert effective["Read"] == default


def test_admin_can_select_full_policy_replacement(monkeypatch):
    from pramagent import hook_state

    client, csrf = _login_admin(monkeypatch)
    response = client.post(
        "/hooks/policy-mode",
        data={"policy_mode": "replace", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert hook_state.get_policy_mode() == "replace"
    assert hook_state.get_policies() == []


def test_csrf_required_for_toggle(monkeypatch):
    client, _ = _login_admin(monkeypatch)
    resp = client.post(
        "/hooks/surface/claude",
        data={"enabled": "false", "csrf_token": "wrong"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


def test_upsert_tenant_permissions(monkeypatch):
    from pramagent import hook_state

    client, csrf = _login_admin(monkeypatch)
    resp = client.post(
        "/hooks/tenant",
        data={
            "tenant_id": "acme",
            "enabled": "true",
            "allowed_tools": "Read, Grep, Glob",
            "denied_tools": "Bash",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert hook_state.tenant_tool_allowed("acme", "Read") is True
    assert hook_state.tenant_tool_allowed("acme", "Bash") is False


def test_upsert_tenant_rejects_unknown_tool(monkeypatch):
    from pramagent import hook_state

    client, csrf = _login_admin(monkeypatch)
    resp = client.post(
        "/hooks/tenant",
        data={"tenant_id": "beta", "enabled": "true",
              "allowed_tools": "NotATool", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error" in resp.headers.get("location", "")
    assert "beta" not in hook_state.get_tenants()


def test_delete_tenant(monkeypatch):
    from pramagent import hook_admin, hook_state

    client, csrf = _login_admin(monkeypatch)
    hook_admin.upsert_tenant("temp", allowed_tools=["Read"], actor="seed")
    resp = client.post(
        "/hooks/tenant/temp/delete",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "temp" not in hook_state.get_tenants()


def test_admin_can_restore_a_prior_hook_config(monkeypatch):
    from pramagent import hook_admin, hook_state

    client, csrf = _login_admin(monkeypatch)
    hook_admin.set_surface_enabled("claude", False, actor="seed")
    target_hash = hook_admin.read_audit(1)[0]["this_hash"]
    hook_admin.set_surface_enabled("claude", True, actor="seed")

    response = client.post(
        "/hooks/rollback",
        data={"target_hash": target_hash, "csrf_token": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert hook_state.is_enabled("claude") is False
    assert hook_admin.read_audit(1)[0]["actor"] == "dashboard:alice"
