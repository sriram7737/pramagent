"""
Tests for API authentication, cross-tenant guard, and retention endpoints.

The critical security test here is `test_cross_tenant_trace_access_blocked`: it
proves a holder of tenant-A's key cannot fetch tenant-B's trace by call_id.
That was the actual bug reported in the analysis.
"""
import datetime as _dt
import json
import sys
import time

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from pramagent.api.app import create_app  # noqa: E402
from pramagent.auth import (  # noqa: E402
    APIKeyRegistry,
    JWTError,
    JWTManager,
    PostgresAPIKeyRegistry,
    _b64url_decode,
    load_registry_from_env,
)


# ── Finding 1.3: admin does not implicitly grant the approve scope ──
def test_admin_scope_does_not_imply_approve():
    from pramagent.auth import (ADMIN_SCOPE, APPROVE_SCOPE, AuthRecord,
                                READ_SCOPE, WRITE_SCOPE)

    admin = AuthRecord(tenant_id="t", scopes=frozenset({ADMIN_SCOPE}))
    # admin still implies the ordinary scopes...
    assert admin.has_scope(READ_SCOPE) is True
    assert admin.has_scope(WRITE_SCOPE) is True
    # ...but NOT approve — that must be held explicitly (separation of duties).
    assert admin.has_scope(APPROVE_SCOPE) is False

    both = AuthRecord(tenant_id="t", scopes=frozenset({ADMIN_SCOPE, APPROVE_SCOPE}))
    assert both.has_scope(APPROVE_SCOPE) is True


# ── unauthenticated mode (empty registry) ──────────────────────────────
def test_unauthenticated_mode_works_when_no_keys_configured():
    """With no keys registered, the API runs open (single-tenant / dev mode)."""
    client = TestClient(create_app(registry=APIKeyRegistry()))
    r = client.post("/v1/run", json={"prompt": "hi", "tenant_id": "t1"})
    assert r.status_code == 200
    # readiness deliberately discloses nothing beyond dependency status
    ready = client.get("/health/ready").json()
    assert ready["status"] == "ready"


# ── authenticated mode ─────────────────────────────────────────────────
# A strong shared JWT secret mirrors production: token issuance refuses to
# mint per-process tokens when no shared secret is configured (P2-12).
_TEST_JWT_SECRET = "unit-test-jwt-secret-0123456789abcdef"


@pytest.fixture
def auth_client(monkeypatch):
    monkeypatch.setenv("PRAMAGENT_JWT_SECRET", _TEST_JWT_SECRET)
    reg = APIKeyRegistry()
    # These keys exercise run/erase/rca, so grant the scopes explicitly.
    # Unscoped keys default to read-only (A1); see
    # test_unscoped_key_defaults_to_read_only for that guarantee.
    all_scopes = "read|write|admin|audit"
    key_a = reg.issue_key("tenant_a", scopes=all_scopes)
    key_b = reg.issue_key("tenant_b", scopes=all_scopes)
    client = TestClient(create_app(registry=reg))
    return client, key_a, key_b


def test_token_endpoint_refuses_without_shared_secret(monkeypatch):
    """Auth on + no PRAMAGENT_JWT_SECRET(S) → 503, never a per-process random
    secret whose tokens other workers cannot verify (P2-12/T2-6)."""
    monkeypatch.delenv("PRAMAGENT_JWT_SECRET", raising=False)
    monkeypatch.delenv("PRAMAGENT_JWT_SECRETS", raising=False)
    reg = APIKeyRegistry()
    key = reg.issue_key("tenant_a")
    client = TestClient(create_app(registry=reg))
    r = client.post("/v1/auth/token", json={"api_key": key, "ttl_s": 120})
    assert r.status_code == 503
    assert "PRAMAGENT_JWT_SECRET" in r.json()["detail"]


def test_token_endpoint_is_rate_limited(monkeypatch):
    """The bootstrap endpoint carries an IP-keyed bucket: exhausting it
    returns 429 with Retry-After (T1-2)."""
    monkeypatch.setenv("PRAMAGENT_JWT_SECRET", _TEST_JWT_SECRET)
    monkeypatch.setenv("PRAMAGENT_RATE_BURST", "3")
    monkeypatch.setenv("PRAMAGENT_RATE_PER_SEC", "0.001")
    reg = APIKeyRegistry()
    reg.issue_key("tenant_a")
    client = TestClient(create_app(registry=reg))
    statuses = [
        client.post("/v1/auth/token",
                    json={"api_key": "wrong-key", "ttl_s": 120}).status_code
        for _ in range(6)
    ]
    assert 429 in statuses
    # everything before exhaustion is the normal invalid-key 401
    assert statuses[0] == 401
    last = client.post("/v1/auth/token", json={"api_key": "wrong-key", "ttl_s": 120})
    assert last.status_code == 429
    assert "Retry-After" in last.headers


def test_missing_bearer_token_is_401(auth_client):
    client, _, _ = auth_client
    r = client.post("/v1/run", json={"prompt": "hi"})
    assert r.status_code == 401


def test_invalid_bearer_token_is_401(auth_client):
    client, _, _ = auth_client
    r = client.post("/v1/run", json={"prompt": "hi"},
                    headers={"Authorization": "Bearer not-a-real-key"})
    assert r.status_code == 401


def test_valid_key_authenticates(auth_client):
    client, key_a, _ = auth_client
    r = client.post("/v1/run", json={"prompt": "hi"},
                    headers={"Authorization": f"Bearer {key_a}"})
    assert r.status_code == 200


def test_api_key_exchanges_for_short_lived_jwt(auth_client):
    client, key_a, _ = auth_client
    token_resp = client.post("/v1/auth/token", json={"api_key": key_a, "ttl_s": 120})
    assert token_resp.status_code == 200
    token_body = token_resp.json()
    assert token_body["token_type"] == "bearer"
    assert token_body["tenant_id"] == "tenant_a"
    assert token_body["expires_in"] == 120

    r = client.post("/v1/run", json={"prompt": "hi"},
                    headers={"Authorization": f"Bearer {token_body['access_token']}"})
    assert r.status_code == 200


def test_scoped_api_keys_enforce_read_write_admin(monkeypatch):
    monkeypatch.setenv("PRAMAGENT_JWT_SECRET", _TEST_JWT_SECRET)
    reg = APIKeyRegistry()
    write_key = reg.issue_key("tenant_a", scopes="read|write")
    read_key = reg.issue_key("tenant_a", scopes="read")
    admin_key = reg.issue_key("tenant_a", scopes="admin")
    client = TestClient(create_app(registry=reg))

    created = client.post(
        "/v1/run",
        json={"prompt": "tenant scoped data"},
        headers={"Authorization": f"Bearer {write_key}"},
    )
    assert created.status_code == 200
    call_id = created.json()["call_id"]

    read = client.get(
        f"/v1/trace/{call_id}",
        headers={"Authorization": f"Bearer {read_key}"},
    )
    assert read.status_code == 200

    blocked_write = client.post(
        "/v1/run",
        json={"prompt": "should not run"},
        headers={"Authorization": f"Bearer {read_key}"},
    )
    assert blocked_write.status_code == 403

    blocked_admin = client.delete(
        "/v1/tenant/tenant_a/traces",
        headers={"Authorization": f"Bearer {write_key}"},
    )
    assert blocked_admin.status_code == 403

    erased = client.delete(
        "/v1/tenant/tenant_a/traces",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert erased.status_code == 200


def test_jwt_preserves_api_key_scopes(monkeypatch):
    monkeypatch.setenv("PRAMAGENT_JWT_SECRET", _TEST_JWT_SECRET)
    reg = APIKeyRegistry()
    read_key = reg.issue_key("tenant_a", scopes="read")
    client = TestClient(create_app(registry=reg))

    token_resp = client.post(
        "/v1/auth/token",
        json={"api_key": read_key, "ttl_s": 120},
    )
    assert token_resp.status_code == 200
    token = token_resp.json()["access_token"]
    assert token_resp.json()["scopes"] == ["read"]

    r = client.post(
        "/v1/run",
        json={"prompt": "read-only token should not run"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 403


def test_env_var_registry_picks_up_revocation_file_without_restart(monkeypatch, tmp_path):
    """A registry already constructed by load_registry_from_env() (i.e. the
    long-lived one held by a running API server) must start rejecting a key
    as soon as its hash appears in PRAMAGENT_API_KEY_REVOCATION_FILE — no
    process restart required. This is what makes `pramagent auth-revoke`
    actually useful in env-var-only mode (ISSUE-6)."""
    revocation_file = str(tmp_path / "revoked.txt")
    monkeypatch.delenv("PRAMAGENT_API_KEY_DSN", raising=False)
    monkeypatch.setenv("PRAMAGENT_API_KEY_REVOCATION_FILE", revocation_file)
    monkeypatch.setenv("PRAMAGENT_API_KEYS", "tenant_a:alpha-key")

    reg = load_registry_from_env()
    assert reg.tenant_for_key("alpha-key") == "tenant_a"

    from pramagent.auth import revoke_env_key
    revoke_env_key("alpha-key", revocation_file)

    # same, already-constructed registry instance — no reload/re-init
    assert reg.tenant_for_key("alpha-key") is None


def test_env_api_keys_can_define_scopes(monkeypatch):
    monkeypatch.setenv(
        "PRAMAGENT_API_KEYS",
        "tenant_a:alpha:read|write,tenant_b:bravo:read",
    )
    reg = load_registry_from_env()

    assert reg.record_for_key("alpha").tenant_id == "tenant_a"
    assert reg.record_for_key("alpha").scopes == frozenset({"read", "write"})
    assert reg.record_for_key("bravo").scopes == frozenset({"read"})


def test_unscoped_key_defaults_to_read_only(monkeypatch):
    """A1: a key issued with NO scopes must be read-only, not full admin.
    Covers both the programmatic issue_key() path and the 2-field
    PRAMAGENT_API_KEYS="tenant:key" env form."""
    reg = APIKeyRegistry()
    prog_key = reg.issue_key("tenant_a")            # no scopes arg
    assert reg.record_for_key(prog_key).scopes == frozenset({"read"})

    monkeypatch.setenv("PRAMAGENT_API_KEYS", "tenant_b:barekey")  # 2-field form
    env_reg = load_registry_from_env()
    rec = env_reg.record_for_key("barekey")
    assert rec.tenant_id == "tenant_b"
    assert rec.scopes == frozenset({"read"})
    # crucially, NOT write/admin/audit
    assert not (rec.scopes & {"write", "admin", "audit"})


def test_read_only_key_cannot_write_or_erase(monkeypatch):
    """A1, behaviourally: a read-only key authenticates and reads, but a
    write (/v1/run) and an admin op (GDPR erasure) are rejected."""
    monkeypatch.setenv("PRAMAGENT_JWT_SECRET", _TEST_JWT_SECRET)
    reg = APIKeyRegistry()
    read_key = reg.issue_key("tenant_a")            # unscoped → read-only
    client = TestClient(create_app(registry=reg))
    h = {"Authorization": f"Bearer {read_key}"}

    assert client.get("/traces", headers=h).status_code == 200      # read OK
    assert client.post("/v1/run", json={"prompt": "hi"},
                       headers=h).status_code == 403                 # write denied
    assert client.delete("/v1/tenant/tenant_a/traces",
                         headers=h).status_code == 403               # admin denied


def test_revocation_file_never_existing_allows_keys(tmp_path):
    """MEDIUM-2: a configured revocation file that has never been created is
    the normal 'no revocations issued yet' state — keys must still work."""
    reg = APIKeyRegistry(revocation_file=str(tmp_path / "revocations.txt"))
    key = reg.issue_key("tenant_a", scopes="read")
    assert reg.record_for_key(key) is not None


def test_revocation_file_unreadable_fails_closed(tmp_path):
    """MEDIUM-2: a configured revocation file that exists but cannot be read
    means we cannot confirm a key isn't revoked → fail closed (deny)."""
    # A directory stats fine but cannot be open()'d as a file — a portable
    # stand-in for an unreadable revocation file.
    unreadable = tmp_path / "revdir"
    unreadable.mkdir()
    reg = APIKeyRegistry(revocation_file=str(unreadable))
    key = reg.issue_key("tenant_a", scopes="read")
    assert reg.record_for_key(key) is None


def test_revocation_file_vanishing_after_load_fails_closed(tmp_path):
    """MEDIUM-2: once loaded, a revocation file that disappears is treated as
    an operational failure/tampering (fail closed), not as 'revocations
    cleared' (which would silently re-enable revoked keys)."""
    revfile = tmp_path / "revocations.txt"
    revfile.write_text("", encoding="utf-8")
    reg = APIKeyRegistry(revocation_file=str(revfile))
    key = reg.issue_key("tenant_a", scopes="read")
    assert reg.record_for_key(key) is not None    # loads the empty file
    revfile.unlink()
    assert reg.record_for_key(key) is None         # gone → fail closed


def test_public_runtime_requires_auth_or_explicit_dev_flag(monkeypatch):
    monkeypatch.setenv("RAILWAY_ENVIRONMENT", "production")
    monkeypatch.delenv("PRAMAGENT_ALLOW_UNAUTHENTICATED_API", raising=False)

    with pytest.raises(RuntimeError, match="unauthenticated public API"):
        create_app(registry=APIKeyRegistry())

    monkeypatch.setenv("PRAMAGENT_ALLOW_UNAUTHENTICATED_API", "1")
    client = TestClient(create_app(registry=APIKeyRegistry()))
    assert client.get("/health").status_code == 200


def test_bare_cli_host_flag_without_paas_env_is_detected_as_public(monkeypatch):
    monkeypatch.delenv("PRAMAGENT_ALLOW_UNAUTHENTICATED_API", raising=False)
    for var in ("RAILWAY_ENVIRONMENT", "RAILWAY_SERVICE_NAME", "RENDER",
                "FLY_APP_NAME", "K_SERVICE", "AWS_EXECUTION_ENV",
                "KUBERNETES_SERVICE_HOST", "DYNO", "WEBSITE_SITE_NAME",
                "GAE_INSTANCE", "ECS_CONTAINER_METADATA_URI_V4",
                "PRAMAGENT_API_BIND_HOST", "UVICORN_HOST", "HOST"):
        monkeypatch.delenv(var, raising=False)
    wildcard = ".".join(["0"] * 4)
    monkeypatch.setattr(
        sys, "argv",
        ["uvicorn", "pramagent.api.app:create_app", "--factory", "--host", wildcard],
    )

    with pytest.raises(RuntimeError, match="unauthenticated public API"):
        create_app(registry=APIKeyRegistry())


def test_local_dev_with_no_signals_at_all_still_warns_not_silent(monkeypatch, caplog):
    monkeypatch.delenv("PRAMAGENT_ALLOW_UNAUTHENTICATED_API", raising=False)
    for var in ("RAILWAY_ENVIRONMENT", "RAILWAY_SERVICE_NAME", "RENDER",
                "FLY_APP_NAME", "K_SERVICE", "AWS_EXECUTION_ENV",
                "KUBERNETES_SERVICE_HOST", "DYNO", "WEBSITE_SITE_NAME",
                "GAE_INSTANCE", "ECS_CONTAINER_METADATA_URI_V4",
                "PRAMAGENT_API_BIND_HOST", "UVICORN_HOST", "HOST"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(sys, "argv", ["pytest"])

    with caplog.at_level("WARNING"):
        create_app(registry=APIKeyRegistry())

    assert any("no auth check beyond IP rate limiting" in r.message for r in caplog.records)


def test_unauthenticated_opt_in_expiry_forces_re_decision(monkeypatch):
    """PRAMAGENT_ALLOW_UNAUTHENTICATED_API_UNTIL must not let a demo opt-in
    stay silently in effect forever — once the deadline passes it must be
    refused exactly as if the flag were never set."""
    import datetime

    monkeypatch.setenv("RAILWAY_ENVIRONMENT", "production")
    monkeypatch.setenv("PRAMAGENT_ALLOW_UNAUTHENTICATED_API", "1")

    future = (datetime.datetime.now(datetime.timezone.utc)
              + datetime.timedelta(hours=1)).isoformat()
    monkeypatch.setenv("PRAMAGENT_ALLOW_UNAUTHENTICATED_API_UNTIL", future)
    client = TestClient(create_app(registry=APIKeyRegistry()))
    assert client.get("/health").status_code == 200

    past = (datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(hours=1)).isoformat()
    monkeypatch.setenv("PRAMAGENT_ALLOW_UNAUTHENTICATED_API_UNTIL", past)
    with pytest.raises(RuntimeError, match="unauthenticated public API"):
        create_app(registry=APIKeyRegistry())


def test_unauthenticated_opt_in_malformed_expiry_fails_closed(monkeypatch):
    monkeypatch.setenv("RAILWAY_ENVIRONMENT", "production")
    monkeypatch.setenv("PRAMAGENT_ALLOW_UNAUTHENTICATED_API", "1")
    monkeypatch.setenv("PRAMAGENT_ALLOW_UNAUTHENTICATED_API_UNTIL", "not-a-real-timestamp")

    with pytest.raises(RuntimeError, match="unauthenticated public API"):
        create_app(registry=APIKeyRegistry())


# ── Finding 1.2: auth required by default, enforced in the REQUEST PATH ──
def test_empty_registry_denies_data_endpoint_without_optin(monkeypatch):
    """1.2: with no API key registry and no explicit PRAMAGENT_ALLOW_
    UNAUTHENTICATED_API opt-in, a data endpoint must fail closed (401) in the
    request path — not fall through to an empty-tenant, no-scope pass. This
    closes the 'bare container the startup heuristic can't detect' gap: the
    gate no longer depends on public-runtime detection at boot."""
    monkeypatch.delenv("PRAMAGENT_ALLOW_UNAUTHENTICATED_API", raising=False)
    # non-public runtime so the (unchanged) startup enforcement does not raise;
    # the request-path gate is what must now reject.
    monkeypatch.setattr(sys, "argv", ["pytest"])
    for var in ("RAILWAY_ENVIRONMENT", "RAILWAY_SERVICE_NAME", "RENDER",
                "FLY_APP_NAME", "K_SERVICE", "AWS_EXECUTION_ENV",
                "KUBERNETES_SERVICE_HOST", "DYNO", "WEBSITE_SITE_NAME",
                "GAE_INSTANCE", "ECS_CONTAINER_METADATA_URI_V4",
                "PRAMAGENT_API_BIND_HOST", "UVICORN_HOST", "HOST"):
        monkeypatch.delenv(var, raising=False)

    client = TestClient(create_app(registry=APIKeyRegistry()))
    assert client.get("/v1/metrics").status_code == 401


def test_empty_registry_allows_data_endpoint_with_explicit_optin(monkeypatch):
    """1.2: the explicit dev/demo opt-in still permits the empty-tenant pass."""
    monkeypatch.setenv("PRAMAGENT_ALLOW_UNAUTHENTICATED_API", "1")
    monkeypatch.delenv("PRAMAGENT_ALLOW_UNAUTHENTICATED_API_UNTIL", raising=False)
    client = TestClient(create_app(registry=APIKeyRegistry()))
    assert client.get("/v1/metrics").status_code != 401


# ── Finding 4.1: no-auth mode is single-tenant under strict flag ──
def test_noauth_strict_flag_refuses_non_default_tenant(monkeypatch):
    """4.1: in no-auth mode a client-supplied tenant_id is unauthenticated and
    thus untrustworthy. With PRAMAGENT_STRICT_SINGLE_TENANT set, any tenant
    other than the shared 'default' bucket is refused (403), so an operator can
    hard-enforce the single-tenant contract no-auth mode implies."""
    monkeypatch.setenv("PRAMAGENT_ALLOW_UNAUTHENTICATED_API", "1")
    monkeypatch.setenv("PRAMAGENT_STRICT_SINGLE_TENANT", "1")
    client = TestClient(create_app(registry=APIKeyRegistry()))

    refused = client.post("/v1/run", json={"prompt": "hi", "tenant_id": "victim"})
    assert refused.status_code == 403
    allowed = client.post("/v1/run", json={"prompt": "hi", "tenant_id": "default"})
    assert allowed.status_code != 403


def test_noauth_without_strict_flag_still_allows_tenant_selection(monkeypatch):
    """4.1: default (flag unset) preserves no-auth multi-tenant for dev/test."""
    monkeypatch.setenv("PRAMAGENT_ALLOW_UNAUTHENTICATED_API", "1")
    monkeypatch.delenv("PRAMAGENT_STRICT_SINGLE_TENANT", raising=False)
    client = TestClient(create_app(registry=APIKeyRegistry()))
    assert client.post(
        "/v1/run", json={"prompt": "hi", "tenant_id": "acme"}
    ).status_code != 403


def test_phi_mode_requires_authenticated_api(monkeypatch):
    monkeypatch.setenv("PRAMAGENT_PHI_MODE", "1")

    with pytest.raises(RuntimeError, match="PHI"):
        create_app(registry=APIKeyRegistry())


def test_api_key_rotation_policy_rejects_stale_key(monkeypatch):
    """PRAMAGENT_API_KEY_MAX_AGE_DAYS must actually reject an over-age key —
    rotation mechanisms existed before this with nothing enforcing them."""
    monkeypatch.setenv("PRAMAGENT_API_KEY_MAX_AGE_DAYS", "90")
    reg = APIKeyRegistry()
    stale_key = "pramagent_stale"
    reg.add_key("tenant_a", stale_key, created_at=time.time() - 100 * 86400)
    fresh_key = "pramagent_fresh"
    reg.add_key("tenant_a", fresh_key, created_at=time.time() - 10 * 86400)
    client = TestClient(create_app(registry=reg))

    stale = client.get("/v1/trace/whatever", headers={"Authorization": f"Bearer {stale_key}"})
    assert stale.status_code == 401
    assert "rotation policy" in stale.json()["detail"]

    fresh = client.get("/v1/trace/whatever", headers={"Authorization": f"Bearer {fresh_key}"})
    assert fresh.status_code == 404  # trace doesn't exist, but auth succeeded


def test_api_key_rotation_policy_off_by_default(monkeypatch):
    monkeypatch.delenv("PRAMAGENT_API_KEY_MAX_AGE_DAYS", raising=False)
    reg = APIKeyRegistry()
    ancient_key = "pramagent_ancient"
    reg.add_key("tenant_a", ancient_key, created_at=time.time() - 10 * 365 * 86400)
    client = TestClient(create_app(registry=reg))

    r = client.get("/v1/trace/whatever", headers={"Authorization": f"Bearer {ancient_key}"})
    assert r.status_code == 404  # not rejected — enforcement is opt-in


def test_api_key_rotation_policy_malformed_config_fails_closed(monkeypatch):
    monkeypatch.setenv("PRAMAGENT_API_KEY_MAX_AGE_DAYS", "ninety")

    with pytest.raises(RuntimeError, match="PRAMAGENT_API_KEY_MAX_AGE_DAYS"):
        create_app(registry=APIKeyRegistry())


def test_api_key_rotation_policy_non_positive_config_fails_closed(monkeypatch):
    monkeypatch.setenv("PRAMAGENT_API_KEY_MAX_AGE_DAYS", "0")

    with pytest.raises(RuntimeError, match="PRAMAGENT_API_KEY_MAX_AGE_DAYS"):
        create_app(registry=APIKeyRegistry())


def test_token_endpoint_rejects_invalid_api_key(auth_client):
    client, _, _ = auth_client
    r = client.post("/v1/auth/token", json={"api_key": "not-real", "ttl_s": 120})
    assert r.status_code == 401


def test_jwt_audience_is_issued_and_verified():
    """aud pins tokens to this API (P3-4/T1-3): issued tokens carry it and
    tokens without (or with a foreign) audience are rejected."""
    mgr = JWTManager("a-strong-unit-test-secret-123456")
    token = mgr.issue("tenant_a", ttl_s=60)
    payload = mgr.verify(token)
    assert payload["aud"] == "pramagent-api"

    # forge a same-secret token without the aud claim → rejected
    import base64 as _b64
    import hashlib as _hashlib
    import hmac as _hmac
    import time as _time

    def b64(x: bytes) -> str:
        return _b64.urlsafe_b64encode(x).rstrip(b"=").decode()

    hdr = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    pl = b64(json.dumps({"iss": "pramagent", "sub": "tenant_a",
                         "tenant_id": "tenant_a",
                         "exp": int(_time.time()) + 600}).encode())
    sig = b64(_hmac.new(b"a-strong-unit-test-secret-123456",
                        f"{hdr}.{pl}".encode(), _hashlib.sha256).digest())
    with pytest.raises(JWTError, match="audience"):
        mgr.verify(f"{hdr}.{pl}.{sig}")


def test_invalid_jwt_is_rejected(auth_client):
    client, key_a, _ = auth_client
    token = client.post("/v1/auth/token", json={"api_key": key_a, "ttl_s": 60}).json()["access_token"]
    client.app.state.jwt.secret = b"different-secret"
    r = client.post("/v1/run", json={"prompt": "hi"},
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_tenant_in_body_is_ignored_when_authenticated(auth_client):
    """The tenant comes from the key, not the request body — this is the
    invariant that defeats body-spoofing attacks."""
    client, key_a, _ = auth_client
    # Caller tries to claim tenant_b in the body while authenticating as tenant_a
    r = client.post("/v1/run",
                    json={"prompt": "hi", "tenant_id": "tenant_b"},
                    headers={"Authorization": f"Bearer {key_a}"})
    body = r.json()
    # Fetch the trace back — it should be owned by tenant_a regardless of body
    trace = client.get(f"/v1/trace/{body['call_id']}",
                       headers={"Authorization": f"Bearer {key_a}"}).json()
    assert trace["tenant_id"] == "tenant_a"


def test_cross_tenant_trace_access_blocked(auth_client):
    """The headline security test. Tenant A creates a trace, tenant B holds a
    valid key, tenant B must NOT be able to read that trace by guessing its id.
    """
    client, key_a, key_b = auth_client
    # tenant_a creates a trace
    cid = client.post("/v1/run", json={"prompt": "secret data for A"},
                      headers={"Authorization": f"Bearer {key_a}"}).json()["call_id"]
    # tenant_a can read it
    own = client.get(f"/v1/trace/{cid}",
                     headers={"Authorization": f"Bearer {key_a}"})
    assert own.status_code == 200
    # tenant_b CANNOT read it (404 not 403 — don't leak that the id exists)
    cross = client.get(f"/v1/trace/{cid}",
                       headers={"Authorization": f"Bearer {key_b}"})
    assert cross.status_code == 404


def test_cross_tenant_rca_blocked(auth_client):
    """RCA endpoints must enforce the same guard — replay leaks the trace too."""
    client, key_a, key_b = auth_client
    cid = client.post("/v1/run", json={"prompt": "dump all accounts now"},
                      headers={"Authorization": f"Bearer {key_a}"}).json()["call_id"]
    # tenant_b cannot replay tenant_a's trace
    r = client.post(f"/v1/rca/{cid}/replay",
                    headers={"Authorization": f"Bearer {key_b}"})
    assert r.status_code == 404
    # tenant_b cannot fetch the incident report
    r = client.get(f"/v1/rca/{cid}/incident",
                   headers={"Authorization": f"Bearer {key_b}"})
    assert r.status_code == 404


def test_retention_minimum_is_180_days(auth_client):
    """Article 12 minimum: never accept a retention window below 180 days."""
    client, key_a, _ = auth_client
    r = client.post("/v1/retention/prune?older_than_days=30",
                    headers={"Authorization": f"Bearer {key_a}"})
    assert r.status_code == 400
    # 180 is allowed
    r = client.post("/v1/retention/prune?older_than_days=180",
                    headers={"Authorization": f"Bearer {key_a}"})
    assert r.status_code == 200


def test_gdpr_erasure_only_for_own_tenant(auth_client):
    """A tenant may erase its own data; never another tenant's."""
    client, key_a, key_b = auth_client
    client.post("/v1/run", json={"prompt": "stuff"},
                headers={"Authorization": f"Bearer {key_a}"})
    # tenant_b cannot erase tenant_a's data
    r = client.delete("/v1/tenant/tenant_a/traces",
                      headers={"Authorization": f"Bearer {key_b}"})
    assert r.status_code == 403
    # tenant_a can erase its own
    r = client.delete("/v1/tenant/tenant_a/traces",
                      headers={"Authorization": f"Bearer {key_a}"})
    assert r.status_code == 200
    assert r.json()["deleted"] >= 1


# ── auth module unit tests ────────────────────────────────────────────
def test_keys_are_never_stored_plaintext():
    reg = APIKeyRegistry()
    key = reg.issue_key("tenant_x")
    # the registry's internal dict must contain only hashes, not the key itself
    assert key not in reg._keys
    assert all(len(h) == 64 for h in reg._keys)  # SHA-256 hex


def test_revoke_key_removes_access():
    reg = APIKeyRegistry()
    key = reg.issue_key("tenant_x")
    assert reg.tenant_for_key(key) == "tenant_x"
    assert reg.revoke_key(key) is True
    assert reg.tenant_for_key(key) is None


def test_jwt_manager_supports_kid_rotation_and_retirement():
    mgr = JWTManager({"old": "old-secret"}, active_kid="old")
    old_token = mgr.issue("tenant_a", ttl_s=120)

    mgr.rotate("new", "new-secret", activate=True)
    new_token = mgr.issue("tenant_a", ttl_s=120)

    assert mgr.tenant_for_token(old_token) == "tenant_a"
    assert mgr.tenant_for_token(new_token) == "tenant_a"

    assert mgr.retire("old") is True
    with pytest.raises(JWTError):
        mgr.verify(old_token)
    assert mgr.tenant_for_token(new_token) == "tenant_a"


def test_jwt_manager_loads_key_registry_from_env(monkeypatch):
    monkeypatch.setenv("PRAMAGENT_JWT_SECRETS", "old:old-secret,new:new-secret")
    monkeypatch.setenv("PRAMAGENT_JWT_ACTIVE_KID", "new")

    mgr = JWTManager.from_env(fallback_secret="fallback-secret")
    token = mgr.issue("tenant_env", ttl_s=120)
    header = json.loads(_b64url_decode(token.split(".")[0]))

    assert header["kid"] == "new"
    assert mgr.tenant_for_token(token) == "tenant_env"


class _FakePostgresCursor:
    def __init__(self, db):
        self.db = db
        self.rowcount = 0
        self._row = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        sql_norm = " ".join(sql.lower().split())
        params = params or ()
        if "create table" in sql_norm or "create index" in sql_norm:
            return
        if "insert into pramagent_api_keys" in sql_norm:
            hashed, tenant, scopes = params
            self.db[hashed] = {
                "tenant_id": tenant,
                "scopes": scopes,
                "revoked": False,
                "created_at": _dt.datetime.now(_dt.timezone.utc),
            }
            self.rowcount = 1
            return
        if "insert into pramagent_api_key_audit" in sql_norm:
            self.rowcount = 1
            return
        if "update pramagent_api_keys" in sql_norm:
            hashed = params[0]
            entry = self.db.get(hashed)
            if entry and not entry["revoked"]:
                entry["revoked"] = True
                self.rowcount = 1
            else:
                self.rowcount = 0
            return
        if "select tenant_id, scopes, created_at" in sql_norm:
            hashed = params[0]
            entry = self.db.get(hashed)
            self._row = (
                (entry["tenant_id"], entry["scopes"], entry.get("created_at"))
                if entry and not entry["revoked"]
                else None
            )
            return
        if "select tenant_id" in sql_norm:
            hashed = params[0]
            entry = self.db.get(hashed)
            self._row = (
                (entry["tenant_id"], entry["scopes"])
                if entry and not entry["revoked"]
                else None
            )
            return
        if "select count" in sql_norm:
            self._row = (sum(1 for entry in self.db.values() if not entry["revoked"]),)
            return
        raise AssertionError(f"unexpected SQL: {sql}")

    def fetchone(self):
        return self._row


class _FakePostgresConnection:
    def __init__(self, db):
        self.db = db
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self):
        return _FakePostgresCursor(self.db)

    def close(self):
        self.closed = True


def test_postgres_api_key_registry_matches_registry_contract():
    db = {}

    def connect(_dsn):
        return _FakePostgresConnection(db)

    reg = PostgresAPIKeyRegistry("postgresql://unit-test", connect=connect)
    key = reg.issue_key("tenant_pg")

    assert len(reg) == 1
    assert reg.tenant_for_key(key) == "tenant_pg"
    assert key not in db
    assert reg.revoke_key(key) is True
    assert reg.tenant_for_key(key) is None
    assert len(reg) == 0
