"""Tests for pramagent.secrets: env-var-direct, AWS Secrets Manager, and
HashiCorp Vault secret resolution."""
from __future__ import annotations

import sys
import types

import pytest

from pramagent import secrets as secrets_mod
from pramagent.secrets import clear_secret_cache, resolve_secret


@pytest.fixture(autouse=True)
def _clear_cache():
    clear_secret_cache()
    yield
    clear_secret_cache()


def test_direct_env_var_takes_precedence(monkeypatch):
    monkeypatch.setenv("PRAMAGENT_JWT_SECRET", "direct-value")
    monkeypatch.setenv("PRAMAGENT_JWT_SECRET_AWS_SECRET_ID", "should-not-be-used")

    assert resolve_secret("PRAMAGENT_JWT_SECRET") == "direct-value"


def test_missing_everywhere_returns_default(monkeypatch):
    monkeypatch.delenv("PRAMAGENT_JWT_SECRET", raising=False)
    monkeypatch.delenv("PRAMAGENT_JWT_SECRET_AWS_SECRET_ID", raising=False)
    monkeypatch.delenv("PRAMAGENT_JWT_SECRET_VAULT_PATH", raising=False)

    assert resolve_secret("PRAMAGENT_JWT_SECRET", default="fallback") == "fallback"


def test_aws_secrets_manager_backend(monkeypatch):
    monkeypatch.delenv("PRAMAGENT_JWT_SECRET", raising=False)
    monkeypatch.setenv("PRAMAGENT_JWT_SECRET_AWS_SECRET_ID", "arn:aws:secretsmanager:x")

    calls = []

    class FakeClient:
        def get_secret_value(self, SecretId):
            calls.append(SecretId)
            return {"SecretString": "from-aws"}

    fake_boto3 = types.SimpleNamespace(client=lambda service, **kw: FakeClient())
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    assert resolve_secret("PRAMAGENT_JWT_SECRET") == "from-aws"
    assert calls == ["arn:aws:secretsmanager:x"]

    # Second call must hit the cache, not fetch again.
    assert resolve_secret("PRAMAGENT_JWT_SECRET") == "from-aws"
    assert calls == ["arn:aws:secretsmanager:x"]


def test_aws_backend_missing_boto3_fails_gracefully(monkeypatch):
    monkeypatch.delenv("PRAMAGENT_JWT_SECRET", raising=False)
    monkeypatch.setenv("PRAMAGENT_JWT_SECRET_AWS_SECRET_ID", "arn:aws:secretsmanager:x")
    monkeypatch.setitem(sys.modules, "boto3", None)  # simulate ImportError

    assert resolve_secret("PRAMAGENT_JWT_SECRET", default="fallback") == "fallback"


def test_aws_backend_error_falls_back_to_default(monkeypatch):
    monkeypatch.delenv("PRAMAGENT_JWT_SECRET", raising=False)
    monkeypatch.setenv("PRAMAGENT_JWT_SECRET_AWS_SECRET_ID", "arn:aws:secretsmanager:x")

    class FailingClient:
        def get_secret_value(self, SecretId):
            raise RuntimeError("access denied")

    fake_boto3 = types.SimpleNamespace(client=lambda service, **kw: FailingClient())
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    assert resolve_secret("PRAMAGENT_JWT_SECRET", default="fallback") == "fallback"


def test_vault_backend(monkeypatch):
    monkeypatch.delenv("PRAMAGENT_JWT_SECRET", raising=False)
    monkeypatch.setenv("PRAMAGENT_JWT_SECRET_VAULT_PATH", "secret/data/pramagent/jwt")
    monkeypatch.setenv("VAULT_ADDR", "https://vault.internal:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test-token")

    import json as _json

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return _json.dumps({"data": {"data": {"value": "from-vault"}}}).encode()

    captured_requests = []

    def fake_urlopen(req, timeout=None):
        captured_requests.append(req)
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    assert resolve_secret("PRAMAGENT_JWT_SECRET") == "from-vault"
    assert captured_requests[0].full_url == "https://vault.internal:8200/v1/secret/data/pramagent/jwt"
    assert captured_requests[0].headers["X-vault-token"] == "test-token"


def test_vault_backend_missing_addr_or_token_fails_gracefully(monkeypatch):
    monkeypatch.delenv("PRAMAGENT_JWT_SECRET", raising=False)
    monkeypatch.setenv("PRAMAGENT_JWT_SECRET_VAULT_PATH", "secret/data/pramagent/jwt")
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)

    assert resolve_secret("PRAMAGENT_JWT_SECRET", default="fallback") == "fallback"


def test_vault_backend_rejects_unsafe_address(monkeypatch):
    """An operator-misconfigured (or attacker-influenced) VAULT_ADDR must not
    turn secret resolution into an arbitrary outbound HTTP request."""
    monkeypatch.delenv("PRAMAGENT_JWT_SECRET", raising=False)
    monkeypatch.setenv("PRAMAGENT_JWT_SECRET_VAULT_PATH", "secret/data/pramagent/jwt")
    monkeypatch.setenv("VAULT_ADDR", "ftp://vault.internal:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test-token")

    assert resolve_secret("PRAMAGENT_JWT_SECRET", default="fallback") == "fallback"


def test_vault_backend_http_error_falls_back_to_default(monkeypatch):
    monkeypatch.delenv("PRAMAGENT_JWT_SECRET", raising=False)
    monkeypatch.setenv("PRAMAGENT_JWT_SECRET_VAULT_PATH", "secret/data/pramagent/jwt")
    monkeypatch.setenv("VAULT_ADDR", "https://vault.internal:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test-token")

    import urllib.error

    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    assert resolve_secret("PRAMAGENT_JWT_SECRET", default="fallback") == "fallback"


# ── HIGH-2: CLI and API must resolve the signing key identically ──────────

def test_cli_store_resolves_signing_key_via_indirection(tmp_path, monkeypatch):
    """HIGH-2: when PRAMAGENT_SIGNING_KEY is supplied only through
    secret-manager indirection (a *_VAULT_PATH, not the direct env var), the
    CLI's _store_from_env() must resolve the SAME key the API writes with —
    via resolve_secret, not a bare os.environ.get. Otherwise the CLI opens
    the store with an empty key and reports a correctly-signed production
    chain as tampered."""
    from pramagent import cli
    from pramagent.store import SQLiteStore

    db = str(tmp_path / "audit.db")
    for var in ("PRAMAGENT_SIGNING_KEY", "PRAMAGENT_POSTGRES_DSN",
                "PRAMAGENT_ENCRYPTION_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PRAMAGENT_DB", db)
    monkeypatch.setenv("PRAMAGENT_SIGNING_KEY_VAULT_PATH",
                       "secret/data/pramagent/signing")
    monkeypatch.setattr(secrets_mod, "_fetch_vault_secret",
                        lambda path: "the-real-production-signing-key")

    # API-side write path (build_default_armor resolves the key this way).
    api_key = resolve_secret("PRAMAGENT_SIGNING_KEY")
    assert api_key == "the-real-production-signing-key"
    api_store = SQLiteStore(db, signing_key=api_key)
    api_store.append({"tenant_id": "t", "event": "one"})
    api_store.append({"tenant_id": "t", "event": "two"})
    assert api_store.verify_chain() is True

    # CLI-side store must resolve the identical key → chain verifies.
    cli_store = cli._store_from_env()
    assert cli_store.verify_chain() is True

    # Contrast: opening with the wrong (empty) key — the pre-fix behaviour,
    # since only the *_VAULT_PATH var was set — flags the chain as tampered.
    assert SQLiteStore(db, signing_key="").verify_chain() is False


# ── Finding 7.1 / 7.2: audit-chain signing-key ROTATION via env ──
def test_resolve_signing_key_ring_parses_multi_key(monkeypatch):
    from pramagent.secrets import resolve_signing_key_ring

    monkeypatch.setenv("PRAMAGENT_SIGNING_KEYS", "v1:key-one,v2:key-two")
    monkeypatch.setenv("PRAMAGENT_SIGNING_ACTIVE_KID", "v2")
    cfg = resolve_signing_key_ring()
    assert cfg["signing_keys"] == {"v1": "key-one", "v2": "key-two"}
    assert cfg["active_kid"] == "v2"
    assert cfg["signing_key"] == ""


def test_resolve_signing_key_ring_single_key_fallback(monkeypatch):
    from pramagent.secrets import resolve_signing_key_ring

    monkeypatch.delenv("PRAMAGENT_SIGNING_KEYS", raising=False)
    monkeypatch.setenv("PRAMAGENT_SIGNING_KEY", "solo-key")
    cfg = resolve_signing_key_ring()
    assert cfg["signing_key"] == "solo-key"
    assert cfg["signing_keys"] is None
    assert cfg["active_kid"] is None


def test_cli_store_verifies_rotated_chain_via_signing_keys_env(tmp_path, monkeypatch):
    """7.2: a chain written across a key rotation (rows tagged v1 then v2) must
    verify when the CLI store is built from PRAMAGENT_SIGNING_KEYS holding the
    full ring. Pre-fix _store_from_env read only the single PRAMAGENT_SIGNING_KEY,
    so audit-verify-watch/audit-export reported the post-rotation tail as
    tampered and fired a false alarm."""
    from pramagent import cli
    from pramagent.store import SQLiteStore

    db = str(tmp_path / "rotated.db")
    for var in ("PRAMAGENT_SIGNING_KEY", "PRAMAGENT_POSTGRES_DSN",
                "PRAMAGENT_ENCRYPTION_KEY"):
        monkeypatch.delenv(var, raising=False)

    # write v1 rows, then rotate to v2 and write more (rows are _kid-tagged)
    s1 = SQLiteStore(db, signing_keys={"v1": "key-one"}, active_kid="v1")
    s1.append({"tenant_id": "t", "event": "one"})
    s1.close()
    s2 = SQLiteStore(db, signing_keys={"v1": "key-one", "v2": "key-two"},
                     active_kid="v2")
    s2.append({"tenant_id": "t", "event": "two"})
    assert s2.verify_chain() is True
    s2.close()

    # CLI store built from the multi-key env must verify BOTH segments.
    monkeypatch.setenv("PRAMAGENT_DB", db)
    monkeypatch.setenv("PRAMAGENT_SIGNING_KEYS", "v1:key-one,v2:key-two")
    monkeypatch.setenv("PRAMAGENT_SIGNING_ACTIVE_KID", "v2")
    cli_store = cli._store_from_env()
    assert cli_store.verify_chain() is True
    cli_store.close()
