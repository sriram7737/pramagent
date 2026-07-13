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
