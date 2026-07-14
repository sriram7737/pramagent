"""Tests for token-bucket rate limiting at the API boundary."""
import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from pramagent.api.app import create_app  # noqa: E402
from pramagent.auth import APIKeyRegistry  # noqa: E402
from pramagent.ratelimit import TokenBucket  # noqa: E402


# ── bucket unit tests ──────────────────────────────────────────────────
def test_token_bucket_allows_within_capacity():
    b = TokenBucket(capacity=3, refill_per_sec=0.1)
    for _ in range(3):
        allowed, _ = b.allow("k")
        assert allowed
    # 4th: bucket empty -> rejected
    allowed, retry = b.allow("k")
    assert not allowed
    assert retry > 0


def test_token_bucket_isolates_keys():
    b = TokenBucket(capacity=1, refill_per_sec=0.001)
    assert b.allow("a")[0] is True
    assert b.allow("a")[0] is False   # a exhausted
    assert b.allow("b")[0] is True    # b has its own bucket


# ── API integration ────────────────────────────────────────────────────
def test_api_rate_limits_after_burst(monkeypatch):
    """Set burst=3, hit the endpoint 4 times, expect a 429 on the 4th."""
    monkeypatch.setenv("PRAMAGENT_RATE_BURST", "3")
    monkeypatch.setenv("PRAMAGENT_RATE_PER_SEC", "0.01")
    client = TestClient(create_app(registry=APIKeyRegistry()))
    for i in range(3):
        r = client.post("/v1/run", json={"prompt": f"hi-{i}"})
        assert r.status_code == 200, f"call {i} should succeed"
    r = client.post("/v1/run", json={"prompt": "hi-4"})
    assert r.status_code == 429
    assert "Retry-After" in r.headers


def test_rate_limit_is_per_tenant_when_authenticated(monkeypatch):
    """Tenant A exhausting its bucket must NOT block tenant B."""
    monkeypatch.setenv("PRAMAGENT_RATE_BURST", "2")
    monkeypatch.setenv("PRAMAGENT_RATE_PER_SEC", "0.01")
    reg = APIKeyRegistry()
    # write scope needed for /v1/run; unscoped keys are read-only (A1).
    key_a = reg.issue_key("tenant_a", scopes="read|write")
    key_b = reg.issue_key("tenant_b", scopes="read|write")
    client = TestClient(create_app(registry=reg))

    # exhaust tenant A
    for _ in range(2):
        r = client.post("/v1/run", json={"prompt": "x"},
                        headers={"Authorization": f"Bearer {key_a}"})
        assert r.status_code == 200
    r = client.post("/v1/run", json={"prompt": "x"},
                    headers={"Authorization": f"Bearer {key_a}"})
    assert r.status_code == 429
    # tenant B still has its full bucket
    r = client.post("/v1/run", json={"prompt": "x"},
                    headers={"Authorization": f"Bearer {key_b}"})
    assert r.status_code == 200
