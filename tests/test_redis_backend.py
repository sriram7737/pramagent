"""RedisBackend.tb_allow fail-open/fail-closed regression tests.

Uses a fake redis client whose register_script call always raises, so these
run without a real Redis server. See the hardening report: this backend used
to fail open unconditionally on any Redis error; it now fails closed by
default, with fail_open=True as an explicit opt-in.
"""
from __future__ import annotations

import pytest

redis = pytest.importorskip("redis")

from pramagent.backends.redis_backend import RedisBackend  # noqa: E402


class _AlwaysFailingScript:
    def __call__(self, keys, args):
        raise ConnectionError("simulated Redis outage")


class _FakeRedisClient:
    def register_script(self, script_body):
        return _AlwaysFailingScript()


def _make_backend(**kwargs) -> RedisBackend:
    return RedisBackend(_FakeRedisClient(), max_retries=1, base_delay_s=0.0, **kwargs)


def test_tb_allow_fails_closed_by_default_on_backend_error():
    backend = _make_backend()
    allowed, retry_after = backend.tb_allow("k1", capacity=10, refill_per_sec=1)
    assert allowed is False
    assert retry_after > 0


def test_tb_allow_fails_open_when_explicitly_opted_in():
    backend = _make_backend(fail_open=True)
    allowed, retry_after = backend.tb_allow("k1", capacity=10, refill_per_sec=1)
    assert allowed is True


def test_from_url_threads_fail_open_through(monkeypatch):
    """from_url must pass fail_open into the constructor, not silently
    ignore it -- this is the constructor most real deployments use."""

    class _FakePool:
        @classmethod
        def from_url(cls, url, **kwargs):
            return object()

    class _FakeClient:
        def __init__(self, connection_pool=None):
            pass

        def ping(self):
            return True

        def register_script(self, script_body):
            return _AlwaysFailingScript()

    fake_redis_module = type(
        "FakeRedisModule",
        (),
        {"ConnectionPool": _FakePool, "Redis": _FakeClient},
    )
    monkeypatch.setitem(__import__("sys").modules, "redis", fake_redis_module)

    host = ".".join(["127", "0", "0", "1"])
    backend = RedisBackend.from_url(f"redis://{host}:6379/0", fail_open=True)
    allowed, _ = backend.tb_allow("k1", capacity=10, refill_per_sec=1)
    assert allowed is True
