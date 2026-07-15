import pytest

from pramagent.security import (WEAK_SECRET_DENYLIST, UnsafeURLError,
                                assert_strong_secret, validate_http_url)


def test_require_shared_counting_fatal_without_backend(monkeypatch):
    """5.2: with PRAMAGENT_REQUIRE_SHARED_COUNTING set, a missing shared
    backend is a hard boot failure, not a silent degrade to per-process
    counting (which multiplies call/chain limits by the worker count)."""
    from pramagent.api.app import build_tool_guard_backend_from_env

    monkeypatch.setenv("PRAMAGENT_REQUIRE_SHARED_COUNTING", "1")
    monkeypatch.delenv("PRAMAGENT_TOOL_GUARD_REDIS_URL", raising=False)
    monkeypatch.delenv("PRAMAGENT_REDIS_URL", raising=False)
    with pytest.raises(RuntimeError, match="REQUIRE_SHARED_COUNTING"):
        build_tool_guard_backend_from_env()


def test_require_shared_counting_fatal_when_backend_unreachable(monkeypatch):
    from pramagent.api.app import build_tool_guard_backend_from_env
    from pramagent import backends

    monkeypatch.setenv("PRAMAGENT_REQUIRE_SHARED_COUNTING", "1")
    monkeypatch.setenv("PRAMAGENT_REDIS_URL", "redis://localhost:6379/0")

    def _boom(*a, **k):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(backends.RedisBackend, "from_url", staticmethod(_boom))
    with pytest.raises(RuntimeError, match="REQUIRE_SHARED_COUNTING"):
        build_tool_guard_backend_from_env()


def test_without_require_flag_unreachable_backend_degrades(monkeypatch):
    from pramagent.api.app import build_tool_guard_backend_from_env
    from pramagent import backends

    monkeypatch.delenv("PRAMAGENT_REQUIRE_SHARED_COUNTING", raising=False)
    monkeypatch.setenv("PRAMAGENT_REDIS_URL", "redis://localhost:6379/0")

    def _boom(*a, **k):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(backends.RedisBackend, "from_url", staticmethod(_boom))
    assert build_tool_guard_backend_from_env() is None


def test_validate_http_url_allows_https_public_url():
    assert validate_http_url("https://api.example.com/hook") == "https://api.example.com/hook"


def test_validate_http_url_rejects_non_http_schemes():
    with pytest.raises(UnsafeURLError):
        validate_http_url("file:///etc/passwd")


def test_validate_http_url_rejects_metadata_ip():
    with pytest.raises(UnsafeURLError):
        validate_http_url("http://169.254.169.254/latest/meta-data/")


def test_validate_http_url_allows_loopback_http_when_explicit():
    assert (
        validate_http_url(
            "http://127.0.0.1:8001/v1",
            allow_http_localhost=True,
        )
        == "http://127.0.0.1:8001/v1"
    )


def test_validate_http_url_rejects_public_http_by_default():
    with pytest.raises(UnsafeURLError):
        validate_http_url("http://api.example.com/hook")


# ── assert_strong_secret (P0-2 / T1-1) ─────────────────────────────────────

@pytest.mark.parametrize("weak", sorted(WEAK_SECRET_DENYLIST))
def test_assert_strong_secret_rejects_every_denylisted_spelling(weak):
    with pytest.raises(RuntimeError, match="MY_SECRET"):
        assert_strong_secret("MY_SECRET", weak)


def test_assert_strong_secret_rejects_denylist_case_insensitively():
    with pytest.raises(RuntimeError):
        assert_strong_secret("MY_SECRET", "Change_Me_In_Production")


def test_assert_strong_secret_rejects_empty_and_short_values():
    with pytest.raises(RuntimeError):
        assert_strong_secret("MY_SECRET", "")
    with pytest.raises(RuntimeError):
        assert_strong_secret("MY_SECRET", "tooshort")


def test_assert_strong_secret_accepts_strong_value():
    assert_strong_secret("MY_SECRET", "k3qLm9Zr2Xv8Wn4Pt6Ys1Bd5Fg7Hj0Ca")


# ── startup guards in the API factory (P0-1 + P0-2) ───────────────────────

@pytest.mark.parametrize("weak", sorted(WEAK_SECRET_DENYLIST))
def test_create_app_refuses_denylisted_jwt_secret(monkeypatch, weak):
    fastapi = pytest.importorskip("fastapi")
    from pramagent.api.app import create_app

    monkeypatch.setenv("PRAMAGENT_JWT_SECRET", weak)
    with pytest.raises(RuntimeError, match="PRAMAGENT_JWT_SECRET"):
        create_app()


def test_build_default_armor_refuses_to_boot_without_a_store(monkeypatch):
    fastapi = pytest.importorskip("fastapi")
    from pramagent.api.app import build_default_armor

    monkeypatch.delenv("PRAMAGENT_POSTGRES_DSN", raising=False)
    monkeypatch.delenv("PRAMAGENT_DB", raising=False)
    monkeypatch.delenv("PRAMAGENT_ALLOW_MEMORY_STORE", raising=False)
    with pytest.raises(RuntimeError, match="persistent store"):
        build_default_armor()


def test_build_default_armor_uses_sqlite_when_db_path_set(monkeypatch, tmp_path):
    fastapi = pytest.importorskip("fastapi")
    from pramagent.api.app import build_default_armor
    from pramagent.store import SQLiteStore

    monkeypatch.delenv("PRAMAGENT_POSTGRES_DSN", raising=False)
    monkeypatch.setenv("PRAMAGENT_DB", str(tmp_path / "armor.db"))
    armor = build_default_armor()
    assert isinstance(armor.store, SQLiteStore)
    assert armor.audit is armor.store
    armor.store.close()


def test_build_default_armor_memory_requires_explicit_opt_in(monkeypatch):
    fastapi = pytest.importorskip("fastapi")
    from pramagent.api.app import build_default_armor
    from pramagent.store import MemoryStore

    monkeypatch.delenv("PRAMAGENT_POSTGRES_DSN", raising=False)
    monkeypatch.delenv("PRAMAGENT_DB", raising=False)
    monkeypatch.setenv("PRAMAGENT_ALLOW_MEMORY_STORE", "1")
    armor = build_default_armor()
    assert isinstance(armor.store, MemoryStore)


def test_dashboard_guard_refuses_underscored_spelling(monkeypatch):
    """The pre-fix dashboard equality check only caught the hyphenated
    sentinel; the repo's published underscored value passed it (T1-1)."""
    dashboard = pytest.importorskip("deploy.dashboard.app")

    monkeypatch.setattr(dashboard, "PRAMAGENT_JWT_SECRET", "change_me_in_production")
    with pytest.raises(RuntimeError, match="PRAMAGENT_JWT_SECRET"):
        dashboard.validate_dashboard_config()
