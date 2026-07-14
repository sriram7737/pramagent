"""C4: pramagent._pg defaults Postgres connections to TLS (sslmode=require)
for non-loopback hosts, respects an explicit sslmode and the override env
var, and leaves loopback dev connections alone."""
from __future__ import annotations

from pramagent import _pg


def test_remote_dsn_defaults_to_require(monkeypatch):
    monkeypatch.delenv("PRAMAGENT_POSTGRES_SSLMODE", raising=False)
    dsn = "postgresql://user:pw@db.example.com:5432/pramagent"
    out = _pg._apply_sslmode(dsn)
    assert "sslmode=require" in out


def test_keyword_dsn_defaults_to_require(monkeypatch):
    monkeypatch.delenv("PRAMAGENT_POSTGRES_SSLMODE", raising=False)
    dsn = "host=db.example.com port=5432 dbname=pramagent user=u password=p"
    out = _pg._apply_sslmode(dsn)
    assert out.endswith("sslmode=require")


def test_loopback_dsn_left_alone(monkeypatch):
    monkeypatch.delenv("PRAMAGENT_POSTGRES_SSLMODE", raising=False)
    for dsn in ("postgresql://u:p@localhost:5432/db",
                "host=127.0.0.1 port=5432 dbname=db user=u"):
        assert _pg._apply_sslmode(dsn) == dsn


def test_explicit_sslmode_is_respected(monkeypatch):
    monkeypatch.delenv("PRAMAGENT_POSTGRES_SSLMODE", raising=False)
    dsn = "postgresql://u:p@db.example.com/db?sslmode=verify-full"
    # already set → untouched, no duplicate param appended
    assert _pg._apply_sslmode(dsn) == dsn


def test_env_override_wins(monkeypatch):
    monkeypatch.setenv("PRAMAGENT_POSTGRES_SSLMODE", "verify-full")
    dsn = "postgresql://u:p@db.example.com/db"
    assert "sslmode=verify-full" in _pg._apply_sslmode(dsn)
    # override even applies to loopback if the operator asks for it
    assert "sslmode=verify-full" in _pg._apply_sslmode(
        "host=localhost dbname=db")
