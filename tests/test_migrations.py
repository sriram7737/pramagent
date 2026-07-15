"""Tests for the stdlib migration runner (SQLite)."""
import os
import sqlite3
import tempfile

import pytest

from pramagent.backends.migrations import (MIGRATIONS, MIGRATIONS_PG, Migration,
                                           MigrationRunner)


def test_pg_migrations_provision_tenant_isolation_and_append_only_guard():
    """4.2: the Postgres migration path must add the same tenant-isolation
    policy and append-only chain guard the auto-DDL store applies — otherwise a
    migration-only deployment runs with isolation and chain immutability absent.
    The SQL is derived from PostgresStore's own templates (source of truth); the
    enforcement itself is proven live in tests/test_postgres_rls_live.py, which
    applies the identical statements."""
    by_name = {m.name: m.up_sql.lower() for m in MIGRATIONS_PG}

    assert "enable_traces_row_level_security" in by_name
    rls = by_name["enable_traces_row_level_security"]
    assert "row level security" in rls            # ENABLE + FORCE
    assert "current_setting" in rls               # the per-tenant policy predicate
    assert "policy" in rls

    assert "chain_append_only_guard" in by_name
    guard = by_name["chain_append_only_guard"]
    assert "trigger" in guard
    assert "append-only" in guard


def _tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


def test_runner_applies_all_default_migrations():
    path = _tmp_db()
    try:
        runner = MigrationRunner(sqlite_path=path)
        applied = runner.run(MIGRATIONS)
        assert applied == [1, 2, 3]
        assert runner.current_version() == 3
        # tables exist
        conn = sqlite3.connect(path)
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert {"traces", "audit_chain", "schema_migrations"} <= names
        conn.close()
    finally:
        os.unlink(path)


def test_runner_is_idempotent():
    path = _tmp_db()
    try:
        runner = MigrationRunner(sqlite_path=path)
        runner.run(MIGRATIONS)
        # second run applies nothing
        assert runner.run(MIGRATIONS) == []
        assert runner.applied_versions() == [1, 2, 3]
    finally:
        os.unlink(path)


def test_runner_applies_only_new_migrations():
    path = _tmp_db()
    try:
        runner = MigrationRunner(sqlite_path=path)
        runner.run(MIGRATIONS)
        extra = Migration(version=4, name="add_col",
                          up_sql="ALTER TABLE traces ADD COLUMN note TEXT")
        assert runner.run(MIGRATIONS + [extra]) == [4]
        assert runner.current_version() == 4
    finally:
        os.unlink(path)


def test_runner_requires_exactly_one_target():
    with pytest.raises(ValueError):
        MigrationRunner()
    with pytest.raises(ValueError):
        MigrationRunner(sqlite_path="x", dsn="y")


def test_failed_migration_rolls_back_and_stops():
    path = _tmp_db()
    try:
        runner = MigrationRunner(sqlite_path=path)
        bad = Migration(version=1, name="bad", up_sql="THIS IS NOT SQL")
        with pytest.raises(Exception):
            runner.run([bad])
        assert runner.current_version() == 0
    finally:
        os.unlink(path)
