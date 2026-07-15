"""
pramagent.backends.migrations
=============================
Tiny, dependency-free schema migration runner for the trace/audit stores.

Why not Alembic? Alembic is excellent but pulls in SQLAlchemy. Pramagent's
stores are deliberately thin (sqlite3 / psycopg2 directly), so a ~100-line
forward-only runner keeps the dependency surface tiny while giving ops the one
thing they actually need: ordered, idempotent, recorded schema changes.

Model
-----
A Migration has an integer ``version``, a human ``name``, and ``up_sql``.
Migrations are applied in ascending version order. Applied versions are recorded
in a ``schema_migrations`` table, so re-running is a no-op (idempotent).

Usage
-----
    from pramagent.backends.migrations import MigrationRunner, Migration

    runner = MigrationRunner(sqlite_path="pramagent.db")        # or dsn=...
    runner.run(MIGRATIONS)        # applies anything not yet applied
    print(runner.current_version())

The default MIGRATIONS list bootstraps the same schema the stores create on
first connect, plus forward changes. Stores remain self-bootstrapping; the
runner is for controlled, audited upgrades in multi-instance deployments.
"""
from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    up_sql: str


class MigrationRunner:
    """Forward-only migration runner for SQLite or Postgres.

    Pass exactly one of ``sqlite_path`` or ``dsn``.
    """

    def __init__(self, *, sqlite_path: Optional[str] = None,
                 dsn: Optional[str] = None) -> None:
        if bool(sqlite_path) == bool(dsn):
            raise ValueError("pass exactly one of sqlite_path or dsn")
        self._sqlite_path = sqlite_path
        self._dsn = dsn
        self._is_pg = dsn is not None

    # ── connection helpers ─────────────────────────────────────────────────
    def _connect(self):
        if self._is_pg:
            from .. import _pg
            return _pg.connect(self._dsn)
        return sqlite3.connect(self._sqlite_path)

    @property
    def _param(self) -> str:
        return "%s" if self._is_pg else "?"

    def _ensure_table(self, conn) -> None:
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " version INTEGER PRIMARY KEY,"
            " name TEXT NOT NULL,"
            " applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        conn.commit()

    # ── public API ─────────────────────────────────────────────────────────
    def current_version(self) -> int:
        conn = self._connect()
        try:
            self._ensure_table(conn)
            cur = conn.cursor()
            cur.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
            row = cur.fetchone()
            return int(row[0]) if row and row[0] is not None else 0
        finally:
            conn.close()

    def applied_versions(self) -> list[int]:
        conn = self._connect()
        try:
            self._ensure_table(conn)
            cur = conn.cursor()
            cur.execute("SELECT version FROM schema_migrations ORDER BY version")
            return [int(r[0]) for r in cur.fetchall()]
        finally:
            conn.close()

    def run(self, migrations: list[Migration]) -> list[int]:
        """Apply every migration whose version is not yet recorded.

        Returns the list of versions applied in this run (empty if up-to-date).
        Each migration runs in its own transaction; a failure rolls back that
        migration and stops the run (forward-only, fail-fast).
        """
        applied_now: list[int] = []
        conn = self._connect()
        try:
            self._ensure_table(conn)
            cur = conn.cursor()
            cur.execute("SELECT version FROM schema_migrations")
            done = {int(r[0]) for r in cur.fetchall()}
            for mig in sorted(migrations, key=lambda m: m.version):
                if mig.version in done:
                    continue
                try:
                    cur.execute(mig.up_sql)
                    if self._param == "%s":
                        insert_sql = "INSERT INTO schema_migrations (version, name) VALUES (%s, %s)"
                    else:
                        insert_sql = "INSERT INTO schema_migrations (version, name) VALUES (?, ?)"
                    cur.execute(insert_sql, (mig.version, mig.name))
                    conn.commit()
                    applied_now.append(mig.version)
                    log.info("applied migration %d: %s", mig.version, mig.name)
                except Exception:
                    conn.rollback()
                    log.exception("migration %d (%s) failed; stopping",
                                  mig.version, mig.name)
                    raise
            return applied_now
        finally:
            conn.close()


# ── default migrations (mirror the stores' bootstrap schema) ────────────────
# SQLite-flavoured DDL; Postgres deployments should use MIGRATIONS_PG.

MIGRATIONS: list[Migration] = [
    Migration(
        version=1,
        name="create_traces",
        up_sql=(
            "CREATE TABLE IF NOT EXISTS traces ("
            " call_id TEXT PRIMARY KEY,"
            " tenant_id TEXT NOT NULL,"
            " session_id TEXT NOT NULL,"
            " created_at REAL NOT NULL,"
            " data TEXT NOT NULL)"
        ),
    ),
    Migration(
        version=2,
        name="create_audit_chain",
        up_sql=(
            "CREATE TABLE IF NOT EXISTS audit_chain ("
            " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
            " payload TEXT NOT NULL,"
            " prev_hash TEXT NOT NULL,"
            " this_hash TEXT NOT NULL)"
        ),
    ),
    Migration(
        version=3,
        name="index_traces_tenant",
        up_sql="CREATE INDEX IF NOT EXISTS idx_traces_tenant ON traces(tenant_id, session_id)",
    ),
]


# Postgres-flavoured migrations. Versions 1-2 mirror PostgresStore's bootstrap
# DDL; version 3 re-keys pre-0.7.1 rows from this_hash to call_id — the v0.7.1
# protocol fix (P1-6/T2-3) keys pramagent_traces.trace_id by the payload's
# call_id so /v1/trace/{call_id} can find rows written by older releases.
# Versions 4-5 add the tenant-isolation policy and the append-only chain guard
# (finding 4.2), reusing PostgresStore's own DDL so the two schema sources
# cannot diverge.


def _pg_traces_isolation_sql() -> str:
    """The RLS/policy DDL PostgresStore applies to pramagent_traces, taken
    verbatim from its template (source of truth). payload_type only affects the
    idempotent CREATE TABLE line, so JSONB here is inconsequential to the
    isolation statements this migration exists to add."""
    from ..store_postgres import _PostgresBase
    return _PostgresBase._DDL_TRACES_TEMPLATE.format(payload_type="JSONB")


def _pg_chain_guard_sql() -> str:
    """The append-only trigger DDL PostgresStore applies to pramagent_chain."""
    from ..store_postgres import _PostgresBase
    return _PostgresBase._DDL_CHAIN_TEMPLATE.format(payload_type="JSONB")


MIGRATIONS_PG: list[Migration] = [
    Migration(
        version=1,
        name="create_pramagent_traces",
        up_sql=(
            "CREATE TABLE IF NOT EXISTS pramagent_traces ("
            " id BIGSERIAL PRIMARY KEY,"
            " tenant_id TEXT NOT NULL,"
            " session_id TEXT NOT NULL,"
            " trace_id TEXT NOT NULL UNIQUE,"
            " payload JSONB NOT NULL,"
            " created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        ),
    ),
    Migration(
        version=2,
        name="create_pramagent_chain",
        up_sql=(
            "CREATE TABLE IF NOT EXISTS pramagent_chain ("
            " id BIGSERIAL PRIMARY KEY,"
            " this_hash TEXT NOT NULL UNIQUE,"
            " prev_hash TEXT NOT NULL,"
            " payload JSONB NOT NULL,"
            " anchor_tx TEXT NOT NULL DEFAULT '',"
            " created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        ),
    ),
    Migration(
        version=3,
        name="key_traces_by_call_id",
        up_sql=(
            "UPDATE pramagent_traces"
            " SET trace_id = payload->>'call_id'"
            " WHERE payload->>'call_id' IS NOT NULL"
            " AND trace_id IS DISTINCT FROM payload->>'call_id'"
        ),
    ),
    # Finding 4.2: the runner used to omit tenant isolation and chain
    # immutability entirely, so a deployment that provisions schema via the
    # MigrationRunner (and never boots PostgresStore, which re-applies these on
    # every startup) ran with RLS and the append-only guard absent. Rather than
    # duplicate the DDL (and let it drift), these two migrations run the exact
    # idempotent templates PostgresStore uses — that store is the source of
    # truth and is what the live RLS test exercises. The templates are wholly
    # idempotent (CREATE TABLE IF NOT EXISTS, ALTER ... ENABLE/FORCE, DROP
    # POLICY IF EXISTS + CREATE POLICY, CREATE OR REPLACE FUNCTION, DROP TRIGGER
    # IF EXISTS + CREATE TRIGGER), so re-running the table DDL is a no-op.
    Migration(
        version=4,
        name="enable_traces_row_level_security",
        up_sql=_pg_traces_isolation_sql(),
    ),
    Migration(
        version=5,
        name="chain_append_only_guard",
        up_sql=_pg_chain_guard_sql(),
    ),
]
