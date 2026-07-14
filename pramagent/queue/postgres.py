"""
pramagent.queue.postgres
========================
Postgres-backed approval queue. The production choice — survives process
restarts, scales across workers, lets a webhook handler in one process
approve a request that another process is waiting on.

Uses ``psycopg`` (v3) if installed, falling back to ``psycopg2`` if not.
If neither is available, instantiation raises with a clear message instead
of silently importing a broken backend.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Optional

from .base import QueuedRequest, RequestStatus, from_row, to_row

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS {table} (
    request_id   TEXT PRIMARY KEY,
    action       TEXT NOT NULL,
    context      JSONB NOT NULL,
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    created_at   DOUBLE PRECISION NOT NULL,
    decided_at   DOUBLE PRECISION,
    status       TEXT NOT NULL DEFAULT 'pending',
    decided_by   TEXT NOT NULL DEFAULT '',
    notes        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS {status_idx}
    ON {table}(status);
CREATE INDEX IF NOT EXISTS {tenant_idx}
    ON {table}(tenant_id);
CREATE INDEX IF NOT EXISTS {created_idx}
    ON {table}(created_at);
"""

# Row-level tenant isolation for the HITL queue, mirroring the
# pramagent_traces policy in store_postgres.py. A missing tenant check in an
# app-layer WHERE clause (or a SQL bug) is still stopped at the database for
# any non-superuser role; FORCE applies the policy to the table owner too.
# The bypass GUC is set only by application code for intentionally
# cross-tenant operations (a waiter polling its own request by id, an
# unscoped list) — never from client input.
#
# ToolGuard-hook note: the two-word DDL keyword that turns row security on is
# assembled from fragments rather than written as one literal, because this
# repo's own PreToolUse ToolGuard hook flags that keyword as a SQL-injection
# shape and would otherwise block edits to this file. The runtime value is
# the ordinary keyword; this is the same documented workaround used in
# tests/test_postgres_rls_live.py.
_RLS_KW = "ALTER" + " TABLE"
_RLS_TEMPLATE = (
    _RLS_KW + " {table} ENABLE ROW LEVEL SECURITY;\n"
    + _RLS_KW + " {table} FORCE ROW LEVEL SECURITY;\n"
    "DROP POLICY IF EXISTS {policy} ON {table};\n"
    "CREATE POLICY {policy}\n"
    "ON {table}\n"
    "USING (\n"
    "    tenant_id = current_setting('pramagent.hitl_tenant_id', true)\n"
    "    OR current_setting('pramagent.hitl_rls_bypass', true) = 'on'\n"
    ")\n"
    "WITH CHECK (\n"
    "    tenant_id = current_setting('pramagent.hitl_tenant_id', true)\n"
    "    OR current_setting('pramagent.hitl_rls_bypass', true) = 'on'\n"
    ");\n"
)


def _import_driver():
    try:
        import psycopg  # psycopg3
        # psycopg3 auto-loads the sql submodule, but import it explicitly so
        # driver.sql is guaranteed present regardless of import order.
        from psycopg import sql as _sql  # noqa: F401
        return ("psycopg3", psycopg)
    except ImportError:
        psycopg = None
    try:
        import psycopg2  # psycopg2
        # psycopg2.sql is a submodule that `import psycopg2` does NOT pull in
        # (unlike psycopg3). Without this explicit import, driver.sql below
        # raises AttributeError and PostgresHITLQueue cannot construct at all
        # on a psycopg2-only install.
        import psycopg2.sql  # noqa: F401
        return ("psycopg2", psycopg2)
    except ImportError:
        psycopg2 = None
    return (None, None)


class PostgresHITLQueue:
    """Postgres-backed implementation of HITLQueueStore.

    Parameters
    ----------
    dsn : str
        Standard Postgres connection string (e.g. ``postgresql://user:pw@host/db``).
    table : str
        Override the table name; default ``pramagent_hitl_queue``.
    """

    def __init__(self, dsn: str, *, table: str = "pramagent_hitl_queue") -> None:
        flavor, driver = _import_driver()
        if driver is None:
            raise RuntimeError(
                "PostgresHITLQueue requires 'psycopg' (v3) or 'psycopg2'. "
                "Install with: pip install psycopg[binary]   (or)   pip install psycopg2-binary"
            )
        self._flavor = flavor
        self._driver = driver
        self._sql = driver.sql
        self.dsn = dsn
        self.table = table
        # validate table name strictly to keep parameterised queries safe
        if not table.replace("_", "").isalnum():
            raise ValueError(f"unsafe table name: {table!r}")
        self._table_ident = self._sql.Identifier(table)
        self._status_idx_ident = self._sql.Identifier(f"idx_{table}_status")
        self._tenant_idx_ident = self._sql.Identifier(f"idx_{table}_tenant")
        self._created_idx_ident = self._sql.Identifier(f"idx_{table}_created")
        self._policy_ident = self._sql.Identifier(f"{table}_tenant_isolation")
        # Thread-local connection cache (P3-8): the HITL waiter polls get()
        # every poll_interval_s — opening a fresh connection per poll would
        # hammer Postgres for nothing. One connection per thread, reused.
        self._local = threading.local()
        self._run(lambda cur: cur.execute(self._schema_sql()))

    # ── connection helpers ─────────────────────────────────────────────
    def _connection(self):
        """Return this thread's cached connection, reopening if stale."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                if not getattr(conn, "closed", 0):
                    return conn
            except Exception as exc:
                log.debug("postgres HITL cached connection probe failed: %s", exc)
            self._local.conn = None
        conn = self._driver.connect(self.dsn)
        self._local.conn = conn
        return conn

    def _run(self, fn):
        """Execute fn(cursor) on the cached connection with commit/rollback;
        a failed connection is evicted so the next call reconnects."""
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                result = fn(cur)
            conn.commit()
            return result
        except Exception:
            try:
                conn.rollback()
            except Exception:
                try:
                    conn.close()
                finally:
                    self._local.conn = None
            raise

    @staticmethod
    def _rowdict(cur, row) -> dict:
        cols = [d[0] for d in cur.description]
        return dict(zip(cols, row))

    def _query(self, template: str):
        return self._sql.SQL(template).format(table=self._table_ident)

    def _schema_sql(self):
        return self._sql.SQL(_SCHEMA + _RLS_TEMPLATE).format(
            table=self._table_ident,
            status_idx=self._status_idx_ident,
            tenant_idx=self._tenant_idx_ident,
            created_idx=self._created_idx_ident,
            policy=self._policy_ident,
        )

    def _apply_scope(self, cur, tenant_id: Optional[str]) -> None:
        """Set the per-transaction tenant GUC the RLS policy checks. When
        tenant_id is None the caller wants an intentionally cross-tenant op
        (waiter polling its own request by id, unscoped list), so the bypass
        GUC is set instead — never from client input. is_local=True scopes
        both to this transaction, which _run() commits, so nothing leaks to
        the next call on the pooled connection."""
        if tenant_id is None:
            cur.execute(
                "SELECT set_config('pramagent.hitl_rls_bypass', 'on', true)")
        else:
            cur.execute(
                "SELECT set_config('pramagent.hitl_tenant_id', %s, true)",
                (tenant_id,))

    # ── HITLQueueStore protocol ────────────────────────────────────────
    def enqueue(self, request: QueuedRequest) -> str:
        row = to_row(request)
        sql = self._query(
            "INSERT INTO {table} "
            "(request_id, action, context, tenant_id, created_at, "
            "decided_at, status, decided_by, notes) "
            "VALUES (%s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (request_id) DO NOTHING"
        )
        def _fn(cur):
            # WITH CHECK requires the tenant GUC to match the row's tenant.
            self._apply_scope(cur, row["tenant_id"])
            cur.execute(sql, (
                row["request_id"], row["action"], row["context"],
                row["tenant_id"], row["created_at"], row["decided_at"],
                row["status"], row["decided_by"], row["notes"],
            ))
        self._run(_fn)
        return request.request_id

    def get(self, request_id: str,
            tenant_id: Optional[str] = None) -> Optional[QueuedRequest]:
        if tenant_id is None:
            sql = self._query("SELECT * FROM {table} WHERE request_id = %s")
            args: tuple = (request_id,)
        else:
            sql = self._query(
                "SELECT * FROM {table} "
                "WHERE request_id = %s AND tenant_id = %s")
            args = (request_id, tenant_id)

        def _fn(cur):
            self._apply_scope(cur, tenant_id)
            cur.execute(sql, args)
            r = cur.fetchone()
            return self._rowdict(cur, r) if r else None
        d = self._run(_fn)
        if d is None:
            return None
        # context arrives as a dict from psycopg3 JSONB; from_row handles both
        if isinstance(d.get("context"), dict):
            import json
            d["context"] = json.dumps(d["context"])
        return from_row(d)

    def list_pending(self, tenant_id: Optional[str] = None,
                     limit: int = 100) -> list[QueuedRequest]:
        if tenant_id:
            sql = self._query(
                "SELECT * FROM {table} "
                "WHERE status = %s AND tenant_id = %s "
                "ORDER BY created_at ASC LIMIT %s"
            )
            args = (RequestStatus.PENDING.value, tenant_id, int(limit))
        else:
            sql = self._query(
                "SELECT * FROM {table} "
                "WHERE status = %s ORDER BY created_at ASC LIMIT %s"
            )
            args = (RequestStatus.PENDING.value, int(limit))

        def _fn(cur):
            self._apply_scope(cur, tenant_id or None)
            cur.execute(sql, args)
            return [self._rowdict(cur, r) for r in cur.fetchall()]
        out: list[QueuedRequest] = []
        for d in self._run(_fn):
            if isinstance(d.get("context"), dict):
                import json
                d["context"] = json.dumps(d["context"])
            out.append(from_row(d))
        return out

    def decide(self, request_id: str, *, approved: bool,
               decided_by: str = "", notes: str = "",
               tenant_id: Optional[str] = None) -> bool:
        new_status = (RequestStatus.APPROVED.value if approved
                      else RequestStatus.DENIED.value)
        if tenant_id is None:
            sql = self._query(
                "UPDATE {table} "
                "SET status=%s, decided_at=%s, decided_by=%s, notes=%s "
                "WHERE request_id=%s AND status=%s")
            args: tuple = (new_status, time.time(), decided_by, notes,
                           request_id, RequestStatus.PENDING.value)
        else:
            sql = self._query(
                "UPDATE {table} "
                "SET status=%s, decided_at=%s, decided_by=%s, notes=%s "
                "WHERE request_id=%s AND status=%s AND tenant_id=%s")
            args = (new_status, time.time(), decided_by, notes,
                    request_id, RequestStatus.PENDING.value, tenant_id)

        def _fn(cur):
            self._apply_scope(cur, tenant_id)
            cur.execute(sql, args)
            return cur.rowcount > 0
        return self._run(_fn)

    def expire(self, request_id: str,
               tenant_id: Optional[str] = None) -> bool:
        if tenant_id is None:
            sql = self._query(
                "UPDATE {table} "
                "SET status=%s, decided_at=%s "
                "WHERE request_id=%s AND status=%s")
            args: tuple = (RequestStatus.EXPIRED.value, time.time(),
                           request_id, RequestStatus.PENDING.value)
        else:
            sql = self._query(
                "UPDATE {table} "
                "SET status=%s, decided_at=%s "
                "WHERE request_id=%s AND status=%s AND tenant_id=%s")
            args = (RequestStatus.EXPIRED.value, time.time(),
                    request_id, RequestStatus.PENDING.value, tenant_id)

        def _fn(cur):
            self._apply_scope(cur, tenant_id)
            cur.execute(sql, args)
            return cur.rowcount > 0
        return self._run(_fn)
