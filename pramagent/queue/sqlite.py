"""
pramagent.queue.sqlite
======================
SQLite-backed approval queue. Single file, no daemon, zero dependencies.

Good for: single-process deployments, dev/staging, demos, and any place where
the trace store is also SQLite. Multi-process writers work because SQLite is
serialised, but Postgres is the right choice past a handful of workers.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from typing import Optional

from .base import QueuedRequest, RequestStatus, from_row, to_row


_SCHEMA = """
CREATE TABLE IF NOT EXISTS hitl_queue (
    request_id  TEXT PRIMARY KEY,
    action      TEXT NOT NULL,
    context     TEXT NOT NULL,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    created_at  REAL NOT NULL,
    decided_at  REAL,
    status      TEXT NOT NULL DEFAULT 'pending',
    decided_by  TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT '',
    expires_at  REAL,
    binding_hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_hitl_status   ON hitl_queue(status);
CREATE INDEX IF NOT EXISTS idx_hitl_tenant   ON hitl_queue(tenant_id);
CREATE INDEX IF NOT EXISTS idx_hitl_created  ON hitl_queue(created_at);
"""


class SQLiteHITLQueue:
    """SQLite-backed implementation of HITLQueueStore."""

    def __init__(self, path: str = "pramagent_hitl.db", *,
                 check_same_thread: bool = False) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=check_same_thread,
                                     isolation_level=None)  # autocommit
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._migrate_schema()

    def _migrate_schema(self) -> None:
        """Add binding fields to databases created by earlier releases."""
        from .base import approval_binding

        columns = {
            row[1] for row in self._conn.execute("PRAGMA table_info(hitl_queue)")
        }
        if "expires_at" not in columns:
            self._conn.execute("ALTER TABLE hitl_queue ADD COLUMN expires_at REAL")
        if "binding_hash" not in columns:
            self._conn.execute(
                "ALTER TABLE hitl_queue ADD COLUMN binding_hash TEXT NOT NULL DEFAULT ''"
            )
        rows = self._conn.execute(
            """
            SELECT request_id, action, context, tenant_id
            FROM hitl_queue WHERE binding_hash = ''
            """
        ).fetchall()
        import json
        for row in rows:
            try:
                context = json.loads(row[2])
            except (TypeError, ValueError):
                context = {}
            binding = approval_binding(row[1], context, row[3] or "default")
            self._conn.execute(
                "UPDATE hitl_queue SET binding_hash = ? WHERE request_id = ?",
                (binding, row[0]),
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # HITLQueueStore protocol
    def enqueue(self, request: QueuedRequest) -> str:
        row = to_row(request)
        with self._lock:
            self._conn.execute(
                """INSERT INTO hitl_queue
                   (request_id, action, context, tenant_id, created_at,
                    decided_at, status, decided_by, notes, expires_at, binding_hash)
                   VALUES (:request_id, :action, :context, :tenant_id,
                           :created_at, :decided_at, :status, :decided_by, :notes,
                           :expires_at, :binding_hash)""",
                row,
            )
        return request.request_id

    def get(self, request_id: str,
            tenant_id: Optional[str] = None) -> Optional[QueuedRequest]:
        if tenant_id is None:
            sql = "SELECT * FROM hitl_queue WHERE request_id = ?"
            args: tuple = (request_id,)
        else:
            sql = ("SELECT * FROM hitl_queue "
                   "WHERE request_id = ? AND tenant_id = ?")
            args = (request_id, tenant_id)
        with self._lock:
            now = time.time()
            self._conn.execute(
                """
                UPDATE hitl_queue SET status = ?, decided_at = ?
                WHERE request_id = ? AND status = ?
                  AND expires_at IS NOT NULL AND expires_at <= ?
                """,
                (RequestStatus.EXPIRED.value, now, request_id,
                 RequestStatus.PENDING.value, now),
            )
            cur = self._conn.execute(sql, args)
            r = cur.fetchone()
        return from_row(dict(r)) if r else None

    def list_pending(self, tenant_id: Optional[str] = None,
                     limit: int = 100) -> list[QueuedRequest]:
        if tenant_id:
            sql = (
                "SELECT * FROM hitl_queue WHERE status = ? AND tenant_id = ? "
                "ORDER BY created_at ASC LIMIT ?"
            )
            args: tuple = (RequestStatus.PENDING.value, tenant_id, int(limit))
        else:
            sql = (
                "SELECT * FROM hitl_queue WHERE status = ? "
                "ORDER BY created_at ASC LIMIT ?"
            )
            args = (RequestStatus.PENDING.value, int(limit))
        with self._lock:
            now = time.time()
            self._conn.execute(
                """
                UPDATE hitl_queue SET status = ?, decided_at = ?
                WHERE status = ? AND expires_at IS NOT NULL AND expires_at <= ?
                """,
                (RequestStatus.EXPIRED.value, now,
                 RequestStatus.PENDING.value, now),
            )
            cur = self._conn.execute(sql, args)
            rows = cur.fetchall()
        return [from_row(dict(r)) for r in rows]

    def decide(self, request_id: str, *, approved: bool,
               decided_by: str = "", notes: str = "",
               tenant_id: Optional[str] = None,
               expected_binding: Optional[str] = None) -> bool:
        new_status = (RequestStatus.APPROVED.value if approved
                      else RequestStatus.DENIED.value)
        now = time.time()
        conditions = "request_id = ? AND status = ?"
        tail: list = [request_id, RequestStatus.PENDING.value]
        if tenant_id is not None:
            conditions += " AND tenant_id = ?"
            tail.append(tenant_id)
        if expected_binding is not None:
            conditions += " AND binding_hash = ?"
            tail.append(expected_binding)
        conditions += " AND (expires_at IS NULL OR expires_at > ?)"
        tail.append(now)
        sql = (
            "UPDATE hitl_queue SET status = ?, decided_at = ?, "
            "decided_by = ?, notes = ? WHERE " + conditions
        )
        args = (new_status, now, decided_by, notes, *tail)

        lookup_sql = "SELECT * FROM hitl_queue WHERE request_id = ?"
        lookup_args: tuple = (request_id,)
        if tenant_id is not None:
            lookup_sql += " AND tenant_id = ?"
            lookup_args = (request_id, tenant_id)
        with self._lock:
            row = self._conn.execute(lookup_sql, lookup_args).fetchone()
            if row is None or not from_row(dict(row)).binding_is_valid():
                return False
            cur = self._conn.execute(sql, args)
            if cur.rowcount > 0:
                return True
            self._conn.execute(
                """
                UPDATE hitl_queue SET status = ?, decided_at = ?
                WHERE request_id = ? AND status = ?
                  AND expires_at IS NOT NULL AND expires_at <= ?
                """,
                (RequestStatus.EXPIRED.value, now, request_id,
                 RequestStatus.PENDING.value, now),
            )
            return False

    def expire(self, request_id: str,
               tenant_id: Optional[str] = None) -> bool:
        if tenant_id is None:
            sql = ("""UPDATE hitl_queue
                   SET status = ?, decided_at = ?
                   WHERE request_id = ? AND status = ?""")
            args: tuple = (RequestStatus.EXPIRED.value, time.time(),
                           request_id, RequestStatus.PENDING.value)
        else:
            sql = ("""UPDATE hitl_queue
                   SET status = ?, decided_at = ?
                   WHERE request_id = ? AND status = ? AND tenant_id = ?""")
            args = (RequestStatus.EXPIRED.value, time.time(),
                    request_id, RequestStatus.PENDING.value, tenant_id)
        with self._lock:
            cur = self._conn.execute(sql, args)
            return cur.rowcount > 0
