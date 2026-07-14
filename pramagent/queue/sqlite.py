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
    notes       TEXT NOT NULL DEFAULT ''
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

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ── HITLQueueStore protocol ────────────────────────────────────────
    def enqueue(self, request: QueuedRequest) -> str:
        row = to_row(request)
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO hitl_queue
                   (request_id, action, context, tenant_id, created_at,
                    decided_at, status, decided_by, notes)
                   VALUES (:request_id, :action, :context, :tenant_id,
                           :created_at, :decided_at, :status, :decided_by, :notes)""",
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
            cur = self._conn.execute(sql, args)
            rows = cur.fetchall()
        return [from_row(dict(r)) for r in rows]

    def decide(self, request_id: str, *, approved: bool,
               decided_by: str = "", notes: str = "",
               tenant_id: Optional[str] = None) -> bool:
        new_status = (RequestStatus.APPROVED.value if approved
                      else RequestStatus.DENIED.value)
        import time
        if tenant_id is None:
            sql = ("""UPDATE hitl_queue
                   SET status = ?, decided_at = ?, decided_by = ?, notes = ?
                   WHERE request_id = ? AND status = ?""")
            args: tuple = (new_status, time.time(), decided_by, notes,
                           request_id, RequestStatus.PENDING.value)
        else:
            sql = ("""UPDATE hitl_queue
                   SET status = ?, decided_at = ?, decided_by = ?, notes = ?
                   WHERE request_id = ? AND status = ? AND tenant_id = ?""")
            args = (new_status, time.time(), decided_by, notes,
                    request_id, RequestStatus.PENDING.value, tenant_id)
        with self._lock:
            cur = self._conn.execute(sql, args)
            return cur.rowcount > 0

    def expire(self, request_id: str,
               tenant_id: Optional[str] = None) -> bool:
        import time
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
