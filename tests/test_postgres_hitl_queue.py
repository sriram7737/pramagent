"""Tests for PostgresHITLQueue: construction under a psycopg2-only install
(F1), CRUD via a fake psycopg driver (T1), and cross-tenant isolation on
get()/decide()/expire() (D1).

The fake driver exposes the *real* ``psycopg2.sql`` module so the queue's
``sql.SQL(...).format(Identifier(...))`` composable path is exercised exactly
as production builds it; the fake cursor renders those composables back to a
SQL string and interprets the handful of statements the queue issues. This is
the same fake-driver approach as tests/test_postgres_store.py, adapted for the
HITL queue table. Swap the driver for a real DSN to run the identical
assertions against live Postgres (and see
test_postgres_hitl_queue_rls_live.py for the live tenant-isolation proof).
"""
from __future__ import annotations

import pytest

import pramagent.queue.postgres as pg_mod
from pramagent.queue.base import QueuedRequest, RequestStatus
from pramagent.queue.postgres import PostgresHITLQueue, _import_driver

psycopg2 = pytest.importorskip("psycopg2")
import psycopg2.sql  # noqa: E402  (F1: not auto-imported by `import psycopg2`)


# ─────────────────── F1: driver.sql must exist on psycopg2 ──────────────────

def test_import_driver_exposes_sql_submodule():
    """F1 regression: ``import psycopg2`` alone does NOT bind the ``sql``
    submodule, so ``driver.sql`` raised AttributeError and the queue could
    not construct at all on a psycopg2-only install. _import_driver() must
    now guarantee the submodule is loaded."""
    flavor, driver = _import_driver()
    assert driver is not None
    # The attribute access itself is what used to blow up.
    assert driver.sql is not None
    assert hasattr(driver.sql, "Identifier")


# ────────────────────────── fake psycopg driver ────────────────────────────

_COLUMNS = ["request_id", "action", "context", "tenant_id", "created_at",
            "decided_at", "status", "decided_by", "notes"]


def _render(sql) -> str:
    """Render a psycopg2 sql.Composable (or plain str) to its SQL text."""
    if isinstance(sql, str):
        return sql
    parts = []
    for part in getattr(sql, "seq", [sql]):
        strings = getattr(part, "strings", None)
        if strings is not None:            # Identifier
            parts.append('"' + '"."'.join(strings) + '"')
        else:                              # SQL
            parts.append(part.string)
    return "".join(parts)


class _FakeDB:
    def __init__(self):
        self.rows: dict[str, dict] = {}


class _FakeCursor:
    def __init__(self, db: _FakeDB):
        self.db = db
        self.rowcount = 0
        self.description = [(c,) for c in _COLUMNS]
        self._rows: list[tuple] = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        s = " ".join(_render(sql).lower().split())
        params = tuple(params or ())
        # DDL + GUC statements: accept and ignore. Match specific phrases,
        # not a bare "create" (the "created_at" column would false-match).
        if ("create table" in s or "create index" in s or "create policy" in s
                or "policy" in s or "row level security" in s
                or "set_config" in s):
            return
        if "insert" in s:                                   # enqueue
            row = dict(zip(_COLUMNS, params))
            self.db.rows.setdefault(row["request_id"], row)
            self.rowcount = 1
            return
        if s.startswith("select"):                          # get
            req_id = params[0]
            tenant = params[1] if len(params) > 1 else None
            row = self.db.rows.get(req_id)
            if row and (tenant is None or row["tenant_id"] == tenant):
                self._rows = [tuple(row[c] for c in _COLUMNS)]
            else:
                self._rows = []
            return
        if "update" in s:                                   # decide / expire
            is_decide = "decided_by" in s
            if is_decide:
                new_status, _ts, decided_by, notes = params[0:4]
                req_id, pending = params[4], params[5]
                tenant = params[6] if len(params) > 6 else None
            else:
                new_status, _ts = params[0:2]
                req_id, pending = params[2], params[3]
                tenant = params[4] if len(params) > 4 else None
                decided_by = notes = None
            row = self.db.rows.get(req_id)
            if (row is None or row["status"] != pending
                    or (tenant is not None and row["tenant_id"] != tenant)):
                self.rowcount = 0
                return
            row["status"] = new_status
            if is_decide:
                row["decided_by"], row["notes"] = decided_by, notes
            self.rowcount = 1
            return
        raise AssertionError(f"unexpected SQL: {s}")

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _FakeConnection:
    def __init__(self, db: _FakeDB):
        self.db = db
        self.closed = 0

    def cursor(self):
        return _FakeCursor(self.db)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        self.closed = 1


class _FakeDriver:
    """Stands in for the psycopg2 module: real ``sql`` submodule so the
    composable path is genuine, fake ``connect`` so no server is needed."""
    sql = psycopg2.sql

    def __init__(self, db: _FakeDB):
        self._db = db

    def connect(self, dsn):
        return _FakeConnection(self._db)


@pytest.fixture
def queue(monkeypatch):
    db = _FakeDB()
    driver = _FakeDriver(db)
    monkeypatch.setattr(pg_mod, "_import_driver",
                        lambda: ("psycopg2", driver))
    q = PostgresHITLQueue("postgresql://unit-test")
    return q, db


def _enqueue(q, tenant="acme", action="wire_transfer"):
    req = QueuedRequest.new(action, {"amount": 1}, tenant_id=tenant)
    q.enqueue(req)
    return req


# ─────────────────────────── T1: CRUD coverage ─────────────────────────────

def test_construct_and_enqueue_get_roundtrip(queue):
    q, _ = queue
    req = _enqueue(q)
    got = q.get(req.request_id)
    assert got is not None
    assert got.request_id == req.request_id
    assert got.tenant_id == "acme"
    assert got.status == RequestStatus.PENDING.value


def test_decide_marks_approved(queue):
    q, _ = queue
    req = _enqueue(q)
    assert q.decide(req.request_id, approved=True, decided_by="alice") is True
    got = q.get(req.request_id)
    assert got.status == RequestStatus.APPROVED.value
    assert got.decided_by == "alice"
    # second decide finds no pending row
    assert q.decide(req.request_id, approved=False) is False


def test_expire_marks_expired(queue):
    q, _ = queue
    req = _enqueue(q)
    assert q.expire(req.request_id) is True
    assert q.get(req.request_id).status == RequestStatus.EXPIRED.value


# ─────────────────── D1: cross-tenant isolation ─────────────────────────────

def test_get_is_tenant_scoped(queue):
    q, _ = queue
    req = _enqueue(q, tenant="tenant-a")
    # correct tenant sees it, wrong tenant does not
    assert q.get(req.request_id, tenant_id="tenant-a") is not None
    assert q.get(req.request_id, tenant_id="tenant-b") is None


def test_decide_rejects_cross_tenant(queue):
    """The exact D1 exploit: tenant B must not be able to approve tenant A's
    queued request by guessing/replaying its request_id."""
    q, db = queue
    req = _enqueue(q, tenant="tenant-a")
    assert q.decide(req.request_id, approved=True,
                    decided_by="attacker", tenant_id="tenant-b") is False
    # row untouched — still pending, no attacker recorded
    assert db.rows[req.request_id]["status"] == RequestStatus.PENDING.value
    # legitimate owner still can
    assert q.decide(req.request_id, approved=True,
                    decided_by="owner", tenant_id="tenant-a") is True


def test_expire_rejects_cross_tenant(queue):
    q, db = queue
    req = _enqueue(q, tenant="tenant-a")
    assert q.expire(req.request_id, tenant_id="tenant-b") is False
    assert db.rows[req.request_id]["status"] == RequestStatus.PENDING.value
