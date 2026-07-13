"""Tests for PostgresStore: protocol conformance (call_id keying, TraceEvent
returns, KeyError/PermissionError), the chained hash (canonical_hash with
prev_hash in the material), tenant isolation, and GDPR erasure.

Uses an in-memory fake driver implementing the exact SQL surface
PostgresStore issues (the same pattern as test_auth.py's fake Postgres
registry). The fake returns JSONB columns as dicts, matching the real
psycopg/psycopg2 behaviour, so the str/dict payload handling is exercised
the way production would exercise it. Swap `connect=` for a real DSN or a
testcontainers fixture to run the identical assertions against live Postgres.
"""
import json
import re

import pytest

from pramagent.store_postgres import GENESIS, PostgresStore, PostgresUnavailable
from pramagent.types import TraceEvent


# ─────────────────────────── fake psycopg driver ──────────────────────────

class _FakeDB:
    def __init__(self):
        self.traces: dict[str, dict] = {}     # trace_id -> row
        self.chain: list[dict] = []           # ordered rows
        self._chain_seq = 0
        self._trace_seq = 0

    def next_chain_id(self) -> int:
        self._chain_seq += 1
        return self._chain_seq

    def next_trace_seq(self) -> int:
        self._trace_seq += 1
        return self._trace_seq

    def traces_by_recency(self) -> list[dict]:
        return sorted(self.traces.values(), key=lambda r: -r["seq"])


class _FakeCursor:
    def __init__(self, db: _FakeDB):
        self.db = db
        self.rowcount = 0
        self._rows: list[tuple] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        sql_norm = " ".join(sql.lower().split())
        params = params or ()
        if "create table" in sql_norm or "create index" in sql_norm:
            return
        if "set_config('pramagent.tenant_id'" in sql_norm:
            return
        if "set_config('pramagent.tenant_rls_bypass'" in sql_norm:
            return
        if "set_config('pramagent.chain_redaction_in_progress'" in sql_norm:
            return
        if "rolsuper, rolbypassrls from pg_roles" in sql_norm:
            self._rows = []
            return
        if sql_norm == "select 1":
            self._rows = [(1,)]
            return
        if "insert into pramagent_traces" in sql_norm:
            tenant_id, session_id, trace_id, payload = params
            existing = self.db.traces.get(trace_id)
            seq = existing["seq"] if existing else self.db.next_trace_seq()
            self.db.traces[trace_id] = {
                "tenant_id": tenant_id, "session_id": session_id,
                "trace_id": trace_id, "payload": json.loads(payload),
                "seq": seq,
            }
            self.rowcount = 1
            return
        if "select payload from pramagent_traces where trace_id" in sql_norm:
            row = self.db.traces.get(params[0])
            self._rows = [(row["payload"],)] if row else []
            return
        if ("select payload from pramagent_traces where tenant_id = %s and session_id"
                in sql_norm):
            tenant_id, session_id, limit = params
            rows = [r for r in self.db.traces_by_recency()
                    if r["tenant_id"] == tenant_id and r["session_id"] == session_id]
            self._rows = [(r["payload"],) for r in rows[: int(limit)]]
            return
        if "select payload from pramagent_traces where tenant_id" in sql_norm:
            tenant_id, limit = params
            rows = [r for r in self.db.traces_by_recency()
                    if r["tenant_id"] == tenant_id]
            self._rows = [(r["payload"],) for r in rows[: int(limit)]]
            return
        if "select count(*) from pramagent_traces where tenant_id" in sql_norm:
            tenant_id = params[0]
            self._rows = [(sum(1 for r in self.db.traces.values() if r["tenant_id"] == tenant_id),)]
            return
        if "select count(*) from pramagent_traces" in sql_norm:
            self._rows = [(len(self.db.traces),)]
            return
        if "select payload from pramagent_traces order by created_at desc" in sql_norm:
            rows = self.db.traces_by_recency()
            if params:
                rows = rows[: int(params[0])]
            self._rows = [(r["payload"],) for r in rows]
            return
        if "select payload from pramagent_traces order by created_at asc" in sql_norm:
            rows = list(reversed(self.db.traces_by_recency()))
            self._rows = [(r["payload"],) for r in rows]
            return
        if "delete from pramagent_traces where tenant_id = %s and session_id = %s" in sql_norm:
            tenant_id, session_id = params
            doomed = [tid for tid, r in self.db.traces.items()
                      if r["tenant_id"] == tenant_id and r["session_id"] == session_id]
            for tid in doomed:
                del self.db.traces[tid]
            self.rowcount = len(doomed)
            return
        if "delete from pramagent_traces where tenant_id" in sql_norm:
            doomed = [tid for tid, r in self.db.traces.items()
                      if r["tenant_id"] == params[0]]
            for tid in doomed:
                del self.db.traces[tid]
            self.rowcount = len(doomed)
            return
        if "insert into pramagent_chain" in sql_norm:
            this_hash, prev_hash, payload = params
            if any(r["this_hash"] == this_hash for r in self.db.chain):
                self.rowcount = 0   # ON CONFLICT DO NOTHING
                return
            self.db.chain.append({
                "id": self.db.next_chain_id(),
                "this_hash": this_hash, "prev_hash": prev_hash,
                "payload": json.loads(payload),
            })
            self.rowcount = 1
            return
        if re.search(r"select this_hash from pramagent_chain order by id desc", sql_norm):
            self._rows = ([(self.db.chain[-1]["this_hash"],)]
                          if self.db.chain else [])
            return
        if "select id, this_hash, prev_hash, payload from pramagent_chain" in sql_norm:
            self._rows = [(r["id"], r["this_hash"], r["prev_hash"], r["payload"])
                          for r in sorted(self.db.chain, key=lambda r: r["id"])]
            return
        if "select this_hash, prev_hash, payload from pramagent_chain" in sql_norm:
            self._rows = [(r["this_hash"], r["prev_hash"], r["payload"])
                          for r in sorted(self.db.chain, key=lambda r: r["id"])]
            return
        if "update pramagent_chain set payload" in sql_norm:
            payload, this_hash, prev_hash, row_id = params
            for r in self.db.chain:
                if r["id"] == row_id:
                    r["payload"] = json.loads(payload)
                    r["this_hash"] = this_hash
                    r["prev_hash"] = prev_hash
                    self.rowcount = 1
                    return
            self.rowcount = 0
            return
        if "update pramagent_chain set prev_hash" in sql_norm:
            prev_hash, row_id = params
            for r in self.db.chain:
                if r["id"] == row_id:
                    r["prev_hash"] = prev_hash
                    self.rowcount = 1
                    return
            self.rowcount = 0
            return
        raise AssertionError(f"unexpected SQL: {sql}")

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _FakeConnection:
    def __init__(self, db: _FakeDB):
        self.db = db
        self.closed = 0
        self.autocommit = False

    def cursor(self):
        return _FakeCursor(self.db)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        self.closed = 1


@pytest.fixture
def pg():
    db = _FakeDB()
    store = PostgresStore.from_dsn(
        "postgresql://unit-test", connect=lambda dsn: _FakeConnection(db))
    return store, db


def _trace(tenant: str, text: str, session: str = "s") -> TraceEvent:
    tr = TraceEvent(tenant_id=tenant, session_id=session, input_text=text)
    tr.this_hash = __import__("hashlib").sha256(
        f"{tenant}:{text}".encode()).hexdigest()
    return tr


# ───────────────────────────── store behaviour ────────────────────────────

def test_save_and_get_roundtrip_keyed_by_call_id(pg):
    store, _ = pg
    tr = _trace("acme", "hello world")
    store.save(tr)
    got = store.get(tr.call_id)
    assert isinstance(got, TraceEvent)
    assert got.tenant_id == "acme"
    assert got.input_text == "hello world"
    assert got.call_id == tr.call_id


def test_get_raises_keyerror_when_missing(pg):
    store, _ = pg
    with pytest.raises(KeyError):
        store.get("no-such-call-id")


def test_get_raises_permissionerror_on_tenant_mismatch(pg):
    store, _ = pg
    tr = _trace("acme", "private data")
    store.save(tr)
    with pytest.raises(PermissionError):
        store.get(tr.call_id, tenant_id="globex")
    # correct tenant still reads it
    assert store.get(tr.call_id, tenant_id="acme").tenant_id == "acme"


def test_list_all_returns_traceevents_most_recent_when_limited(pg):
    store, _ = pg
    for i in range(5):
        store.save(_trace("acme", f"trace {i}"))
    everything = store.list_all()
    assert len(everything) == 5
    assert all(isinstance(t, TraceEvent) for t in everything)
    recent = store.list_all(limit=2)
    assert len(recent) == 2
    assert all(isinstance(t, TraceEvent) for t in recent)
    assert recent[-1].input_text == "trace 4"   # newest last, like SQLiteStore


def test_list_by_tenant_returns_traceevents(pg):
    store, _ = pg
    store.save(_trace("acme", "acme data", session="s1"))
    store.save(_trace("globex", "globex data", session="s1"))
    rows = store.list_by_tenant("acme")
    assert len(rows) == 1 and isinstance(rows[0], TraceEvent)
    assert rows[0].tenant_id == "acme"
    scoped = store.list_by_tenant("acme", session_id="s1")
    assert len(scoped) == 1
    assert store.list_by_tenant("acme", session_id="other") == []


def test_tenant_isolation_in_listing(pg):
    store, _ = pg
    store.save(_trace("acme", "acme data"))
    store.save(_trace("globex", "globex data"))
    acme = store.list_for_tenant("acme")
    assert len(acme) == 1
    assert acme[0]["tenant_id"] == "acme"
    assert all(r["tenant_id"] == "globex" for r in store.list_for_tenant("globex"))


def test_erasure_deletes_only_target_tenant(pg):
    store, _ = pg
    store.save(_trace("erase-me", "subject data"))
    store.save(_trace("keeper", "other data"))
    deleted = store.delete_for_tenant("erase-me")
    assert deleted == 1
    assert store.list_for_tenant("erase-me") == []
    assert len(store.list_for_tenant("keeper")) == 1


def test_ping_returns_true(pg):
    store, _ = pg
    assert store.ping() is True


# ───────────────────────────── hash chain ─────────────────────────────────

def test_chain_append_updates_head_and_verifies(pg):
    store, _ = pg
    h1, _ = store.append({"tenant_id": "t", "n": 1})
    h2, _ = store.append({"tenant_id": "t", "n": 2})
    assert store.head == h2
    assert store.verify() == []          # no broken links
    assert store.verify_chain() is True


def test_chain_hash_includes_prev_hash(pg):
    """The hash material must include prev — identical payloads at different
    positions must produce different hashes (the non-chained sha256(payload)
    bug made them identical)."""
    from pramagent.audit import canonical_hash
    store, db = pg
    h1, _ = store.append({"tenant_id": "t", "n": 1})
    assert h1 == canonical_hash({"tenant_id": "t", "n": 1}, GENESIS)
    h2, _ = store.append({"tenant_id": "t", "n": 2})
    assert h2 == canonical_hash({"tenant_id": "t", "n": 2}, h1)
    assert db.chain[1]["prev_hash"] == h1


def test_chain_tamper_is_detected(pg):
    store, db = pg
    store.append({"tenant_id": "t", "n": 1})
    db.chain[0]["payload"]["n"] = 999    # tamper directly in storage
    broken = store.verify()
    assert broken and broken[0]["reason"] == "hash mismatch"
    assert store.verify_chain() is False


def test_chain_row_deletion_is_detected(pg):
    """Deleting an interior link must break verification — this is exactly
    what the unchained sha256(payload) hash could not detect (T2-3)."""
    store, db = pg
    store.append({"tenant_id": "t", "n": 1})
    store.append({"tenant_id": "t", "n": 2})
    store.append({"tenant_id": "t", "n": 3})
    del db.chain[1]                      # silently drop the middle link
    assert store.verify_chain() is False


def test_chain_row_reorder_is_detected(pg):
    store, db = pg
    store.append({"tenant_id": "t", "n": 1})
    store.append({"tenant_id": "t", "n": 2})
    db.chain[0]["id"], db.chain[1]["id"] = db.chain[1]["id"], db.chain[0]["id"]
    assert store.verify_chain() is False


def test_head_restored_on_reopen(pg):
    store, db = pg
    h1, _ = store.append({"tenant_id": "t", "n": 1})
    # simulate process restart against the same database
    reopened = PostgresStore.from_dsn(
        "postgresql://unit-test", connect=lambda dsn: _FakeConnection(db))
    assert reopened.head == h1


def test_concurrent_appends_never_fork_the_chain(pg):
    """Each append derives prev inside the transaction (FOR UPDATE), so even
    interleaved writers that pre-read the same stale head cannot fork the
    chain (P1-5 / T2-4)."""
    store, db = pg
    stale_head = store.head
    store.append({"tenant_id": "t", "n": 1}, stale_head)
    store.append({"tenant_id": "t", "n": 2}, stale_head)   # stale prev ignored
    assert store.verify_chain() is True
    assert db.chain[1]["prev_hash"] == db.chain[0]["this_hash"]


# ───────────────────── erasure redacts the chain too ──────────────────────

def test_erasure_redacts_chain_payloads_and_still_verifies(pg):
    store, db = pg
    store.append({"tenant_id": "erase-me", "input_text": "SSN 123-45-6789",
                  "output_text": "ok"})
    store.append({"tenant_id": "keeper", "input_text": "innocuous",
                  "output_text": "fine"})
    store.save(_trace("erase-me", "SSN 123-45-6789"))

    store.delete_for_tenant("erase-me")

    chain_dump = json.dumps([r["payload"] for r in db.chain])
    assert "123-45-6789" not in chain_dump
    assert "innocuous" in chain_dump          # other tenant untouched
    assert store.verify() == []               # re-anchored, still verifies
    assert store.verify_chain() is True
    assert store.list_for_tenant("erase-me") == []


def test_redact_for_tenant_is_idempotent(pg):
    store, db = pg
    store.append({"tenant_id": "x", "input_text": "SSN 123-45-6789"})
    assert store.redact_for_tenant("x") == 1
    assert store.redact_for_tenant("x") == 0
    assert store.verify() == []


def test_delete_for_session_scoped_within_tenant(pg):
    """One end user's erasure request must not touch another user sharing
    the same tenant — the practical per-user erasure unit given the schema
    has no separate user-id column."""
    store, db = pg
    store.save(_trace("acme", "SSN 123-45-6789", session="user-a"))
    store.save(_trace("acme", "unrelated data", session="user-b"))
    store.append({"tenant_id": "acme", "session_id": "user-a", "input_text": "SSN 123-45-6789"})
    store.append({"tenant_id": "acme", "session_id": "user-b", "input_text": "unrelated data"})

    deleted = store.delete_for_session("acme", "user-a")

    assert deleted == 1
    assert store.count(tenant_id="acme") == 1
    remaining = store.list_for_tenant("acme")
    assert remaining[0]["session_id"] == "user-b"
    assert store.verify() == []
    chain = json.dumps([r["payload"] for r in db.chain])
    assert "123-45-6789" not in chain
    assert "unrelated data" in chain


# ───────────────────────────── failure modes ──────────────────────────────

def test_unreachable_postgres_raises_early():
    def refuse(dsn):
        raise ConnectionRefusedError("nope")

    with pytest.raises(PostgresUnavailable):
        PostgresStore.from_dsn("postgresql://down", connect=refuse)
