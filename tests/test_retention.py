"""Tests for retention / GDPR erasure on MemoryStore and SQLiteStore."""
import asyncio
import os
import tempfile
import time

from pramagent import Pramagent
from pramagent.providers import MockProvider
from pramagent.store import MemoryStore, SQLiteStore


def run(coro):
    return asyncio.run(coro)


# MemoryStore
def test_memory_prune_older_than():
    store = MemoryStore()
    armor = Pramagent(provider=MockProvider(), store=store)
    run(armor.run("old", tenant_id="t", session_id="s"))
    # write directly to backdate the trace
    store._traces[0].created_at = time.time() - 200 * 86400   # ~200 days old
    run(armor.run("new", tenant_id="t", session_id="s"))
    cutoff = time.time() - 180 * 86400
    deleted = store.prune_older_than(cutoff)
    assert deleted == 1
    assert len(store.list_all()) == 1
    assert store.list_all()[0].input_text == "new"


def test_memory_delete_for_tenant():
    store = MemoryStore()
    armor = Pramagent(provider=MockProvider(), store=store)
    run(armor.run("a", tenant_id="bank", session_id="s"))
    run(armor.run("b", tenant_id="hospital", session_id="s"))
    run(armor.run("c", tenant_id="bank", session_id="s"))
    deleted = store.delete_for_tenant("bank")
    assert deleted == 2
    remaining = store.list_all()
    assert len(remaining) == 1
    assert remaining[0].tenant_id == "hospital"


# SQLiteStore
def _sqlite_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


def test_sqlite_prune_older_than():
    path = _sqlite_path()
    try:
        db = SQLiteStore(path)
        armor = Pramagent(provider=MockProvider(), store=db, audit=db)
        run(armor.run("recent", tenant_id="t", session_id="s"))
        # backdate the row
        db._conn.execute("UPDATE traces SET created_at = ?",
                         (time.time() - 365 * 86400,))
        db._conn.commit()
        run(armor.run("fresh", tenant_id="t", session_id="s"))
        deleted = db.prune_older_than(time.time() - 180 * 86400)
        assert deleted == 1
        assert len(db.list_all()) == 1
        # audit chain rows are intentionally NOT pruned — chain integrity
        assert db.verify_chain() is True
        db.close()
    finally:
        os.unlink(path)


def test_sqlite_delete_for_tenant_preserves_chain():
    """GDPR erasure for a tenant must not break the audit chain."""
    path = _sqlite_path()
    try:
        db = SQLiteStore(path)
        armor = Pramagent(provider=MockProvider(), store=db, audit=db)
        run(armor.run("alpha", tenant_id="bank", session_id="s"))
        run(armor.run("beta", tenant_id="hospital", session_id="s"))
        run(armor.run("gamma", tenant_id="bank", session_id="s"))
        assert db.verify_chain() is True
        deleted = db.delete_for_tenant("bank")
        assert deleted == 2
        assert len(db.list_all()) == 1
        # the chain itself stays intact — payloads remain in audit_chain
        assert db.verify_chain() is True
        db.close()
    finally:
        os.unlink(path)
