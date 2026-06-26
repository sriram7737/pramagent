"""Tests for pramagent.memory -- agent-memory contract + integrity wrapper."""
import sqlite3

import pytest

from pramagent.memory import (GENESIS, InMemoryBackend, IntegrityMemoryStore,
                              MemoryIntegrityError, SQLiteMemoryBackend,
                              chain_digest, value_digest)


def test_put_get_roundtrip():
    mem = IntegrityMemoryStore(InMemoryBackend())
    rec = mem.put("agent-1", "scratch", b"plan v1", session_id="s1")
    assert rec.value == b"plan v1"
    assert rec.prev_hash == GENESIS
    assert mem.get("agent-1", "scratch").value == b"plan v1"


def test_get_missing_returns_none():
    mem = IntegrityMemoryStore(InMemoryBackend())
    assert mem.get("nobody", "nothing") is None
    assert mem.history("nobody", "nothing") == []


def test_chain_links_successive_writes():
    mem = IntegrityMemoryStore(InMemoryBackend())
    r1 = mem.put("a", "k", b"v1", session_id="s1")
    r2 = mem.put("a", "k", b"v2", session_id="s1")
    assert r2.prev_hash == r1.chain_hash
    assert r1.prev_hash == GENESIS
    hist = mem.history("a", "k")
    assert [r.value for r in hist] == [b"v1", b"v2"]
    assert mem.get("a", "k").value == b"v2"  # get returns the latest


def test_keys_and_agents_have_independent_chains():
    mem = IntegrityMemoryStore(InMemoryBackend())
    mem.put("a", "k1", b"x", session_id="s")
    r = mem.put("a", "k2", b"y", session_id="s")
    assert r.prev_hash == GENESIS  # different key starts a fresh chain
    assert mem.get("a", "k1").value == b"x"
    assert mem.get("b", "k1") is None  # different agent, isolated


def test_non_bytes_value_rejected():
    mem = IntegrityMemoryStore(InMemoryBackend())
    with pytest.raises(TypeError):
        mem.put("a", "k", "not bytes", session_id="s")  # type: ignore[arg-type]


def test_tamper_in_memory_value_is_detected():
    """Mutate a stored record's bytes out-of-band; read must raise."""
    backend = InMemoryBackend()
    mem = IntegrityMemoryStore(backend)
    mem.put("a", "k", b"trusted", session_id="s")
    # Reach past the wrapper and corrupt the persisted record.
    stored = backend._by_key[("a", "k")][0]
    backend._by_key[("a", "k")][0] = stored.__class__(
        **{**stored.__dict__, "value": b"poisoned"})
    with pytest.raises(MemoryIntegrityError):
        mem.get("a", "k")


def test_sqlite_roundtrip_and_persistence(tmp_path):
    path = str(tmp_path / "mem.db")
    backend = SQLiteMemoryBackend(path)
    mem = IntegrityMemoryStore(backend)
    mem.put("a", "k", b"first", session_id="s1")
    mem.put("a", "k", b"second", session_id="s1")
    backend.close()

    # Reopen -- records survive restart and still verify.
    backend2 = SQLiteMemoryBackend(path)
    mem2 = IntegrityMemoryStore(backend2)
    assert mem2.get("a", "k").value == b"second"
    assert len(mem2.history("a", "k")) == 2
    backend2.close()


def test_sqlite_tamper_is_detected(tmp_path):
    """The negative test that IS the feature: mutate the row directly in
    SQLite, then assert the read raises."""
    path = str(tmp_path / "mem.db")
    backend = SQLiteMemoryBackend(path)
    mem = IntegrityMemoryStore(backend)
    mem.put("a", "k", b"trusted value", session_id="s1")
    backend.close()

    raw = sqlite3.connect(path)
    raw.execute("UPDATE agent_memory SET value = ? WHERE key = ?",
                (b"poisoned value", "k"))
    raw.commit()
    raw.close()

    backend2 = SQLiteMemoryBackend(path)
    mem2 = IntegrityMemoryStore(backend2)
    with pytest.raises(MemoryIntegrityError):
        mem2.get("a", "k")
    backend2.close()


def test_head_accessor():
    mem = IntegrityMemoryStore(InMemoryBackend())
    assert mem.head("a", "k") == GENESIS  # empty chain
    r = mem.put("a", "k", b"v", session_id="s")
    assert mem.head("a", "k") == r.chain_hash


def test_expected_head_matches_genuine_head():
    mem = IntegrityMemoryStore(InMemoryBackend())
    mem.put("a", "k", b"v", session_id="s")
    head = mem.head("a", "k")
    assert mem.get("a", "k", expected_head=head).value == b"v"  # no raise


def test_full_rewrite_caught_only_with_external_head():
    """A self-consistent rewrite of the latest record passes internal
    verification (the limit we document) but is caught when the caller holds
    the genuine head externally and passes it as expected_head."""
    backend = InMemoryBackend()
    mem = IntegrityMemoryStore(backend)
    mem.put("a", "k", b"trusted", session_id="s")
    genuine_head = mem.head("a", "k")

    # Attacker controls the store: forge a fully self-consistent record.
    from pramagent.memory import chain_digest, value_digest
    vh = value_digest(b"forged")
    ch = chain_digest(GENESIS, vh, "a", "k", 1.0)
    forged = backend._by_key[("a", "k")][0].__class__(
        agent_id="a", key="k", value=b"forged", session_id="s",
        created_at=1.0, value_hash=vh, prev_hash=GENESIS, chain_hash=ch)
    backend._by_key[("a", "k")][0] = forged

    # Internal verification passes (documented limit) ...
    assert mem.get("a", "k").value == b"forged"
    # ... but the externally held head catches the rewrite.
    with pytest.raises(MemoryIntegrityError):
        mem.get("a", "k", expected_head=genuine_head)


def test_digests_are_deterministic():
    assert value_digest(b"x") == value_digest(b"x")
    a = chain_digest(GENESIS, value_digest(b"x"), "a", "k", 1.5)
    b = chain_digest(GENESIS, value_digest(b"x"), "a", "k", 1.5)
    assert a == b
    # changing the key changes the link (binding holds)
    c = chain_digest(GENESIS, value_digest(b"x"), "a", "k2", 1.5)
    assert a != c
