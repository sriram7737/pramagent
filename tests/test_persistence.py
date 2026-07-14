"""Tests for SQLiteStore: persistence, chain integrity, and survival across restarts."""
import asyncio
import json
import os
import tempfile

from pramagent import Pramagent, Verdict
from pramagent.layers import ComplianceLayer, SafetyLayer, Rule
from pramagent.providers import MockProvider
from pramagent.store import SQLiteStore
from pramagent.types import TraceEvent


def run(coro):
    return asyncio.run(coro)


def _make_armor(db_path):
    """Build a Pramagent instance backed by SQLite at the given path."""
    db = SQLiteStore(db_path)
    return Pramagent(
        provider=MockProvider(),
        safety=SafetyLayer(rules=[Rule("blk", Verdict.BLOCK, pattern=r"forbidden")]),
        compliance=ComplianceLayer(),
        store=db,
        audit=db,
    ), db


def test_sqlite_saves_and_retrieves():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        armor, db = _make_armor(path)
        r = run(armor.run("hello", tenant_id="t", session_id="s"))
        retrieved = db.get(r.trace.call_id)
        assert retrieved.call_id == r.trace.call_id
        assert retrieved.output_text == r.trace.output_text
        assert len(db.list_all()) == 1
    finally:
        db.close()
        os.unlink(path)


def test_sqlite_survives_restart():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        # session 1: write a trace
        armor1, db1 = _make_armor(path)
        r = run(armor1.run("remember this", tenant_id="a", session_id="1"))
        cid = r.trace.call_id
        chain_head = db1.head
        db1.close()

        # session 2: reopen the same file
        db2 = SQLiteStore(path)
        assert len(db2.list_all()) == 1
        retrieved = db2.get(cid)
        assert retrieved.input_text == "remember this"
        assert db2.head == chain_head          # chain head restored
        assert db2.verify_chain()              # chain still valid
        db2.close()
    finally:
        os.unlink(path)


def test_sqlite_chain_integrity():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        armor, db = _make_armor(path)
        run(armor.run("a")); run(armor.run("b")); run(armor.run("c"))
        assert len(db.list_all()) == 3
        assert db.verify_chain()
        db.close()
    finally:
        os.unlink(path)


def test_sqlite_chain_uses_hmac_signing_key_when_configured():
    """When PRAMAGENT_SIGNING_KEY is wired in, verify_chain() must fail if the
    wrong key (or no key) is used to recompute it — otherwise the setting is
    dead config that implies a security property the chain doesn't have
    (ISSUE-3)."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        db = SQLiteStore(path, signing_key="correct-signing-key")
        armor = Pramagent(
            provider=MockProvider(),
            compliance=ComplianceLayer(),
            store=db,
            audit=db,
        )
        run(armor.run("a")); run(armor.run("b"))
        assert db.verify_chain()
        db.close()

        # reopening with the same key: still valid
        same_key = SQLiteStore(path, signing_key="correct-signing-key")
        assert same_key.verify_chain()
        same_key.close()

        # reopening with the wrong key: the chain must NOT verify — proving
        # recomputation actually requires the secret, not just the payload
        wrong_key = SQLiteStore(path, signing_key="wrong-signing-key")
        assert not wrong_key.verify_chain()
        wrong_key.close()

        # reopening with no key at all: also must not verify
        no_key = SQLiteStore(path)
        assert not no_key.verify_chain()
        no_key.close()
    finally:
        os.unlink(path)


def test_canonical_hash_differs_with_and_without_signing_key():
    from pramagent.audit import canonical_hash

    unkeyed = canonical_hash({"a": 1}, "0" * 64)
    keyed = canonical_hash({"a": 1}, "0" * 64, "some-secret")
    other_key = canonical_hash({"a": 1}, "0" * 64, "different-secret")
    assert unkeyed != keyed
    assert keyed != other_key


def test_sqlite_pii_scrubbing_persisted():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        armor, db = _make_armor(path)
        r = run(armor.run("email me at a@b.com", tenant_id="t", session_id="s"))
        db.close()
        # reopen and verify PII was scrubbed in the persisted trace
        db2 = SQLiteStore(path)
        t = db2.get(r.trace.call_id)
        assert "email" in t.pii_redactions
        assert "a@b.com" not in t.output_text
        db2.close()
    finally:
        os.unlink(path)


def test_sqlite_erasure_redacts_chain_and_reanchors():
    """run -> store -> erase: the audit chain must hold no original PII
    afterwards, and must still verify because the links were re-hashed."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        db = SQLiteStore(path)
        # compliance disabled simulates PII that reached the record anyway —
        # erasure must remove it from the chain regardless of how it got there
        armor = Pramagent(
            provider=MockProvider(),
            compliance=ComplianceLayer(enabled=False),
            store=db, audit=db,
        )
        run(armor.run("subject SSN 123-45-6789 email bob@x.com", tenant_id="erase-me"))
        run(armor.run("keeper tenant data", tenant_id="keeper"))
        chain_before = str([r["payload"] for r in db.records()])
        assert "123-45-6789" in chain_before

        deleted = db.delete_for_tenant("erase-me")

        assert deleted == 1
        chain_after = str([r["payload"] for r in db.records()])
        assert "123-45-6789" not in chain_after
        assert "bob@x.com" not in chain_after
        assert "keeper tenant data" in chain_after    # other tenant untouched
        assert db.verify_chain()                      # re-anchored, still valid
        assert db.head == db.records()[-1]["this_hash"]
        assert len(db.list_by_tenant("keeper")) == 1
        assert len(db.list_by_tenant("erase-me")) == 0
        db.close()

        # the redaction must survive a restart
        db2 = SQLiteStore(path)
        assert "123-45-6789" not in str([r["payload"] for r in db2.records()])
        assert db2.verify_chain()
        db2.close()
    finally:
        os.unlink(path)


def test_sqlite_redact_for_tenant_is_idempotent():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        db = SQLiteStore(path)
        db.append({"tenant_id": "x", "input_text": "SSN 123-45-6789",
                   "output_text": "ok"})
        assert db.redact_for_tenant("x") == 1
        head_after_first = db.head
        assert db.redact_for_tenant("x") == 0          # already tombstoned
        assert db.head == head_after_first             # no double re-anchor
        assert db.verify_chain()
        db.close()
    finally:
        os.unlink(path)


def test_sqlite_delete_for_session_scoped_within_tenant():
    """One end user's erasure request must not touch another user's data
    sharing the same tenant — the whole point of session-scoped erasure."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        db = SQLiteStore(path)
        db.save(TraceEvent(call_id="c1", tenant_id="acme", session_id="user-a",
                            input_text="SSN 123-45-6789"))
        db.save(TraceEvent(call_id="c2", tenant_id="acme", session_id="user-b",
                            input_text="unrelated data"))
        db.append({"tenant_id": "acme", "session_id": "user-a", "input_text": "SSN 123-45-6789"})
        db.append({"tenant_id": "acme", "session_id": "user-b", "input_text": "unrelated data"})

        deleted = db.delete_for_session("acme", "user-a")

        assert deleted == 1
        assert db.count(tenant_id="acme") == 1
        remaining = db.list_by_tenant("acme")
        assert remaining[0].session_id == "user-b"
        chain = json.dumps(db.records())
        assert "123-45-6789" not in chain
        assert "unrelated data" in chain
        assert db.verify_chain()
        db.close()
    finally:
        os.unlink(path)


def test_sqlite_multiple_tenants_isolated():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        armor, db = _make_armor(path)
        run(armor.run("alpha", tenant_id="bank", session_id="s1"))
        run(armor.run("beta", tenant_id="hospital", session_id="s2"))
        assert len(db.list_by_tenant("bank")) == 1
        assert len(db.list_by_tenant("hospital")) == 1
        assert len(db.list_all()) == 2
        db.close()
    finally:
        os.unlink(path)
