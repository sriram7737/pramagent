"""Tests for EncryptedSQLiteStore: confidentiality at rest + functional parity."""
import asyncio
import json
import os
import sqlite3
import tempfile

import pytest

pytest.importorskip("cryptography")
from cryptography.fernet import Fernet  # noqa: E402

from pramagent import Pramagent, Verdict  # noqa: E402
from pramagent.layers import SafetyLayer, Rule  # noqa: E402
from pramagent.providers import MockProvider  # noqa: E402
from pramagent.store_encrypted import EncryptedSQLiteStore  # noqa: E402


def run(coro):
    return asyncio.run(coro)


def _new_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


def test_payload_is_actually_encrypted_on_disk():
    """The headline confidentiality test: open the raw SQLite file and confirm
    plaintext does NOT appear anywhere in the encrypted columns."""
    path = _new_db()
    key = Fernet.generate_key()
    try:
        db = EncryptedSQLiteStore(path, key=key)
        armor = Pramagent(provider=MockProvider(), store=db, audit=db)
        secret = "this-secret-phrase-must-not-appear-on-disk-12345"
        run(armor.run(secret, tenant_id="t", session_id="s"))
        db.close()

        # Read the raw bytes from the file — we should NOT find the plaintext
        with open(path, "rb") as f:
            raw = f.read()
        assert secret.encode() not in raw, "plaintext leaked into the database file"

        # Inspect the encrypted column directly: it must be a Fernet token
        conn = sqlite3.connect(path)
        row = conn.execute("SELECT data_enc FROM traces").fetchone()
        conn.close()
        assert row[0].startswith(b"gAAAAA"), "data_enc is not a Fernet token"
    finally:
        os.unlink(path)


def test_roundtrip_with_correct_key():
    path = _new_db()
    key = Fernet.generate_key()
    try:
        db1 = EncryptedSQLiteStore(path, key=key)
        armor = Pramagent(provider=MockProvider(), store=db1, audit=db1)
        r = run(armor.run("hello encrypted world", tenant_id="t", session_id="s"))
        db1.close()

        # Reopen with the same key — should decrypt cleanly
        db2 = EncryptedSQLiteStore(path, key=key)
        t = db2.get(r.trace.call_id)
        assert t.input_text == "hello encrypted world"
        assert db2.verify_chain()
        db2.close()
    finally:
        os.unlink(path)


def test_wrong_key_fails_to_decrypt():
    """A different Fernet key must not be able to read the data."""
    path = _new_db()
    real_key = Fernet.generate_key()
    wrong_key = Fernet.generate_key()
    try:
        db = EncryptedSQLiteStore(path, key=real_key)
        armor = Pramagent(provider=MockProvider(), store=db, audit=db)
        r = run(armor.run("secret", tenant_id="t", session_id="s"))
        db.close()

        attacker = EncryptedSQLiteStore(path, key=wrong_key)
        with pytest.raises(Exception):
            attacker.get(r.trace.call_id)
        # chain verification with the wrong key must return False, not crash
        assert attacker.verify_chain() is False
        # B4: verify() (broken-link list, used by audit-verify-watch) must
        # also work on the encrypted backend — undecryptable ciphertext is a
        # broken link, not a crash.
        broken = attacker.verify()
        assert broken and broken[0]["reason"] == "hash mismatch"
        attacker.close()
    finally:
        os.unlink(path)


def test_tenant_guard_works_on_encrypted_store():
    """The same cross-tenant defense as on plain SQLiteStore."""
    path = _new_db()
    key = Fernet.generate_key()
    try:
        db = EncryptedSQLiteStore(path, key=key)
        armor = Pramagent(
            provider=MockProvider(),
            safety=SafetyLayer(rules=[Rule("blk", Verdict.BLOCK, pattern=r"forbidden")]),
            store=db, audit=db,
        )
        r = run(armor.run("hi", tenant_id="tenant_a", session_id="s"))
        # correct tenant: ok
        assert db.get(r.trace.call_id, tenant_id="tenant_a").call_id == r.trace.call_id
        # wrong tenant: PermissionError
        with pytest.raises(PermissionError):
            db.get(r.trace.call_id, tenant_id="tenant_b")
        db.close()
    finally:
        os.unlink(path)


def test_chain_integrity_under_encryption():
    """Encryption must not break the audit chain semantics."""
    path = _new_db()
    key = Fernet.generate_key()
    try:
        db = EncryptedSQLiteStore(path, key=key)
        armor = Pramagent(provider=MockProvider(), store=db, audit=db)
        for s in ["a", "b", "c"]:
            run(armor.run(s, tenant_id="t", session_id="s"))
        assert db.verify_chain() is True
        assert len(db.list_all()) == 3
        db.close()
    finally:
        os.unlink(path)


def test_encrypted_erasure_redacts_chain_and_reanchors():
    """Parity with test_sqlite_erasure_redacts_chain_and_reanchors (P1-2/T3-1):
    erasure on the encrypted store must tombstone the tenant's chain payloads
    and re-anchor — encryption under one global key is retention, not erasure."""
    from pramagent.layers import ComplianceLayer

    path = _new_db()
    key = Fernet.generate_key()
    try:
        db = EncryptedSQLiteStore(path, key=key)
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
        db2 = EncryptedSQLiteStore(path, key=key)
        assert "123-45-6789" not in str([r["payload"] for r in db2.records()])
        assert db2.verify_chain()
        db2.close()
    finally:
        os.unlink(path)


def test_encrypted_store_protocol_signatures():
    """list_all(limit) and prune_older_than(tenant_id) must match the
    TraceStore protocol the API depends on (P1-2 drift)."""
    path = _new_db()
    key = Fernet.generate_key()
    try:
        db = EncryptedSQLiteStore(path, key=key)
        armor = Pramagent(provider=MockProvider(), store=db, audit=db)
        for s in ["a", "b", "c"]:
            run(armor.run(s, tenant_id="t", session_id="s"))
        assert len(db.list_all(limit=2)) == 2          # no TypeError
        assert db.prune_older_than(0.0, tenant_id="other") == 0   # scoped, no-op
        assert db.ping() is True
        db.close()
    finally:
        os.unlink(path)


def test_missing_key_raises():
    """Constructing the store without a key (and no env var) must fail loudly."""
    path = _new_db()
    try:
        # ensure env var isn't set
        os.environ.pop("PRAMAGENT_ENCRYPTION_KEY", None)
        with pytest.raises(ValueError):
            EncryptedSQLiteStore(path)
    finally:
        os.unlink(path)
