"""
pramagent.store_encrypted
=========================
EncryptedSQLiteStore — application-level encryption of sensitive payloads at
rest. Same interface as SQLiteStore; drop-in replacement.

Design choice
-------------
Two practical paths exist for SQLite-at-rest encryption:

  (a) Full-database encryption (SQLCipher / sqleet). Requires a custom system
      build of SQLite. Strong, but adds a system dependency that complicates
      installs.

  (b) Application-level field encryption. Encrypt the payload columns the app
      writes (trace JSON, audit-payload JSON) using a symmetric AEAD primitive,
      and leave indexed columns (call_id, tenant_id, created_at) in plain text
      so the database can still query them. Plain-Python; no system deps.

This module implements (b) using Fernet (AES-128-CBC + HMAC-SHA256 via the
`cryptography` package). It is the right default for the prototype: real PII
and trace content are encrypted at rest, while operational queries still work.

Key management
--------------
The encryption key is supplied to the constructor or read from the
PRAMAGENT_ENCRYPTION_KEY environment variable. Generate one with::

    from cryptography.fernet import Fernet
    print(Fernet.generate_key().decode())

The key MUST be stored in a secret manager (AWS Secrets Manager, Vault, etc.)
in production. The store does not log the key, derive it from passwords, or
attempt key rotation — those concerns belong upstream and a real deployment
should layer them on (envelope encryption with a KMS data key is the usual
production pattern).
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading

from .audit import AuditAppendResult, canonical_hash, redact_chain_payload
from .store import GENESIS
from .types import TraceEvent


class EncryptedSQLiteStore:
    """SQLite store with application-level encryption on payload columns.

    Indexed columns (call_id, tenant_id, session_id, created_at, prev_hash,
    this_hash) remain in plain text so the database can index and query them.
    All free-form content (trace JSON, audit-payload JSON) is encrypted with
    Fernet before INSERT and decrypted on SELECT.

    The hash chain is computed over the *plaintext* payload, exactly as in
    SQLiteStore, so verify_chain() works identically — the encryption layer is
    invisible to the audit semantics.
    """

    def __init__(self, path: str = "pramagent.db", key: bytes | str | None = None,
                 signing_key: str = "", *, signing_keys: dict | None = None,
                 active_kid: str | None = None) -> None:
        # HMAC key for canonical_hash (PRAMAGENT_SIGNING_KEY); see its
        # docstring for why an unkeyed chain alone isn't tamper-evident
        # against an actor with raw DB write access. signing_keys/active_kid
        # enable kid-versioned rotation (G1).
        from .audit import SigningKeyRing
        self._keyring = SigningKeyRing.from_config(
            signing_key=signing_key, signing_keys=signing_keys,
            active_kid=active_kid)
        self._signing_key = self._keyring.active_key()
        try:
            from cryptography.fernet import Fernet
        except ImportError as e:
            raise RuntimeError(
                "EncryptedSQLiteStore requires the 'cryptography' package. "
                "Install with: pip install 'pramagent[encrypted]'"
            ) from e

        if key is None:
            key = os.environ.get("PRAMAGENT_ENCRYPTION_KEY")
        if not key:
            raise ValueError(
                "encryption key required: pass key= or set PRAMAGENT_ENCRYPTION_KEY"
            )
        self._fernet = Fernet(key if isinstance(key, bytes) else key.encode())

        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        # Same shared-connection serialization as SQLiteStore (P1-5/T2-4).
        self._lock = threading.RLock()
        self._create_tables()
        self._head = self._load_head()
        # prev of the most recent append — core records it on the trace
        self.last_prev_hash = GENESIS

    # ── encryption helpers ────────────────────────────────────────────────
    def _encrypt(self, data: str) -> bytes:
        return self._fernet.encrypt(data.encode("utf-8"))

    def _decrypt(self, blob: bytes) -> str:
        return self._fernet.decrypt(blob).decode("utf-8")

    # ── schema ────────────────────────────────────────────────────────────
    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS traces (
                call_id    TEXT PRIMARY KEY,
                tenant_id  TEXT NOT NULL,
                session_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                data_enc   BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_traces_tenant
                ON traces(tenant_id, session_id);
            CREATE INDEX IF NOT EXISTS idx_traces_time
                ON traces(created_at);

            CREATE TABLE IF NOT EXISTS audit_chain (
                seq         INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_enc BLOB NOT NULL,
                prev_hash   TEXT NOT NULL,
                this_hash   TEXT NOT NULL
            );
        """)

    def close(self) -> None:
        self._conn.close()

    # ── TraceStore interface ──────────────────────────────────────────────
    def save(self, trace: TraceEvent) -> None:
        blob = self._encrypt(json.dumps(trace.to_dict(), sort_keys=True))
        self._conn.execute(
            "INSERT OR REPLACE INTO traces "
            " (call_id, tenant_id, session_id, created_at, data_enc)"
            " VALUES (?, ?, ?, ?, ?)",
            (trace.call_id, trace.tenant_id, trace.session_id,
             trace.created_at, blob),
        )
        self._conn.commit()

    def get(self, call_id: str, tenant_id: str | None = None) -> TraceEvent:
        row = self._conn.execute(
            "SELECT data_enc, tenant_id FROM traces WHERE call_id = ?", (call_id,)
        ).fetchone()
        if row is None:
            raise KeyError(call_id)
        if tenant_id is not None and row[1] != tenant_id:
            raise PermissionError(
                f"trace {call_id} does not belong to tenant {tenant_id}")
        return TraceEvent.from_dict(json.loads(self._decrypt(row[0])))

    def list_all(self, limit: int | None = None) -> list[TraceEvent]:
        sql = "SELECT data_enc FROM traces ORDER BY created_at"
        if limit is not None:
            sql += f" DESC LIMIT {int(limit)}"
        with self._lock:
            rows = self._conn.execute(sql).fetchall()
        out = [TraceEvent.from_dict(json.loads(self._decrypt(r[0]))) for r in rows]
        if limit is not None:
            out.reverse()
        return out

    def list_by_tenant(self, tenant_id: str, session_id: str | None = None,
                       limit: int = 100) -> list[TraceEvent]:
        if session_id:
            rows = self._conn.execute(
                "SELECT data_enc FROM traces WHERE tenant_id=? AND session_id=?"
                " ORDER BY created_at DESC LIMIT ?",
                (tenant_id, session_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data_enc FROM traces WHERE tenant_id=?"
                " ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [TraceEvent.from_dict(json.loads(self._decrypt(r[0]))) for r in rows]

    def prune_older_than(self, cutoff_ts: float, tenant_id: str | None = None) -> int:
        """Delete trace rows older than cutoff. When tenant_id is given the
        prune is scoped to that tenant only (TraceStore protocol parity)."""
        with self._lock:
            if tenant_id is None:
                cur = self._conn.execute(
                    "DELETE FROM traces WHERE created_at < ?", (cutoff_ts,))
            else:
                cur = self._conn.execute(
                    "DELETE FROM traces WHERE created_at < ? AND tenant_id = ?",
                    (cutoff_ts, tenant_id))
            self._conn.commit()
            return cur.rowcount

    def delete_for_tenant(self, tenant_id: str) -> int:
        """GDPR erasure for one tenant: deletes the trace rows AND redacts the
        tenant's payloads inside audit_chain — identical semantics to
        SQLiteStore (P1-2/T3-1). Encryption under a single global key is
        retention, not erasure; the PII-bearing fields must be tombstoned."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM traces WHERE tenant_id = ?", (tenant_id,))
            self.redact_for_tenant(tenant_id)
            self._conn.commit()
            return cur.rowcount

    def delete_for_session(self, tenant_id: str, session_id: str) -> int:
        """GDPR erasure scoped to one session within a tenant — see
        SQLiteStore.delete_for_session for why session_id is the practical
        per-end-user erasure unit given the current schema."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM traces WHERE tenant_id = ? AND session_id = ?",
                (tenant_id, session_id),
            )
            self.redact_for_session(tenant_id, session_id)
            self._conn.commit()
            return cur.rowcount

    def redact_for_tenant(self, tenant_id: str) -> int:
        """Tombstone PII fields in this tenant's chain payloads, then
        re-anchor: every link from the first redaction onward gets recomputed
        prev/this hashes (over the plaintext payload, exactly as append hashes
        it) so verify_chain() still passes. Returns payloads redacted."""
        return self._redact_matching(lambda payload: payload.get("tenant_id") == tenant_id)

    def redact_for_session(self, tenant_id: str, session_id: str) -> int:
        """Same as redact_for_tenant, scoped to one session."""
        return self._redact_matching(
            lambda payload: (
                payload.get("tenant_id") == tenant_id
                and payload.get("session_id") == session_id
            )
        )

    def _redact_matching(self, predicate) -> int:
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, payload_enc, prev_hash, this_hash FROM audit_chain ORDER BY seq"
            ).fetchall()
            prev, redacted, rehash = GENESIS, 0, False
            for seq, payload_enc, _stored_prev, stored_hash in rows:
                payload = json.loads(self._decrypt(payload_enc))
                if predicate(payload) and redact_chain_payload(payload):
                    redacted += 1
                    rehash = True
                if rehash:
                    new_hash = canonical_hash(payload, prev, self._signing_key)
                    blob = self._encrypt(json.dumps(payload, sort_keys=True,
                                                    separators=(",", ":")))
                    self._conn.execute(
                        "UPDATE audit_chain SET payload_enc=?, prev_hash=?, this_hash=?"
                        " WHERE seq=?", (blob, prev, new_hash, seq))
                    prev = new_hash
                else:
                    prev = stored_hash
            if rehash:
                self._head = prev
                self._conn.commit()
            return redacted

    # ── AuditBackend interface ────────────────────────────────────────────
    @property
    def head(self) -> str:
        return self._head

    def append(self, payload: dict, prev_hash: str | None = None) -> AuditAppendResult:
        """Append one chain link. `prev` is re-read from the DB inside
        BEGIN IMMEDIATE under the write lock — same fork-proof linkage
        derivation as SQLiteStore (P1-5/T2-4); the prev_hash parameter is
        retained for interface compatibility and ignored."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")   # cross-process write lock
            row = self._conn.execute(
                "SELECT this_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev = row[0] if row else GENESIS       # re-read under the lock
            if self._keyring.versioned:              # G1: tag row's key version
                from .audit import CHAIN_KID_FIELD
                payload = {**payload, CHAIN_KID_FIELD: self._keyring.active_kid}
            canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            this_hash = canonical_hash(payload, prev, self._keyring.active_key())
            self._conn.execute(
                "INSERT INTO audit_chain (payload_enc, prev_hash, this_hash) VALUES (?, ?, ?)",
                (self._encrypt(canonical_json), prev, this_hash),
            )
            self._conn.commit()
            self.last_prev_hash = prev
            self._head = this_hash
            return AuditAppendResult(this_hash, f"sqlite-enc:{this_hash[:16]}", prev)

    def verify_chain(self) -> bool:
        rows = self._conn.execute(
            "SELECT payload_enc, prev_hash, this_hash FROM audit_chain ORDER BY seq"
        ).fetchall()
        from .audit import chain_link_hash_ok
        prev = GENESIS
        for payload_enc, stored_prev, stored_hash in rows:
            try:
                payload = json.loads(self._decrypt(payload_enc))
            except Exception:
                return False    # tampering with ciphertext or wrong key
            if (not chain_link_hash_ok(payload, prev, stored_hash, self._keyring)
                    or stored_prev != prev):
                return False
            prev = stored_hash
        return True

    def verify(self) -> list[dict]:
        """Broken-link list (empty = intact), matching PostgresStore.verify()
        so `pramagent audit-verify-watch` works against the encrypted SQLite
        backend too (B4). A ciphertext that will not decrypt is reported as a
        hash mismatch rather than crashing."""
        rows = self._conn.execute(
            "SELECT payload_enc, prev_hash, this_hash FROM audit_chain ORDER BY seq"
        ).fetchall()
        from .audit import chain_link_hash_ok
        broken: list[dict] = []
        prev = GENESIS
        for payload_enc, stored_prev, stored_hash in rows:
            try:
                payload = json.loads(self._decrypt(payload_enc))
            except Exception:
                broken.append({"this_hash": stored_hash, "reason": "hash mismatch"})
                prev = stored_hash
                continue
            if not chain_link_hash_ok(payload, prev, stored_hash, self._keyring):
                broken.append({"this_hash": stored_hash, "reason": "hash mismatch"})
            elif stored_prev != prev:
                broken.append({"this_hash": stored_hash, "reason": "broken prev link"})
            prev = stored_hash
        return broken

    def records(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT payload_enc, prev_hash, this_hash FROM audit_chain ORDER BY seq"
        ).fetchall()
        return [
            {"payload": json.loads(self._decrypt(r[0])),
             "prev_hash": r[1], "this_hash": r[2]}
            for r in rows
        ]

    def ping(self) -> bool:
        """O(1) connectivity check for readiness probes."""
        with self._lock:
            self._conn.execute("SELECT 1").fetchone()
        return True

    def count(self, tenant_id: str | None = None) -> int:
        """Trace count via SQL COUNT — never a full-table load (P2-14)."""
        with self._lock:
            if tenant_id:
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM traces WHERE tenant_id = ?",
                    (tenant_id,)).fetchone()
            else:
                row = self._conn.execute("SELECT COUNT(*) FROM traces").fetchone()
        return int(row[0])

    def _load_head(self) -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT this_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        return row[0] if row else GENESIS
