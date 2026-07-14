"""
pramagent.store
===============
Pluggable trace storage. MemoryStore is the zero-dependency default (traces
live in-process, lost on restart). SQLiteStore persists traces and the audit
hash chain to disk so they survive restarts — this is what a real deployment
uses.

Both stores implement the same protocol, so swapping is one line:

    from pramagent.store import SQLiteStore
    db = SQLiteStore("pramagent.db")
    armor = Pramagent(provider=..., store=db, audit=db)

SQLiteStore also implements the AuditBackend interface (append, verify_chain,
head, records), so a single object replaces both the in-memory store and the
in-memory hash chain — all persisted to one file.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Protocol, runtime_checkable

from .audit import AuditAppendResult, canonical_hash, redact_chain_payload
from .types import TraceEvent


GENESIS = "0" * 64


# ──────────────────────────── protocol (duck-typing) ───────────────────────
@runtime_checkable
class TraceStore(Protocol):
    def save(self, trace: TraceEvent) -> None: ...
    def get(self, call_id: str, tenant_id: str | None = None) -> TraceEvent: ...
    def list_all(self, limit: int | None = None) -> list[TraceEvent]: ...
    def prune_older_than(self, cutoff_ts: float, tenant_id: str | None = None) -> int: ...
    def delete_for_tenant(self, tenant_id: str) -> int: ...


# ──────────────────────────── in-memory (default) ──────────────────────────
class MemoryStore:
    """Zero-dependency in-process store. Traces lost on restart."""

    def __init__(self) -> None:
        self._traces: list[TraceEvent] = []

    def save(self, trace: TraceEvent) -> None:
        self._traces.append(trace)

    def get(self, call_id: str, tenant_id: str | None = None) -> TraceEvent:
        for t in self._traces:
            if t.call_id == call_id:
                if tenant_id is not None and t.tenant_id != tenant_id:
                    raise PermissionError(
                        f"trace {call_id} does not belong to tenant {tenant_id}")
                return t
        raise KeyError(call_id)

    def list_all(self, limit: int | None = None) -> list[TraceEvent]:
        items = list(self._traces)
        if limit is not None:
            return items[-limit:]
        return items

    def prune_older_than(self, cutoff_ts: float, tenant_id: str | None = None) -> int:
        """Delete traces older than cutoff. Returns the count deleted. Use only
        after the EU AI Act minimum retention (six months) has elapsed.

        When tenant_id is given the prune is scoped to that tenant only, so one
        tenant can never prune another tenant's records."""
        before = len(self._traces)
        if tenant_id is None:
            self._traces = [t for t in self._traces if t.created_at >= cutoff_ts]
        else:
            self._traces = [
                t for t in self._traces
                if not (t.tenant_id == tenant_id and t.created_at < cutoff_ts)
            ]
        return before - len(self._traces)

    def delete_for_tenant(self, tenant_id: str) -> int:
        """GDPR erasure: delete all traces for a tenant. Returns the count deleted.
        MemoryStore does not hold the audit chain; when the audit backend is a
        separate object (the default HashChainBackend), call its
        redact_for_tenant() as well so chain payloads are tombstoned too —
        the API erase endpoint does both."""
        before = len(self._traces)
        self._traces = [t for t in self._traces if t.tenant_id != tenant_id]
        return before - len(self._traces)

    def delete_for_session(self, tenant_id: str, session_id: str) -> int:
        """Same as delete_for_tenant, scoped to one session — the practical
        per-end-user erasure unit given the schema has no separate
        per-user column. Pair with the audit backend's redact_for_session()
        exactly as delete_for_tenant pairs with redact_for_tenant."""
        before = len(self._traces)
        self._traces = [
            t for t in self._traces
            if not (t.tenant_id == tenant_id and t.session_id == session_id)
        ]
        return before - len(self._traces)

    def count(self, tenant_id: str | None = None) -> int:
        if tenant_id:
            return sum(1 for t in self._traces if t.tenant_id == tenant_id)
        return len(self._traces)


# ──────────────────────────── SQLite (persistent) ──────────────────────────
class SQLiteStore:
    """
    Persists traces AND the audit hash chain to a single SQLite file. Implements
    both the TraceStore protocol and the AuditBackend protocol, so one object
    replaces both in-memory defaults.

    Tables:
        traces       — full TraceEvent as JSON + indexed columns for lookup
        audit_chain  — ordered chain records for tamper verification
    """

    def __init__(self, path: str = "pramagent.db", signing_key: str = "",
                 *, signing_keys: dict | None = None,
                 active_kid: str | None = None) -> None:
        # HMAC key for canonical_hash (PRAMAGENT_SIGNING_KEY); see its
        # docstring for why an unkeyed chain alone isn't tamper-evident
        # against an actor with raw DB write access. signing_keys/active_kid
        # enable kid-versioned rotation (G1); a lone signing_key is the
        # classic single-key mode.
        from .audit import SigningKeyRing
        self._keyring = SigningKeyRing.from_config(
            signing_key=signing_key, signing_keys=signing_keys,
            active_kid=active_kid)
        self._signing_key = self._keyring.active_key()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")   # safe for concurrent reads
        # One shared connection used from multiple threads (core offloads
        # persistence via asyncio.to_thread): every method that touches it is
        # serialized through this re-entrant lock so interleaved execute/commit
        # pairs can never commit another writer's half-done work (P1-5/T2-4).
        self._lock = threading.RLock()
        self._create_tables()
        self._head = self._load_head()
        # prev of the most recent append — core records it on the trace
        self.last_prev_hash = GENESIS

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS traces (
                call_id    TEXT PRIMARY KEY,
                tenant_id  TEXT NOT NULL,
                session_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                data       TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_traces_tenant
                ON traces(tenant_id, session_id);
            CREATE INDEX IF NOT EXISTS idx_traces_time
                ON traces(created_at);

            CREATE TABLE IF NOT EXISTS audit_chain (
                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                payload    TEXT NOT NULL,
                prev_hash  TEXT NOT NULL,
                this_hash  TEXT NOT NULL
            );
        """)

    def close(self) -> None:
        self._conn.close()

    # ── TraceStore interface ──────────────────────────────────────────────
    def save(self, trace: TraceEvent) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO traces (call_id, tenant_id, session_id, created_at, data)"
                " VALUES (?, ?, ?, ?, ?)",
                (trace.call_id, trace.tenant_id, trace.session_id,
                 trace.created_at, json.dumps(trace.to_dict(), sort_keys=True)),
            )
            self._conn.commit()

    def get(self, call_id: str, tenant_id: str | None = None) -> TraceEvent:
        with self._lock:
            row = self._conn.execute(
                "SELECT data, tenant_id FROM traces WHERE call_id = ?", (call_id,)
            ).fetchone()
        if row is None:
            raise KeyError(call_id)
        if tenant_id is not None and row[1] != tenant_id:
            raise PermissionError(
                f"trace {call_id} does not belong to tenant {tenant_id}")
        return TraceEvent.from_dict(json.loads(row[0]))

    def list_all(self, limit: int | None = None) -> list[TraceEvent]:
        sql = "SELECT data FROM traces ORDER BY created_at"
        if limit is not None:
            sql += f" DESC LIMIT {int(limit)}"
        with self._lock:
            rows = self._conn.execute(sql).fetchall()
        out = [TraceEvent.from_dict(json.loads(r[0])) for r in rows]
        if limit is not None:
            out.reverse()
        return out

    def list_by_tenant(self, tenant_id: str, session_id: str | None = None,
                       limit: int = 100) -> list[TraceEvent]:
        with self._lock:
            if session_id:
                rows = self._conn.execute(
                    "SELECT data FROM traces WHERE tenant_id=? AND session_id=?"
                    " ORDER BY created_at DESC LIMIT ?",
                    (tenant_id, session_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT data FROM traces WHERE tenant_id=?"
                    " ORDER BY created_at DESC LIMIT ?",
                    (tenant_id, limit),
                ).fetchall()
        return [TraceEvent.from_dict(json.loads(r[0])) for r in rows]

    def prune_older_than(self, cutoff_ts: float, tenant_id: str | None = None) -> int:
        """Delete trace rows older than cutoff. Use only after the EU AI Act
        minimum retention (six months) has elapsed.

        When tenant_id is given the prune is scoped to that tenant only."""
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
        tenant's payloads inside audit_chain. Chain links are never deleted
        (that would orphan every subsequent hash); instead the PII-bearing
        fields are tombstoned and the chain is re-anchored — every link from
        the first redaction onward is re-hashed so verification still
        succeeds without the erased content."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM traces WHERE tenant_id = ?", (tenant_id,))
            self.redact_for_tenant(tenant_id)
            self._conn.commit()
            return cur.rowcount

    def delete_for_session(self, tenant_id: str, session_id: str) -> int:
        """GDPR erasure scoped to one session within a tenant.

        The schema has no separate per-end-user column, but session_id
        already identifies one user's conversation in practice — this is
        the "delete my data" primitive for a multi-user tenant, so a request
        from one end user doesn't require erasing (or hand-writing SQL
        against) every other user sharing that tenant."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM traces WHERE tenant_id = ? AND session_id = ?",
                (tenant_id, session_id),
            )
            self.redact_for_session(tenant_id, session_id)
            self._conn.commit()
            return cur.rowcount

    def redact_for_tenant(self, tenant_id: str) -> int:
        """Tombstone PII fields in this tenant's chain payloads (see
        pramagent.audit.redact_chain_payload), then re-anchor the chain:
        every link from the first redaction onward gets recomputed prev/this
        hashes so verify_chain() still passes. Returns payloads redacted."""
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
                "SELECT seq, payload, prev_hash, this_hash FROM audit_chain ORDER BY seq"
            ).fetchall()
            prev = GENESIS
            redacted = 0
            rehash = False
            for seq, payload_json, _stored_prev, stored_hash in rows:
                payload = json.loads(payload_json)
                if predicate(payload) and redact_chain_payload(payload):
                    redacted += 1
                    rehash = True
                if rehash:
                    new_hash = canonical_hash(payload, prev, self._signing_key)
                    self._conn.execute(
                        "UPDATE audit_chain SET payload = ?, prev_hash = ?, this_hash = ?"
                        " WHERE seq = ?",
                        (json.dumps(payload, sort_keys=True, separators=(",", ":")),
                         prev, new_hash, seq))
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
        """Append one chain link.

        `prev` is re-read from the DB inside BEGIN IMMEDIATE under the write
        lock — never taken from the caller or the cached head — so concurrent
        writers (threads in this process, or other processes sharing the
        file) can never both link from the same stale head and fork the
        chain (P1-5/T2-4). The prev_hash parameter is retained for interface
        compatibility and ignored."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")   # cross-process write lock
            row = self._conn.execute(
                "SELECT this_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev = row[0] if row else GENESIS       # re-read under the lock
            # G1: tag the row with the active key version when rotation is
            # configured, so verification can select the right key later.
            if self._keyring.versioned:
                from .audit import CHAIN_KID_FIELD
                payload = {**payload, CHAIN_KID_FIELD: self._keyring.active_kid}
            this_hash = canonical_hash(payload, prev, self._keyring.active_key())
            self._conn.execute(
                "INSERT INTO audit_chain (payload, prev_hash, this_hash) VALUES (?, ?, ?)",
                (json.dumps(payload, sort_keys=True, separators=(",", ":")),
                 prev, this_hash),
            )
            self._conn.commit()
            self.last_prev_hash = prev
            self._head = this_hash
            return AuditAppendResult(this_hash, f"sqlite:{this_hash[:16]}", prev)

    def verify_chain(self) -> bool:
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload, prev_hash, this_hash FROM audit_chain ORDER BY seq"
            ).fetchall()
        from .audit import chain_link_hash_ok
        prev = GENESIS
        for payload_json, stored_prev, stored_hash in rows:
            payload = json.loads(payload_json)
            if (not chain_link_hash_ok(payload, prev, stored_hash, self._keyring)
                    or stored_prev != prev):
                return False
            prev = stored_hash
        return True

    def verify(self) -> list[dict]:
        """Verify hash-chain integrity, returning a list of broken links
        (empty = intact) — the same shape PostgresStore.verify() returns, so
        `pramagent audit-verify-watch` works against SQLite too (B4). This
        was previously Postgres-only, so the watch command crashed with
        AttributeError on the documented default SQLite backend."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload, prev_hash, this_hash FROM audit_chain ORDER BY seq"
            ).fetchall()
        from .audit import chain_link_hash_ok
        broken: list[dict] = []
        prev = GENESIS
        for payload_json, stored_prev, stored_hash in rows:
            payload = json.loads(payload_json)
            if not chain_link_hash_ok(payload, prev, stored_hash, self._keyring):
                broken.append({"this_hash": stored_hash, "reason": "hash mismatch"})
            elif stored_prev != prev:
                broken.append({"this_hash": stored_hash, "reason": "broken prev link"})
            prev = stored_hash
        return broken

    def records(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload, prev_hash, this_hash FROM audit_chain ORDER BY seq"
            ).fetchall()
        return [
            {"payload": json.loads(r[0]), "prev_hash": r[1], "this_hash": r[2]}
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
