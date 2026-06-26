"""
pramagent.memory
================
Persistent agent memory with tamper-evident integrity.

Pramagent already gives traces a hash chain (see pramagent.audit); this module
extends the same discipline to the *memory* an agent reads back across
sessions. The contract is deliberately small -- three methods -- so any backend
(in-process, SQLite, or a future Redis/Postgres store) can satisfy it:

    class AgentMemoryStore(Protocol):
        def put(self, agent_id, key, value, *, session_id) -> MemoryRecord
        def get(self, agent_id, key) -> MemoryRecord | None
        def history(self, agent_id, key) -> list[MemoryRecord]

The integrity guarantee is NOT baked into each backend. Backends are dumb
persistence (append / latest / records); the chaining and verification live in
one wrapper, IntegrityMemoryStore, so every backend inherits the same guarantee
for free:

    from pramagent.memory import IntegrityMemoryStore, InMemoryBackend
    mem = IntegrityMemoryStore(InMemoryBackend())
    rec = mem.put("agent-1", "scratchpad", b"plan v1", session_id="s1")
    mem.get("agent-1", "scratchpad")        # re-verifies the chain on read

Each record carries the same hash-chain fields the audit chain uses:
``value_hash = sha256(value)``, ``prev_hash`` (the previous record's
``chain_hash`` for this agent_id+key, or GENESIS), and
``chain_hash = sha256(prev_hash | value_hash | agent_id | key | created_at)``.
On every read the wrapper recomputes the whole chain for that key and raises
MemoryIntegrityError if any record was mutated out-of-band between sessions
(e.g. a row edited directly in the database). That is the poisoning-detection
win, and it is backend-independent.

THREAT SCOPE -- read this honestly before relying on it. Two independent limits:

1. Integrity, not authenticity. This detects whether a stored value was altered
   after it was written -- NOT whether the value was true when written. A value
   poisoned at write time through a legitimate put() chains cleanly and passes
   verification. Detecting bad-but-validly-written content is a separate concern
   (validation/provenance), out of scope here.

2. Point mutation, not full rewrite. The chain is self-describing: each record
   carries its own value_hash/prev_hash/chain_hash. Recomputing on read catches
   a single mutated row (its value_hash, or the next row's prev_hash link,
   breaks) -- the common "someone edited one cell" case. It does NOT, on its own,
   catch a self-consistent rewrite by an attacker who *controls the store*: such
   an attacker can recompute value_hash and chain_hash for the latest record (or
   re-chain every row forward) and the result verifies. This is exactly the same
   property as the trace audit chain. The only defence against a full rewrite is
   anchoring to a head you hold OUTSIDE the store: persist head(agent_id, key)
   elsewhere (the audit chain, a client, an external anchor) and pass it back as
   ``expected_head`` on get()/history(). Without an external head, treat this as
   tamper-*evidence* against a non-privileged mutator, not tamper-proofing
   against whoever owns the database.
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


GENESIS = "0" * 64


class MemoryIntegrityError(RuntimeError):
    """Raised when a stored memory record fails hash-chain verification --
    i.e. its bytes were altered out-of-band after it was written."""


@dataclass(frozen=True)
class MemoryRecord:
    """One versioned memory write, with the hash-chain fields that make
    out-of-band tampering detectable. Records for the same (agent_id, key)
    form an append-only chain ordered by write time."""

    agent_id: str
    key: str
    value: bytes
    session_id: str
    created_at: float
    value_hash: str
    prev_hash: str
    chain_hash: str


def value_digest(value: bytes) -> str:
    """SHA-256 of the raw stored bytes."""
    return hashlib.sha256(value).hexdigest()


def chain_digest(prev_hash: str, value_hash: str, agent_id: str, key: str,
                 created_at: float) -> str:
    """Deterministic link hash. Binds the value to its position in the chain
    AND to the (agent_id, key) it was written under, so a record cannot be
    moved between keys or agents without breaking verification. created_at is
    stored on the record and reused verbatim so recomputation is exact."""
    material = "|".join(
        (prev_hash, value_hash, agent_id, key, repr(created_at)))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# ---------------------------- contracts ------------------------------------
@runtime_checkable
class AgentMemoryStore(Protocol):
    """The public agent-memory contract. Distinct from pramagent.store's
    MemoryStore, which stores *traces* -- this stores agent key/value memory."""

    def put(self, agent_id: str, key: str, value: bytes, *,
            session_id: str) -> MemoryRecord: ...
    def get(self, agent_id: str, key: str) -> MemoryRecord | None: ...
    def history(self, agent_id: str, key: str) -> list[MemoryRecord]: ...


@runtime_checkable
class MemoryBackend(Protocol):
    """Persistence-only interface. A backend stores records verbatim and
    returns them in write order; it does NOT compute or check hashes. All
    integrity discipline lives in IntegrityMemoryStore, so backends stay
    simple and every backend inherits the same guarantee."""

    def append(self, record: MemoryRecord) -> None: ...
    def latest(self, agent_id: str, key: str) -> MemoryRecord | None: ...
    def records(self, agent_id: str, key: str) -> list[MemoryRecord]: ...


# ---------------------------- backends -------------------------------------
class InMemoryBackend:
    """Zero-dependency in-process backend. Records lost on restart."""

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], list[MemoryRecord]] = {}
        self._lock = threading.Lock()

    def append(self, record: MemoryRecord) -> None:
        with self._lock:
            self._by_key.setdefault((record.agent_id, record.key), []).append(record)

    def latest(self, agent_id: str, key: str) -> MemoryRecord | None:
        with self._lock:
            chain = self._by_key.get((agent_id, key))
            return chain[-1] if chain else None

    def records(self, agent_id: str, key: str) -> list[MemoryRecord]:
        with self._lock:
            return list(self._by_key.get((agent_id, key), []))


class SQLiteMemoryBackend:
    """Persistent backend. One shared connection serialized through a re-entrant
    lock (matching pramagent.store.SQLiteStore), so worker threads can't
    interleave half-done writes. value is stored as a BLOB exactly as given."""

    def __init__(self, path: str = "pramagent_memory.db") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.RLock()
        self._create_table()

    def _create_table(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS agent_memory (
                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id   TEXT NOT NULL,
                key        TEXT NOT NULL,
                session_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                value      BLOB NOT NULL,
                value_hash TEXT NOT NULL,
                prev_hash  TEXT NOT NULL,
                chain_hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_agent_memory_key
                ON agent_memory(agent_id, key, seq);
        """)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def append(self, record: MemoryRecord) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO agent_memory (agent_id, key, session_id, created_at,"
                " value, value_hash, prev_hash, chain_hash)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (record.agent_id, record.key, record.session_id, record.created_at,
                 record.value, record.value_hash, record.prev_hash, record.chain_hash),
            )
            self._conn.commit()

    def _row_to_record(self, row) -> MemoryRecord:
        agent_id, key, session_id, created_at, value, vh, ph, ch = row
        return MemoryRecord(
            agent_id=agent_id, key=key, value=bytes(value), session_id=session_id,
            created_at=created_at, value_hash=vh, prev_hash=ph, chain_hash=ch)

    def latest(self, agent_id: str, key: str) -> MemoryRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT agent_id, key, session_id, created_at, value, value_hash,"
                " prev_hash, chain_hash FROM agent_memory"
                " WHERE agent_id = ? AND key = ? ORDER BY seq DESC LIMIT 1",
                (agent_id, key)).fetchone()
        return self._row_to_record(row) if row else None

    def records(self, agent_id: str, key: str) -> list[MemoryRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT agent_id, key, session_id, created_at, value, value_hash,"
                " prev_hash, chain_hash FROM agent_memory"
                " WHERE agent_id = ? AND key = ? ORDER BY seq",
                (agent_id, key)).fetchall()
        return [self._row_to_record(r) for r in rows]


# ---------------------------- integrity wrapper ----------------------------
class IntegrityMemoryStore:
    """Wraps any MemoryBackend and turns it into a tamper-evident
    AgentMemoryStore. Chain computation happens here on put(); chain
    verification happens here on every get()/history(). Because the discipline
    lives in this one place, swapping the backend never weakens the guarantee.
    """

    def __init__(self, backend: MemoryBackend) -> None:
        self._backend = backend

    def put(self, agent_id: str, key: str, value: bytes, *,
            session_id: str) -> MemoryRecord:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("memory value must be bytes")
        value = bytes(value)
        prev = self._backend.latest(agent_id, key)
        prev_hash = prev.chain_hash if prev else GENESIS
        created_at = time.time()
        vh = value_digest(value)
        record = MemoryRecord(
            agent_id=agent_id, key=key, value=value, session_id=session_id,
            created_at=created_at, value_hash=vh, prev_hash=prev_hash,
            chain_hash=chain_digest(prev_hash, vh, agent_id, key, created_at))
        self._backend.append(record)
        return record

    def get(self, agent_id: str, key: str, *,
            expected_head: str | None = None) -> MemoryRecord | None:
        chain = self._verified(agent_id, key, expected_head=expected_head)
        return chain[-1] if chain else None

    def history(self, agent_id: str, key: str, *,
                expected_head: str | None = None) -> list[MemoryRecord]:
        return self._verified(agent_id, key, expected_head=expected_head)

    def head(self, agent_id: str, key: str) -> str:
        """The current chain head for (agent_id, key) -- the latest record's
        chain_hash, or GENESIS if none. Persist this OUTSIDE the store and pass
        it back as expected_head to detect a full self-consistent rewrite (see
        the THREAT SCOPE note in the module docstring)."""
        rec = self._backend.latest(agent_id, key)
        return rec.chain_hash if rec else GENESIS

    def _verified(self, agent_id: str, key: str, *,
                  expected_head: str | None = None) -> list[MemoryRecord]:
        """Recompute the whole chain for (agent_id, key) and raise if any link
        is broken. This catches a record mutated directly in the backend
        between sessions (point mutation). If expected_head is given, the final
        head must equal it -- this is what additionally catches a full,
        self-consistent rewrite by an attacker who controls the store, provided
        the caller held the genuine head externally."""
        records = self._backend.records(agent_id, key)
        prev = GENESIS
        for i, rec in enumerate(records):
            expected_vh = value_digest(rec.value)
            if rec.value_hash != expected_vh:
                raise MemoryIntegrityError(
                    f"value hash mismatch for {agent_id}/{key} at position {i}")
            if rec.prev_hash != prev:
                raise MemoryIntegrityError(
                    f"broken chain for {agent_id}/{key} at position {i}")
            expected_ch = chain_digest(prev, expected_vh, agent_id, key, rec.created_at)
            if rec.chain_hash != expected_ch:
                raise MemoryIntegrityError(
                    f"chain hash mismatch for {agent_id}/{key} at position {i}")
            prev = rec.chain_hash
        if expected_head is not None and prev != expected_head:
            raise MemoryIntegrityError(
                f"head mismatch for {agent_id}/{key}: chain verifies internally "
                f"but its head does not match the externally held head "
                f"(possible full rewrite)")
        return records
