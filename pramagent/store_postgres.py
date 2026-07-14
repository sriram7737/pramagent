"""
pramagent.store_postgres
========================
PostgreSQL implementations of the Store and HashChainBackend interfaces.

Operational features
--------------------
- Connection pooling via a thread-local connection cache with max_pool_size cap
  (True pooling would use psycopg2.pool.ThreadedConnectionPool or pgbouncer; this
  is a lightweight production-oriented approach without adding another dependency)
- Exponential-backoff retry on transient errors (OperationalError, InterfaceError)
- Circuit breaker: opens after threshold consecutive failures, auto-resets after
  cooldown_s; prevents cascade when Postgres is flapping
- Startup validation: connects and runs a test query on construction; raises
  PostgresUnavailable early so misconfiguration is caught at boot, not at runtime
- Auto-DDL: creates tables if they don't exist (idempotent)
- Graceful degradation: callers can catch PostgresUnavailable and fall back to
  MemoryStore / HashChainBackend so the system stays partially operational

Usage
-----
    from pramagent.store_postgres import PostgresStore
    db = PostgresStore.from_dsn(
        "postgresql://user:pass@host:5432/pramagent",
        max_pool_size=10,
        max_retries=3,
    )
    armor = Pramagent(store=db, audit=db)
"""
from __future__ import annotations

import json
import logging
import random
import threading
import time
from dataclasses import asdict
from typing import Any, List, Optional

from .audit import AuditAppendResult

log = logging.getLogger(__name__)

GENESIS = "0" * 64


class PostgresUnavailable(RuntimeError):
    """Raised when Postgres is configured but unreachable or misconfigured."""


class PostgresCircuitOpen(RuntimeError):
    """Raised when the Postgres circuit breaker has tripped."""


# ─────────────────────────── retry helper ─────────────────────────────────

def _retry(fn, *, max_attempts: int = 3, base_delay_s: float = 0.1,
           max_delay_s: float = 2.0):
    """Run fn() with exponential backoff + full jitter. Re-raises on last attempt."""
    for attempt in range(max_attempts):
        try:
            return fn()
        except Exception as exc:
            _is_transient = _transient(exc)
            if attempt == max_attempts - 1 or not _is_transient:
                raise
            # Retry jitter does not require cryptographic randomness.
            delay = min(base_delay_s * (2 ** attempt) + random.uniform(0, 0.05), max_delay_s)  # nosec B311
            log.warning("postgres retry %d/%d in %.2fs: %s", attempt + 1, max_attempts, delay, exc)
            time.sleep(delay)


def _transient(exc: Exception) -> bool:
    """True for errors that are worth retrying (connection blips, timeouts)."""
    from . import _pg
    transient = _pg.transient_exceptions()
    return bool(transient) and isinstance(exc, transient)


# ─────────────────────────── circuit breaker ──────────────────────────────

class _CircuitBreaker:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(self, threshold: int = 5, cooldown_s: float = 30.0) -> None:
        self._threshold = threshold
        self._cooldown_s = cooldown_s
        self._failures = 0
        self._opened_at: Optional[float] = None
        self._state = self.CLOSED
        self._lock = threading.Lock()

    def _effective_state(self) -> str:
        if self._state == self.OPEN:
            if time.monotonic() - (self._opened_at or 0) >= self._cooldown_s:
                return self.HALF_OPEN
        return self._state

    def allow(self) -> bool:
        with self._lock:
            return self._effective_state() != self.OPEN

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._state = self.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self._threshold:
                self._state = self.OPEN
                self._opened_at = time.monotonic()
                log.error("Postgres circuit breaker OPENED after %d failures", self._failures)

    @property
    def state(self) -> str:
        with self._lock:
            return self._effective_state()


# ─────────────────────── connection pool (thread-local) ───────────────────

class _ThreadLocalPool:
    """Thread-local psycopg2 connections with a global cap on open connections.

    Each thread gets at most one connection. The global cap prevents runaway
    thread-proliferation from exhausting Postgres max_connections.
    """

    def __init__(self, dsn: str, max_pool_size: int = 10, *, connect=None) -> None:
        self._dsn = dsn
        self._max_pool_size = max_pool_size
        self._local = threading.local()
        self._count_lock = threading.Lock()
        self._open_count = 0
        # injectable connection factory (tests pass a fake driver here)
        self._connect = connect

    def get(self):
        """Return a healthy connection for the current thread."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                # lightweight liveness check — no round-trip
                if conn.closed == 0:
                    return conn
            except Exception as exc:
                log.warning("failed to inspect cached Postgres connection: %s", exc)
            # stale connection: evict and reopen
            with self._count_lock:
                self._open_count -= 1
            self._local.conn = None

        with self._count_lock:
            if self._open_count >= self._max_pool_size:
                raise PostgresUnavailable(
                    f"Postgres pool exhausted ({self._max_pool_size} connections open)"
                )
            self._open_count += 1

        try:
            if self._connect is not None:
                conn = self._connect(self._dsn)
            else:
                from . import _pg
                conn = _pg.connect(self._dsn)
            conn.autocommit = False
        except Exception as exc:
            with self._count_lock:
                self._open_count -= 1
            raise PostgresUnavailable(f"Could not connect to Postgres: {exc}") from exc

        self._local.conn = conn
        return conn

    def close_current(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception as exc:
                log.warning("failed to close Postgres connection: %s", exc)
            self._local.conn = None
            with self._count_lock:
                self._open_count -= 1

    @property
    def open_count(self) -> int:
        with self._count_lock:
            return self._open_count


# ─────────────────────────── base class ───────────────────────────────────

class _PostgresBase:
    """Shared pool + circuit-breaker + retry infrastructure."""

    # payload column type depends on whether application-level encryption is
    # active (see _ddl_traces/_ddl_chain properties): JSONB in plain mode so
    # operators can still query into it; BYTEA (opaque Fernet ciphertext) when
    # encrypted, since encrypted bytes are not valid JSON.
    _DDL_TRACES_TEMPLATE = """
    CREATE TABLE IF NOT EXISTS pramagent_traces (
        id          BIGSERIAL PRIMARY KEY,
        tenant_id   TEXT NOT NULL,
        session_id  TEXT NOT NULL,
        trace_id    TEXT NOT NULL UNIQUE,
        payload     {payload_type} NOT NULL,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS pramagent_traces_tenant ON pramagent_traces(tenant_id);
    CREATE INDEX IF NOT EXISTS pramagent_traces_created ON pramagent_traces(created_at);

    -- Row-level tenant isolation is on by default (not an opt-in migration):
    -- a SQL-injection or app-layer bug in a WHERE clause is still stopped at
    -- the database. FORCE applies the policy to the table owner too, since
    -- the role that ran this DDL usually owns the table it just created.
    -- pramagent_chain is deliberately NOT RLS-scoped: its rows are tombstoned
    -- (see redact_chain_payload), not tenant-partitioned.
    ALTER TABLE pramagent_traces ENABLE ROW LEVEL SECURITY;
    ALTER TABLE pramagent_traces FORCE ROW LEVEL SECURITY;

    -- No "CREATE POLICY IF NOT EXISTS" in Postgres; DROP + CREATE is the
    -- idempotent replace pattern, safe to re-run on every startup.
    -- pramagent.tenant_rls_bypass is set only by application code for
    -- intentionally cross-tenant operations (global count/prune/list, or a
    -- no-auth-mode fetch) — never from client input — so it does not reopen
    -- the cross-tenant leak this policy exists to close.
    DROP POLICY IF EXISTS pramagent_trace_tenant_isolation ON pramagent_traces;
    CREATE POLICY pramagent_trace_tenant_isolation
    ON pramagent_traces
    USING (
        tenant_id = current_setting('pramagent.tenant_id', true)
        OR current_setting('pramagent.tenant_rls_bypass', true) = 'on'
    )
    WITH CHECK (
        tenant_id = current_setting('pramagent.tenant_id', true)
        OR current_setting('pramagent.tenant_rls_bypass', true) = 'on'
    );
    """

    _DDL_CHAIN_TEMPLATE = """
    CREATE TABLE IF NOT EXISTS pramagent_chain (
        id          BIGSERIAL PRIMARY KEY,
        this_hash   TEXT NOT NULL UNIQUE,
        prev_hash   TEXT NOT NULL,
        payload     {payload_type} NOT NULL,
        anchor_tx   TEXT NOT NULL DEFAULT '',
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    -- Append-only enforcement at the DB level, not just GRANT-based (GRANT
    -- alone is bypassable by the table owner re-granting itself rights, and
    -- was the only restriction before this trigger existed). DELETE is never
    -- legitimate for chain rows. UPDATE is legitimate exactly once: the GDPR
    -- tombstone-and-rehash in redact_for_tenant(), which sets
    -- pramagent.chain_redaction_in_progress before its UPDATE.
    --
    -- Honest scope: this stops SQL injection reaching a raw UPDATE/DELETE,
    -- application bugs that bypass redact_for_tenant(), and casual direct-DB
    -- access. It does NOT stop a genuinely malicious actor with live SQL
    -- access who sets the same GUC themselves before forging an update — the
    -- algorithm is public and deterministic, so a privileged writer can still
    -- rewrite a self-consistent alternate chain tail. The real defense
    -- against that threat is anchoring the chain head outside this database
    -- (see EthereumBackend/HyperledgerBackend in pramagent/audit), not a
    -- trigger a co-located attacker can also satisfy.
    CREATE OR REPLACE FUNCTION pramagent_chain_append_only_guard()
    RETURNS trigger AS $body$
    BEGIN
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'pramagent_chain rows cannot be deleted (append-only audit chain)';
        END IF;
        IF TG_OP = 'UPDATE'
           AND current_setting('pramagent.chain_redaction_in_progress', true) IS DISTINCT FROM 'on'
        THEN
            RAISE EXCEPTION 'pramagent_chain rows can only be updated via the GDPR redaction path';
        END IF;
        RETURN COALESCE(NEW, OLD);
    END;
    $body$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS pramagent_chain_append_only_guard_trigger ON pramagent_chain;
    CREATE TRIGGER pramagent_chain_append_only_guard_trigger
    BEFORE UPDATE OR DELETE ON pramagent_chain
    FOR EACH ROW EXECUTE FUNCTION pramagent_chain_append_only_guard();
    """

    def __init__(
        self,
        dsn: str,
        *,
        max_pool_size: int = 10,
        max_retries: int = 3,
        base_delay_s: float = 0.1,
        breaker_threshold: int = 5,
        breaker_cooldown_s: float = 30.0,
        connect=None,
        encryption_key: "bytes | str | None" = None,
        signing_key: str = "",
        signing_keys: dict | None = None,
        active_kid: str | None = None,
    ) -> None:
        self._pool = _ThreadLocalPool(dsn, max_pool_size=max_pool_size,
                                      connect=connect)
        self._max_retries = max_retries
        self._base_delay_s = base_delay_s
        self._breaker = _CircuitBreaker(threshold=breaker_threshold, cooldown_s=breaker_cooldown_s)
        self._head_lock = threading.Lock()
        self._head = GENESIS
        # prev of the most recent append — core records it on the trace
        self.last_prev_hash = GENESIS
        self._fernet = self._build_fernet(encryption_key)
        # HMAC key for canonical_hash (PRAMAGENT_SIGNING_KEY); see its
        # docstring for why an unkeyed chain alone isn't tamper-evident
        # against an actor with raw DB write access. signing_keys/active_kid
        # enable kid-versioned rotation (G1).
        from .audit import SigningKeyRing
        self._keyring = SigningKeyRing.from_config(
            signing_key=signing_key, signing_keys=signing_keys,
            active_kid=active_kid)
        self._signing_key = self._keyring.active_key()

    @staticmethod
    def _build_fernet(encryption_key: "bytes | str | None"):
        if encryption_key is None:
            return None
        try:
            from cryptography.fernet import Fernet
        except ImportError as exc:
            raise RuntimeError(
                "encryption_key was provided but the 'cryptography' package "
                "is not installed. Install with: pip install 'pramagent[encrypted]'"
            ) from exc
        key = encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
        return Fernet(key)

    @property
    def _ddl_traces(self) -> str:
        payload_type = "BYTEA" if self._fernet is not None else "JSONB"
        return self._DDL_TRACES_TEMPLATE.format(payload_type=payload_type)

    @property
    def _ddl_chain(self) -> str:
        payload_type = "BYTEA" if self._fernet is not None else "JSONB"
        return self._DDL_CHAIN_TEMPLATE.format(payload_type=payload_type)

    def _serialize_payload(self, payload: dict):
        """Payload -> the value passed as the SQL parameter for the payload
        column: encrypted bytes (BYTEA) when a key is configured, otherwise
        a JSON string (JSONB, unencrypted — the pre-existing behavior)."""
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if self._fernet is not None:
            return self._fernet.encrypt(canonical.encode("utf-8"))
        return canonical

    def _deserialize_payload(self, raw) -> dict:
        """The inverse of _serialize_payload. Decrypts first when encrypted —
        the hash chain is always computed over the plaintext payload, so
        verify()/verify_chain() are unaffected by encryption either way,
        matching EncryptedSQLiteStore's contract."""
        if self._fernet is not None:
            blob = bytes(raw)
            return json.loads(self._fernet.decrypt(blob).decode("utf-8"))
        return raw if isinstance(raw, dict) else json.loads(raw)

    @classmethod
    def from_dsn(
        cls,
        dsn: str,
        *,
        max_pool_size: int = 10,
        max_retries: int = 3,
        base_delay_s: float = 0.1,
        breaker_threshold: int = 5,
        breaker_cooldown_s: float = 30.0,
        connect=None,
        encryption_key: "bytes | str | None" = None,
        signing_key: str = "",
        signing_keys: dict | None = None,
        active_kid: str | None = None,
    ) -> "_PostgresBase":
        """Construct, validate connectivity, run DDL, return instance."""
        instance = cls(
            dsn,
            max_pool_size=max_pool_size,
            max_retries=max_retries,
            base_delay_s=base_delay_s,
            breaker_threshold=breaker_threshold,
            breaker_cooldown_s=breaker_cooldown_s,
            connect=connect,
            encryption_key=encryption_key,
            signing_key=signing_key,
            signing_keys=signing_keys,
            active_kid=active_kid,
        )
        instance._validate_and_init()
        return instance

    def _validate_and_init(self) -> None:
        """Ping Postgres and create tables. Raises PostgresUnavailable on failure."""
        try:
            self._execute_ddl()
        except PostgresUnavailable:
            raise
        except Exception as exc:
            raise PostgresUnavailable(f"Postgres startup validation failed: {exc}") from exc

    def _execute_ddl(self) -> None:
        conn = self._pool.get()
        with conn.cursor() as cur:
            cur.execute(self._ddl_traces)
            cur.execute(self._ddl_chain)
            # load head hash from chain on startup
            cur.execute("SELECT this_hash FROM pramagent_chain ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            if row:
                self._head = row[0]
            self._warn_if_rls_inert(cur)
        conn.commit()
        log.info("PostgresStore DDL complete, chain head=%s", self._head[:12])

    @staticmethod
    def _warn_if_rls_inert(cur) -> None:
        """Surface it loudly when the tenant-isolation policy is a no-op.

        Postgres superusers and BYPASSRLS roles skip row security entirely —
        FORCE ROW LEVEL SECURITY does not apply to them. If the DSN connects
        as such a role (the case for a default docker-compose deployment
        that reuses POSTGRES_USER as the app role), the policy just added by
        this DDL provides no actual protection: only the app-layer
        `WHERE tenant_id = %s` filters are enforcing isolation. Connect as a
        dedicated non-superuser role (see deploy/postgres/init.sh) to close
        that gap for real.
        """
        try:
            cur.execute(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
            )
            row = cur.fetchone()
        except Exception:
            return
        if not row:
            return
        is_super, bypass_rls = row[0], row[1]
        if is_super or bypass_rls:
            log.warning(
                "Postgres role for this connection %s row-level security "
                "(rolsuper=%s, rolbypassrls=%s) — the pramagent_traces tenant "
                "isolation policy is a no-op for this role. Isolation is "
                "enforced only by the app's own WHERE-clause filters. "
                "Connect as a dedicated non-superuser role to make the "
                "database-level policy actually take effect.",
                "bypasses" if (is_super or bypass_rls) else "respects",
                is_super, bypass_rls,
            )

    def _run(self, fn):
        """Execute fn(conn, cursor) with circuit-breaker + retry."""
        if not self._breaker.allow():
            raise PostgresCircuitOpen("Postgres circuit breaker is open")
        def _attempt():
            conn = self._pool.get()
            try:
                with conn.cursor() as cur:
                    result = fn(conn, cur)
                conn.commit()
                return result
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    self._pool.close_current()
                raise
        try:
            result = _retry(_attempt, max_attempts=self._max_retries,
                            base_delay_s=self._base_delay_s)
            self._breaker.record_success()
            return result
        except (PostgresUnavailable, PostgresCircuitOpen):
            raise
        except Exception:
            self._breaker.record_failure()
            raise

    @property
    def circuit_state(self) -> str:
        return self._breaker.state

    @property
    def pool_open_count(self) -> int:
        return self._pool.open_count


def _set_tenant_context(cur, tenant_id: Optional[str]) -> None:
    """Set the tenant GUC the pramagent_traces RLS policy checks.

    Always sets it — even to "" — rather than skipping when falsy: a row
    inserted with tenant_id="" only satisfies the policy's WITH CHECK if the
    GUC is explicitly set to "" too (an unset GUC compares as NULL, which
    never equals "", and FORCE ROW LEVEL SECURITY would reject the insert).
    """
    cur.execute("SELECT set_config('pramagent.tenant_id', %s, true)", (tenant_id or "",))


def _clear_tenant_scope(cur) -> None:
    """Mark this transaction as an intentional cross-tenant operation.

    Used only by store methods that are explicitly unscoped by design (a
    global count/prune, list_all(), or a get() with tenant_id=None meaning
    "no tenant enforcement requested") — never derived from client input, so
    it does not reopen the leak the RLS policy exists to close.
    """
    cur.execute("SELECT set_config('pramagent.tenant_rls_bypass', 'on', true)")


# ──────────────────────────── Store impl ──────────────────────────────────

class PostgresStore(_PostgresBase):
    """PostgreSQL-backed Store + HashChainBackend.

    Implements both interfaces so a single instance can be passed as both
    ``store=db`` and ``audit=db`` to Pramagent. Conforms to the same
    ``TraceStore`` protocol as SQLiteStore (call_id keying, TraceEvent
    returns, KeyError/PermissionError semantics) and uses the same
    ``canonical_hash(payload, prev, signing_key)`` chained hashing, so the tamper-evidence
    guarantee is identical on the production backend (T2-3 / P1-6).
    """

    # ── Store interface ───────────────────────────────────────────────────

    def save(self, trace) -> None:
        payload = trace.to_dict() if hasattr(trace, "to_dict") else vars(trace)
        # Rows are keyed by call_id — the id the API fetches by — never by
        # this_hash (which the chain redaction may legitimately rewrite).
        trace_id = payload.get("call_id") or payload.get("this_hash", "")

        def _fn(conn, cur):
            _set_tenant_context(cur, payload.get("tenant_id", ""))
            cur.execute(
                """
                INSERT INTO pramagent_traces (tenant_id, session_id, trace_id, payload)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (trace_id) DO UPDATE SET payload = EXCLUDED.payload
                """,
                (
                    payload.get("tenant_id", ""),
                    payload.get("session_id", ""),
                    trace_id,
                    self._serialize_payload(payload),
                ),
            )
        self._run(_fn)

    def get(self, trace_id: str, tenant_id: Optional[str] = None):
        """Fetch one trace by call_id.

        Raises KeyError when missing, and PermissionError on tenant mismatch
        when the row is actually visible to this query — _fetch_trace() in
        the API maps both onto 404-not-403 either way, so callers should not
        depend on which one fires. Which one fires depends on whether the
        pramagent_traces RLS policy is enforced for the connecting role: a
        real (non-superuser) role never sees the other tenant's row at the
        SQL level, so this raises KeyError before the mismatch check below
        even runs; a superuser/BYPASSRLS role (see
        _warn_if_rls_inert) sees the row and this raises PermissionError
        instead.
        """
        def _fn(conn, cur):
            if tenant_id is None:
                _clear_tenant_scope(cur)
            else:
                _set_tenant_context(cur, tenant_id)
            cur.execute("SELECT payload FROM pramagent_traces WHERE trace_id = %s", (trace_id,))
            row = cur.fetchone()
            return self._deserialize_payload(row[0]) if row else None
        payload = self._run(_fn)
        if payload is None:
            raise KeyError(trace_id)
        if tenant_id is not None and payload.get("tenant_id") != tenant_id:
            raise PermissionError(
                f"trace {trace_id} does not belong to tenant {tenant_id}")
        from .types import TraceEvent
        return TraceEvent.from_dict(payload)

    def list_all(self, limit: Optional[int] = None):
        """Return traces oldest-first (most recent N when limit is given)."""
        def _fn(conn, cur):
            _clear_tenant_scope(cur)
            if limit is not None:
                cur.execute(
                    "SELECT payload FROM pramagent_traces ORDER BY created_at DESC LIMIT %s",
                    (int(limit),),
                )
            else:
                cur.execute(
                    "SELECT payload FROM pramagent_traces ORDER BY created_at ASC")
            return [self._deserialize_payload(r[0]) for r in cur.fetchall()]
        rows = self._run(_fn)
        if limit is not None:
            rows.reverse()
        from .types import TraceEvent
        return [TraceEvent.from_dict(r) for r in rows]

    def list_by_tenant(self, tenant_id: str, session_id: Optional[str] = None,
                       limit: int = 100):
        """Tenant-scoped listing returning TraceEvents (same shape as SQLiteStore)."""
        def _fn(conn, cur):
            _set_tenant_context(cur, tenant_id)
            if session_id:
                cur.execute(
                    "SELECT payload FROM pramagent_traces"
                    " WHERE tenant_id = %s AND session_id = %s"
                    " ORDER BY created_at DESC LIMIT %s",
                    (tenant_id, session_id, int(limit)),
                )
            else:
                cur.execute(
                    "SELECT payload FROM pramagent_traces WHERE tenant_id = %s"
                    " ORDER BY created_at DESC LIMIT %s",
                    (tenant_id, int(limit)),
                )
            return [self._deserialize_payload(r[0]) for r in cur.fetchall()]
        from .types import TraceEvent
        return [TraceEvent.from_dict(r) for r in self._run(_fn)]

    def list_for_tenant(self, tenant_id: str, limit: int = 100) -> List[dict]:
        def _fn(conn, cur):
            _set_tenant_context(cur, tenant_id)
            cur.execute(
                "SELECT payload FROM pramagent_traces WHERE tenant_id = %s ORDER BY created_at DESC LIMIT %s",
                (tenant_id, limit),
            )
            return [self._deserialize_payload(r[0]) for r in cur.fetchall()]
        return self._run(_fn)

    def ping(self) -> bool:
        """O(1) connectivity check for readiness probes."""
        def _fn(conn, cur):
            cur.execute("SELECT 1")
            return True
        return bool(self._run(_fn))

    def count(self, tenant_id: Optional[str] = None) -> int:
        """Trace count via SQL COUNT — never a full-table load (P2-14)."""
        def _fn(conn, cur):
            if tenant_id:
                _set_tenant_context(cur, tenant_id)
                cur.execute(
                    "SELECT COUNT(*) FROM pramagent_traces WHERE tenant_id = %s",
                    (tenant_id,))
            else:
                _clear_tenant_scope(cur)
                cur.execute("SELECT COUNT(*) FROM pramagent_traces")
            row = cur.fetchone()
            return int(row[0]) if row else 0
        return self._run(_fn)

    def delete_for_tenant(self, tenant_id: str) -> int:
        """GDPR erasure: delete the tenant's trace rows AND tombstone its
        payloads in the hash chain (see redact_for_tenant)."""
        def _fn(conn, cur):
            _set_tenant_context(cur, tenant_id)
            cur.execute("DELETE FROM pramagent_traces WHERE tenant_id = %s", (tenant_id,))
            return cur.rowcount
        deleted = self._run(_fn)
        self.redact_for_tenant(tenant_id)
        return deleted

    def delete_for_session(self, tenant_id: str, session_id: str) -> int:
        """GDPR erasure scoped to one session within a tenant — see
        SQLiteStore.delete_for_session for why session_id is the practical
        per-end-user erasure unit given the current schema."""
        def _fn(conn, cur):
            _set_tenant_context(cur, tenant_id)
            cur.execute(
                "DELETE FROM pramagent_traces WHERE tenant_id = %s AND session_id = %s",
                (tenant_id, session_id),
            )
            return cur.rowcount
        deleted = self._run(_fn)
        self.redact_for_session(tenant_id, session_id)
        return deleted

    def redact_for_tenant(self, tenant_id: str) -> int:
        """Tombstone PII fields in this tenant's chain payloads, then re-anchor:
        every link from the first redaction onward gets recomputed prev/this
        hashes (same canonical_hash chaining as SQLiteStore) so verify_chain()
        still passes without the erased content. Returns payloads redacted."""
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
        from .audit import (CHAIN_KID_FIELD, canonical_hash,
                            redact_chain_payload)

        def _read(conn, cur):
            cur.execute(
                "SELECT id, this_hash, prev_hash, payload FROM pramagent_chain ORDER BY id ASC"
            )
            return cur.fetchall()
        rows = self._run(_read)

        redacted = 0
        rehash = False   # once a payload changes, every later row re-hashes
        prev = GENESIS
        for row_id, stored_hash, _stored_prev, payload_raw in rows:
            payload = self._deserialize_payload(payload_raw)
            if predicate(payload) and redact_chain_payload(payload):
                redacted += 1
                rehash = True
            if rehash:
                # G1: re-sign each row with the key its own _kid names, so a
                # rotated chain stays verifiable per-row after redaction.
                row_key = self._keyring.key_for(payload.get(CHAIN_KID_FIELD))
                new_hash = canonical_hash(payload, prev, row_key or self._signing_key)

                def _update(conn, cur, *, _id=row_id, _payload=payload,
                            _hash=new_hash, _prev=prev):
                    # Required by pramagent_chain_append_only_guard_trigger —
                    # without it, this UPDATE is rejected the same as any
                    # other attempted mutation of a chain row.
                    cur.execute(
                        "SELECT set_config('pramagent.chain_redaction_in_progress', 'on', true)"
                    )
                    cur.execute(
                        "UPDATE pramagent_chain SET payload = %s, this_hash = %s,"
                        " prev_hash = %s WHERE id = %s",
                        (self._serialize_payload(_payload), _hash, _prev, _id),
                    )
                self._run(_update)
                prev = new_hash
            else:
                prev = stored_hash
        if rehash:
            with self._head_lock:
                self._head = prev
        return redacted

    def prune_older_than(self, cutoff_ts: float, tenant_id: Optional[str] = None) -> int:
        """Delete traces older than UNIX timestamp cutoff_ts. Returns count deleted.

        When tenant_id is given the prune is scoped to that tenant only."""
        import datetime
        dt = datetime.datetime.fromtimestamp(cutoff_ts, tz=datetime.timezone.utc)

        def _fn(conn, cur):
            if tenant_id is None:
                _clear_tenant_scope(cur)
                cur.execute("DELETE FROM pramagent_traces WHERE created_at < %s", (dt,))
            else:
                _set_tenant_context(cur, tenant_id)
                cur.execute(
                    "DELETE FROM pramagent_traces WHERE created_at < %s AND tenant_id = %s",
                    (dt, tenant_id),
                )
            return cur.rowcount
        return self._run(_fn)

    # ── HashChainBackend interface ────────────────────────────────────────

    @property
    def head(self) -> str:
        with self._head_lock:
            return self._head

    def append(self, payload: dict, prev_hash: Optional[str] = None) -> AuditAppendResult:
        """Append one chain link.

        The hash material includes prev_hash — canonical_hash(payload, prev, signing_key) —
        exactly like SQLiteStore, so deleting or reordering rows breaks every
        subsequent link (T2-3). `prev` is re-read from the DB inside the
        transaction with FOR UPDATE, serializing concurrent writers across
        processes so the chain can never fork (P1-5 / T2-4)."""
        from .audit import CHAIN_KID_FIELD, canonical_hash

        if self._keyring.versioned:                  # G1: tag row's key version
            payload = {**payload, CHAIN_KID_FIELD: self._keyring.active_kid}

        def _fn(conn, cur):
            cur.execute(
                "SELECT this_hash FROM pramagent_chain ORDER BY id DESC LIMIT 1 FOR UPDATE"
            )
            row = cur.fetchone()
            prev = row[0] if row else GENESIS
            this_hash = canonical_hash(payload, prev, self._keyring.active_key())
            cur.execute(
                """
                INSERT INTO pramagent_chain (this_hash, prev_hash, payload)
                VALUES (%s, %s, %s)
                ON CONFLICT (this_hash) DO NOTHING
                """,
                (this_hash, prev, self._serialize_payload(payload)),
            )
            return prev, this_hash
        prev, this_hash = self._run(_fn)

        with self._head_lock:
            self.last_prev_hash = prev
            self._head = this_hash
        return AuditAppendResult(this_hash, f"postgres:{this_hash[:16]}", prev)

    def verify_chain(self) -> bool:
        """Walk rows in id order; True only when every this_hash matches
        canonical_hash(payload, prev, signing_key) AND stored_prev links to the previous
        row's this_hash. Same contract as SQLiteStore.verify_chain()."""
        return not self.verify()

    def verify(self) -> list[dict]:
        """Verify hash-chain integrity. Returns list of broken links (empty = ok)."""
        from .audit import chain_link_hash_ok

        def _fn(conn, cur):
            cur.execute(
                "SELECT this_hash, prev_hash, payload FROM pramagent_chain ORDER BY id ASC"
            )
            return cur.fetchall()
        rows = self._run(_fn)

        broken = []
        prev = GENESIS
        for this_hash, stored_prev, payload_raw in rows:
            payload = self._deserialize_payload(payload_raw)
            if not chain_link_hash_ok(payload, prev, this_hash, self._keyring):
                broken.append({"this_hash": this_hash, "reason": "hash mismatch"})
            elif stored_prev != prev:
                broken.append({"this_hash": this_hash, "reason": "broken prev link"})
            prev = this_hash
        return broken

    # ── compliance export ─────────────────────────────────────────────────

    def export_audit_jsonl(self, tenant_id: str, out_path: str) -> int:
        """Export all audit chain entries for a tenant as JSONL. Returns count."""
        rows = self.list_for_tenant(tenant_id, limit=100_000)
        with open(out_path, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")
        return len(rows)
