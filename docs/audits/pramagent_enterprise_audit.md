# Pramagent SDK v0.7.0 — Enterprise Pre-Production Code Review

**Reviewer:** Principal Engineer, line-level review
**Date:** 2026-06-10
**Scope:** every `.py` file in `pramagent/`, `deploy/`, `tests/`; `Dockerfile`, `docker-compose.yml`, Helm chart, `.env.example`; ground truth `docs/Pramagent-Design-Document.docx` and `docs/audits/pramagent_full_audit.md`
**Baseline:** post-remediation `main` (commits `f50cfc4`…`de729b1`), suite 505 passed / 1 skipped

> Severity scale: **P0** blocks deploy · **P1** fix before GA · **P2** fix before scale · **P3** hygiene.
> Lens numbers refer to the ten audit lenses in the review brief.

> **REMEDIATION STATUS — added 2026-06-29 (current package v0.8.5).**
> This is a historical pre-production review of v0.7.0, retained as the
> permanent finding record. **Both P0 deploy-blockers and the GA-gating P1
> findings below were remediated in the v0.7.1 series** and verified present in
> the current v0.8.5 source: persistent-store startup refusal (P0-1),
> weak-secret startup denial (P0-2), blocking I/O moved off the async hot path
> via `asyncio.to_thread` (P1-1/P1-8), single-writer chain append via
> `SELECT … FOR UPDATE` (P1-5), GDPR erasure parity across SQLite / encrypted /
> S3 stores (P1-2/P1-7), O(1) `/health/ready` (P1-3), per-trace RCA endpoints
> (P1-4), Postgres protocol + tenant-scoped listing (P1-6/P1-9), and
> compose/Helm hardening (P1-10). Read the findings below as *what was fixed*,
> not as open issues. For the living status and remaining fix-before-scale
> hygiene items see [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md).

---

## P0 FINDINGS — deploy blockers

### P0-1 · The reference deployments silently run on MemoryStore — nothing is persisted

- **Files:** `pramagent/api/app.py:141-147` (`build_default_armor`), `docker-compose.yml` (api service env), `deploy/helm/pramagent/values.yaml` (+ `templates/deployment.yaml`)
- **Lens:** 10 (deployment readiness), 2 (persistence)
- **What the code does today:** `build_default_armor()` selects the store exclusively from `PRAMAGENT_DB` (SQLite path). `docker-compose.yml` and the Helm chart inject `PRAMAGENT_POSTGRES_DSN` — which **nothing in the API path reads** — and never set `PRAMAGENT_DB`. The shipped production stack therefore boots a `MemoryStore` + in-process `HashChainBackend`:
  - every trace and audit-chain link lives in process RAM and is lost on restart — the "tamper-evident, regulation-ready audit trail" evaporates on every deploy;
  - memory grows without bound (one full trace + one chain payload retained per request, forever) until OOM;
  - Helm runs `replicaCount: 3` — three replicas each hold a *different* trace set and a *different* chain head; `/traces`, `/v1/audit/verify`, and GDPR erasure hit whichever replica the LB picks;
  - the Postgres container in the stack sits idle except for the HITL queue (if separately wired).
- **What it should do:** the API factory must honor the Postgres DSN the deployment artifacts already provide, and refuse to start with an in-memory store unless explicitly opted in.
- **Exact fix** (`pramagent/api/app.py`, in `build_default_armor`):

```python
def build_default_armor() -> Pramagent:
    """Build from env. PRAMAGENT_POSTGRES_DSN > PRAMAGENT_DB > opt-in memory."""
    dsn = os.environ.get("PRAMAGENT_POSTGRES_DSN", "").strip()
    db_path = os.environ.get("PRAMAGENT_DB")
    if dsn:
        from ..store_postgres import PostgresStore
        db = PostgresStore.from_dsn(dsn)
        store, audit = db, db
    elif db_path:
        db = SQLiteStore(db_path)
        store, audit = db, db
    elif os.environ.get("PRAMAGENT_ALLOW_MEMORY_STORE", "").lower() in {"1", "true"}:
        store, audit = None, None          # explicit dev/test opt-in
    else:
        raise RuntimeError(
            "no persistent store configured: set PRAMAGENT_POSTGRES_DSN or "
            "PRAMAGENT_DB, or opt into volatile storage with "
            "PRAMAGENT_ALLOW_MEMORY_STORE=1 (dev only)")
    ...
```

  Note: wiring `PostgresStore` in exposes finding **P1-6** (protocol mismatch) — both must land together. Tests set `PRAMAGENT_ALLOW_MEMORY_STORE=1` in `conftest.py` (one line). Update `.env.example` and compose to pass the DSN intent through explicitly.

---

### P0-2 · Published placeholder secrets pass startup validation — forgeable tenant JWTs

- **Files:** `.env.example:1-7`, `pramagent/api/app.py:373-375`, `deploy/dashboard/app.py:104-118` (`validate_dashboard_config`), `pramagent/config.py:166-177`
- **Lens:** 6 (security)
- **What the code does today:** three compounding defects:
  1. `.env.example` ships literal secrets `change_me_in_production` (underscores) for `PRAMAGENT_API_KEY`, `PRAMAGENT_JWT_SECRET`, `PRAMAGENT_SIGNING_KEY`, `PRAMAGENT_DASHBOARD_KEY`, and the compose quick start is `cp .env.example .env`.
  2. The **API has no JWT-secret startup guard at all**: `app.state.jwt = JWTManager.from_env(fallback_secret=os.environ.get("PRAMAGENT_JWT_SECRET") or secrets.token_urlsafe(32))`. `config.Settings.validate()` exists but is never called by `create_app()`. A deployment running with the published example secret mints JWTs any attacker can forge offline (`{"sub": "<any tenant>"}` signed with a string that is in this public repo) → complete cross-tenant authentication bypass on every `/v1/*` and unversioned route.
  3. The dashboard's new guard (audit Finding #6 fix) compares against the **hyphenated** literal `change-me-in-production` only — the repo's own published **underscored** variant passes it.
  4. Compose maps `PRAMAGENT_API_KEYS: "default:${PRAMAGENT_API_KEY}"` — with the example value, the bearer API key is also publicly known.
- **What it should do:** refuse startup on any published/low-entropy secret, in both services, with a shared denylist; `.env.example` should ship empty values so compose's `:?required` interpolation fails loudly instead of booting with known secrets.
- **Exact fix:**

```python
# pramagent/security.py  (new, shared)
WEAK_SECRET_DENYLIST = frozenset({
    "change-me-in-production", "change_me_in_production", "changeme",
    "change-me", "secret", "password", "default",
})

def assert_strong_secret(name: str, value: str, *, min_len: int = 16) -> None:
    if not value or value.lower() in WEAK_SECRET_DENYLIST or len(value) < min_len:
        raise RuntimeError(
            f"{name} is unset, a published default, or shorter than {min_len} "
            f"chars; generate one with: python -c "
            f"\"import secrets; print(secrets.token_urlsafe(32))\"")
```

```python
# pramagent/api/app.py, in create_app() right after registry setup
    jwt_secret = os.environ.get("PRAMAGENT_JWT_SECRET", "")
    if jwt_secret:                       # unset → per-process random (see P2-12)
        assert_strong_secret("PRAMAGENT_JWT_SECRET", jwt_secret)
    app.state.jwt = JWTManager.from_env(
        fallback_secret=jwt_secret or secrets.token_urlsafe(32))
```

```python
# deploy/dashboard/app.py — replace the equality check
def validate_dashboard_config() -> None:
    from pramagent.security import assert_strong_secret
    assert_strong_secret("PRAMAGENT_JWT_SECRET", PRAMAGENT_JWT_SECRET)
```

```bash
# .env.example — required block becomes (no values):
POSTGRES_PASSWORD=
REDIS_PASSWORD=
PRAMAGENT_API_KEY=
PRAMAGENT_SIGNING_KEY=
PRAMAGENT_JWT_SECRET=
PRAMAGENT_DASHBOARD_KEY=
# Generate each with: python -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## P1 FINDINGS — fix before GA

### P1-1 · Ethereum anchoring blocks the event loop for up to 300 s per request

- **Files:** `pramagent/anchoring/ethereum.py:85-106` (`anchor`), `pramagent/audit/__init__.py:131-143` (`EthereumBackend.append`), called from `pramagent/core.py:410` inside `async run()`
- **Lens:** 3, 9
- **Today:** `anchor()` performs synchronous web3 RPC (`get_transaction_count`, `send_raw_transaction`) and then `wait_for_transaction_receipt(timeout=300, poll_latency=5)` — all on the event loop, because `_finalize()` is synchronous and called from the async pipeline. With anchoring configured, **every request stalls the entire process** until the transaction mines (or 5 minutes elapse). Concurrent requests also race the nonce (`get_transaction_count` per call).
- **Should:** anchor asynchronously off the hot path — fire the transaction without waiting for the receipt, or queue anchor jobs and reconcile receipts in a background task; never await mining inside the request.
- **Exact fix (minimal):**

```python
# ethereum.py
    def anchor(self, trace_hash: str, *, wait_for_receipt: bool = False) -> EthereumAnchorReceipt:
        ...
        tx_hash = _to_hex(self._w3, tx_hash_raw)
        if not wait_for_receipt:
            return EthereumAnchorReceipt(tx_hash=tx_hash, block_number=0,
                                         status=-1,    # -1 = submitted, unconfirmed
                                         chain_id=self.chain_id,
                                         anchored_hash=clean_hash)
        receipt = self._w3.eth.wait_for_transaction_receipt(...)
        ...
```

```python
# core.py — _finalize becomes async-aware for anchored backends:
        tr.this_hash, tr.anchor_tx_id = await asyncio.to_thread(
            self.audit.append, payload, tr.prev_hash)
```

  (Make `_finalize` `async def` and `await` it at the five call sites; the `to_thread` hop also fixes P1-8 for SQLite commits.) Guard the nonce with a `threading.Lock` in `EthereumAnchor`.

### P1-2 · `EncryptedSQLiteStore` missed the GDPR chain-redaction fix (Finding #4 parity)

- **Files:** `pramagent/store_encrypted.py:168-172` (`delete_for_tenant`), `:140-144` (`list_all`), `:162-166` (`prune_older_than`)
- **Lens:** 2, 6
- **Today:** the Sprint-2 erasure fix went to `SQLiteStore`, `HashChainBackend`, and `PostgresStore` — but `EncryptedSQLiteStore.delete_for_tenant()` still only deletes trace rows. The tenant's payloads remain in `audit_chain` forever (encrypted, but under a single global key with no per-tenant destruction — that is retention, not erasure). The class has also drifted off the `TraceStore` protocol: `list_all()` takes no `limit` (→ `TypeError` → HTTP 500 on `/traces`) and `prune_older_than()` takes no `tenant_id` (→ the API's prune falls into its 501 branch).
- **Should:** identical redact-and-re-anchor behavior to `SQLiteStore`, and protocol-conformant signatures.
- **Exact fix:**

```python
# store_encrypted.py
from .audit import canonical_hash, redact_chain_payload

    def list_all(self, limit: int | None = None) -> list[TraceEvent]:
        sql = "SELECT data_enc FROM traces ORDER BY created_at"
        if limit is not None:
            sql += f" DESC LIMIT {int(limit)}"
        rows = self._conn.execute(sql).fetchall()
        out = [TraceEvent.from_dict(json.loads(self._decrypt(r[0]))) for r in rows]
        if limit is not None:
            out.reverse()
        return out

    def prune_older_than(self, cutoff_ts: float, tenant_id: str | None = None) -> int:
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
        cur = self._conn.execute(
            "DELETE FROM traces WHERE tenant_id = ?", (tenant_id,))
        self.redact_for_tenant(tenant_id)
        self._conn.commit()
        return cur.rowcount

    def redact_for_tenant(self, tenant_id: str) -> int:
        rows = self._conn.execute(
            "SELECT seq, payload_enc, prev_hash, this_hash FROM audit_chain ORDER BY seq"
        ).fetchall()
        prev, redacted, rehash = GENESIS, 0, False
        for seq, payload_enc, _stored_prev, stored_hash in rows:
            payload = json.loads(self._decrypt(payload_enc))
            if payload.get("tenant_id") == tenant_id and redact_chain_payload(payload):
                redacted += 1
                rehash = True
            if rehash:
                new_hash = canonical_hash(payload, prev)
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
```

  Add a parity test mirroring `test_sqlite_erasure_redacts_chain_and_reanchors`.

### P1-3 · `/health/ready` is O(n) over the entire store and chain — per probe

- **File:** `pramagent/api/app.py:457-471`
- **Lens:** 9, 8, 6
- **Today:** readiness calls `a.audit.verify_chain()` (recomputes the SHA-256 of **every** chain link) and `len(a.store.list_all())` (loads and deserializes **every** trace row) on every probe. Helm probes every 10 s × 3 replicas. At 1 M traces this is a multi-second full-table scan + 1 M hash recomputations per probe — readiness flaps, pods get pulled from rotation under load, and the probe itself drives the load. The endpoint is also unauthenticated and discloses operational details (`auth_enabled`, `slack_last_error`, trace counts).
- **Should:** readiness checks dependency *connectivity* in O(1) (DB ping, Redis ping), never integrity-verifies the chain; chain verification belongs in `/v1/audit/verify` (already rate-limited) or a scheduled job.
- **Exact fix:**

```python
    @app.get("/health/ready")
    async def ready():
        a = app.state.armor
        checks: dict[str, bool] = {}
        try:                                   # O(1) store ping
            ping = getattr(a.store, "ping", None)
            checks["store"] = bool(ping()) if ping else True
        except Exception:
            checks["store"] = False
        backend = app.state.tool_guard_backend
        checks["redis"] = backend.ping() if backend is not None else True
        ok = all(checks.values())
        return JSONResponse(
            {"status": "ready" if ok else "degraded", "checks": checks,
             "auth_enabled": len(app.state.registry) > 0},
            status_code=200 if ok else 503)
```

  Add `SQLiteStore.ping()` (`SELECT 1`) and `PostgresStore.ping()`. Drop `chain_valid`, `slack_last_error`, and trace counts from the unauthenticated surface.

### P1-4 · RCA endpoints load the entire trace store into memory per request

- **File:** `pramagent/api/app.py:589-608` (`RCAEngine(app.state.armor.store.list_all())` ×3)
- **Lens:** 9, 1
- **Today:** every `/v1/rca/{id}/replay|counterfactual|incident` call deserializes **all** traces (no limit) just to index one by `call_id`. O(n) CPU + memory per request; the RCA rate bucket (10 burst) only slows the bleeding.
- **Should:** fetch the single trace and construct the engine around it.
- **Exact fix:**

```python
    @app.post("/v1/rca/{call_id}/replay")
    async def rca_replay(call_id: str, request: Request,
                         tenant: str = Depends(require_tenant)):
        _require_rca_quota(tenant or "anon", request)
        trace = _fetch_trace(call_id, tenant)
        return RCAEngine([trace]).replay(call_id)
```

  Same one-line change in `rca_counterfactual` and `rca_incident` (`RCAEngine([trace])`). `RCAEngine` already operates per-trace; no engine change needed.

### P1-5 · Audit-chain head race: concurrent writers fork the chain and break verification

- **Files:** `pramagent/core.py:409-410`, `pramagent/store.py:107,248-258` (`check_same_thread=False`, cached `_head`), `pramagent/store_postgres.py` (per-process `_head`)
- **Lens:** 5, 2
- **Today:** `_finalize` reads `self.audit.head` then calls `append(payload, prev_hash)` — a classic TOCTOU. Safe on one event loop (no `await` between), but: (a) any threaded host or `asyncio.to_thread` offload makes two writers read the same head and both insert with it; (b) **multiple processes** sharing one SQLite file or Postgres DB each cache `_head` at startup — every worker forks the chain from its boot-time head. `SQLiteStore.verify_chain()` walks rows in `seq` order expecting `stored_prev == previous row's this_hash`, so a forked insert makes the chain verify **False** — the system reports tampering that is actually a concurrency bug. The shared `sqlite3` connection is also used without a lock (interleaved `execute`/`commit` across threads can commit another writer's half-done work or raise).
- **Should:** the append must derive `prev` inside a single serialized critical section (lock in-process; `SELECT ... FOR UPDATE` / `BEGIN IMMEDIATE` cross-process), and core should stop passing a pre-read head.
- **Exact fix:**

```python
# core.py — let the backend own linkage:
        tr.this_hash, tr.anchor_tx_id = self.audit.append(payload)   # no prev arg
        tr.prev_hash = getattr(self.audit, "last_prev_hash", self.audit.head)
```

```python
# store.py SQLiteStore
    def __init__(self, path: str = "pramagent.db") -> None:
        ...
        self._write_lock = threading.Lock()

    def append(self, payload: dict, prev_hash: str | None = None) -> tuple[str, str]:
        with self._write_lock:
            self._conn.execute("BEGIN IMMEDIATE")        # cross-process write lock
            row = self._conn.execute(
                "SELECT this_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev = row[0] if row else GENESIS            # re-read under the lock
            self.last_prev_hash = prev
            this_hash = canonical_hash(payload, prev)
            self._conn.execute(
                "INSERT INTO audit_chain (payload, prev_hash, this_hash) VALUES (?, ?, ?)",
                (json.dumps(payload, sort_keys=True, separators=(",", ":")), prev, this_hash))
            self._conn.commit()
            self._head = this_hash
            return this_hash, f"sqlite:{this_hash[:16]}"
```

  Mirror in `PostgresStore.append` with `SELECT this_hash FROM pramagent_chain ORDER BY id DESC LIMIT 1 FOR UPDATE` inside the transaction. Wrap `save/get/prune/delete` in the same `_write_lock` for the shared-connection problem.

### P1-6 · `PostgresStore` does not implement the `TraceStore` protocol the API depends on

- **File:** `pramagent/store_postgres.py:349-369` (`get`, `list_for_tenant`, missing `list_all`), vs `pramagent/store.py:33-39` (protocol) and `pramagent/api/app.py:415-425` (`_fetch_trace`)
- **Lens:** 4, 1
- **Today:** `PostgresStore.get(trace_id)` returns `Optional[dict]`, takes no `tenant_id` kwarg, and returns `None` instead of raising `KeyError`/`PermissionError`. There is no `list_all`. The moment P0-1 wires it into the API: `_fetch_trace` calls `store.get(call_id, tenant_id=...)` → `TypeError` → unhandled 500 on every trace fetch; `/traces`, `/health/ready`, and the RCA endpoints crash on the missing `list_all`. The keying is also wrong: rows are keyed by `this_hash`, not `call_id`, so `/v1/trace/{call_id}` can never find anything.
- **Should:** conform to the protocol — `get(call_id, tenant_id=None) -> TraceEvent` raising `KeyError`/`PermissionError`, key rows by `call_id`, add `list_all(limit=None)` and tenant-scoped `prune_older_than`.
- **Exact fix (core of it):**

```python
    def save(self, trace) -> None:
        payload = trace.to_dict() if hasattr(trace, "to_dict") else vars(trace)
        trace_id = payload.get("call_id") or payload.get("this_hash", "")
        ...

    def get(self, trace_id: str, tenant_id: str | None = None):
        def _fn(conn, cur):
            cur.execute("SELECT payload FROM pramagent_traces WHERE trace_id = %s",
                        (trace_id,))
            row = cur.fetchone()
            return _as_dict(row[0]) if row else None
        payload = self._run(_fn)
        if payload is None:
            raise KeyError(trace_id)
        if tenant_id is not None and payload.get("tenant_id") != tenant_id:
            raise PermissionError(
                f"trace {trace_id} does not belong to tenant {tenant_id}")
        from .types import TraceEvent
        return TraceEvent.from_dict(payload)

    def list_all(self, limit: int | None = None):
        def _fn(conn, cur):
            sql = "SELECT payload FROM pramagent_traces ORDER BY created_at DESC"
            if limit is not None:
                sql += " LIMIT %s"
                cur.execute(sql, (int(limit),))
            else:
                cur.execute(sql)
            return [_as_dict(r[0]) for r in cur.fetchall()]
        from .types import TraceEvent
        rows = self._run(_fn)
        rows.reverse()
        return [TraceEvent.from_dict(r) for r in rows]
```

  (Existing `trace_id UNIQUE` column makes the `call_id` keying a data migration for existing rows — add `MIGRATIONS_PG` entry.)

### P1-7 · GDPR erasure through `S3ColdArchiveStore` copies the data out instead of destroying it

- **File:** `pramagent/store_s3.py:149-156` (`delete_for_tenant`), `:87` (`_metadata` in-memory only)
- **Lens:** 2, 6
- **Today:** `delete_for_tenant()` **archives every one of the tenant's traces to S3** (encrypted, but under one global key) before deleting them from the primary store. An Art. 17 erasure request routed through this wrapper *preserves* the personal data in cold storage indefinitely — the opposite of the API contract on `DELETE /v1/tenant/{id}/traces`. Archive-then-delete is correct for `prune_older_than` (retention), not for erasure. Separately, `_metadata` lives only in process memory, so archived objects become unreadable through `get()` after a restart unless a `metadata_sink` was wired.
- **Should:** erasure must bypass archival (and delete any previously archived objects for that tenant); retention keeps the archive path.
- **Exact fix:**

```python
    def delete_for_tenant(self, tenant_id: str) -> int:
        """GDPR erasure: destroy, never archive. Also removes any objects this
        wrapper previously archived for the tenant."""
        doomed = [r for r in self._metadata.values() if r.tenant_id == tenant_id]
        for record in doomed:
            self.s3.delete_object(Bucket=record.bucket, Key=record.key)
            self._metadata.pop(record.call_id, None)
        return self.primary.delete_for_tenant(tenant_id)
```

  Document that pre-existing S3 objects from other processes need a lifecycle/inventory sweep (tenant prefix `tenant={id}/` makes `list_objects_v2 + delete_objects` straightforward).

### P1-8 · Blocking I/O on the event loop throughout the hot path

- **Files:** `pramagent/core.py:416` (`self.store.save(tr)` → SQLite `commit`), `:409-410` (`audit.append` → SQLite commit / web3), `pramagent/usage.py:294-312` (`WebhookUsageSink.emit` — synchronous `urllib`, 2 s timeout, called from `/v1/run` via `reserve_call`/`record_cost`), `pramagent/layers/__init__.py` SafetyLayer classifier + `pramagent/classifier.py:367-392` (embedding inference), `pramagent/layers/__init__.py:351-352` (`_gate_persistent` → sync Postgres `store.get` per poll), `deploy/dashboard/app.py:384-405` (sync Redis in async deps)
- **Lens:** 9, 3, 1
- **Today:** the pipeline is `async def` but its persistence, billing webhook, quota I/O, and ML inference are synchronous. One slow disk fsync, one 2-second billing webhook, or one 45 ms embedding encode stalls **every** in-flight request in the worker. This caps the architecture at "one request at a time, effectively" under adverse conditions.
- **Should:** every potentially-blocking call inside `async run()`/handlers goes through `asyncio.to_thread` (or async-native clients).
- **Exact fix (pattern, applied at each site):**

```python
# core.py _finalize → async (see P1-1), then:
        tr.this_hash, tr.anchor_tx_id = await asyncio.to_thread(
            self.audit.append, payload)
        await asyncio.to_thread(self.store.save, tr)

# api/app.py /v1/run:
        quota_decision = await asyncio.to_thread(
            app.state.usage.reserve_call, effective_tenant)
        ...
        await asyncio.to_thread(app.state.usage.record_cost,
                                effective_tenant, t.provider_cost_usd)

# layers/__init__.py SafetyLayer — add async path used by core:
    async def pre_async(self, text):
        return await asyncio.to_thread(self.pre, text)
```

### P1-9 · `GET /traces` filters after the limit — tenants can be served empty pages they shouldn't get

- **File:** `pramagent/api/app.py:711-756`
- **Lens:** 1, 2
- **Today:** the handler fetches `store.list_all(limit=limit)` — the most recent N rows **across all tenants** — then filters to the caller's tenant in Python. If the most recent 50 traces belong to tenant B, tenant A's `/traces` returns `[]` even though A has thousands of rows. It is also an unindexed full-recent-scan + Python filter for every dashboard refresh, and `limit` is uncapped (`?limit=10000000` is accepted). The `elif hasattr(store, "_traces")` branch calls `.values()` on `MemoryStore._traces`, which is a **list** — latent `AttributeError` (dead code today, booby trap tomorrow).
- **Should:** push the tenant filter into SQL (`list_by_tenant` already exists and is indexed by `idx_traces_tenant`), cap the limit, delete the dead branch.
- **Exact fix:**

```python
    @app.get("/traces")
    async def traces_list(
        tenant_id: str = "",
        session_id: str = "",
        blocked: str = "",
        limit: int = Query(50, ge=1, le=500),
        tenant: str = Depends(require_tenant),
    ):
        if tenant:
            tenant_id = tenant
        store = app.state.armor.store
        if tenant_id and hasattr(store, "list_by_tenant"):
            items = store.list_by_tenant(tenant_id, session_id or None, limit=limit)
        else:
            items = store.list_all(limit=limit)
        items = [t.to_dict() if hasattr(t, "to_dict") else t for t in items]
        if tenant_id:
            items = [t for t in items if t.get("tenant_id") == tenant_id]
        if session_id:
            items = [t for t in items if t.get("session_id") == session_id]
        if blocked in ("true", "false"):
            want = blocked == "true"
            items = [t for t in items if bool(t.get("blocked")) == want]
        return items
```

  (`from fastapi import Query`.) Cursor pagination is the P2 follow-up (P2-1).

### P1-10 · Compose publishes Postgres and Redis to the host; dashboard image runs as root with unpinned deps

- **Files:** `docker-compose.yml` (postgres `ports: 5432:5432`, redis `ports: 6379:6379`), `deploy/dashboard/Dockerfile`
- **Lens:** 10, 6
- **Today:** the datastores are reachable from outside the compose network — anything that can reach the host can attack Postgres/Redis directly with just the password (and the Redis healthcheck leaks that password into `docker inspect` via `redis-cli -a`). The dashboard image has no `USER` directive (runs as root), installs `fastapi uvicorn httpx jinja2 redis python-multipart bcrypt psycopg2-binary` with **no version pins** (unreproducible builds; silently picks up any future major), and still ships `psycopg2-binary`, contradicting the v0.7.0 psycopg3 migration.
- **Exact fix:**

```yaml
# docker-compose.yml — remove host port mappings on datastores:
  postgres:
    expose: ["5432"]           # internal-only
  redis:
    expose: ["6379"]
    healthcheck:
      test: ["CMD-SHELL", "redis-cli --no-auth-warning -a \"$$REDIS_PASSWORD\" ping | grep PONG"]
```

```dockerfile
# deploy/dashboard/Dockerfile
RUN pip install --no-cache-dir \
    "fastapi>=0.110,<1.0" "uvicorn[standard]>=0.29,<0.35" "httpx>=0.27,<0.29" \
    "jinja2>=3.1,<4" "redis>=5.0,<6" "python-multipart>=0.0.18,<0.1" \
    "bcrypt>=4.1,<5" "psycopg[binary]>=3.1,<4"
RUN useradd -r -u 1001 -g root dashboard && chown -R 1001:0 /app
USER 1001
```

  (Better: install the package itself with extras so the pins live in `pyproject.toml` once.)

---

## P2 FINDINGS — fix before scale

### P2-1 · No pagination on any list surface (Lens 1, 9)
- **Files:** `pramagent/api/app.py:711` (`/traces`), `store.py:156` (`list_all`), `deploy/dashboard/app.py` export (`limit: 10000`)
- Lists are offset-free `limit`-only with results fully materialized. At enterprise volume, `/traces` and the CSV export become multi-hundred-MB responses built in RAM.
- **Fix:** keyset pagination — `list_by_tenant(tenant, before_ts: float | None, limit)` using the existing `created_at` index; response shape `{"items": [...], "next_cursor": <created_at of last row>}`. Stream the CSV export with `StreamingResponse` writing row-by-row.

### P2-2 · Unbounded in-process growth: ToolGuard logs, judge log, call counters, usage ledger (Lens 9, 5)
- **Files:** `tool_guard.py:612-613` (`_provenance_log`, `audit_log` — now appended on **every** `run()` since validate_output was wired in), `:610` (`_call_counts` keys never expire), `llm_judge.py:175`, `usage.py:194` (`InMemoryUsageLedger._entries`), `deploy/dashboard/app.py:355` (`_rl_state` per-IP)
- Long-lived processes leak memory linearly with traffic.
- **Fix:** bound with `collections.deque(maxlen=...)`:
```python
# tool_guard.py __init__
        self._provenance_log: deque[OutputProvenance] = deque(maxlen=10_000)
        self.audit_log: deque[ToolDecision] = deque(maxlen=10_000)
```
  For `_call_counts`, store `(count, window_started)` and reset when `chain_ttl_s` elapses; for the ledger, document the cap or back it with the SQLite store; for `_rl_state`, evict entries idle > 2× refill window.

### P2-3 · JSON-Schema validator rebuilt and re-checked on every tool call (Lens 9)
- **File:** `tool_guard.py:348-355` — `Draft202012Validator.check_schema(schema)` + constructor per `evaluate()`.
- **Fix:** compile once per policy:
```python
@dataclass
class ToolPolicy:
    ...
    _validator: Any = field(default=None, init=False, repr=False)

# in validate_schema, accept a prebuilt validator; in ToolGuardLayer.register/__init__:
        policy._validator = Draft202012Validator(policy.schema,
                                                 format_checker=FormatChecker())
```

### P2-4 · `RunRequest.prompt` is unbounded before the isolation cap (Lens 1, 6)
- **File:** `api/app.py:69-73`. The 64 KiB isolation cap runs *after* FastAPI parses an arbitrarily large JSON body into memory; uvicorn imposes no body limit.
- **Fix:** `prompt: str = Field(..., min_length=1, max_length=262_144)` and document a reverse-proxy `client_max_body_size 1m`. (Pydantic rejects oversized bodies with 422 before they hit the pipeline.)

### P2-5 · Quota accounting is not atomic across workers (Lens 5)
- **File:** `usage.py:452-491` — `self._lock` is per-process; with a Redis backend the `get → mutate → set` of tenant state races across workers exactly like the ToolGuard history did pre-fix (audit Finding #10 class).
- **Fix:** same pattern as `history_append`: a Lua script (`HINCRBY calls/tools`, `HINCRBYFLOAT cost`, `EXPIRE window`) on `RedisBackend`, used when available:
```python
# backends/redis_backend.py
    _QUOTA_SCRIPT = """
local key = KEYS[1]
redis.call('HINCRBY', key, ARGV[1], ARGV[2])
if redis.call('TTL', key) < 0 then redis.call('EXPIRE', key, ARGV[3]) end
return redis.call('HGETALL', key)
"""
```

### P2-6 · Gemini API key travels in the URL query string (Lens 6)
- **File:** `providers/__init__.py:278`.
- Keys in URLs end up in proxy logs, error reprs, and tracing systems.
- **Fix:**
```python
        req = urllib.request.Request(
            f"{self.base_url}/models/{model}:generateContent",
            data=data,
            headers={"Content-Type": "application/json",
                     "x-goog-api-key": self.api_key},
            method="POST",
        )
```

### P2-7 · Redis URL (with password) logged at INFO (Lens 6, 8)
- **File:** `backends/redis_backend.py:381` — `log.info("RedisBackend connected: %s (pool max=%d)", url, ...)`; compose URLs embed `:${REDIS_PASSWORD}@`.
- **Fix:**
```python
        safe = url.split("@")[-1] if "@" in url else url
        log.info("RedisBackend connected: %s (pool max=%d)", safe, max_connections)
```

### P2-8 · Dashboard renders exception text into raw HTML; CSV export allows formula injection (Lens 6)
- **File:** `deploy/dashboard/app.py` `approve`/`deny` (`HTMLResponse(f'<span ...>{msg}</span>')` with `msg = f"Error: {exc}"`), `export_csv` (`csv_value` passes strings through).
- Upstream error bodies can carry markup → stored/reflected XSS in the admin UI; prompt text beginning `=`/`+`/`-`/`@` executes as a formula when the compliance CSV opens in Excel.
- **Fix:**
```python
import html
        msg, cls = f"Error: {exc}", "badge-block"
    return HTMLResponse(f'<span class="badge {cls}">{html.escape(msg)}</span>')

    def csv_value(value):
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            value = json.dumps(value, sort_keys=True)
        if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t"):
            return "'" + value          # neutralize spreadsheet formulas
        return value
```

### P2-9 · Rate-limit key is the raw socket IP — collapses behind any proxy (Lens 1, 10)
- **Files:** `api/app.py:397`, `deploy/dashboard/app.py:436`; Dockerfile CMD lacks `--proxy-headers`.
- Behind an LB every unauthenticated caller shares the proxy's IP → one bucket for the world (DoS pivot: one abuser exhausts it for everyone).
- **Fix:** run `uvicorn ... --proxy-headers --forwarded-allow-ips=<lb-cidr>` (then `request.client.host` is the real client), and document that the unauthenticated mode must not face the internet.

### P2-10 · Raw-dict responses on every endpoint except `/v1/run` (Lens 1, 4)
- **File:** `api/app.py` — `/v1/trace/{id}`, `/v1/metrics`, `/v1/usage*`, RCA, HITL, erase/prune all return untyped dicts; shape changes ship silently and the OpenAPI schema says `{}`.
- **Fix:** declare response models for the stable surfaces, e.g.:
```python
class EraseResponse(BaseModel):
    deleted: int
    tenant_id: str

@app.delete("/v1/tenant/{tenant_id}/traces", response_model=EraseResponse)
```
  (`TraceEvent` already has `to_dict`; add a `TraceModel` mirroring it for `/v1/trace/{id}` or generate via `pydantic.create_model`.)

### P2-11 · `replay`/`verify_chain` are O(n) with no incremental option (Lens 9)
- **Files:** `store.py:260-271`, `audit/__init__.py:67-75`.
- `/v1/audit/verify` recomputes every link each call. At 1 M links that is ~1 M JSON parses + hashes per request.
- **Fix:** add `verify_chain(since_seq: int = 0, limit: int | None = None)` returning `(ok, last_verified_seq)` and persist a verification watermark; expose `?since=` on the endpoint. Full verification moves to a scheduled job.

### P2-12 · Random per-process JWT fallback secret breaks multi-worker token auth (Lens 6, 10)
- **File:** `api/app.py:373-375`.
- With `PRAMAGENT_JWT_SECRET` unset, each worker/replica mints with its own random secret: `/v1/auth/token` from replica A is 401 on replica B (intermittent, maddening to debug), and every restart invalidates all tokens.
- **Fix:** when the registry is non-empty (auth on) and no JWT secret is configured, **refuse to issue tokens** rather than mint un-verifiable ones:
```python
    @app.post("/v1/auth/token", response_model=TokenResponse)
    async def issue_token(body: TokenRequest):
        if len(app.state.registry) == 0:
            raise HTTPException(status_code=400, detail="API-key auth is not enabled")
        if not os.environ.get("PRAMAGENT_JWT_SECRET") and not os.environ.get("PRAMAGENT_JWT_SECRETS"):
            raise HTTPException(status_code=503,
                detail="JWT issuance requires PRAMAGENT_JWT_SECRET(S) shared across workers")
```

### P2-13 · LLM-judge exception text flows to API callers; 3.10 timeout class mismatch (Lens 3, 4)
- **File:** `layers/llm_judge.py:217` (`except TimeoutError` — on Python 3.10, `asyncio.TimeoutError` is *not* `builtins.TimeoutError`, so timeouts take the generic path), `:236` (`reason=f"LLM judge error: {exc}"` → `ToolDecision.reason` → `/v1/tools/validate` response body — provider internals leak to callers, same class as the fixed `block_reason` leak).
- **Fix:**
```python
        except (TimeoutError, asyncio.TimeoutError):
            ...
        except Exception as exc:
            log.error("LLM judge error for %s: %r; escalating", tool_name, exc)
            return self._record(JudgeDecision(
                ...,
                reason="LLM judge unavailable — escalating for human review",
                raw_response=repr(exc)[:500],   # stays in the audit log, not the API
                ...))
```

### P2-14 · Compliance evidence asserts `in_place: True` unconditionally; counts via full scan (Lens 2, 8)
- **File:** `compliance.py:271-283` (`_controls` hardcodes True for 4/5 rows), `:213-226` (`list_all()` full load to count).
- Known residual from the previous audit — now with a concrete fix: probe the live objects (`audit.verify_chain()` already feeds row 1; check `consent` non-empty for the consent row; call `store.count()` instead of `len(list_all())`):
```python
# store.py SQLiteStore
    def count(self, tenant_id: str | None = None) -> int:
        if tenant_id:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM traces WHERE tenant_id = ?", (tenant_id,)).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) FROM traces").fetchone()
        return int(row[0])
```

### P2-15 · No graceful shutdown: stores never closed, in-flight HITL waits dropped silently (Lens 10, 3)
- **Files:** `api/app.py` (no shutdown hook), `store.py:135` (`close()` exists, never called), Dockerfile CMD (no `--timeout-graceful-shutdown`).
- **Fix:**
```python
    @app.on_event("shutdown")
    async def _close_stores() -> None:
        log.info("shutdown: closing stores")
        for obj in (app.state.armor.store, app.state.armor.audit):
            close = getattr(obj, "close", None)
            if close:
                try:
                    close()
                except Exception:
                    log.warning("store close failed", exc_info=True)
```
  and `CMD ... --timeout-graceful-shutdown 30` so SIGTERM drains in-flight requests.

### P2-16 · Observability is JSON-only and logs lack correlation IDs (Lens 8)
- **Files:** `layers/observability.py` (no Prometheus exposition; no per-tenant labels), `api/app.py:336-358` (request log has `request_id` but pipeline logs don't carry `call_id`/`tenant_id`; no JSON formatter anywhere).
- **Fix:** (a) add a `text/plain; version=0.0.4` Prometheus rendering of the existing counters on `/metrics` via content negotiation, or mount `prometheus_client.make_asgi_app()`; (b) bind context into logs:
```python
# core.py run(), after tr is created
        log_extra = {"call_id": tr.call_id, "tenant_id": tenant_id, "session_id": session_id}
        ...
        log.warning("provider call failed", extra=log_extra, exc_info=True)
```
  plus a `logging.basicConfig` JSON formatter documented in DEPLOYMENT.md. Today a Datadog/Loki user cannot join the request log line to a trace.

### P2-17 · Embedding classifier loads (and may download) the model at import of `pramagent.api.app` (Lens 10, 9)
- **Files:** `api/app.py:833` (`app = create_app()` at module import), `classifier.py:343-356` (`SentenceTransformer(model_name)` in `__init__` — network fetch on cold cache).
- A pod with the `ml` extra and a cold HF cache does a network download during import, before any probe can see it; if the registry is unreachable the worker crash-loops with no readiness signal.
- **Fix:** lazy-load on first call instead of `__init__` (move `_load_model()` into `__call__` behind `if self._model is None and self._load_error is None:`), and pre-bake the model into the image (`RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"`).

### P2-18 · `/health/ready` (and `/health`) info disclosure (Lens 6)
- **File:** `api/app.py:455-471`.
- Unauthenticated callers learn whether auth is enabled, whether Slack HITL is configured, the last Slack error string, and total trace count. Reconnaissance gold.
- **Fix:** covered by the P1-3 rewrite — return only `status` + boolean dependency checks to unauthenticated callers; move the detailed view behind `Depends(require_tenant)` as `/v1/health/detail`.

---

## P3 FINDINGS — hygiene

| # | File:Line | Lens | Issue | Fix |
|---|---|---|---|---|
| P3-1 | `api/app.py:388` | 4 | `require_tenant(request: Request = None)` — non-Optional annotation with `None` default | `request: Optional[Request] = None` |
| P3-2 | `api/app.py:833` | 10 | Module-level `app = create_app()` runs env parsing/classifier builds at import; breaks `--factory` patterns | expose `create_app` as uvicorn factory: `uvicorn pramagent.api.app:create_app --factory`; keep `app` for back-compat behind `if os.environ.get("PRAMAGENT_EAGER_APP", "1") == "1"` |
| P3-3 | `deploy/dashboard/app.py:120-133` | 3 | `@app.on_event("startup")` deprecated since FastAPI 0.103 | migrate both services to lifespan context managers |
| P3-4 | `auth.py:319-385` | 6 | JWT has no `aud`, no `nbf`, `iat` unchecked; `alg=none` rejected only implicitly via the HS256 equality check | add `aud="pramagent-api"` claim + verification; assert `header.get("alg") == "HS256"` explicitly with a comment that this is the none-algorithm defense |
| P3-5 | `core.py:322` (`mark("IsolationLayer.cap_output", ..., time.perf_counter())`) | 8 | latency_ms ≈ 0 for the cap event (documented residual) | pass the `t0` captured before `truncate_output` |
| P3-6 | `usage.py:349-358` | 4 | `_env_int_optional("PRAMAGENT_QUOTA_CALLS", "PRAMAGENT_QUOTA_CALLS")` — same name twice, copy-paste across 6 call sites | single-name calls |
| P3-7 | `providers/__init__.py:300-312` | 3 | `OllamaProvider` host unvalidated (every other provider validates), new `ClientSession` per call, no request timeout | `validate_http_url(host, allow_http_localhost=True, allow_private=True)`; `aiohttp.ClientTimeout(total=60)`; reuse session |
| P3-8 | `queue/postgres.py:87-90` | 2 | new connection per operation; `_connect` has identical branches | thread-local pool like `store_postgres`; delete the dead branch |
| P3-9 | `cli.py:61-62` | 6 | `pramagent init` writes `.env` with default umask (world-readable secrets on POSIX) | `os.open(env_path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o600)` |
| P3-10 | `hitl/slack.py:386` | 1 | `registry.decide()` returns `True` for unknown ids (multi-worker design), so the "expired" Slack response path is unreachable in-process | return `found = request_id in self._pending or backend-known`; acceptable to document instead |
| P3-11 | `layers/__init__.py:296-302` | 3 | `HITLLayer.on_enqueue` failures only logged — a Slack notification outage silently leaves approvals invisible until timeout | emit a metric (`observability.record_result`-style counter) in the except branch |
| P3-12 | `compliance.py:217-219` | 3 | `except Exception: all_traces = []` — a store outage yields a report asserting zero traces, signed as evidence | let the exception propagate or stamp `"store_error": str(exc)` into the report |
| P3-13 | `deploy/helm/pramagent/values.yaml:4` | 10 | image tag `0.3.0` vs package 0.7.0; no `securityContext`, no PDB | bump tag; add `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, a PodDisruptionBudget |
| P3-14 | `docker-compose.yml` | 10 | no resource limits on any service | add `deploy.resources.limits` / `mem_limit` per service |
| P3-15 | `Dockerfile:14` | 10 | builder copies `docs/` into the build context layer needlessly; comment still says "System deps for psycopg2" | drop `COPY docs/`; update comment to psycopg3 |
| P3-16 | `tests/test_pipeline.py`, `tests/test_hitl_workflow.py` etc. | 7 | HITL tests wait real wall-clock (`timeout_s=0.05–0.5`) — flaky on saturated CI runners | inject `now_fn`/clock or raise timeouts to ≥1 s where the assert is on the *outcome*, not the latency |
| P3-17 | `tests/test_api.py:300-320` | 7 | `test_unversioned_hitl_decide_blocks_cross_tenant` asserts on `registry._pending` (private attr) | assert through `GET /hitl/pending` instead |
| P3-18 | `rca.py:165` | 4 | `"rules_fired=" + ", ".join(...) or "rules_fired=(none)"` — operator precedence: the `or` binds to the join result, so the `(none)` fallback never renders with the prefix | `"rules_fired=" + (", ".join(r.rule_id for r in t.rules_evaluated if r.fired) or "(none)")` |
| P3-19 | `.env.example` | 10 | missing `PRAMAGENT_DB` / `PRAMAGENT_POSTGRES_DSN` (API), `PRAMAGENT_PROVIDER`, `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`, `PRAMAGENT_CORS_ORIGINS`, `PRAMAGENT_PUBLIC_URL`, `SLACK_*`, `PRAMAGENT_ENCRYPTION_KEY`; no required/optional/type annotations | regenerate grouped by service with `# (required|optional, type, default)` comments — pairs with P0-1/P0-2 |
| P3-20 | `dist/`, `pramagent.egg-info/`, `*.db`, marketing PNG/DOCX in repo root | 10 | build artifacts and binaries in the working tree (untracked but noisy) | extend `.gitignore`, move marketing assets to `assets/` |

---

## Test-quality verdict (Lens 7)

The suite is genuinely integration-first: `test_api.py` drives a real `TestClient` against the real pipeline with real in-memory stores — no store mocking anywhere in the API tests. Negative auth tests exist for every route after the Sprint-1 fix. No assertion-free tests were found; no order-dependent shared state was found (fixtures build fresh apps per test).

**The single test most likely to give a false green on a real regression:**
`tests/test_load_smoke.py::test_concurrent_runs_preserve_trace_uniqueness_and_hash_chain`. It asserts `armor.audit.verify_chain()` holds under 40 "concurrent" runs — but all 40 share one event loop, where the head-read→append sequence in `_finalize` is never preempted. It therefore certifies exactly the guarantee that **breaks** under threads or multiple workers (P1-5) while staying green. After the P1-5 fix, extend it:

```python
def test_chain_survives_threaded_writers():
    db = SQLiteStore(path)
    def writer(i):
        asyncio.run(Pramagent(store=db, audit=db).run(f"t{i}"))
    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(writer, range(64)))
    assert db.verify_chain()          # fails today; passes with P1-5
```

Honorable mentions: `test_ready_reports_chain_valid` asserts `chain_valid is True` against an *empty* chain (vacuously true — seed one trace first); the dashboard `_login_dashboard` helper monkeypatches module globals, which is correct but means the dashboard is never tested with its real env-derived config.

---

## Executive summary

**Production-ready today.** The trust pipeline itself is in good shape: deterministic rule precedence, ESCALATE→HITL with silence-is-never-consent, output exfiltration scanning, scrubbed-only persistence, real chain redaction on erasure, tenant-scoped authenticated API surface, careful Slack signature verification, strict SSRF validation on outbound URLs, parameterized SQL throughout, and a 505-test integration-first suite. For a single-process, SQLite-backed, single-tenant-ish pilot behind a trusted network, this deploys today.

**Not production-ready.** The gap is everything *around* the pipeline:
1. **The reference deployment does not persist anything** (P0-1) — compose/Helm boot MemoryStore while shipping an idle Postgres.
2. **Secrets hygiene fails open** (P0-2) — the repo's own published placeholder secrets pass both services' startup validation; the API never validates its JWT secret at all.
3. **The audit chain is single-writer** (P1-5) — any threaded or multi-process deployment forks the chain and manufactures false tamper alarms; the load test that should catch this can't (Lens 7).
4. **The event loop is unprotected** (P1-1, P1-8) — SQLite commits, billing webhooks, embedding inference, and (catastrophically) Ethereum receipt-waits all block it.
5. **O(n) operational surfaces** (P1-3, P1-4, P2-11) — readiness probes and RCA calls scale linearly with history; at a million traces the health check takes down the service it guards.
6. **GDPR parity holes** (P1-2, P1-7) — the encrypted store and the S3 wrapper both undermine the erasure guarantee the core stores now honor.

**90-day hardening roadmap.**
- **Days 0–14 — stop the bleeding (P0s + deployment truth):** land P0-1 (Postgres wiring + memory-store opt-in + P1-6 protocol conformance as one change), P0-2 (weak-secret denylist in both services, regenerated `.env.example`), P1-10 (compose port closure, dashboard image), P3-19 (env documentation). Cut a 0.7.1 with these alone.
- **Days 15–45 — correctness under concurrency and load:** P1-5 (serialized chain append + threaded chain test), P1-8/P1-1 (async offload of all blocking I/O; anchor without receipt-wait), P1-3/P1-4 (O(1) readiness, per-trace RCA), P1-9 (tenant-scoped trace listing), P2-2 (bounded logs), P2-3 (validator caching). Re-run the load smoke as a real k6 profile against compose; add saturation and breaker-recovery tests (the Domain-6 gap from the prior audit).
- **Days 46–90 — enterprise polish:** P1-2/P1-7 (erasure parity in encrypted + S3 stores, with parity tests), P2-1 (pagination + streaming export), P2-5 (atomic Redis quotas), P2-10 (typed responses), P2-11 (incremental verification + scheduled full verify), P2-16 (Prometheus exposition + correlation-ID logging), P2-15 (graceful shutdown), remaining P2/P3 sweep. Exit criteria: a 3-replica Helm deployment passes a 1 M-trace soak with flat memory, green readiness, a verifying chain, and a clean `pip-audit` — at which point "defensibly pilot-ready" becomes "defensibly production-ready."

---

*Found in this review: 2 P0, 10 P1, 18 P2, 20 P3. The previous audit's ten findings remain resolved as documented; nothing in this review reopens them, but P1-2 and P1-7 show two sibling code paths the Finding #3/#4 remediation did not reach.*
