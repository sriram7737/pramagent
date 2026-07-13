"""
pramagent.auth
==============
API-key-per-tenant authentication for the HTTP service.

Why this exists
---------------
Without authentication, the tenant guard on the store is moot: any caller can
claim to be any tenant. A request must arrive with a key, that key must map to
a tenant, and every downstream check uses that *server-determined* tenant — not
a tenant id the caller asserts in the body.

Key handling
------------
Keys are never compared in plain text and never logged. The registry stores the
SHA-256 of each key. Lookups iterate all entries with `secrets.compare_digest`
to prevent timing-based key recovery. Keys are presented in the
`Authorization: Bearer <key>` header.

This is the minimum useful authentication, not the maximum. Production
deployments would layer JWTs with short TTLs, per-key scopes/roles, key
rotation, and an audit log of key issuance. The interface here is small enough
to swap out for any of those without touching the rest of the codebase.
"""
from __future__ import annotations

import base64
import json
import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

READ_SCOPE = "read"
WRITE_SCOPE = "write"
ADMIN_SCOPE = "admin"
# Separate from READ_SCOPE so an operator can issue a key that can only check
# audit-chain integrity (e.g. a monitoring/alerting integration) without
# granting it general read access to trace content. /v1/audit/verify accepts
# either scope — READ_SCOPE keeps working so this is additive, not a breaking
# cutover for anyone already polling that endpoint with a read-scoped key.
AUDIT_SCOPE = "audit"
DEFAULT_SCOPES = frozenset({READ_SCOPE, WRITE_SCOPE, ADMIN_SCOPE, AUDIT_SCOPE})


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def normalize_scopes(scopes: Optional[object] = None) -> frozenset[str]:
    """Normalize scope input for API keys and JWTs."""
    if scopes is None:
        return DEFAULT_SCOPES
    if isinstance(scopes, str):
        raw = scopes.replace("|", ",").replace("+", ",").replace(" ", ",")
        values = [item.strip().lower() for item in raw.split(",")]
    else:
        values = [str(item).strip().lower() for item in scopes]  # type: ignore[arg-type]
    normalized = {item for item in values if item}
    if not normalized:
        return DEFAULT_SCOPES
    unknown = normalized - set(DEFAULT_SCOPES)
    if unknown:
        raise ValueError(f"unknown API key scope(s): {', '.join(sorted(unknown))}")
    return frozenset(normalized)


def encode_scopes(scopes: Optional[object] = None) -> str:
    return ",".join(sorted(normalize_scopes(scopes)))


@dataclass(frozen=True)
class AuthRecord:
    tenant_id: str
    scopes: frozenset[str]
    kind: str = "api_key"
    # Unix epoch. 0.0 (the default) means "unknown" — JWT records and
    # registries that predate this field leave it unset, so age-based
    # rotation enforcement treats 0.0 as "do not enforce" rather than
    # "infinitely old" (see PRAMAGENT_API_KEY_MAX_AGE_DAYS in api/app.py).
    created_at: float = 0.0

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes or ADMIN_SCOPE in self.scopes

    def age_days(self) -> float:
        if self.created_at <= 0:
            return 0.0
        return max(0.0, (time.time() - self.created_at) / 86400.0)


class APIKeyRegistry:
    """Maps API keys to tenants. Keys are stored as SHA-256, never plain text."""

    def __init__(self) -> None:
        # hashed_key -> AuthRecord
        self._keys: dict[str, AuthRecord] = {}

    def add_key(
        self,
        tenant_id: str,
        key: str,
        *,
        scopes: Optional[object] = None,
        created_at: Optional[float] = None,
    ) -> None:
        """Register an existing key for a tenant.

        created_at defaults to now — for env-var-configured keys (no
        persistent store) this tracks "how long has this process been
        running with this key," an approximation of true key age, not the
        credential's real-world issuance date. Still useful: a long-lived
        process holding the same static key for months is itself a rotation
        signal worth surfacing.
        """
        self._keys[_hash_key(key)] = AuthRecord(
            tenant_id=tenant_id,
            scopes=normalize_scopes(scopes),
            kind="api_key",
            created_at=created_at if created_at is not None else time.time(),
        )

    def issue_key(self, tenant_id: str, *, scopes: Optional[object] = None) -> str:
        """Generate a new random key for a tenant and return it (plain text,
        one time only — store it on the caller side immediately)."""
        key = "pramagent_" + secrets.token_urlsafe(32)
        self.add_key(tenant_id, key, scopes=scopes)
        return key

    def revoke_key(self, key: str) -> bool:
        return self._keys.pop(_hash_key(key), None) is not None

    def tenant_for_key(self, presented: str) -> Optional[str]:
        """Constant-time lookup. Returns the tenant_id or None."""
        record = self.record_for_key(presented)
        return record.tenant_id if record else None

    def record_for_key(self, presented: str) -> Optional[AuthRecord]:
        """Constant-time lookup. Returns the auth record or None."""
        if not presented:
            return None
        target = _hash_key(presented)
        # iterate every entry so timing reveals nothing about presence
        match: Optional[AuthRecord] = None
        for hashed, record in self._keys.items():
            if secrets.compare_digest(hashed, target):
                match = record
        return match

    def __len__(self) -> int:
        return len(self._keys)


class PostgresAPIKeyRegistry(APIKeyRegistry):
    """Postgres-backed API-key registry with the same interface as
    ``APIKeyRegistry``.

    Schema:

    ``pramagent_api_keys(hashed_key, tenant_id, created_at, revoked_at)``

    The plain API key is still returned only once from ``issue_key``. Postgres
    stores only the SHA-256 hash, tenant, creation timestamp, and revocation
    timestamp.
    """

    _DDL = """
    CREATE TABLE IF NOT EXISTS pramagent_api_keys (
        hashed_key TEXT PRIMARY KEY,
        tenant_id  TEXT NOT NULL,
        scopes     TEXT NOT NULL DEFAULT 'admin,read,write',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        revoked_at TIMESTAMPTZ NULL
    );
    CREATE TABLE IF NOT EXISTS pramagent_api_key_audit (
        id BIGSERIAL PRIMARY KEY,
        hashed_key TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        scopes TEXT NOT NULL,
        action TEXT NOT NULL,
        actor TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS pramagent_api_keys_tenant
        ON pramagent_api_keys(tenant_id);
    CREATE INDEX IF NOT EXISTS pramagent_api_keys_active
        ON pramagent_api_keys(revoked_at)
        WHERE revoked_at IS NULL;
    CREATE INDEX IF NOT EXISTS pramagent_api_key_audit_created
        ON pramagent_api_key_audit(created_at DESC);
    ALTER TABLE pramagent_api_keys
        ADD COLUMN IF NOT EXISTS scopes TEXT NOT NULL DEFAULT 'admin,read,write';
    """

    def __init__(self, dsn: str, *, connect=None) -> None:
        if not dsn:
            raise ValueError("Postgres API key DSN must not be empty")
        self._dsn = dsn
        self._connect = connect
        self._init_schema()

    @classmethod
    def from_dsn(cls, dsn: str) -> "PostgresAPIKeyRegistry":
        return cls(dsn)

    def _connection(self):
        if self._connect is not None:
            return self._connect(self._dsn)
        from . import _pg
        try:
            return _pg.connect(self._dsn)
        except RuntimeError as exc:
            raise RuntimeError(
                "a Postgres driver is required for PostgresAPIKeyRegistry; "
                "install pramagent[postgres]"
            ) from exc

    def _run(self, fn):
        conn = self._connection()
        try:
            with conn:
                with conn.cursor() as cur:
                    return fn(cur)
        finally:
            try:
                conn.close()
            except Exception:
                log.warning("failed to close registry connection")

    def _init_schema(self) -> None:
        self._run(lambda cur: cur.execute(self._DDL))

    def add_key(
        self,
        tenant_id: str,
        key: str,
        *,
        scopes: Optional[object] = None,
        actor: str = "",
    ) -> None:
        hashed = _hash_key(key)
        encoded_scopes = encode_scopes(scopes)

        def _fn(cur):
            cur.execute(
                """
                INSERT INTO pramagent_api_keys (hashed_key, tenant_id, scopes)
                VALUES (%s, %s, %s)
                ON CONFLICT (hashed_key) DO UPDATE
                SET tenant_id = EXCLUDED.tenant_id,
                    scopes = EXCLUDED.scopes,
                    revoked_at = NULL
                """,
                (hashed, tenant_id, encoded_scopes),
            )
            cur.execute(
                """
                INSERT INTO pramagent_api_key_audit
                    (hashed_key, tenant_id, scopes, action, actor)
                VALUES (%s, %s, %s, 'issue', %s)
                """,
                (hashed, tenant_id, encoded_scopes, actor),
            )

        self._run(_fn)

    def issue_key(
        self,
        tenant_id: str,
        *,
        scopes: Optional[object] = None,
        actor: str = "",
    ) -> str:
        key = "pramagent_" + secrets.token_urlsafe(32)
        self.add_key(tenant_id, key, scopes=scopes, actor=actor)
        return key

    def revoke_key(self, key: str, *, actor: str = "") -> bool:
        hashed = _hash_key(key)

        def _fn(cur):
            cur.execute(
                """
                SELECT tenant_id, scopes
                FROM pramagent_api_keys
                WHERE hashed_key = %s AND revoked_at IS NULL
                """,
                (hashed,),
            )
            row = cur.fetchone()
            if not row:
                return False
            tenant_id, scopes = row
            cur.execute(
                """
                UPDATE pramagent_api_keys
                SET revoked_at = now()
                WHERE hashed_key = %s AND revoked_at IS NULL
                """,
                (hashed,),
            )
            revoked = cur.rowcount > 0
            if revoked:
                cur.execute(
                    """
                    INSERT INTO pramagent_api_key_audit
                        (hashed_key, tenant_id, scopes, action, actor)
                    VALUES (%s, %s, %s, 'revoke', %s)
                    """,
                    (hashed, tenant_id, scopes, actor),
                )
            return revoked

        return bool(self._run(_fn))

    def tenant_for_key(self, presented: str) -> Optional[str]:
        record = self.record_for_key(presented)
        return record.tenant_id if record else None

    def record_for_key(self, presented: str) -> Optional[AuthRecord]:
        if not presented:
            return None
        hashed = _hash_key(presented)

        def _fn(cur):
            cur.execute(
                """
                SELECT tenant_id, scopes, created_at
                FROM pramagent_api_keys
                WHERE hashed_key = %s AND revoked_at IS NULL
                """,
                (hashed,),
            )
            row = cur.fetchone()
            if not row:
                return None
            created_at = row[2]
            return AuthRecord(
                tenant_id=row[0],
                scopes=normalize_scopes(row[1]),
                kind="api_key",
                created_at=created_at.timestamp() if hasattr(created_at, "timestamp") else 0.0,
            )

        record = self._run(_fn)
        return record if isinstance(record, AuthRecord) else None

    def __len__(self) -> int:
        def _fn(cur):
            cur.execute(
                "SELECT COUNT(*) FROM pramagent_api_keys WHERE revoked_at IS NULL"
            )
            row = cur.fetchone()
            return int(row[0]) if row else 0

        return self._run(_fn)


class JWTError(ValueError):
    pass


class JWTManager:
    """Small HS256 JWT issuer/verifier for tenant-scoped API tokens.

    Supports ``kid``-based key rotation while retaining the original single
    secret constructor. New tokens include the active ``kid`` in the header;
    verification accepts tokens signed by any registered, non-retired key.
    """

    def __init__(
        self,
        secret: str | dict[str, str],
        *,
        issuer: str = "pramagent",
        active_kid: str | None = None,
    ) -> None:
        self.issuer = issuer
        if isinstance(secret, dict):
            if not secret:
                raise ValueError("JWT secret registry must not be empty")
            self._secrets = {
                str(kid): value.encode("utf-8")
                for kid, value in secret.items()
                if kid and value
            }
            if not self._secrets:
                raise ValueError("JWT secret registry must contain non-empty keys")
            self.active_kid = active_kid or next(iter(self._secrets))
            if self.active_kid not in self._secrets:
                raise ValueError("active_kid must exist in JWT secret registry")
            self.secret = self._secrets[self.active_kid]
        else:
            if not secret:
                raise ValueError("JWT secret must not be empty")
            self.active_kid = active_kid or "default"
            self.secret = secret.encode("utf-8")
            self._secrets = {self.active_kid: self.secret}

    @classmethod
    def from_env(
        cls,
        *,
        env_var: str = "PRAMAGENT_JWT_SECRETS",
        fallback_secret: str = "",
        issuer: str = "pramagent",
    ) -> "JWTManager":
        """Build from env.

        ``PRAMAGENT_JWT_SECRETS`` format:
            ``kid1:secret1,kid2:secret2``

        ``PRAMAGENT_JWT_ACTIVE_KID`` chooses the signing key. If unset, the
        first listed key signs new tokens. ``fallback_secret`` preserves the
        existing single-secret deployment path.
        """
        raw = os.environ.get(env_var, "").strip()
        if raw:
            secrets_by_kid: dict[str, str] = {}
            for pair in raw.split(","):
                if ":" not in pair:
                    continue
                kid, value = pair.split(":", 1)
                kid = kid.strip()
                value = value.strip()
                if kid and value:
                    secrets_by_kid[kid] = value
            if secrets_by_kid:
                return cls(
                    secrets_by_kid,
                    issuer=issuer,
                    active_kid=os.environ.get("PRAMAGENT_JWT_ACTIVE_KID") or None,
                )
        return cls(fallback_secret, issuer=issuer)

    def rotate(self, kid: str, secret: str, *, activate: bool = True) -> None:
        """Register a new signing secret and optionally make it active."""
        if not kid or not secret:
            raise ValueError("kid and secret must be non-empty")
        self._secrets[kid] = secret.encode("utf-8")
        if activate:
            self.active_kid = kid
            self.secret = self._secrets[kid]

    def retire(self, kid: str) -> bool:
        """Stop accepting tokens signed by ``kid``.

        The active signing key cannot be retired without rotating first.
        """
        if kid == self.active_kid:
            raise ValueError("cannot retire active JWT key")
        return self._secrets.pop(kid, None) is not None

    AUDIENCE = "pramagent-api"

    def issue(
        self,
        tenant_id: str,
        *,
        ttl_s: int = 900,
        scopes: Optional[object] = None,
    ) -> str:
        now = int(time.time())
        header = {"alg": "HS256", "typ": "JWT", "kid": self.active_kid}
        normalized_scopes = sorted(normalize_scopes(scopes))
        payload = {
            "iss": self.issuer,
            "aud": self.AUDIENCE,
            "sub": tenant_id,
            "tenant_id": tenant_id,
            "scope": " ".join(normalized_scopes),
            "scopes": normalized_scopes,
            "iat": now,
            "exp": now + int(ttl_s),
        }
        signing_input = ".".join([
            _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
        ])
        sig = hmac.new(self.secret, signing_input.encode("ascii"), hashlib.sha256).digest()
        return f"{signing_input}.{_b64url_encode(sig)}"

    def tenant_for_token(self, token: str, *, now: Optional[int] = None) -> Optional[str]:
        record = self.record_for_token(token, now=now)
        return record.tenant_id if record else None

    def record_for_token(self, token: str, *, now: Optional[int] = None) -> Optional[AuthRecord]:
        try:
            payload = self.verify(token, now=now)
        except JWTError:
            return None
        tenant = payload.get("tenant_id") or payload.get("sub")
        if not isinstance(tenant, str) or not tenant:
            return None
        scopes = payload.get("scopes")
        if not scopes:
            scopes = payload.get("scope", "")
        return AuthRecord(
            tenant_id=tenant,
            scopes=normalize_scopes(scopes),
            kind="jwt",
        )

    def verify(self, token: str, *, now: Optional[int] = None) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            raise JWTError("malformed token")
        signing_input = f"{parts[0]}.{parts[1]}"
        try:
            header = json.loads(_b64url_decode(parts[0]))
        except Exception as exc:
            raise JWTError("malformed header") from exc
        # Explicit HS256 allow-list: this is the none-algorithm defense (and
        # the RS256→HS256 key-confusion defense) — any alg value other than
        # the one we sign with, including "none", is rejected before any
        # signature work happens (P3-4/T1-3).
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            raise JWTError("unsupported token header")
        kid = header.get("kid")
        if kid is not None:
            if not isinstance(kid, str):
                raise JWTError("invalid key id")
            secret = self.secret if kid == self.active_kid else self._secrets.get(kid)
            if secret is None:
                raise JWTError("unknown key id")
        else:
            secret = self.secret
        expected = hmac.new(
            secret, signing_input.encode("ascii"), hashlib.sha256
        ).digest()
        try:
            supplied = _b64url_decode(parts[2])
        except Exception as exc:
            raise JWTError("malformed signature") from exc
        if not hmac.compare_digest(expected, supplied):
            raise JWTError("invalid signature")

        try:
            payload = json.loads(_b64url_decode(parts[1]))
        except Exception as exc:
            raise JWTError("malformed payload") from exc
        if payload.get("iss") != self.issuer:
            raise JWTError("invalid issuer")
        # aud pins the token to this API so a token minted for another
        # service signed with a shared secret cannot be replayed here (T1-3).
        if payload.get("aud") != self.AUDIENCE:
            raise JWTError("invalid audience")
        exp = payload.get("exp")
        if not isinstance(exp, int):
            raise JWTError("missing expiration")
        if (int(time.time()) if now is None else now) >= exp:
            raise JWTError("token expired")
        return payload


def load_registry_from_env(
    env_var: str = "PRAMAGENT_API_KEYS",
) -> APIKeyRegistry:
    """Build a registry from an env var.

    Formats:
      ``tenant1:key1,tenant2:key2`` keeps the legacy all-scope behavior.
      ``tenant1:key1:read|write`` narrows the key to named scopes.

    Returns an empty registry if the variable is unset. Useful for the demo
    server; real deployments load keys from a secret manager.
    """
    dsn = os.environ.get("PRAMAGENT_API_KEY_DSN", "").strip()
    reg: APIKeyRegistry
    if dsn:
        reg = PostgresAPIKeyRegistry.from_dsn(dsn)
    else:
        reg = APIKeyRegistry()
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return reg
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        parts = pair.split(":", 2)
        tenant = parts[0].strip()
        key = parts[1].strip()
        scopes = parts[2].strip() if len(parts) == 3 else None
        reg.add_key(tenant, key, scopes=scopes)
    return reg
