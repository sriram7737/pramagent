"""
pramagent.config
================
Centralized configuration via Pydantic Settings.

All environment variables are prefixed PRAMAGENT_ and can be overridden by a .env
file in the working directory. Import ``settings`` for the singleton; call
``Settings()`` to create an isolated instance in tests.

Usage
-----
    from pramagent.config import settings

    armor = Pramagent(
        isolation=IsolationLayer(max_input_bytes=settings.max_input_bytes),
        ...
    )

    # In FastAPI startup:
    backend = RedisBackend.from_url(settings.redis_url)

Environment variables
---------------------
PRAMAGENT_REDIS_URL              redis://localhost:6379/0
PRAMAGENT_POSTGRES_DSN           postgresql://pramagent:secret@localhost/pramagent
PRAMAGENT_MAX_INPUT_BYTES        65536
PRAMAGENT_MAX_OUTPUT_BYTES       65536
PRAMAGENT_RATE_LIMIT_CAPACITY    100
PRAMAGENT_RATE_LIMIT_REFILL      10          tokens/second
PRAMAGENT_QUOTA_CALLS            10000       per-tenant window cap (optional)
PRAMAGENT_QUOTA_TOOL_VALIDATIONS 50000       per-tenant window cap (optional)
PRAMAGENT_QUOTA_COST_USD         100.0       per-tenant provider spend cap (optional)
PRAMAGENT_QUOTA_WINDOW_S         86400       quota window in seconds
PRAMAGENT_BILLING_WEBHOOK_URL    (optional fail-open usage/billing event sink)
PRAMAGENT_BILLING_WEBHOOK_SECRET (optional shared secret header for billing webhook)
PRAMAGENT_INJECTION_THRESHOLD    0.65        cosine similarity for embedding classifier
PRAMAGENT_BREAKER_THRESHOLD      5           failures before circuit opens
PRAMAGENT_BREAKER_COOLDOWN_S     30.0
PRAMAGENT_POOL_MAX_CONNECTIONS   10
PRAMAGENT_LOG_LEVEL              info
PRAMAGENT_API_KEY                (required in production)
PRAMAGENT_API_KEY_DSN            optional Postgres-backed API key registry
PRAMAGENT_SIGNING_KEY            (required in production)
PRAMAGENT_JWT_SECRET             change-me-in-production
PRAMAGENT_OTEL_ENDPOINT          (optional OTLP gRPC endpoint)
PRAMAGENT_OTEL_SERVICE_NAME      pramagent
PRAMAGENT_HITL_SLACK_TOKEN       (optional)
PRAMAGENT_HITL_SLACK_CHANNEL     (optional)
PRAMAGENT_HITL_TIMEOUT_S         300
PRAMAGENT_CHAIN_WINDOW           10
PRAMAGENT_TOOL_GUARD_REDIS_URL   optional Redis override for ToolGuard state
PRAMAGENT_TOOL_GUARD_TTL_S       300
PRAMAGENT_DASHBOARD_TENANT       default     tenant scope for dashboard sessions
PRAMAGENT_DASHBOARD_ALLOW_SUPER_ADMIN false  required before tenant "*" is honored
PRAMAGENT_DASHBOARD_USER_DSN     optional Postgres-backed dashboard users
PRAMAGENT_DASHBOARD_USERS_SQLITE optional SQLite dashboard users for dev/tests
PRAMAGENT_DASHBOARD_LOCAL_USERS_PATH .pramagent/dashboard-users.db
PRAMAGENT_DASHBOARD_SIGNUP_ENABLED true      disable for public deployments
PRAMAGENT_DASHBOARD_PASSWORD_RESET_ENABLED true
"""
from __future__ import annotations

import os
from typing import Optional


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _env_bool(key: str, default: bool = False) -> bool:
    val = os.environ.get(key, "").lower()
    if val in ("1", "true", "yes", "on"):
        return True
    if val in ("0", "false", "no", "off"):
        return False
    return default


class Settings:
    """
    Immutable configuration snapshot.

    Reads from environment at construction time. Use the module-level
    ``settings`` singleton in application code; construct a fresh ``Settings()``
    in tests to pick up monkeypatched env vars.
    """

    def __init__(self) -> None:
        # ── networking / backends ──────────────────────────────────────────────
        self.redis_url: str = _env(
            "PRAMAGENT_REDIS_URL", "redis://localhost:6379/0")
        # No phantom default DSN: an unset PRAMAGENT_POSTGRES_DSN means "not
        # configured", never "assume localhost with a guessable password".
        self.postgres_dsn: str = _env("PRAMAGENT_POSTGRES_DSN", "")
        # Store selection (priority: postgres_dsn > db_path > opt-in memory).
        self.db_path: str = _env("PRAMAGENT_DB", "")
        self.allow_memory_store: bool = _env_bool("PRAMAGENT_ALLOW_MEMORY_STORE", False)

        # ── isolation / safety ────────────────────────────────────────────────
        self.max_input_bytes: int  = _env_int("PRAMAGENT_MAX_INPUT_BYTES",  64 * 1024)
        self.max_output_bytes: int = _env_int("PRAMAGENT_MAX_OUTPUT_BYTES", 64 * 1024)
        self.injection_threshold: float = _env_float("PRAMAGENT_INJECTION_THRESHOLD", 0.65)
        self.block_on_injection: bool   = _env_bool("PRAMAGENT_BLOCK_ON_INJECTION", True)

        # ── rate limiting ─────────────────────────────────────────────────────
        self.rate_limit_capacity: float = _env_float("PRAMAGENT_RATE_LIMIT_CAPACITY", 100.0)
        self.rate_limit_refill:   float = _env_float("PRAMAGENT_RATE_LIMIT_REFILL",   10.0)

        # usage quotas / budget controls
        self.quota_calls: Optional[int] = (
            _env_int("PRAMAGENT_QUOTA_CALLS", -1)
            if _env("PRAMAGENT_QUOTA_CALLS") else None
        )
        self.quota_tool_validations: Optional[int] = (
            _env_int("PRAMAGENT_QUOTA_TOOL_VALIDATIONS", -1)
            if _env("PRAMAGENT_QUOTA_TOOL_VALIDATIONS") else None
        )
        self.quota_cost_usd: Optional[float] = (
            _env_float("PRAMAGENT_QUOTA_COST_USD", -1.0)
            if _env("PRAMAGENT_QUOTA_COST_USD") else None
        )
        self.quota_window_s: int = _env_int("PRAMAGENT_QUOTA_WINDOW_S", 86_400)

        # ── circuit breaker ───────────────────────────────────────────────────
        self.breaker_threshold:  int   = _env_int("PRAMAGENT_BREAKER_THRESHOLD", 5)
        self.breaker_cooldown_s: float = _env_float("PRAMAGENT_BREAKER_COOLDOWN_S", 30.0)

        # ── connection pool ───────────────────────────────────────────────────
        self.pool_max_connections: int = _env_int("PRAMAGENT_POOL_MAX_CONNECTIONS", 10)

        # ── tool guard ────────────────────────────────────────────────────────
        self.chain_window: int = _env_int("PRAMAGENT_CHAIN_WINDOW", 10)

        # ── HITL ──────────────────────────────────────────────────────────────
        self.hitl_timeout_s:      float = _env_float("PRAMAGENT_HITL_TIMEOUT_S", 300.0)
        self.hitl_slack_token:    str   = _env("PRAMAGENT_HITL_SLACK_TOKEN")
        self.hitl_slack_channel:  str   = _env("PRAMAGENT_HITL_SLACK_CHANNEL")

        # ── auth / security ───────────────────────────────────────────────────
        self.api_key:      str = _env("PRAMAGENT_API_KEY")
        self.signing_key:  str = _env("PRAMAGENT_SIGNING_KEY")
        # Sentinel default is detected and warned by validate().
        self.jwt_secret:   str = _env("PRAMAGENT_JWT_SECRET", "change-me-in-production")
        self.session_ttl:  int = _env_int("PRAMAGENT_SESSION_TTL_S", 3600)

        # ── observability ─────────────────────────────────────────────────────
        self.log_level:          str = _env("PRAMAGENT_LOG_LEVEL", "info")
        self.otel_endpoint:      str = _env("PRAMAGENT_OTEL_ENDPOINT")
        self.otel_service_name:  str = _env("PRAMAGENT_OTEL_SERVICE_NAME", "pramagent")

    def is_production(self) -> bool:
        """True when critical secrets are set (not defaults).

        Includes the audit signing key (finding 2.1): without it the audit
        chain is unkeyed SHA-256 and not tamper-evident against a writer, so a
        deployment missing it is not a production-grade posture."""
        return (
            bool(self.api_key)
            and self.jwt_secret != "change-me-in-production"  # nosec B105
            and bool(self.signing_key)
        )

    def validate(self) -> list[str]:
        """Return list of configuration warnings. Empty = all good."""
        from .security import WEAK_SECRET_DENYLIST

        warnings = []
        if not self.api_key:
            warnings.append("PRAMAGENT_API_KEY is not set — API is unauthenticated")
        if self.jwt_secret.lower() in WEAK_SECRET_DENYLIST:
            warnings.append("PRAMAGENT_JWT_SECRET is using a published default value — insecure in production")
        if not self.signing_key:
            warnings.append(
                "PRAMAGENT_SIGNING_KEY is not set — the audit chain is unkeyed "
                "SHA-256 and NOT tamper-evident (forgeable by anyone with DB "
                "write access; detects accidental corruption only). "
                "build_default_armor() refuses a persistent store without it "
                "unless PRAMAGENT_ALLOW_UNSIGNED_AUDIT=1.")
        if not self.redis_url.startswith("redis"):
            warnings.append("PRAMAGENT_REDIS_URL does not look like a Redis URL")
        if not self.postgres_dsn and not self.db_path and not self.allow_memory_store:
            warnings.append(
                "no persistent store configured — set PRAMAGENT_POSTGRES_DSN or "
                "PRAMAGENT_DB (or PRAMAGENT_ALLOW_MEMORY_STORE=1 for dev only)")
        return warnings

    def redis_backend(self):
        """Construct a RedisBackend from current settings. Returns None if URL empty."""
        if not self.redis_url:
            return None
        try:
            from .backends.redis_backend import RedisBackend
            return RedisBackend.from_url(
                self.redis_url,
                max_connections=self.pool_max_connections,
                breaker_threshold=self.breaker_threshold,
                breaker_cooldown_s=self.breaker_cooldown_s,
            )
        except Exception:
            return None

    def postgres_store(self):
        """Construct a PostgresStore from current settings. Returns None if DSN empty.

        C2/HIGH-2: the signing and encryption keys are resolved through the
        same secret-manager indirection layer build_default_armor() uses
        (resolve_secret), and wired into the store. Previously this path
        built the store with neither, so following the documented `init`
        template silently yielded an unencrypted store whose audit chain the
        API-signed entries could not be verified against."""
        if not self.postgres_dsn:
            return None
        try:
            from .secrets import resolve_secret, resolve_signing_key_ring
            from .store_postgres import PostgresStore
            # Finding 7.1/7.2: honor the PRAMAGENT_SIGNING_KEYS rotation ring
            # (falls back to the single PRAMAGENT_SIGNING_KEY) so this path
            # matches build_default_armor()/_store_from_env().
            key_cfg = resolve_signing_key_ring()
            encryption_key = resolve_secret("PRAMAGENT_ENCRYPTION_KEY").strip()
            return PostgresStore.from_dsn(
                self.postgres_dsn,
                max_pool_size=self.pool_max_connections,
                breaker_threshold=self.breaker_threshold,
                breaker_cooldown_s=self.breaker_cooldown_s,
                encryption_key=encryption_key or None,
                **key_cfg,
            )
        except Exception:
            return None

    def __repr__(self) -> str:
        safe_redis = self.redis_url.split("@")[-1] if "@" in self.redis_url else self.redis_url
        return (
            f"Settings(redis={safe_redis!r}, "
            f"max_input={self.max_input_bytes}, "
            f"rate_limit={self.rate_limit_capacity}/{self.rate_limit_refill}tok/s, "
            f"production={self.is_production()})"
        )


# ── module-level singleton ────────────────────────────────────────────────────
settings = Settings()
