"""
pramagent.api.app
=================
A thin FastAPI sidecar that exposes the Pramagent pipeline over HTTP. This is
what turns Pramagent from a Python library into a deployable service: any agent,
in any language, can wrap its LLM calls in the full trust stack by calling these
endpoints — no need to embed the library.

Run it:
    pip install -e ".[api]"
    uvicorn pramagent.api.app:app --reload --port 8000
    # or:  python -m pramagent.api.app

Then:
    curl -s localhost:8000/v1/run -H 'content-type: application/json' \\
         -d '{"prompt":"Summarize the notes","tenant_id":"acme","session_id":"s1"}'

Endpoints
    GET  /health                         liveness
    GET  /health/ready                   readiness + audit-chain validity
    POST /v1/run                         run one agent call through the stack
    GET  /v1/trace/{call_id}             fetch the full immutable trace
    GET  /v1/audit/verify                verify the tamper-evident hash chain
    GET  /v1/metrics                     observability snapshot
    POST /v1/rca/{call_id}/replay        deterministic decision replay
    POST /v1/rca/{call_id}/counterfactual  "what if rule X had not fired?"
    GET  /v1/rca/{call_id}/incident      human-readable incident report
    GET  /v1/usage                       tenant quota snapshot
    GET  /v1/usage/ledger                tenant usage ledger evidence
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import secrets
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs
from typing import Optional

from fastapi import Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

log = logging.getLogger("pramagent.api")

from ..auth import APIKeyRegistry, JWTManager, load_registry_from_env
from ..classifier import (build_classifier, build_safety_classifier,
                         get_shared_classifier, get_shared_safety_classifier)
from ..core import Pramagent
from ..layers import IsolationLayer
from ..hitl.slack import (SlackApprovalError, SlackHITLApprover,
                          slack_decision_response, verify_slack_signature)
from ..layers import (ComplianceLayer, HITLLayer, ReliabilityLayer, Rule,
                      SafetyLayer, ToolGuardLayer, ToolPolicy)
from ..layers.llm_judge import OutputJudgeLayer
from ..providers import (AnthropicProvider, GeminiProvider, MockProvider,
                         NvidiaProvider, OllamaProvider, OpenAICompatibleProvider,
                         OpenAIProvider)
from ..ratelimit import TokenBucket
from ..rca import RCAEngine
from ..store import MemoryStore, SQLiteStore
from ..telemetry import configure_otel
from ..types import Verdict
from ..usage import UsageTracker


# ──────────────────────────── request / response ───────────────────────────
class RunRequest(BaseModel):
    # max_length rejects oversized bodies with 422 BEFORE they are handed to
    # the pipeline — the 64 KiB isolation cap runs after FastAPI has already
    # parsed the JSON into memory, so it cannot defend the parse itself
    # (P2-4/T1-8). Pair with a reverse-proxy body cap (see DEPLOYMENT.md).
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=262_144,
        description="The input to run through the trust stack",
    )
    tenant_id: Optional[str] = Field(
        None,
        description="Tenant id. IGNORED when API-key auth is enabled — the tenant"
                    " is derived from the key. Used only when running unauthenticated.",
    )
    session_id: str = "default"
    action: str = Field("respond", description="Action label; consequential ones gate on HITL")


class RunResponse(BaseModel):
    call_id: str
    output: str
    blocked: bool
    block_reason: str
    hitl: str
    pre_verdict: Optional[str]
    post_verdict: Optional[str]
    pii_redactions: list[str]
    provider: str
    provider_model: str
    used_fallback: bool
    this_hash: str
    prev_hash: str
    total_latency_ms: float


class CounterfactualRequest(BaseModel):
    disable_rule: str = Field(..., description="rule_id to disable in the recomputation")


class ToolValidateRequest(BaseModel):
    tool_name: str
    arguments: dict
    tenant_id: Optional[str] = Field(
        None,
        description="Ignored when API-key/JWT auth is enabled.",
    )
    session_id: str = "default"
    action: str = "tool_call"


class ToolValidateResponse(BaseModel):
    decision_id: str
    tool_name: str
    verdict: str
    reason: str
    side_effect: str
    tenant_id: str
    session_id: str
    action_label: str


class HITLDecideRequest(BaseModel):
    approved: bool = Field(False, description="True to approve the pending action")


class TokenRequest(BaseModel):
    api_key: str = Field(..., description="Bootstrap API key")
    ttl_s: int = Field(900, ge=60, le=3600, description="JWT lifetime in seconds")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    tenant_id: str


# Typed response models for the stable surfaces (P2-10): shape changes can
# no longer ship silently, and the OpenAPI schema documents real fields.

class RuleResultModel(BaseModel):
    rule_id: str
    fired: bool
    action: str
    detail: str = ""
    phase: str = "pre"


class LayerEventModel(BaseModel):
    layer: str
    decision: str
    detail: str = ""
    latency_ms: float = 0.0
    data: dict = Field(default_factory=dict)


class TraceModel(BaseModel):
    """Mirror of pramagent.types.TraceEvent for the API surface."""
    call_id: str
    tenant_id: str
    session_id: str
    created_at: float
    input_text: str
    input_hash: str
    output_text: str
    pii_redactions: list[str]
    pre_verdict: Optional[str]
    post_verdict: Optional[str]
    rules_evaluated: list[RuleResultModel]
    provider: str
    provider_model: str
    provider_cost_usd: float
    provider_latency_ms: float
    provider_prompt_tokens: int
    provider_completion_tokens: int
    used_fallback: bool
    hitl_status: str
    layer_events: list[LayerEventModel]
    total_latency_ms: float
    prev_hash: str
    this_hash: str
    anchor_tx_id: str
    anchor_block_number: int
    anchor_metadata: dict


class EraseResponse(BaseModel):
    deleted: int
    tenant_id: str


class PruneResponse(BaseModel):
    pruned: int
    older_than_days: int
    tenant_id: str


# ─────────────────────────── default configuration ─────────────────────────
NVIDIA_DEMO_MODELS: dict[str, str] = {
    "mistralai/mistral-small-4-119b-2603": "Mistral Small 4",
    "meta/llama-3.3-70b-instruct": "Llama 3.3 70B",
    "nvidia/llama-3.3-nemotron-super-49b-v1": "Nemotron Super 49B",
    "nvidia/llama-3.3-nemotron-super-49b-v1.5": "Nemotron Super 49B v1.5",
    "nvidia/llama-3.1-nemotron-nano-8b-v1": "Nemotron Nano 8B",
}
DEFAULT_NVIDIA_DEMO_MODEL = "mistralai/mistral-small-4-119b-2603"


def _demo_enabled() -> bool:
    return os.environ.get("PRAMAGENT_DEMO_ENABLED", "").lower() in {
        "1", "true", "yes", "on"
    }


def _demo_classifier_keyword_only() -> bool:
    """Demo classifier mode via PRAMAGENT_DEMO_CLASSIFIER: keyword|embedding.

    Default "keyword" uses the zero-dependency path. Set "embedding" only when
    pramagent[ml] is installed and the deployment accepts the model-load cost.
    The classifier is process-cached, so the model loads at most once even
    though the demo builds a fresh pipeline per request."""
    return os.environ.get("PRAMAGENT_DEMO_CLASSIFIER", "keyword").strip().lower() != "embedding"


def _as_bool(value, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def build_default_armor() -> Pramagent:
    """Build from env. Store priority: PRAMAGENT_POSTGRES_DSN > PRAMAGENT_DB >
    explicit opt-in volatile memory (PRAMAGENT_ALLOW_MEMORY_STORE=1).

    Refuses to start without one of the three so the reference deployment can
    never silently boot on a MemoryStore that loses every trace on restart
    (P0-1 / T1-12)."""
    dsn = os.environ.get("PRAMAGENT_POSTGRES_DSN", "").strip()
    db_path = os.environ.get("PRAMAGENT_DB", "").strip()
    if dsn:
        from ..store_postgres import PostgresStore
        db = PostgresStore.from_dsn(dsn)
        store, audit = db, db          # single object handles both
    elif db_path:
        db = SQLiteStore(db_path)
        store, audit = db, db          # single object handles both
    elif os.environ.get("PRAMAGENT_ALLOW_MEMORY_STORE", "").lower() in {"1", "true"}:
        store, audit = None, None       # Pramagent defaults to MemoryStore + HashChainBackend
    else:
        raise RuntimeError(
            "no persistent store configured: set PRAMAGENT_POSTGRES_DSN or "
            "PRAMAGENT_DB, or opt into volatile storage with "
            "PRAMAGENT_ALLOW_MEMORY_STORE=1 (dev only)"
        )

    slack_approver = build_slack_approver_from_env()
    hitl_timeout = float(os.environ.get("PRAMAGENT_HITL_TIMEOUT_S", "2.0"))

    provider_name = os.environ.get("PRAMAGENT_PROVIDER", "mock").lower()
    if provider_name == "anthropic":
        provider = AnthropicProvider(
            model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
            max_tokens=int(os.environ.get("ANTHROPIC_MAX_TOKENS", "1024")),
        )
    elif provider_name == "openai":
        provider = OpenAIProvider(
            model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
            base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            max_tokens=int(os.environ.get("OPENAI_MAX_TOKENS", "1024")),
        )
    elif provider_name in {"nvidia", "nim"}:
        provider = NvidiaProvider(
            model=os.environ.get("NVIDIA_MODEL", "meta/llama-3.3-70b-instruct"),
            api_key=os.environ.get("NVIDIA_API_KEY", ""),
            max_tokens=int(os.environ.get("NVIDIA_MAX_TOKENS", "1024")),
        )
    elif provider_name in {"openai-compatible", "local", "vllm", "lmstudio"}:
        provider = OpenAICompatibleProvider(
            model=os.environ.get("OPENAI_COMPAT_MODEL", os.environ.get("LOCAL_MODEL", "local-model")),
            base_url=os.environ.get("OPENAI_COMPAT_BASE_URL", os.environ.get("LOCAL_LLM_BASE_URL", "http://localhost:8001/v1")),
            api_key=os.environ.get("OPENAI_COMPAT_API_KEY", os.environ.get("LOCAL_LLM_API_KEY", "")) or None,
            max_tokens=int(os.environ.get("OPENAI_COMPAT_MAX_TOKENS", "1024")),
        )
    elif provider_name == "gemini":
        provider = GeminiProvider(
            model=os.environ.get("GEMINI_MODEL", "gemini-1.5-flash"),
            max_tokens=int(os.environ.get("GEMINI_MAX_TOKENS", "1024")),
        )
    elif provider_name == "ollama":
        provider = OllamaProvider(
            model=os.environ.get("OLLAMA_MODEL", "llama3.2:1b"),
            host=os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
        )
    else:
        provider = MockProvider(model="api-demo")

    # Default prompt-injection defense: embedding classifier when
    # sentence-transformers is installed, else graceful keyword fallback.
    # Wired into BOTH IsolationLayer (input scoping) and SafetyLayer (verdicts).
    # Shared (cached) classifiers. Default is the zero-dependency keyword path;
    # PRAMAGENT_CLASSIFIER=embedding opts into sentence-transformers when
    # pramagent[ml] is installed.
    kw_only = os.environ.get("PRAMAGENT_CLASSIFIER", "keyword").lower() != "embedding"
    iso_clf = get_shared_classifier(force_keyword_only=kw_only)
    safety_clf = get_shared_safety_classifier(force_keyword_only=kw_only)

    # Optional LLM-as-judge on the model OUTPUT, reusing the configured
    # provider. Off by default (it adds a second model call per request);
    # PRAMAGENT_OUTPUT_JUDGE=1 enables it. Fail-closed on judge error/timeout.
    output_judge = None
    if os.environ.get("PRAMAGENT_OUTPUT_JUDGE", "").lower() in {"1", "true", "yes", "on"}:
        output_judge = OutputJudgeLayer(
            provider=provider,
            timeout_s=float(os.environ.get("PRAMAGENT_OUTPUT_JUDGE_TIMEOUT_S", "15.0")),
            withhold_on_error=True,
        )

    return Pramagent(
        provider=provider,
        isolation=IsolationLayer(classifier=iso_clf, block_on_injection=True),
        compliance=ComplianceLayer(standards=["HIPAA", "PCI_DSS", "GDPR"]),
        safety=SafetyLayer(rules=[
            Rule("block_account_dump", Verdict.BLOCK, pattern=r"dump .*accounts?"),
            Rule(
                "block_destructive_database_operation",
                Verdict.BLOCK,
                pattern=(
                    r"\b(drop|delete|wipe|truncate|erase|destroy)\b"
                    r"[\s\S]{0,120}\b(database|schema|db|tables?)\b|"
                    r"\b(database|schema|db|tables?)\b[\s\S]{0,120}"
                    r"\b(drop|delete|wipe|truncate|erase|destroy)\b"
                ),
                detail="destructive database operation is blocked",
            ),
            Rule("escalate_transfer", Verdict.ESCALATE, pattern=r"transfer \$?\d+"),
            Rule(
                "escalate_ambiguous_payment",
                Verdict.ESCALATE,
                pattern=(
                    r"\b(transfer|wire|send|move)\s+(?:some\s+)?funds\b|"
                    r"\b(process|approve|initiate|authorize)\s+(?:a\s+)?payment\b"
                ),
                detail="ambiguous payment action requires human approval",
            ),
            Rule(
                "escalate_broad_account_access",
                Verdict.ESCALATE,
                pattern=(
                    r"\b(retrieve|pull|export|review|access)\b[\s\S]{0,80}"
                    r"\b(account|user|customer)\s+(information|data|records?)\b"
                    r"[\s\S]{0,100}\b(broad|quarterly\s+audit|compliance\s+team|audit)\b"
                ),
                detail="broad account-data access requires human approval",
            ),
            Rule(
                "escalate_production_credentials",
                Verdict.ESCALATE,
                pattern=(
                    r"\b(make|apply|perform)\s+(?:some\s+)?changes?\b[\s\S]{0,80}"
                    r"\b(production\s+)?(access\s+)?(credentials?|api\s+keys?|secrets?)\b|"
                    r"\b(semi-authori[sz]ed|probably\s+okay)\b[\s\S]{0,120}"
                    r"\b(production\s+)?(access\s+)?(credentials?|api\s+keys?|secrets?)\b"
                ),
                detail="uncertain production-credential changes require human approval",
            ),
        ], classifier=safety_clf),
        reliability=ReliabilityLayer(max_concurrent=20, timeout_s=15.0),
        hitl=HITLLayer(
            require_approval_for=["wire_transfer", "delete_data"],
            timeout_s=hitl_timeout,
            approver=slack_approver,
        ),
        # The reference deployment enforces input escalations: the
        # escalate_transfer rule above is ESCALATE, so a "transfer $N" prompt
        # is held for human approval before the model runs. With no approver
        # configured (no Slack), propose() idles and the call is not executed —
        # fail-safe. Output escalations stay "log" (record only). Deployments
        # that want a different posture pass their own escalate_policy.
        escalate_policy={"pre": "hitl"},
        output_judge=output_judge,
        audit=audit,
        store=store,
    )


def build_slack_approver_from_env() -> Optional[SlackHITLApprover]:
    """Return a Slack approver only when all required Slack env vars are set."""
    token = os.environ.get("SLACK_BOT_TOKEN")
    channel = os.environ.get("SLACK_CHANNEL_ID")
    secret = os.environ.get("SLACK_SIGNING_SECRET")
    public_url = os.environ.get("PRAMAGENT_PUBLIC_URL")
    if not all([token, channel, secret, public_url]):
        return None
    return SlackHITLApprover(
        bot_token=token,
        channel_id=channel,
        signing_secret=secret,
        public_url=public_url,
    )


def build_tool_guard_backend_from_env():
    """Use Redis for ToolGuard distributed history when configured."""
    url = (
        os.environ.get("PRAMAGENT_TOOL_GUARD_REDIS_URL")
        or os.environ.get("PRAMAGENT_REDIS_URL")
        or ""
    ).strip()
    if not url:
        return None
    try:
        from ..backends import RedisBackend
        return RedisBackend.from_url(
            url,
            max_connections=int(os.environ.get("PRAMAGENT_REDIS_MAX_CONNECTIONS", "10")),
            breaker_threshold=int(os.environ.get("PRAMAGENT_BACKEND_BREAKER_THRESHOLD", "5")),
            breaker_cooldown_s=float(os.environ.get("PRAMAGENT_BACKEND_BREAKER_COOLDOWN_S", "30")),
        )
    except Exception as exc:
        log.warning("ToolGuard Redis backend unavailable; using local history: %s", exc)
        return None


def build_default_tool_guard(backend=None) -> ToolGuardLayer:
    """Demo-safe policies. Real deployments should register their own tools."""
    return ToolGuardLayer(policies=[
        ToolPolicy(
            name="read_record",
            side_effect="read",
            action=Verdict.ALLOW,
            schema={
                "type": "object",
                "required": ["record_id"],
                "additionalProperties": False,
                "properties": {
                    "record_id": {"type": "string", "maxLength": 128},
                },
            },
            detail="read-only lookup allowed",
        ),
        ToolPolicy(
            name="wire_transfer",
            side_effect="payment",
            action=Verdict.ESCALATE,
            allowed_actions={"wire_transfer"},
            schema={
                "type": "object",
                "required": ["amount_usd", "destination_account"],
                "additionalProperties": False,
                "properties": {
                    "amount_usd": {"type": "number", "minimum": 0.01, "maximum": 10000},
                    "destination_account": {
                        "type": "string",
                        "pattern": r"acct[-_ ][0-9]{6,18}",
                    },
                },
            },
            detail="payment tools require human approval",
        ),
    ], backend=backend, chain_ttl_s=int(os.environ.get("PRAMAGENT_TOOL_GUARD_TTL_S", "300")))


# ───────────────────────────────── app factory ─────────────────────────────
def create_app(armor: Optional[Pramagent] = None,
               registry: Optional[APIKeyRegistry] = None,
               tool_guard: Optional[ToolGuardLayer] = None,
               usage_tracker: Optional[UsageTracker] = None):
    """Build the FastAPI app.

    Auth behavior:
      * If `registry` is non-empty (or PRAMAGENT_API_KEYS env var is set),
        every /v1 endpoint requires `Authorization: Bearer <key>`. The tenant
        is taken from the key — request bodies that assert a different tenant
        are rejected.
      * If the registry is empty, the API runs unauthenticated and the tenant
        is read from the request body (single-tenant or trusted-network mode).
    """
    from contextlib import asynccontextmanager

    from fastapi import Depends, FastAPI, Header, HTTPException

    @asynccontextmanager
    async def _lifespan(app_):
        # lifespan context manager replaces the deprecated on_event hooks
        # (P3-3); shutdown closes the stores so SQLite WAL checkpoints and
        # Postgres connections are released cleanly on SIGTERM (P2-15).
        yield
        log.info("shutdown: closing stores")
        armor_obj = app_.state.armor
        for obj in {id(armor_obj.store): armor_obj.store,
                    id(armor_obj.audit): armor_obj.audit}.values():
            close = getattr(obj, "close", None)
            if close:
                try:
                    close()
                except Exception:
                    log.warning("store close failed", exc_info=True)

    app = FastAPI(
        title="Pramagent",
        version="0.8.1",
        description="Trust middleware for AI agents: deterministic guardrails, HITL, tool policy, tamper-evident traces.",
        lifespan=_lifespan,
    )
    if os.environ.get("PRAMAGENT_OTEL_ENDPOINT") or os.environ.get("PRAMAGENT_OTEL_CONSOLE") == "1":
        configure_otel(
            service_name=os.environ.get("PRAMAGENT_OTEL_SERVICE_NAME", "pramagent-api"),
            endpoint=os.environ.get("PRAMAGENT_OTEL_ENDPOINT") or None,
        )

    def _demo_cors_headers() -> dict[str, str]:
        return {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Max-Age": "600",
        }

    # ── CORS ──────────────────────────────────────────────────────────────
    allowed_origins = [
        o.strip()
        for o in os.environ.get("PRAMAGENT_CORS_ORIGINS", "").split(",")
        if o.strip()
    ]
    if "*" in allowed_origins:
        log.warning("PRAMAGENT_CORS_ORIGINS contains '*'; use explicit origins outside local development")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials="*" not in allowed_origins,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-Id"],
        expose_headers=["X-Request-Id", "Retry-After"],
    )

    # ── Security headers + structured request logging ─────────────────────
    @app.middleware("http")
    async def security_and_logging(request: Request, call_next):
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        t0 = time.perf_counter()
        if (
            request.method == "OPTIONS"
            and request.url.path == "/demo/run"
            and _demo_enabled()
        ):
            response = Response(status_code=204, headers=_demo_cors_headers())
            response.headers["X-Request-Id"] = request_id
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Cache-Control"] = "no-store"
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
            return response
        try:
            response: Response = await call_next(request)
        except Exception as exc:
            log.error("unhandled exception request_id=%s path=%s error=%r",
                      request_id, request.url.path, exc)
            raise
        latency_ms = (time.perf_counter() - t0) * 1000
        log.info(
            "request_id=%s method=%s path=%s status=%s latency_ms=%.1f",
            request_id, request.method, request.url.path,
            response.status_code, latency_ms,
        )
        # Security headers
        response.headers["X-Request-Id"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains"
            )
        return response

    app.state.armor = armor or build_default_armor()
    # Optional: eagerly load the shared embedding classifier at startup so the
    # first request does not pay the model-load cost. Off by default because the
    # model may need a network fetch on a cold image.
    if os.environ.get("PRAMAGENT_WARM_CLASSIFIER", "").lower() in {"1", "true", "yes", "on"}:
        from ..classifier import warm_shared_classifiers
        warm_shared_classifiers(
            force_keyword_only=os.environ.get("PRAMAGENT_CLASSIFIER", "keyword").lower() != "embedding")
    app.state.registry = registry if registry is not None else load_registry_from_env()
    app.state.slack_hitl = getattr(app.state.armor.hitl, "approver", None)
    app.state.tool_guard_backend = build_tool_guard_backend_from_env()
    app.state.tool_guard = tool_guard or build_default_tool_guard(
        backend=app.state.tool_guard_backend
    )
    app.state.usage = usage_tracker or UsageTracker.from_env()
    # A configured JWT secret must never be a published placeholder: the repo's
    # own .env.example values would let anyone forge tenant tokens offline
    # (P0-2 / T1-1). Unset → per-process random fallback (token issuance is
    # separately refused in that mode, see issue_token).
    jwt_secret = os.environ.get("PRAMAGENT_JWT_SECRET", "")
    if jwt_secret:
        from ..security import assert_strong_secret
        assert_strong_secret("PRAMAGENT_JWT_SECRET", jwt_secret)
    app.state.jwt = JWTManager.from_env(
        fallback_secret=jwt_secret or secrets.token_urlsafe(32)
    )
    # Rate limit: capacity tokens per key, refill rate per second.
    # Defaults: 60 requests burst, 1 req/sec sustained per tenant/IP.
    app.state.bucket = TokenBucket(
        capacity=int(os.environ.get("PRAMAGENT_RATE_BURST", "60")),
        refill_per_sec=float(os.environ.get("PRAMAGENT_RATE_PER_SEC", "1.0")),
    )
    # Tighter rate limit on expensive RCA endpoints (replay, counterfactual)
    app.state.rca_bucket = TokenBucket(
        capacity=int(os.environ.get("PRAMAGENT_RCA_RATE_BURST", "10")),
        refill_per_sec=float(os.environ.get("PRAMAGENT_RCA_RATE_PER_SEC", "0.2")),
    )
    demo_hourly_limit = max(1, int(os.environ.get("PRAMAGENT_DEMO_RATE_LIMIT", "60")))
    app.state.demo_bucket = TokenBucket(
        capacity=demo_hourly_limit,
        refill_per_sec=demo_hourly_limit / 3600.0,
    )

    # P3-1: the old `request: Request = None` annotation lied about
    # nullability. FastAPI special-cases the bare Request annotation (it is
    # not a Pydantic field, so Optional[...] is rejected) and always injects
    # the request for dependencies — the truthful signature is a required,
    # non-Optional Request with no default.
    def require_tenant(request: Request,
                       authorization: Optional[str] = Header(None)) -> str:
        """Resolve the tenant for this request and apply rate limiting.

        Rate-limit key: tenant when authenticated, client IP otherwise. This
        prevents one tenant (or one IP) from starving the others, and gives the
        unauthenticated mode a basic DoS floor."""
        if len(app.state.registry) == 0:
            tenant = ""
            rate_key = (request.client.host if request and request.client else "anon")
        else:
            if not authorization or not authorization.lower().startswith("bearer "):
                raise HTTPException(status_code=401, detail="missing bearer token")
            bearer = authorization.split(None, 1)[1].strip()
            tenant = app.state.registry.tenant_for_key(bearer)
            if tenant is None:
                tenant = app.state.jwt.tenant_for_token(bearer)
            if tenant is None:
                raise HTTPException(status_code=401, detail="invalid bearer token")
            rate_key = f"tenant:{tenant}"

        allowed, retry_after = app.state.bucket.allow(rate_key)
        if not allowed:
            raise HTTPException(
                status_code=429, detail="rate limit exceeded",
                headers={"Retry-After": str(int(retry_after) + 1)})
        return tenant

    def _fetch_trace(call_id: str, tenant: str):
        """Fetch a trace, enforcing tenant ownership when auth is enabled."""
        tenant_filter = tenant if tenant else None
        try:
            return app.state.armor.store.get(call_id, tenant_id=tenant_filter)
        except KeyError:
            raise HTTPException(status_code=404, detail="trace not found")
        except PermissionError:
            # do not leak existence to other tenants — return 404 not 403
            raise HTTPException(status_code=404, detail="trace not found")

    def _trace_to_dict(trace) -> dict:
        if isinstance(trace, dict):
            data = dict(trace)
        elif hasattr(trace, "to_dict"):
            data = trace.to_dict()
        else:
            data = vars(trace)
        return _with_dashboard_status(data)

    def _with_dashboard_status(trace: dict) -> dict:
        """Derive dashboard verdict fields from immutable TraceEvent data.

        TraceEvent intentionally stores layer decisions and verdicts, while the
        live AgentResponse carries `blocked` / `block_reason`. Older stored
        traces therefore have no explicit blocked field. The dashboard should
        still render the truth by deriving it from layer events at read time.
        """
        data = dict(trace)
        events = data.get("layer_events") or []

        def event_value(event, key: str, default=""):
            if isinstance(event, dict):
                return event.get(key, default)
            return getattr(event, key, default)

        blocking_event = next(
            (
                ev for ev in events
                if str(event_value(ev, "decision")).lower() in {"block", "blocked"}
            ),
            None,
        )
        derived_blocked = (
            blocking_event is not None
            or data.get("pre_verdict") == "block"
            or data.get("post_verdict") == "block"
        )
        if data.get("blocked") is None:
            data["blocked"] = bool(derived_blocked)
        if data.get("blocked") and not data.get("block_reason"):
            if blocking_event is not None:
                detail = str(event_value(blocking_event, "detail", "") or "").strip()
                layer = str(event_value(blocking_event, "layer", "") or "layer").strip()
                data["block_reason"] = detail or f"{layer} blocked the request"
            elif data.get("pre_verdict") == "block":
                data["block_reason"] = "blocked by input safety rule"
            elif data.get("post_verdict") == "block":
                data["block_reason"] = "blocked by output safety rule"
        return data

    def _fetch_trace_for_dashboard(trace_id: str, tenant: str):
        """Fetch by call_id, with this_hash fallback for copied dashboard URLs."""
        try:
            return _fetch_trace(trace_id, tenant)
        except HTTPException as exc:
            if exc.status_code != 404:
                raise

        store = app.state.armor.store
        tenant_filter = tenant if tenant else ""
        if tenant_filter and hasattr(store, "list_by_tenant"):
            traces = store.list_by_tenant(tenant_filter, None, 500)
        else:
            traces = store.list_all(500)
        for trace in traces:
            data = _trace_to_dict(trace)
            if data.get("this_hash") == trace_id:
                if tenant and data.get("tenant_id") != tenant:
                    break
                return trace
        raise HTTPException(status_code=404, detail="trace not found")

    def _raise_quota(decision):
        retry_after = int(decision.retry_after_s) + 1 if decision.retry_after_s else 1
        raise HTTPException(
            status_code=429,
            detail=decision.reason or "tenant usage quota exceeded",
            headers={"Retry-After": str(retry_after)},
        )

    def _usage_ledger_limit(limit: int) -> int:
        return max(1, min(int(limit), 500))

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    async def root():
        if _demo_enabled():
            return RedirectResponse(url="/demo", status_code=307)
        return {
            "service": "pramagent",
            "status": "ok",
            "demo_enabled": False,
            "health": "/health",
            "docs": "/docs",
        }

    def _demo_not_found():
        raise HTTPException(status_code=404, detail="demo is not enabled")

    def _demo_ip(request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip() or "anon"
        return request.client.host if request.client else "anon"

    def _demo_rate_key(request: Request, api_key: str) -> str:
        # Hash the visitor key before it touches the in-memory rate bucket.
        # A new visitor key gets a fresh bucket, but plaintext keys are still
        # never logged, traced, persisted, or used as dictionary keys.
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
        return f"demo:{_demo_ip(request)}:{key_hash}"

    def _looks_like_demo_api_key(api_key: object) -> bool:
        """Cheap shape check before the demo tries a live provider call.

        This is not authentication; the upstream provider still validates the
        key. It rejects obvious placeholders and short fake ``sk-`` strings so
        bad-key tests and demos fail before a provider error can echo context.
        """
        if not isinstance(api_key, str):
            return False
        if api_key.startswith("nvapi-"):
            return len(api_key) >= 12
        if api_key.startswith("sk-proj-"):
            return len(api_key) >= 32
        if api_key.startswith("sk-"):
            suffix = api_key[3:]
            return len(suffix) >= 32 and suffix.isalnum()
        return False

    def _demo_policy(payload: dict) -> dict[str, bool]:
        raw = payload.get("policies") or {}
        if not isinstance(raw, dict):
            raw = {}
        return {
            "pii_scrubbing": _as_bool(raw.get("pii_scrubbing"), True),
            "injection_guard": _as_bool(raw.get("injection_guard"), True),
            "safety_rules": _as_bool(raw.get("safety_rules"), True),
            "hitl": _as_bool(raw.get("hitl"), False),
            # LLM-as-judge on the model OUTPUT. Catches semantic failures the
            # deterministic rules miss (working malware, bypass walkthroughs,
            # confirmed destructive actions, leaked internals). On by default —
            # it is the answer to "is the OUTPUT safe?". Costs one extra NIM
            # call per run (uses the visitor's key) and is fail-closed.
            "output_judge": _as_bool(raw.get("output_judge"), True),
        }

    def _demo_financial_intent(prompt: str, action: str) -> bool:
        import re

        if action == "wire_transfer":
            return True
        patterns = [
            r"\b(wire|transfer|send|initiate|process)\b[\s\S]{0,100}"
            r"(\$|routing\s+number|account|acct[-_ ]?\d{6,}|refund|vendor)",
            r"\b(routing\s+number|account\s+\d{6,18}|acct[-_ ]?\d{6,})\b"
            r"[\s\S]{0,100}\b(wire|transfer|send|refund|payment)\b",
            # Consequential trading actions (SEC-2026-06-15 F-4): approving a
            # margin call or ordering a liquidation moves money and must gate
            # the same way a wire does. "approve the margin call" + "proceed
            # with liquidation of positions" previously sailed through as a
            # plain response.
            r"\b(approve|authori[sz]e|confirm|execute|proceed\s+with|process)\b"
            r"[\s\S]{0,80}\b(margin\s+call|liquidat(?:e|ion|ing)|"
            r"close\s+(?:out\s+)?(?:all\s+)?(?:leveraged\s+|open\s+)?positions?|"
            r"sell\s+(?:off\s+)?(?:all\s+)?positions?)\b",
            r"\b(execute|approve|authori[sz]e|confirm|proceed|order|pre-authori[sz]ed)\b"
            r"[\s\S]{0,80}\bliquidat(?:e|ion|ing)\b[\s\S]{0,80}\b(positions?|holdings)\b",
            r"\b(?:need\s+to|must|should|please)?\s*(?:close|liquidate)\s+"
            r"(?:out\s+)?(?:all\s+)?(?:leveraged\s+|open\s+)?positions?\b"
            r"[\s\S]{0,140}\b(authori[sz]ed|proceed|confirm|immediately|risk\s+committee)\b",
            r"\bmargin\s+call\b[\s\S]{0,80}\b(approve|authori[sz]e|liquidat|proceed|sell|close)\b",
            # International / cross-border transfers (SEC-2026-06-15 F-2): an
            # IBAN or SWIFT/BIC value alongside a move verb must gate like ACH.
            # Requiring both the value and the verb keeps "how do IBAN
            # transfers work?" from being treated as an action.
            r"\b(transfer|wire|send|remit|initiate|process|pay)\b[\s\S]{0,120}"
            r"\b([A-Z]{2}\d{2}[A-Z0-9]{11,30}|SWIFT(?:\s+code)?|BIC)\b",
            r"\b([A-Z]{2}\d{2}[A-Z0-9]{11,30}|SWIFT(?:\s+code)?|BIC)\b[\s\S]{0,120}"
            r"\b(transfer|wire|send|remit|payment)\b",
        ]
        return any(re.search(pattern, prompt, re.IGNORECASE) for pattern in patterns)

    def _build_demo_armor(api_key: str, model: str, policies: dict[str, bool]) -> Pramagent:
        safety_rules = []
        post_rules = []
        safety_classifier = None
        if policies["safety_rules"]:
            safety_rules = [
                Rule(
                    "block_account_dump",
                    Verdict.BLOCK,
                    pattern=r"\b(dump|export)\b.{0,80}\b(user\s+)?accounts?\b",
                    detail="bulk account export is blocked",
                ),
                Rule(
                    "escalate_transfer",
                    Verdict.ESCALATE,
                    pattern=r"\b(transfer|wire)\b.{0,80}\$?\s*\d+",
                    detail="payment-like action requires review",
                ),
                Rule(
                    "escalate_financial_operation",
                    Verdict.ESCALATE,
                    pattern=(
                        r"\b(approve|authori[sz]e|confirm|execute|proceed\s+with|process)\b"
                        r"[\s\S]{0,80}\b(margin\s+call|liquidat(?:e|ion|ing)|"
                        r"close\s+(?:out\s+)?(?:all\s+)?(?:leveraged\s+|open\s+)?positions?|"
                        r"sell\s+(?:off\s+)?(?:all\s+)?positions?)\b|"
                        r"\b(?:close|liquidate)\s+(?:out\s+)?(?:all\s+)?"
                        r"(?:leveraged\s+|open\s+)?positions?\b"
                        r"[\s\S]{0,140}\b(authori[sz]ed|proceed|confirm|immediately|risk\s+committee)\b|"
                        r"\b(transfer|wire|send|remit|initiate|process|pay)\b"
                        r"[\s\S]{0,120}\b([A-Z]{2}\d{2}[A-Z0-9]{11,30}|"
                        r"SWIFT(?:\s+code)?|BIC)\b"
                    ),
                    detail="consequential financial action requires review",
                ),
                Rule(
                    "block_file_exfiltration_code",
                    Verdict.BLOCK,
                    pattern=(
                        r"\b(generate|write|create|build)\b[\s\S]{0,100}"
                        r"\b(python\s+)?script\b[\s\S]{0,220}"
                        r"\b(reads?|open|collects?|exfiltrat(?:e|es)|sends?|uploads?)\b"
                        r"[\s\S]{0,160}\b(all\s+files|files?\s+in\s+a\s+directory|directory)\b"
                        r"[\s\S]{0,200}\b(external\s+url|https?://|http\s+post|post)\b"
                    ),
                    detail="file exfiltration script generation is blocked",
                ),
            ]
            post_rules = [
                Rule(
                    "withhold_file_exfiltration_code",
                    Verdict.BLOCK,
                    pattern=(
                        r"\b(os\.walk|glob\.glob|rglob|Path\()\b[\s\S]{0,360}"
                        r"\b(open\(|read\(|read_bytes\(|read_text\()\b[\s\S]{0,360}"
                        r"\b(requests\.post|httpx\.post|urllib\.request|urlopen)\b"
                    ),
                    detail="provider output appears to contain file exfiltration code",
                ),
                # SEC-2026-06-15-01 (SE-2): catch a model that accepts a fake
                # emergency override and declares its own safety controls off
                # ("OVERRIDE_ACCEPTED ... Content filters disabled"). Even when
                # the input slips past the isolation heuristics, this confirmed
                # self-disabling output must never reach the caller.
                Rule(
                    "withhold_filter_override_confirmation",
                    Verdict.BLOCK,
                    pattern=(
                        r"\boverride[_\s]?(accepted|confirmed|granted|enabled)\b|"
                        r"\b(content\s+)?filters?\s+(are\s+)?(now\s+)?(disabled|off|bypassed|deactivated|lifted)\b|"
                        r"\bsafety\s+(filters?|checks?|guardrails?|controls?)\s+(are\s+)?(now\s+)?(disabled|off|bypassed)\b|"
                        r"\bunrestricted\s+mode\s+(enabled|active|activated|on)\b|"
                        r"\b(all\s+)?restrictions?\s+(are\s+)?(now\s+)?(lifted|removed|disabled|off)\b"
                    ),
                    detail="provider output confirms a fake override / disabled safety controls",
                ),
            ]
            safety_classifier = get_shared_safety_classifier(
                force_keyword_only=_demo_classifier_keyword_only())

        hitl = HITLLayer(
            require_approval_for=["wire_transfer"] if policies["hitl"] else [],
            timeout_s=3.0,
            approver=None,
        )
        tool_guard = ToolGuardLayer(policies=[
            ToolPolicy(
                name="wire_transfer",
                side_effect="payment",
                action=Verdict.ESCALATE,
                allowed_actions={"wire_transfer"},
                schema={
                    "type": "object",
                    "required": ["amount_usd", "destination_account"],
                    "additionalProperties": False,
                    "properties": {
                        "amount_usd": {
                            "type": "number",
                            "minimum": 0.01,
                            "maximum": 1_000_000,
                        },
                        "destination_account": {
                            "type": "string",
                            "pattern": r"acct[-_ ][0-9]{6,18}",
                        },
                    },
                },
                detail="demo payment tool requires human approval",
            )
        ])
        if isinstance(api_key, str) and (api_key.startswith("sk-") or api_key.startswith("sk-proj-")):
            # If the user passed an OpenAI key, route to OpenAI's default mini model
            provider = OpenAIProvider(model="gpt-4o-mini", api_key=api_key)
        else:
            provider = NvidiaProvider(model=model, api_key=api_key)

        # LLM-as-judge on the OUTPUT, using the visitor's key on the same model.
        # Fail-closed: a judge error/timeout/ambiguous verdict withholds output.
        output_judge = None
        if policies.get("output_judge"):
            output_judge = OutputJudgeLayer(
                provider=provider,
                timeout_s=20.0,
                withhold_on_error=True,
            )
        return Pramagent(
            provider=provider,
            compliance=ComplianceLayer(
                standards=["HIPAA", "PCI_DSS", "GDPR"],
                enabled=policies["pii_scrubbing"],
            ),
            isolation=IsolationLayer(
                classifier=get_shared_classifier(
                    force_keyword_only=_demo_classifier_keyword_only())
                if policies["injection_guard"] else None,
                block_on_injection=policies["injection_guard"],
            ),
            safety=SafetyLayer(
                rules=safety_rules,
                classifier=safety_classifier,
                post_rules=post_rules,
                post_classifier=None,
            ),
            reliability=ReliabilityLayer(max_concurrent=2, timeout_s=45.0),
            hitl=hitl,
            tool_guard=tool_guard,
            output_judge=output_judge,
            # Mirror the reference deployment posture: when a safety rule
            # returns ESCALATE, the action is held for human approval before
            # the model runs.  Without this, ESCALATE verdicts are only logged.
            escalate_policy={"pre": "hitl"},
        )

    @app.get("/demo", response_class=HTMLResponse)
    async def demo_page():
        if not _demo_enabled():
            _demo_not_found()
        page = Path(__file__).with_name("demo_page.html")
        return HTMLResponse(page.read_text(encoding="utf-8"))

    @app.options("/demo/run")
    async def demo_run_options():
        if not _demo_enabled():
            raise HTTPException(
                status_code=405,
                detail="demo is not enabled",
                headers={"Allow": "POST, OPTIONS"},
            )
        return Response(status_code=204, headers=_demo_cors_headers())

    @app.get("/demo/verify")
    async def demo_verify():
        if not _demo_enabled():
            _demo_not_found()
        return JSONResponse(
            {
                "chain_valid": True,
                "detail": "Each /demo/run response contains a server-verified isolated audit chain.",
            },
            headers=_demo_cors_headers(),
        )

    @app.post("/demo/run")
    async def demo_run(request: Request):
        if not _demo_enabled():
            _demo_not_found()

        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > 300_000:
                    return JSONResponse(
                        {"detail": "demo request is too large"},
                        status_code=413,
                        headers=_demo_cors_headers(),
                    )
            except ValueError:
                return JSONResponse(
                    {"detail": "invalid Content-Length"},
                    status_code=400,
                    headers=_demo_cors_headers(),
                )

        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(
                {"detail": "invalid JSON body"},
                status_code=400,
                headers=_demo_cors_headers(),
            )
        if not isinstance(payload, dict):
            return JSONResponse(
                {"detail": "invalid JSON body"},
                status_code=400,
                headers=_demo_cors_headers(),
            )

        api_key = payload.get("nvidia_api_key")
        if not _looks_like_demo_api_key(api_key):
            return JSONResponse(
                {"detail": "valid NVIDIA NIM or OpenAI API key required"},
                status_code=400,
                headers=_demo_cors_headers(),
            )

        prompt = payload.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            return JSONResponse(
                {"detail": "prompt is required"},
                status_code=400,
                headers=_demo_cors_headers(),
            )
        if len(prompt.encode("utf-8")) > 262_144:
            return JSONResponse(
                {"detail": "prompt is too large"},
                status_code=400,
                headers=_demo_cors_headers(),
            )

        model = payload.get("model") or DEFAULT_NVIDIA_DEMO_MODEL
        if model not in NVIDIA_DEMO_MODELS:
            return JSONResponse(
                {"detail": "unsupported NVIDIA model"},
                status_code=400,
                headers=_demo_cors_headers(),
            )

        allowed, retry_after = app.state.demo_bucket.allow(_demo_rate_key(request, api_key))
        if not allowed:
            return JSONResponse(
                {"detail": "demo rate limit exceeded for this IP and NVIDIA key"},
                status_code=429,
                headers={**_demo_cors_headers(), "Retry-After": str(int(retry_after) + 1)},
            )

        action = payload.get("action") if isinstance(payload.get("action"), str) else "respond"
        policies = _demo_policy(payload)
        payment_intent = _demo_financial_intent(prompt, action)
        if payment_intent and (policies["safety_rules"] or policies["hitl"]):
            action = "wire_transfer"
            policies["hitl"] = True
        armor = _build_demo_armor(api_key=api_key, model=model, policies=policies)
        session_id = f"demo-{uuid.uuid4().hex[:12]}"

        try:
            result = await armor.run(
                prompt,
                tenant_id="demo",
                session_id=session_id,
                action=action,
            )
        except Exception as exc:
            log.warning("demo run failed type=%s", type(exc).__name__)
            return JSONResponse(
                {"detail": "demo run failed"},
                status_code=502,
                headers=_demo_cors_headers(),
            )

        trace = result.trace
        output_judge_status = next(
            (event.decision for event in trace.layer_events
             if event.layer == "OutputJudgeLayer"),
            None,
        )
        provider_error_detail = next(
            (event.detail for event in trace.layer_events
             if event.layer == "ReliabilityLayer" and event.decision == "degraded"),
            None,
        )
        body = {
            "call_id": trace.call_id,
            "action": action,
            "payment_intent": payment_intent,
            "output": result.output,
            "blocked": result.blocked,
            "block_reason": result.block_reason,
            "provider_error_detail": provider_error_detail,
            "output_judge_status": output_judge_status,
            "hitl_status": trace.hitl_status,
            "pre_verdict": trace.pre_verdict,
            "post_verdict": trace.post_verdict,
            "pii_redactions": trace.pii_redactions,
            "layer_events": [
                {
                    "layer": event.layer,
                    "decision": event.decision,
                    "detail": event.detail,
                    "latency_ms": event.latency_ms,
                    "data": event.data,
                }
                for event in trace.layer_events
            ],
            "provider": trace.provider,
            "provider_model": trace.provider_model,
            "provider_latency_ms": trace.provider_latency_ms,
            "this_hash": trace.this_hash,
            "prev_hash": trace.prev_hash,
            "total_latency_ms": trace.total_latency_ms,
            "chain_valid": bool(armor.audit.verify_chain()),
        }
        return JSONResponse(body, headers=_demo_cors_headers())

    @app.post("/v1/auth/token", response_model=TokenResponse)
    async def issue_token(body: TokenRequest, request: Request):
        # This endpoint is by design unauthenticated (it bootstraps auth), so
        # it gets an IP-keyed rate bucket instead of the tenant one (T1-2).
        ip = request.client.host if request.client else "anon"
        allowed, retry_after = app.state.bucket.allow(f"token:{ip}")
        if not allowed:
            raise HTTPException(
                status_code=429, detail="rate limit exceeded",
                headers={"Retry-After": str(int(retry_after) + 1)})
        if len(app.state.registry) == 0:
            raise HTTPException(status_code=400, detail="API-key auth is not enabled")
        # Without a shared signing secret each worker would mint tokens only
        # it can verify — intermittent 401s across replicas (P2-12). Refuse
        # issuance instead of minting un-verifiable tokens.
        if not os.environ.get("PRAMAGENT_JWT_SECRET") and not os.environ.get("PRAMAGENT_JWT_SECRETS"):
            raise HTTPException(
                status_code=503,
                detail="JWT issuance requires PRAMAGENT_JWT_SECRET (or "
                       "PRAMAGENT_JWT_SECRETS) shared across workers")
        tenant = app.state.registry.tenant_for_key(body.api_key)
        if tenant is None:
            raise HTTPException(status_code=401, detail="invalid api key")
        token = app.state.jwt.issue(tenant, ttl_s=body.ttl_s)
        return TokenResponse(
            access_token=token,
            expires_in=body.ttl_s,
            tenant_id=tenant,
        )

    @app.get("/health/ready")
    async def ready():
        """O(1) readiness: dependency connectivity only.

        Never integrity-verifies the chain or counts traces — that is O(n)
        work an unauthenticated probe must not trigger (P1-3/T1-5); chain
        verification lives in /v1/audit/verify (authenticated, rate-limited).
        Operational detail (auth mode, Slack errors, counts) is not disclosed
        on this unauthenticated surface (P2-18/T1-9)."""
        a = app.state.armor
        checks: dict[str, bool] = {}
        ping = getattr(a.store, "ping", None)
        try:
            checks["store"] = bool(await asyncio.to_thread(ping)) if ping else True
        except Exception:
            checks["store"] = False
        backend = app.state.tool_guard_backend
        try:
            checks["redis"] = (bool(await asyncio.to_thread(backend.ping))
                               if backend is not None else True)
        except Exception:
            checks["redis"] = False
        ok = all(checks.values())
        return JSONResponse(
            {"status": "ready" if ok else "degraded", "checks": checks},
            status_code=200 if ok else 503)

    @app.post("/v1/run", response_model=RunResponse)
    async def run(req: RunRequest, request: Request,
                  tenant: str = Depends(require_tenant)):
        a = app.state.armor
        # When auth is on, the tenant comes from the key — ignore any body assertion.
        # When auth is off, fall back to body or "default".
        effective_tenant = tenant if tenant else (req.tenant_id or "default")
        # Quota accounting may hit Redis and fan out to the billing webhook
        # (sync urllib) — keep both off the event loop (P1-8/T1-7).
        quota_decision = await asyncio.to_thread(
            app.state.usage.reserve_call, effective_tenant)
        if not quota_decision.allowed:
            _raise_quota(quota_decision)
        r = await a.run(req.prompt, tenant_id=effective_tenant,
                        session_id=req.session_id, action=req.action,
                        trace_headers=dict(request.headers))
        t = r.trace
        await asyncio.to_thread(
            app.state.usage.record_cost, effective_tenant, t.provider_cost_usd)
        return RunResponse(
            call_id=t.call_id, output=r.output, blocked=r.blocked,
            block_reason=r.block_reason, hitl=r.hitl,
            pre_verdict=t.pre_verdict, post_verdict=t.post_verdict,
            pii_redactions=t.pii_redactions, provider=t.provider,
            provider_model=t.provider_model, used_fallback=t.used_fallback,
            this_hash=t.this_hash, prev_hash=t.prev_hash,
            total_latency_ms=t.total_latency_ms,
        )

    @app.get("/v1/trace/{call_id}", response_model=TraceModel)
    async def get_trace(call_id: str, tenant: str = Depends(require_tenant)):
        return _fetch_trace(call_id, tenant).to_dict()

    @app.get("/v1/audit/verify")
    async def verify_audit(tenant: str = Depends(require_tenant)):
        a = app.state.armor
        return {"chain_valid": a.audit.verify_chain(),
                "records": len(a.audit.records())}

    @app.get("/v1/metrics")
    async def metrics(tenant: str = Depends(require_tenant)):
        report = app.state.armor.observability.report()
        report["usage_quota_enabled"] = app.state.usage.enabled
        report["usage_event_sinks"] = len(getattr(app.state.usage, "event_sinks", []))
        return report

    @app.get("/v1/usage")
    async def usage(tenant_id: str = "",
                    tenant: str = Depends(require_tenant)):
        effective_tenant = tenant if tenant else (tenant_id or "default")
        return app.state.usage.snapshot(effective_tenant).to_dict()

    @app.get("/v1/usage/ledger")
    async def usage_ledger(tenant_id: str = "",
                           limit: int = 100,
                           tenant: str = Depends(require_tenant)):
        effective_tenant = tenant if tenant else (tenant_id or "default")
        return app.state.usage.ledger_report(
            tenant_id=effective_tenant,
            limit=_usage_ledger_limit(limit),
        )

    @app.post("/v1/tools/validate", response_model=ToolValidateResponse)
    async def validate_tool(req: ToolValidateRequest,
                            tenant: str = Depends(require_tenant)):
        effective_tenant = tenant if tenant else (req.tenant_id or "default")
        quota_decision = await asyncio.to_thread(
            app.state.usage.reserve_tool_validation, effective_tenant)
        if not quota_decision.allowed:
            _raise_quota(quota_decision)
        decision = await app.state.tool_guard.evaluate_async(
            req.tool_name,
            req.arguments,
            tenant_id=effective_tenant,
            session_id=req.session_id,
            action_label=req.action,
        )
        return ToolValidateResponse(**decision.to_dict())

    async def _handle_slack_hitl_action(request: Request):
        """Receive Slack approve/deny button callbacks.

        This endpoint is authenticated with Slack's signing secret, not a
        Pramagent tenant API key, because Slack posts callbacks directly.
        """
        approver = app.state.slack_hitl
        if not isinstance(approver, SlackHITLApprover):
            raise HTTPException(status_code=404, detail="Slack HITL is not configured")

        raw = await request.body()
        if not verify_slack_signature(
            signing_secret=approver.signing_secret,
            timestamp=request.headers.get("X-Slack-Request-Timestamp", ""),
            body=raw,
            signature=request.headers.get("X-Slack-Signature", ""),
        ):
            raise HTTPException(status_code=401, detail="invalid Slack signature")

        form = parse_qs(raw.decode("utf-8"))
        payload_raw = (form.get("payload") or [""])[0]
        try:
            payload = json.loads(payload_raw)
            found, decision = approver.handle_action_payload(payload)
        except (json.JSONDecodeError, SlackApprovalError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        await approver.update_original_message(payload, decision, found=found)
        return slack_decision_response(decision, found=found)

    @app.post("/v1/hitl/slack/action")
    async def slack_hitl_action(request: Request):
        return await _handle_slack_hitl_action(request)

    @app.post("/v1/hitl/slack/actions")
    async def slack_hitl_actions(request: Request):
        return await _handle_slack_hitl_action(request)


    # RCA is per-trace: fetch the single trace (ownership enforced by
    # _fetch_trace, 404 on cross-tenant) instead of deserializing the whole
    # store per request (P1-4/T1-6).

    @app.post("/v1/rca/{call_id}/replay")
    async def rca_replay(call_id: str, request: Request,
                         tenant: str = Depends(require_tenant)):
        _require_rca_quota(tenant or "anon", request)
        trace = _fetch_trace(call_id, tenant)
        return RCAEngine([trace]).replay(call_id)

    @app.post("/v1/rca/{call_id}/counterfactual")
    async def rca_counterfactual(call_id: str, body: CounterfactualRequest,
                                 request: Request,
                                 tenant: str = Depends(require_tenant)):
        _require_rca_quota(tenant or "anon", request)
        trace = _fetch_trace(call_id, tenant)
        return RCAEngine([trace]).counterfactual(call_id, disable_rule=body.disable_rule)

    @app.get("/v1/rca/{call_id}/incident")
    async def rca_incident(call_id: str, request: Request,
                           tenant: str = Depends(require_tenant)):
        _require_rca_quota(tenant or "anon", request)
        trace = _fetch_trace(call_id, tenant)
        return {"report": RCAEngine([trace]).incident_report(call_id)}

    @app.post("/v1/retention/prune", response_model=PruneResponse)
    async def retention_prune(older_than_days: int,
                              tenant: str = Depends(require_tenant)):
        """Prune traces older than `older_than_days`.

        Enforces the EU AI Act Article 12 floor: a retention window shorter than
        180 days is rejected (400) so audit logs are never pruned below the legal
        minimum. When auth is enabled the prune is scoped to the caller's tenant,
        so a tenant can only prune its own records.
        """
        MIN_RETENTION_DAYS = 180
        if older_than_days < MIN_RETENTION_DAYS:
            raise HTTPException(
                status_code=400,
                detail=(f"retention window of {older_than_days} days is below the "
                        f"{MIN_RETENTION_DAYS}-day minimum required for audit logs"),
            )
        # An empty tenant (auth disabled) carries no ownership, so a prune
        # would silently span every tenant. Refuse instead of widening scope.
        if not tenant:
            raise HTTPException(
                status_code=403,
                detail="retention prune requires API-key auth so it can be "
                       "scoped to the caller's tenant",
            )
        cutoff_ts = time.time() - older_than_days * 86400
        store = app.state.armor.store
        try:
            deleted = store.prune_older_than(cutoff_ts, tenant_id=tenant)
        except TypeError:
            # store predates tenant-scoped prune — refusing is safer than
            # falling back to an unscoped, cross-tenant prune
            raise HTTPException(
                status_code=501,
                detail="store does not support tenant-scoped pruning",
            )
        return {"pruned": deleted, "older_than_days": older_than_days,
                "tenant_id": tenant}

    @app.delete("/v1/tenant/{tenant_id}/traces", response_model=EraseResponse)
    async def erase_tenant_traces(tenant_id: str,
                                  tenant: str = Depends(require_tenant)):
        """GDPR right-to-erasure: delete all traces for `tenant_id`.

        A tenant may only erase its OWN data: erasure requires an authenticated
        tenant, and that tenant must match the path. An empty resolved tenant
        (auth disabled) carries no ownership, so the call is refused rather
        than allowing any caller to erase any tenant's data.
        """
        if not tenant:
            raise HTTPException(
                status_code=403,
                detail="erasure requires API-key auth so ownership of the "
                       "target tenant can be verified",
            )
        if tenant != tenant_id:
            raise HTTPException(
                status_code=403,
                detail="a tenant may only erase its own data",
            )
        deleted = app.state.armor.store.delete_for_tenant(tenant_id)
        # When the audit backend is a separate object (default MemoryStore +
        # HashChainBackend), tombstone the tenant's chain payloads too.
        # SQLiteStore is its own audit backend and redacts inside
        # delete_for_tenant; redact_for_tenant is idempotent either way.
        audit = app.state.armor.audit
        if audit is not app.state.armor.store and hasattr(audit, "redact_for_tenant"):
            audit.redact_for_tenant(tenant_id)
        return {"deleted": deleted, "tenant_id": tenant_id}

    # ── dashboard-friendly routes (unversioned prefix, used by admin UI) ─────
    # These mirror the /v1 data surface for the dashboard. They carry the SAME
    # auth dependency as /v1 — the dashboard authenticates with its upstream
    # API key. When auth is enabled, every route is scoped to the caller's
    # tenant so the dashboard key cannot read or decide across tenants.

    @app.get("/metrics")
    async def metrics_unversioned(tenant: str = Depends(require_tenant)):
        """Dashboard-friendly metrics endpoint (same auth as /v1/metrics)."""
        report = app.state.armor.observability.report()
        report["usage_quota_enabled"] = app.state.usage.enabled
        report["usage_event_sinks"] = len(getattr(app.state.usage, "event_sinks", []))
        return report

    @app.get("/usage")
    async def usage_unversioned(tenant_id: str = "default",
                                tenant: str = Depends(require_tenant)):
        effective_tenant = tenant if tenant else (tenant_id or "default")
        return app.state.usage.snapshot(effective_tenant).to_dict()

    @app.get("/usage/ledger")
    async def usage_ledger_unversioned(tenant_id: str = "", limit: int = 100,
                                       tenant: str = Depends(require_tenant)):
        effective_tenant = tenant if tenant else tenant_id
        return app.state.usage.ledger_report(
            tenant_id=effective_tenant,
            limit=_usage_ledger_limit(limit),
        )

    @app.get("/traces")
    async def traces_list(
        tenant_id: str = "",
        session_id: str = "",
        blocked: str = "",
        limit: int = Query(50, ge=1, le=500),
        tenant: str = Depends(require_tenant),
    ):
        """Return recent traces. Dashboard uses this for the trace browser.

        When auth is enabled the listing is hard-scoped to the caller's tenant
        — the tenant_id query parameter cannot widen it. The tenant filter is
        pushed into SQL (idx_traces_tenant) so a busy neighbor tenant can
        never crowd a caller's rows out of the page (P1-9)."""
        if tenant:
            tenant_id = tenant

        store = app.state.armor.store
        if tenant_id and hasattr(store, "list_by_tenant"):
            items = await asyncio.to_thread(
                store.list_by_tenant, tenant_id, session_id or None, limit)
        else:
            items = await asyncio.to_thread(store.list_all, limit)
        items = [_trace_to_dict(t) for t in items]
        # filters (post-filter keeps stores without list_by_tenant correct)
        if tenant_id:
            items = [t for t in items if t.get("tenant_id") == tenant_id]
        if session_id:
            items = [t for t in items if t.get("session_id") == session_id]
        if blocked == "true":
            items = [t for t in items if t.get("blocked")]
        elif blocked == "false":
            items = [t for t in items if not t.get("blocked")]
        return items[-limit:]

    @app.get("/traces/{trace_id}")
    async def trace_detail_unversioned(trace_id: str,
                                       tenant: str = Depends(require_tenant)):
        result = _fetch_trace_for_dashboard(trace_id, tenant)
        if result is None:
            raise HTTPException(status_code=404, detail="trace not found")
        return _trace_to_dict(result)

    def _pending_approvals(hitl) -> list[dict]:
        pending = []
        seen = set()

        registry = getattr(hitl, "registry", None) or getattr(
            getattr(hitl, "approver", None), "registry", None)
        registry_pending = getattr(registry, "_pending", {}) if registry is not None else {}
        for request_id, request in registry_pending.items():
            context = dict(getattr(request, "context", {}) or {})
            tenant_id = context.get("tenant_id") or context.get("tenant") or ""
            pending.append({
                "request_id": request_id,
                "action": getattr(request, "action", ""),
                "tenant_id": tenant_id,
                "context": context,
                "created_at": getattr(request, "created_at", None),
            })
            seen.add(request_id)

        if hasattr(hitl, "_pending"):
            for request_id, action in hitl._pending.items():
                if request_id in seen:
                    continue
                pending.append({
                    "request_id": request_id,
                    "action": action,
                    "tenant_id": "",
                    "context": {},
                })
        return pending

    @app.get("/hitl/pending")
    async def hitl_pending(tenant: str = Depends(require_tenant)):
        pending = _pending_approvals(app.state.armor.hitl)
        if tenant:
            pending = [p for p in pending if p["tenant_id"] == tenant]
        return {"items": pending}

    @app.post("/hitl/{request_id}/decide")
    async def hitl_decide(request_id: str, body: HITLDecideRequest,
                          tenant: str = Depends(require_tenant)):
        hitl = app.state.armor.hitl
        registry = getattr(hitl, "registry", None) or getattr(
            getattr(hitl, "approver", None), "registry", None)
        if registry is None:
            raise HTTPException(status_code=404, detail="approval request not found")
        if tenant:
            # Tenant ownership: a tenant may only decide its own pending
            # approvals. Unknown / cross-tenant ids both return 404 so the
            # response does not leak which request ids exist.
            match = next(
                (p for p in _pending_approvals(hitl)
                 if p["request_id"] == request_id), None)
            if match is None or match["tenant_id"] != tenant:
                raise HTTPException(status_code=404, detail="approval request not found")
        registry.decide(request_id, body.approved)
        return {"request_id": request_id,
                "decision": "approved" if body.approved else "denied"}

    def _require_rca_quota(tenant: str, request: Request) -> None:
        allowed, retry_after = request.app.state.rca_bucket.allow(tenant)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=f"RCA rate limit exceeded; retry after {retry_after:.1f}s",
                headers={"Retry-After": str(int(retry_after) + 1)},
            )

    return app


# Preferred: factory pattern, which defers env parsing and classifier builds
# to server start instead of module import (P3-2):
#     uvicorn pramagent.api.app:create_app --factory
# The module-level `app` is kept for back-compat (uvicorn pramagent.api.app:app)
# behind an opt-out switch.
if os.environ.get("PRAMAGENT_EAGER_APP", "1") == "1":
    app = create_app()
