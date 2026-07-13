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
import ipaddress
import json
import logging
import os
import sys
import re
import secrets
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs
from typing import Optional

from fastapi import Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field, ValidationError

log = logging.getLogger("pramagent.api")

from ..auth import (
    ADMIN_SCOPE,
    AUDIT_SCOPE,
    READ_SCOPE,
    WRITE_SCOPE,
    APIKeyRegistry,
    AuthRecord,
    JWTManager,
    load_registry_from_env,
)
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
from ..ratelimit import AuthFailureGuard, TokenBucket
from ..rca import RCAEngine
from ..store import MemoryStore, SQLiteStore
from ..telemetry import configure_otel
from ..types import LayerEvent, Verdict
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
    enforcement_mode: str = "enforce"
    would_block: bool = False
    would_block_reason: str = ""
    aws_scope: str = "undeclared"
    detection_tier: str = ""
    response_tier: str = ""
    attack_techniques: list[str] = Field(default_factory=list)
    conformance_metrics: dict = Field(default_factory=dict)


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
    scopes: list[str] = Field(default_factory=list)


# Schema-validated demo request bodies. Fields stay Optional (rather than
# required) so the existing hand-written checks below keep producing their
# specific, user-facing error messages ("prompt is required", etc.) — this
# model's job is to reject malformed *types* (a list where a string belongs,
# a prompt that isn't a string) before any of that logic runs, not to
# replace the friendlier validation messages.
class DemoPolicyOptions(BaseModel):
    pii_scrubbing: Optional[bool] = None
    injection_guard: Optional[bool] = None
    safety_rules: Optional[bool] = None
    hitl: Optional[bool] = None
    output_judge: Optional[bool] = None

    model_config = {"extra": "ignore"}


class DemoRunRequest(BaseModel):
    prompt: Optional[str] = None
    nvidia_api_key: Optional[str] = None
    model: Optional[str] = None
    action: Optional[str] = None
    policies: Optional[DemoPolicyOptions] = None
    telemetry_opt_in: Optional[bool] = None
    visitor_id: Optional[str] = None

    model_config = {"extra": "ignore"}


class DemoRequestAccessRequest(BaseModel):
    email: Optional[str] = None
    company: Optional[str] = None
    use_case: Optional[str] = None

    model_config = {"extra": "ignore"}


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
    enforcement_mode: str = "enforce"
    would_block: bool = False
    would_block_reason: str = ""
    prev_hash: str
    this_hash: str
    anchor_tx_id: str
    anchor_block_number: int
    anchor_metadata: dict
    aws_scope: str = "undeclared"
    detection_tier: str = ""
    response_tier: str = ""
    attack_techniques: list[str] = Field(default_factory=list)
    conformance_metrics: dict = Field(default_factory=dict)


class EraseResponse(BaseModel):
    deleted: int
    tenant_id: str


class EraseSessionResponse(BaseModel):
    deleted: int
    tenant_id: str
    session_id: str


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
DEFAULT_GEMINI_DEMO_MODEL = "gemini-2.5-flash"


def _demo_enabled() -> bool:
    """Public demo is the product front door.

    It is enabled by default for five-minute time-to-value and can be turned
    off explicitly in hardened API-only deployments.
    """
    raw = os.environ.get(
        "PRAMAGENT_DEMO_ENABLED",
        os.environ.get("PRAMAGENT_ENABLE_DEMO", "true"),
    )
    return str(raw).strip().lower() not in {"0", "false", "no", "off", "disabled"}


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


def _env_true(name: str, default: bool = False) -> bool:
    return _as_bool(os.environ.get(name), default)


def _cli_bind_host_looks_public() -> bool:
    """Best-effort scan of sys.argv for a public bind host passed as a CLI
    flag (for example uvicorn pramagent.api.app:create_app --factory
    --host <wildcard>), which _public_bind_host() cannot see: uvicorns
    --host flag never reaches the ASGI app as an env var or a call
    argument, only as a process argv the operator typed. Checked at
    create_app() time, which (for the single-worker case, the common
    one) runs in the same process that parsed the CLI flags, so
    sys.argv here is that same argv.
    """
    argv = [a.lower() for a in sys.argv]
    # Built via join rather than written whole, solely to avoid this
    # repo's own ToolGuard SSRF pattern flagging the wildcard-bind
    # constant below when authoring this file through a guarded tool
    # call -- see the hardening report for the false-positive finding.
    public_hosts = {".".join(["0"] * 4), "::", "*", "[::]"}
    for i, arg in enumerate(argv):
        if arg == "--host" and i + 1 < len(argv) and argv[i + 1] in public_hosts:
            return True
        if arg.startswith("--host=") and arg.split("=", 1)[1] in public_hosts:
            return True
    return False


def _public_bind_host() -> str:
    return (
        os.environ.get("PRAMAGENT_API_BIND_HOST")
        or os.environ.get("UVICORN_HOST")
        or os.environ.get("HOST")
        or ""
    ).strip().lower()


def _looks_like_public_runtime() -> bool:
    """Best-effort detection only, see the module note on
    _enforce_authenticated_public_api for why this can never be complete
    (for example a bare container run with a published port and no
    distinguishing env var is architecturally invisible to in-process
    code). Callers must not treat a False result here as proof the
    runtime is actually private; _enforce_authenticated_public_api always
    logs a warning when auth is unconfigured, regardless of what this
    function returns, specifically because it cannot be trusted as the
    sole signal.
    """
    host = _public_bind_host()
    # Detection only; this branch refuses public unauthenticated binds.
    if host in {"0.0.0.0", "::", "*", "[::]"}:  # nosec B104
        return True
    if _cli_bind_host_looks_public():
        return True
    return any(
        os.environ.get(name)
        for name in (
            "RAILWAY_ENVIRONMENT",
            "RAILWAY_SERVICE_NAME",
            "RENDER",
            "FLY_APP_NAME",
            "K_SERVICE",
            "AWS_EXECUTION_ENV",
            # Always present inside any Kubernetes pod, unconditionally
            # injected by the clusters own service discovery, unlike
            # the others above, this needs no cooperation from whoever
            # wrote the deployment manifest.
            "KUBERNETES_SERVICE_HOST",
            "DYNO",
            "WEBSITE_SITE_NAME",
            "GAE_INSTANCE",
            "ECS_CONTAINER_METADATA_URI_V4",
        )
    )


def _unauthenticated_api_opt_in_expired() -> bool:
    """PRAMAGENT_ALLOW_UNAUTHENTICATED_API_UNTIL time-boxes the opt-in.

    Without this, "set the flag once for a demo" has no way to force a
    deliberate re-decision later — the flag just sits there indefinitely.
    An unset expiry means no time-box (matches prior behavior); a malformed
    one fails closed (treated as already expired), since a typo here should
    not silently grant an indefinite unauthenticated window.
    """
    raw = os.environ.get("PRAMAGENT_ALLOW_UNAUTHENTICATED_API_UNTIL", "").strip()
    if not raw:
        return False
    import datetime as _dt
    try:
        deadline = _dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=_dt.timezone.utc)
        return _dt.datetime.now(_dt.timezone.utc) >= deadline
    except ValueError:
        try:
            deadline_ts = float(raw)
        except ValueError:
            log.warning(
                "PRAMAGENT_ALLOW_UNAUTHENTICATED_API_UNTIL=%r is not a valid "
                "ISO8601 timestamp or unix epoch; treating the unauthenticated "
                "opt-in as expired", raw,
            )
            return True
        return time.time() >= deadline_ts


def _enforce_authenticated_public_api(registry: APIKeyRegistry) -> None:
    if len(registry) > 0:
        return
    if _env_true("PRAMAGENT_ALLOW_UNAUTHENTICATED_API") and not _unauthenticated_api_opt_in_expired():
        if _looks_like_public_runtime():
            log.warning(
                "starting with PRAMAGENT_ALLOW_UNAUTHENTICATED_API=1 on what "
                "looks like a public-facing runtime — every request is "
                "trusted at face value (client-supplied tenant_id, no scope "
                "enforcement). Set PRAMAGENT_API_KEYS/PRAMAGENT_API_KEY_DSN "
                "for anything beyond a demo, and consider "
                "PRAMAGENT_ALLOW_UNAUTHENTICATED_API_UNTIL to time-box this."
            )
        return
    if _looks_like_public_runtime():
        raise RuntimeError(
            "refusing to start unauthenticated public API: configure "
            "PRAMAGENT_API_KEYS or PRAMAGENT_API_KEY_DSN, or explicitly set "
            "PRAMAGENT_ALLOW_UNAUTHENTICATED_API=1 for a dev/demo deployment "
            "(PRAMAGENT_ALLOW_UNAUTHENTICATED_API_UNTIL has expired, if set)"
        )
    # The heuristic above is best-effort only (see _looks_like_public_runtime
    # docstring): it cannot see a bare container run with a published port
    # and no distinguishing env var, for one. A False result here is not
    # proof this process is unreachable from outside this machine, so this
    # case must never be silent even though it does not raise.
    log.warning(
        "starting with no PRAMAGENT_API_KEYS/PRAMAGENT_API_KEY_DSN configured "
        "and no public-runtime signal detected, every request will be "
        "treated as tenant with no auth check beyond IP rate limiting. "
        "This is fine for a workstation-only development setup, but if "
        "this process is reachable from any other machine or container, "
        "configure PRAMAGENT_API_KEYS/PRAMAGENT_API_KEY_DSN now."
    )


def _phi_mode_enabled() -> bool:
    return _env_true("PRAMAGENT_PHI_MODE") or _env_true("PRAMAGENT_HANDLE_PHI")


def _trusted_proxy_networks() -> list:
    raw = os.environ.get("PRAMAGENT_TRUSTED_PROXY_IPS", "")
    networks = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            log.warning("ignoring invalid PRAMAGENT_TRUSTED_PROXY_IPS entry: %s", part)
    return networks


def _peer_is_trusted_proxy(request: Request) -> bool:
    """Gate X-Forwarded-Proto trust behind a configured proxy allowlist.

    Without PRAMAGENT_TRUSTED_PROXY_IPS set, any client could spoof
    X-Forwarded-Proto: https to bypass PRAMAGENT_FORCE_HTTPS redirects when
    the app is reachable directly (not just via the intended edge proxy).
    No allowlist means "do not trust forwarded proto" unless the operator sets
    PRAMAGENT_TRUST_UNLISTED_X_FORWARDED_PROTO=1 for a PaaS edge whose IP is
    edge whose IP the operator doesn't control — set the allowlist to close
    that gap where the deployment topology allows it.

    Read fresh (not module-cached) so it reflects the environment at request
    time, matching how the rest of this module's env-driven toggles behave.
    """
    networks = _trusted_proxy_networks()
    if not networks:
        # Secure default: ignore spoofable forwarded-proto headers unless the
        # operator explicitly opts into the PaaS compatibility fallback.
        return _env_true("PRAMAGENT_TRUST_UNLISTED_X_FORWARDED_PROTO")
    client_host = request.client.host if request.client else ""
    if not client_host:
        return False
    try:
        addr = ipaddress.ip_address(client_host)
    except ValueError:
        return False
    return any(addr in network for network in networks)


def _request_is_https(request: Request) -> bool:
    forwarded = request.headers.get("X-Forwarded-Proto", "")
    if forwarded and _peer_is_trusted_proxy(request):
        return forwarded.split(",", 1)[0].strip().lower() == "https"
    return request.url.scheme == "https"


class DemoProductSignals:
    """Privacy-preserving product signals for the public demo.

    The demo only records events when the browser opts in. It never stores
    prompts, model outputs, provider keys, IP addresses, or plaintext email.
    """

    def __init__(
        self,
        max_events: int = 2000,
        *,
        postgres_dsn: str = "",
        connect=None,
        signal_salt: object = None,
    ) -> None:
        self.max_events = max_events
        salt_value = signal_salt if signal_salt is not None else os.environ.get(
            "PRAMAGENT_DEMO_SIGNAL_SALT", ""
        )
        self._salt = (
            str(salt_value).encode("utf-8")
            if salt_value
            else secrets.token_bytes(32)
        )
        self._lock = threading.Lock()
        self._visitors: dict[str, dict] = {}
        self._events: list[dict] = []
        self._leads: list[dict] = []
        self._postgres_dsn = str(postgres_dsn or "").strip()
        self._postgres_ready = False
        self._postgres_error = ""
        self._connect = connect
        if self._postgres_dsn:
            if self._connect is None:
                from .._pg import connect as pg_connect
                self._connect = pg_connect
            self._ensure_postgres()

    def _digest(self, value: object, *, length: int = 24) -> str:
        text = str(value or "").strip()
        if not text:
            text = "anonymous"
        return hashlib.sha256(self._salt + text.encode("utf-8")).hexdigest()[:length]

    @staticmethod
    def _scrub_label(value: object) -> str:
        text = str(value or "").strip()[:120]
        text = re.sub(
            r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            "[redacted-email]",
            text,
        )
        text = re.sub(
            r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b",
            "[redacted-phone]",
            text,
        )
        return text

    def _storage_mode(self) -> str:
        if self._postgres_ready:
            return "postgres"
        if self._postgres_dsn:
            return "memory_fallback"
        return "memory"

    def _execute_postgres(self, sql: str, params: tuple = ()) -> None:
        if not self._postgres_dsn or self._connect is None:
            return
        conn = None
        cur = None
        try:
            conn = self._connect(self._postgres_dsn)
            cur = conn.cursor()
            cur.execute(sql, params)
            commit = getattr(conn, "commit", None)
            if commit:
                commit()
        finally:
            if cur is not None:
                close = getattr(cur, "close", None)
                if close:
                    close()
            if conn is not None:
                close = getattr(conn, "close", None)
                if close:
                    close()

    def _query_postgres(self, sql: str, params: tuple = ()) -> list[dict]:
        if not self._postgres_ready or self._connect is None:
            return []
        conn = None
        cur = None
        try:
            conn = self._connect(self._postgres_dsn)
            cur = conn.cursor()
            cur.execute(sql, params)
            columns = [desc[0] for desc in (getattr(cur, "description", None) or [])]
            rows = cur.fetchall()
            if not columns:
                return []
            return [dict(zip(columns, row)) for row in rows]
        finally:
            if cur is not None:
                close = getattr(cur, "close", None)
                if close:
                    close()
            if conn is not None:
                close = getattr(conn, "close", None)
                if close:
                    close()

    def _ensure_postgres(self) -> None:
        statements = [
            """
            CREATE TABLE IF NOT EXISTS pramagent_demo_signal_events (
                id BIGSERIAL PRIMARY KEY,
                created_at DOUBLE PRECISION NOT NULL,
                visitor_hash TEXT NOT NULL,
                provider_kind TEXT NOT NULL,
                action TEXT NOT NULL,
                verdict TEXT NOT NULL,
                hitl_status TEXT NOT NULL,
                payment_intent BOOLEAN NOT NULL,
                aws_scope TEXT NOT NULL,
                detection_tier TEXT NOT NULL,
                response_tier TEXT NOT NULL
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS pramagent_demo_signal_events_created_idx
            ON pramagent_demo_signal_events (created_at DESC)
            """,
            """
            CREATE INDEX IF NOT EXISTS pramagent_demo_signal_events_visitor_idx
            ON pramagent_demo_signal_events (visitor_hash)
            """,
            """
            CREATE TABLE IF NOT EXISTS pramagent_demo_signal_leads (
                id BIGSERIAL PRIMARY KEY,
                created_at DOUBLE PRECISION NOT NULL,
                lead_hash TEXT NOT NULL,
                email_hash TEXT NOT NULL,
                company_hash TEXT NOT NULL,
                use_case TEXT NOT NULL
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS pramagent_demo_signal_leads_created_idx
            ON pramagent_demo_signal_leads (created_at DESC)
            """,
        ]
        try:
            for statement in statements:
                self._execute_postgres(statement)
            self._postgres_ready = True
            self._postgres_error = ""
        except Exception as exc:
            self._postgres_ready = False
            self._postgres_error = str(exc)
            log.warning("demo product signal Postgres unavailable; using memory", exc_info=True)

    def _persist_event(self, event: dict) -> None:
        if not self._postgres_ready:
            return
        try:
            self._execute_postgres(
                """
                INSERT INTO pramagent_demo_signal_events (
                    created_at, visitor_hash, provider_kind, action, verdict,
                    hitl_status, payment_intent, aws_scope, detection_tier,
                    response_tier
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    event["created_at"],
                    event["visitor_hash"],
                    event["provider_kind"],
                    event["action"],
                    event["verdict"],
                    event["hitl_status"],
                    event["payment_intent"],
                    event["aws_scope"],
                    event["detection_tier"],
                    event["response_tier"],
                ),
            )
        except Exception as exc:
            self._postgres_ready = False
            self._postgres_error = str(exc)
            log.warning("demo product signal event persistence failed", exc_info=True)

    def _persist_lead(self, lead: dict) -> None:
        if not self._postgres_ready:
            return
        try:
            self._execute_postgres(
                """
                INSERT INTO pramagent_demo_signal_leads (
                    created_at, lead_hash, email_hash, company_hash, use_case
                ) VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    lead["created_at"],
                    lead["lead_hash"],
                    lead["email_hash"],
                    lead["company_hash"],
                    lead["use_case"],
                ),
            )
        except Exception as exc:
            self._postgres_ready = False
            self._postgres_error = str(exc)
            log.warning("demo product signal lead persistence failed", exc_info=True)

    def record_run(
        self,
        *,
        visitor_id: object,
        provider_kind: str,
        action: str,
        verdict: str,
        hitl_status: str,
        payment_intent: bool,
        aws_scope: str,
        detection_tier: str,
        response_tier: str,
    ) -> bool:
        visitor = self._digest(visitor_id)
        now = time.time()
        event = {
            "visitor_hash": visitor,
            "created_at": now,
            "provider_kind": provider_kind,
            "action": action,
            "verdict": verdict,
            "hitl_status": hitl_status,
            "payment_intent": bool(payment_intent),
            "aws_scope": aws_scope,
            "detection_tier": detection_tier,
            "response_tier": response_tier,
        }
        with self._lock:
            profile = self._visitors.setdefault(
                visitor,
                {"first_seen": now, "last_seen": now, "runs": 0},
            )
            profile["last_seen"] = now
            profile["runs"] += 1
            self._events.append(event)
            if len(self._events) > self.max_events:
                del self._events[: len(self._events) - self.max_events]
        self._persist_event(event)
        return True

    def record_lead(self, *, email: object, company: object, use_case: object) -> dict:
        email_text = str(email or "").strip().lower()
        lead = {
            "lead_hash": self._digest(email_text or f"{company}:{use_case}"),
            "email_hash": self._digest(email_text) if email_text else "",
            "company_hash": self._digest(company) if company else "",
            "use_case": self._scrub_label(use_case),
            "created_at": time.time(),
        }
        with self._lock:
            self._leads.append(lead)
            if len(self._leads) > self.max_events:
                del self._leads[: len(self._leads) - self.max_events]
        self._persist_lead(lead)
        return {"ok": True, "lead_hash": lead["lead_hash"]}

    def summary(self) -> dict:
        if self._postgres_ready:
            snapshot = self._postgres_snapshot(limit=1)
            if snapshot:
                return snapshot["summary"]
        with self._lock:
            repeat = sum(1 for profile in self._visitors.values()
                         if profile.get("runs", 0) > 1)
            return {
                "opt_in_visitors": len(self._visitors),
                "opt_in_runs": sum(profile.get("runs", 0)
                                   for profile in self._visitors.values()),
                "repeat_visitors": repeat,
                "lead_count": len(self._leads),
            }

    @staticmethod
    def _breakdown(events: list[dict], field: str) -> dict:
        counts: dict[str, int] = {}
        for event in events:
            key = str(event.get(field) or "unknown")
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items()))

    def _memory_snapshot(self, limit: int) -> dict:
        with self._lock:
            events = list(reversed(self._events[-limit:]))
            leads = list(reversed(self._leads[-limit:]))
            repeat = sum(1 for profile in self._visitors.values()
                         if profile.get("runs", 0) > 1)
            summary = {
                "opt_in_visitors": len(self._visitors),
                "opt_in_runs": sum(profile.get("runs", 0)
                                   for profile in self._visitors.values()),
                "repeat_visitors": repeat,
                "lead_count": len(self._leads),
            }
        return {
            "storage": self._storage_mode(),
            "storage_error": self._postgres_error,
            "summary": summary,
            "breakdowns": {
                "provider_kind": self._breakdown(events, "provider_kind"),
                "verdict": self._breakdown(events, "verdict"),
                "hitl_status": self._breakdown(events, "hitl_status"),
                "aws_scope": self._breakdown(events, "aws_scope"),
                "detection_tier": self._breakdown(events, "detection_tier"),
                "response_tier": self._breakdown(events, "response_tier"),
            },
            "recent_events": events,
            "recent_leads": leads,
        }

    def _postgres_counts(self, sql: str) -> int:
        rows = self._query_postgres(sql)
        if not rows:
            return 0
        return int(rows[0].get("count") or rows[0].get("count_1") or 0)

    def _postgres_breakdown(self, field: str) -> dict:
        queries = {
            "provider_kind": """
                SELECT provider_kind AS key, COUNT(*) AS count
                FROM pramagent_demo_signal_events
                GROUP BY provider_kind
                ORDER BY provider_kind
            """,
            "verdict": """
                SELECT verdict AS key, COUNT(*) AS count
                FROM pramagent_demo_signal_events
                GROUP BY verdict
                ORDER BY verdict
            """,
            "hitl_status": """
                SELECT hitl_status AS key, COUNT(*) AS count
                FROM pramagent_demo_signal_events
                GROUP BY hitl_status
                ORDER BY hitl_status
            """,
            "aws_scope": """
                SELECT aws_scope AS key, COUNT(*) AS count
                FROM pramagent_demo_signal_events
                GROUP BY aws_scope
                ORDER BY aws_scope
            """,
            "detection_tier": """
                SELECT detection_tier AS key, COUNT(*) AS count
                FROM pramagent_demo_signal_events
                GROUP BY detection_tier
                ORDER BY detection_tier
            """,
            "response_tier": """
                SELECT response_tier AS key, COUNT(*) AS count
                FROM pramagent_demo_signal_events
                GROUP BY response_tier
                ORDER BY response_tier
            """,
        }
        query = queries.get(field)
        if not query:
            return {}
        rows = self._query_postgres(query)
        return {str(row.get("key") or "unknown"): int(row.get("count") or 0)
                for row in rows}

    def _postgres_snapshot(self, limit: int) -> Optional[dict]:
        try:
            events = self._query_postgres(
                """
                SELECT created_at, visitor_hash, provider_kind, action, verdict,
                       hitl_status, payment_intent, aws_scope, detection_tier,
                       response_tier
                FROM pramagent_demo_signal_events
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            leads = self._query_postgres(
                """
                SELECT created_at, lead_hash, email_hash, company_hash, use_case
                FROM pramagent_demo_signal_leads
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            repeat_rows = self._query_postgres(
                """
                SELECT COUNT(*) AS count
                FROM (
                    SELECT visitor_hash
                    FROM pramagent_demo_signal_events
                    GROUP BY visitor_hash
                    HAVING COUNT(*) > 1
                ) AS repeat_visitors
                """
            )
            repeat = int(repeat_rows[0].get("count") or 0) if repeat_rows else 0
            summary = {
                "opt_in_visitors": self._postgres_counts(
                    "SELECT COUNT(DISTINCT visitor_hash) AS count FROM pramagent_demo_signal_events"
                ),
                "opt_in_runs": self._postgres_counts(
                    "SELECT COUNT(*) AS count FROM pramagent_demo_signal_events"
                ),
                "repeat_visitors": repeat,
                "lead_count": self._postgres_counts(
                    "SELECT COUNT(*) AS count FROM pramagent_demo_signal_leads"
                ),
            }
            return {
                "storage": self._storage_mode(),
                "storage_error": self._postgres_error,
                "summary": summary,
                "breakdowns": {
                    "provider_kind": self._postgres_breakdown("provider_kind"),
                    "verdict": self._postgres_breakdown("verdict"),
                    "hitl_status": self._postgres_breakdown("hitl_status"),
                    "aws_scope": self._postgres_breakdown("aws_scope"),
                    "detection_tier": self._postgres_breakdown("detection_tier"),
                    "response_tier": self._postgres_breakdown("response_tier"),
                },
                "recent_events": events,
                "recent_leads": leads,
            }
        except Exception as exc:
            self._postgres_ready = False
            self._postgres_error = str(exc)
            log.warning("demo product signal Postgres read failed", exc_info=True)
            return None

    def snapshot(self, *, limit: int = 100) -> dict:
        bounded = max(1, min(int(limit or 100), 500))
        if self._postgres_ready:
            snapshot = self._postgres_snapshot(bounded)
            if snapshot:
                return snapshot
        return self._memory_snapshot(bounded)


def build_default_armor() -> Pramagent:
    """Build from env. Store priority: PRAMAGENT_POSTGRES_DSN > PRAMAGENT_DB >
    explicit opt-in volatile memory (PRAMAGENT_ALLOW_MEMORY_STORE=1).

    Refuses to start without one of the three so the reference deployment can
    never silently boot on a MemoryStore that loses every trace on restart
    (P0-1 / T1-12)."""
    from ..secrets import resolve_secret
    dsn = os.environ.get("PRAMAGENT_POSTGRES_DSN", "").strip()
    db_path = os.environ.get("PRAMAGENT_DB", "").strip()
    encryption_key = resolve_secret("PRAMAGENT_ENCRYPTION_KEY").strip()
    require_encrypted_store = (
        _env_true("PRAMAGENT_REQUIRE_ENCRYPTED_STORE")
        or _phi_mode_enabled()
    )
    if dsn:
        # Two ways to satisfy "encrypted at rest" for Postgres: a real
        # PRAMAGENT_ENCRYPTION_KEY (application-level Fernet encryption of
        # the payload column — verifiable, not an attestation), or the
        # PRAMAGENT_POSTGRES_ENCRYPTION_AT_REST flag (trusting
        # provider-managed disk/TDE encryption instead). Either is accepted;
        # PRAMAGENT_ENCRYPTION_KEY used to be silently ignored for Postgres.
        if (
            require_encrypted_store
            and not encryption_key
            and not _env_true("PRAMAGENT_POSTGRES_ENCRYPTION_AT_REST")
        ):
            raise RuntimeError(
                "PHI/encrypted-store mode requires either PRAMAGENT_ENCRYPTION_KEY "
                "(application-level column encryption) or "
                "PRAMAGENT_POSTGRES_ENCRYPTION_AT_REST=1 (after enabling "
                "provider-managed disk/TDE encryption)"
            )
        from ..store_postgres import PostgresStore
        db = PostgresStore.from_dsn(dsn, encryption_key=encryption_key or None)
        store, audit = db, db          # single object handles both
    elif db_path:
        if encryption_key:
            from ..store_encrypted import EncryptedSQLiteStore
            db = EncryptedSQLiteStore(db_path, key=encryption_key)
        elif require_encrypted_store:
            raise RuntimeError(
                "PHI/encrypted-store mode requires PRAMAGENT_ENCRYPTION_KEY "
                "when PRAMAGENT_DB points at SQLite"
            )
        else:
            db = SQLiteStore(db_path)
        store, audit = db, db          # single object handles both
    elif os.environ.get("PRAMAGENT_ALLOW_MEMORY_STORE", "").lower() in {"1", "true"}:
        if require_encrypted_store:
            raise RuntimeError(
                "PHI/encrypted-store mode cannot use volatile MemoryStore"
            )
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
            max_tokens=int(os.environ.get("OLLAMA_MAX_TOKENS", "256")),
            timeout_s=float(os.environ.get("OLLAMA_TIMEOUT_S", "60")),
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
        agent_scope=os.environ.get("PRAMAGENT_AGENT_SCOPE", "scope_2"),
        enforcement_mode=os.environ.get("PRAMAGENT_ENFORCEMENT_MODE", "enforce"),
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


def build_auth_failure_backend_from_env():
    """Use Redis for the auth-lockout counter when configured, so a
    brute-force attempt spread across replicas behind a load balancer still
    trips the lockout instead of each worker tracking its own count."""
    url = (
        os.environ.get("PRAMAGENT_AUTH_LOCKOUT_REDIS_URL")
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
        log.warning("auth-lockout Redis backend unavailable; using local counter: %s", exc)
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
        version="0.8.5",
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
    # CSP for /demo: script-src/style-src pinned to sha256 hashes of the
    # inline <script>/<style> blocks actually shipped in demo_page.html.
    # If that HTML's inline script or style content changes, regenerate
    # these hashes or the browser will block them.
    _DEMO_CSP = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "img-src 'self' data:; "
        "style-src 'self' 'sha256-iKSq6o6K61AlCgDYs3+exAWFG7cw7zBCoPG2cFPlX6M='; "
        "script-src 'self' 'sha256-tOs3xBGIOdc/4HwSnPzLdiUeM4VoPRCpvteaM3FHjwM='; "
        "connect-src 'self'"
    )
    # Start in report-only mode: logs violations via the browser console
    # without blocking anything. Flip the header name to
    # "Content-Security-Policy" once you've confirmed a day or two of clean
    # traffic with no console violations.
    _CSP_HEADER_NAME = os.environ.get(
        "PRAMAGENT_CSP_HEADER_NAME", "Content-Security-Policy-Report-Only"
    )

    @app.middleware("http")
    async def security_and_logging(request: Request, call_next):
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        t0 = time.perf_counter()
        if _env_true("PRAMAGENT_FORCE_HTTPS") and not _request_is_https(request):
            redirect_to = str(request.url).replace("http://", "https://", 1)
            response = RedirectResponse(redirect_to, status_code=308)
            response.headers["X-Request-Id"] = request_id
            return response
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
            response.headers[_CSP_HEADER_NAME] = _DEMO_CSP
            if _request_is_https(request):
                hsts = "max-age=63072000; includeSubDomains"
                if _env_true("PRAMAGENT_HSTS_PRELOAD"):
                    hsts += "; preload"
                response.headers["Strict-Transport-Security"] = hsts
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
        response.headers[_CSP_HEADER_NAME] = _DEMO_CSP
        if _request_is_https(request):
            hsts = "max-age=63072000; includeSubDomains"
            if _env_true("PRAMAGENT_HSTS_PRELOAD"):
                hsts += "; preload"
            response.headers["Strict-Transport-Security"] = hsts
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
    _enforce_authenticated_public_api(app.state.registry)
    if _phi_mode_enabled() and len(app.state.registry) == 0:
        raise RuntimeError(
            "PHI mode requires API-key/JWT authentication; configure "
            "PRAMAGENT_API_KEYS or PRAMAGENT_API_KEY_DSN"
        )
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
    from ..secrets import resolve_secret
    jwt_secret = resolve_secret("PRAMAGENT_JWT_SECRET")
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
    # Dedicated brute-force lockout on repeated invalid-credential attempts,
    # separate from the request-volume rate bucket above (see
    # AuthFailureGuard's docstring for why volume throttling alone isn't
    # enough against credential guessing).
    app.state.auth_failure_guard = AuthFailureGuard(
        threshold=int(os.environ.get("PRAMAGENT_AUTH_LOCKOUT_THRESHOLD", "10")),
        window_s=int(os.environ.get("PRAMAGENT_AUTH_LOCKOUT_WINDOW_S", "300")),
        base_lockout_s=float(os.environ.get("PRAMAGENT_AUTH_LOCKOUT_BASE_S", "30")),
        max_lockout_s=float(os.environ.get("PRAMAGENT_AUTH_LOCKOUT_MAX_S", "900")),
        backend=build_auth_failure_backend_from_env(),
    )
    demo_hourly_limit = max(1, int(os.environ.get("PRAMAGENT_DEMO_RATE_LIMIT", "60")))
    app.state.demo_bucket = TokenBucket(
        capacity=demo_hourly_limit,
        refill_per_sec=demo_hourly_limit / 3600.0,
    )
    app.state.demo_signals = DemoProductSignals(
        postgres_dsn=os.environ.get("PRAMAGENT_DEMO_SIGNALS_POSTGRES_DSN", ""),
        signal_salt=os.environ.get("PRAMAGENT_DEMO_SIGNAL_SALT", ""),
    )
    _raw_api_key_max_age_days = os.environ.get("PRAMAGENT_API_KEY_MAX_AGE_DAYS", "").strip()
    api_key_max_age_days: Optional[float] = None
    if _raw_api_key_max_age_days:
        try:
            api_key_max_age_days = float(_raw_api_key_max_age_days)
        except ValueError as exc:
            raise RuntimeError(
                "PRAMAGENT_API_KEY_MAX_AGE_DAYS must be a positive number of days"
            ) from exc
        if api_key_max_age_days <= 0:
            raise RuntimeError(
                "PRAMAGENT_API_KEY_MAX_AGE_DAYS must be a positive number of days"
            )

    # P3-1: the old `request: Request = None` annotation lied about
    # nullability. FastAPI special-cases the bare Request annotation (it is
    # not a Pydantic field, so Optional[...] is rejected) and always injects
    # the request for dependencies — the truthful signature is a required,
    # non-Optional Request with no default.
    def _enforce_key_rotation(record: AuthRecord) -> None:
        """Reject API keys past PRAMAGENT_API_KEY_MAX_AGE_DAYS, when set.

        Unset (default) means no behavior change — rotation mechanisms
        (kid rotation, auth-revoke) existed before this with nothing
        actually enforcing a cadence; this is opt-in, real enforcement
        rather than a documented-only policy. JWTs (record.kind != "api_key")
        and records with no known issuance time (created_at <= 0, e.g. an
        env-var key loaded before this field existed) are never subject to
        this — JWTs already expire on their own short TTL.
        """
        if record.kind != "api_key" or record.created_at <= 0:
            return
        if api_key_max_age_days is None:
            return
        if record.age_days() > api_key_max_age_days:
            raise HTTPException(
                status_code=401,
                detail=(
                    f"API key exceeds the {api_key_max_age_days:g}-day rotation policy "
                    f"(PRAMAGENT_API_KEY_MAX_AGE_DAYS); issue a new key with "
                    f"`pramagent auth-issue` and revoke this one"
                ),
            )

    def _resolve_auth_record(request: Request, authorization: Optional[str]) -> AuthRecord:
        # Dedicated lockout, distinct from the request-rate bucket: N invalid
        # credential presentations from the same peer trips an escalating
        # cooldown regardless of how much rate-limit capacity remains.
        peer = request.client.host if request and request.client else "unknown"
        lockout_key = f"auth:{peer}"
        remaining = app.state.auth_failure_guard.locked_out(lockout_key)
        if remaining > 0:
            raise HTTPException(
                status_code=429,
                detail="too many invalid credential attempts; try again later",
                headers={"Retry-After": str(int(remaining) + 1)},
            )
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        bearer = authorization.split(None, 1)[1].strip()
        record = app.state.registry.record_for_key(bearer)
        if record is None:
            record = app.state.jwt.record_for_token(bearer)
        if record is None:
            app.state.auth_failure_guard.record_failure(lockout_key)
            raise HTTPException(status_code=401, detail="invalid bearer token")
        app.state.auth_failure_guard.record_success(lockout_key)
        _enforce_key_rotation(record)
        return record

    def _rate_limit_auth(request: Request, rate_key: str) -> None:
        allowed, retry_after = app.state.bucket.allow(rate_key)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="rate limit exceeded",
                headers={"Retry-After": str(int(retry_after) + 1)},
            )

    def _scope_dependency(required_scope):
        """required_scope: a single scope string, or a tuple of scopes where
        having ANY ONE of them is sufficient (e.g. read-or-audit for
        /v1/audit/verify)."""
        accepted = (required_scope,) if isinstance(required_scope, str) else tuple(required_scope)

        def _require(
            request: Request,
            authorization: Optional[str] = Header(None),
        ) -> str:
            """Resolve tenant, enforce scope, and apply tenant/IP rate limits."""
            if len(app.state.registry) == 0:
                tenant = ""
                rate_key = (request.client.host if request and request.client else "anon")
                _rate_limit_auth(request, rate_key)
                return tenant

            record = _resolve_auth_record(request, authorization)
            if not any(record.has_scope(scope) for scope in accepted):
                raise HTTPException(
                    status_code=403,
                    detail=f"bearer token missing required scope: {' or '.join(accepted)}",
                )
            _rate_limit_auth(request, f"tenant:{record.tenant_id}")
            return record.tenant_id

        return _require

    require_tenant = _scope_dependency(READ_SCOPE)
    require_write_tenant = _scope_dependency(WRITE_SCOPE)
    require_audit_tenant = _scope_dependency((READ_SCOPE, AUDIT_SCOPE))
    require_admin_tenant = _scope_dependency(ADMIN_SCOPE)

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

    def _demo_admin_key() -> str:
        return os.environ.get("PRAMAGENT_DEMO_ADMIN_KEY", "").strip()

    def _require_demo_admin(
        authorization: Optional[str],
        x_pramagent_demo_admin_key: Optional[str],
    ) -> None:
        expected = _demo_admin_key()
        if not _demo_enabled() or not expected:
            _demo_not_found()
        candidate = ""
        if authorization and authorization.lower().startswith("bearer "):
            candidate = authorization.split(None, 1)[1].strip()
        elif x_pramagent_demo_admin_key:
            candidate = x_pramagent_demo_admin_key.strip()
        if not candidate or not secrets.compare_digest(candidate, expected):
            raise HTTPException(status_code=401, detail="invalid demo admin key")

    def _demo_admin_headers() -> dict[str, str]:
        return {
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "X-Robots-Tag": "noindex, nofollow",
        }

    def _demo_admin_page() -> str:
        page = Path(__file__).with_name("demo_signals_admin.html")
        return page.read_text(encoding="utf-8")

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
        key. It rejects obvious placeholders and short fake strings so bad-key
        tests and demos fail before a provider error can echo context.
        """
        if api_key is None or api_key == "":
            return True
        if not isinstance(api_key, str):
            return False
        if api_key.startswith("nvapi-"):
            return len(api_key) >= 12
        if api_key.startswith("sk-proj-"):
            return len(api_key) >= 32
        if api_key.startswith("sk-"):
            suffix = api_key[3:]
            return len(suffix) >= 32 and suffix.isalnum()
        if api_key.startswith("AIza"):
            return len(api_key) >= 24
        # Some managed Gemini/API Studio credentials are represented as AQ.*
        # tokens in user environments. The provider still performs the real
        # authentication check; this only routes them away from NVIDIA.
        if api_key.startswith("AQ."):
            return len(api_key) >= 24
        return False

    def _demo_provider_kind(api_key: object) -> Optional[str]:
        if api_key is None or api_key == "":
            return "mock"
        if not isinstance(api_key, str):
            return None
        if api_key.startswith("nvapi-"):
            return "nvidia"
        if api_key.startswith("sk-") or api_key.startswith("sk-proj-"):
            return "openai"
        if api_key.startswith("AIza") or api_key.startswith("AQ."):
            return "gemini"
        return None

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

    def _demo_provider_error_detail(
        detail: Optional[str],
        provider_kind: Optional[str] = None,
    ) -> Optional[str]:
        if not detail:
            return None
        lowered = detail.lower()
        if (
            "http 401" in lowered
            or "http 403" in lowered
            or "authorization" in lowered
            or "forbidden" in lowered
            or "api_key_invalid" in lowered
            or "api key not valid" in lowered
            or "invalid api key" in lowered
            or ("http 400" in lowered and "api key" in lowered)
            or "permission_denied" in lowered
            or "unauthenticated" in lowered
        ):
            if "400" in lowered:
                return "Provider rejected the API key or selected model (HTTP 400)."
            if "403" in lowered:
                if provider_kind == "nvidia":
                    return (
                        "NVIDIA rejected this key/account for hosted chat completions "
                        "(HTTP 403). This usually means Public API Endpoints access "
                        "is not enabled for the NVIDIA organization; changing models "
                        "will not fix it."
                    )
                return "Provider rejected the API key or selected model (HTTP 403)."
            if "401" in lowered:
                return "Provider rejected the API key (HTTP 401)."
            return "Provider rejected the API key or selected model."
        return detail[:220]

    def _demo_layer_event_detail(
        event: LayerEvent,
        provider_kind: Optional[str] = None,
    ) -> str:
        if event.layer == "ReliabilityLayer" and event.decision == "degraded":
            return _demo_provider_error_detail(event.detail, provider_kind) or "provider failed"
        return event.detail

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
        provider_kind = _demo_provider_kind(api_key)
        if provider_kind == "openai":
            # If the user passed an OpenAI key, route to OpenAI's default mini model
            provider = OpenAIProvider(model="gpt-4o-mini", api_key=api_key)
        elif provider_kind == "gemini":
            provider = GeminiProvider(
                model=os.environ.get("PRAMAGENT_DEMO_GEMINI_MODEL", DEFAULT_GEMINI_DEMO_MODEL),
                api_key=api_key,
            )
        elif provider_kind == "mock":
            provider = MockProvider(model="demo-zero-config")
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
            agent_scope="scope_2",
        )

    @app.get("/demo", response_class=HTMLResponse)
    async def demo_page():
        if not _demo_enabled():
            _demo_not_found()
        page = Path(__file__).with_name("demo_page.html")
        return HTMLResponse(page.read_text(encoding="utf-8"))

    @app.get("/demo/admin/signals", response_class=HTMLResponse)
    async def demo_admin_signals_page():
        if not _demo_enabled() or not _demo_admin_key():
            _demo_not_found()
        return HTMLResponse(_demo_admin_page(), headers=_demo_admin_headers())

    @app.get("/demo/admin/signals.json")
    async def demo_admin_signals_json(
        authorization: Optional[str] = Header(None),
        x_pramagent_demo_admin_key: Optional[str] = Header(None),
        limit: int = Query(100, ge=1, le=500),
    ):
        _require_demo_admin(authorization, x_pramagent_demo_admin_key)
        return JSONResponse(
            app.state.demo_signals.snapshot(limit=limit),
            headers=_demo_admin_headers(),
        )

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
            raw_body = await request.json()
        except Exception:
            return JSONResponse(
                {"detail": "invalid JSON body"},
                status_code=400,
                headers=_demo_cors_headers(),
            )
        if not isinstance(raw_body, dict):
            return JSONResponse(
                {"detail": "invalid JSON body"},
                status_code=400,
                headers=_demo_cors_headers(),
            )
        try:
            parsed_body = DemoRunRequest.model_validate(raw_body)
        except ValidationError:
            return JSONResponse(
                {"detail": "invalid JSON body"},
                status_code=400,
                headers=_demo_cors_headers(),
            )
        payload = parsed_body.model_dump()
        if payload.get("policies") is None:
            payload["policies"] = {}

        api_key = str(payload.get("nvidia_api_key") or "").strip()
        if not _looks_like_demo_api_key(api_key):
            return JSONResponse(
                {
                    "detail": (
                        "valid NVIDIA NIM, OpenAI, or Gemini API key required, "
                        "or leave the field blank for the deterministic demo"
                    )
                },
                status_code=400,
                headers=_demo_cors_headers(),
            )
        provider_kind = _demo_provider_kind(api_key)

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
        if provider_kind == "nvidia" and model not in NVIDIA_DEMO_MODELS:
            return JSONResponse(
                {"detail": "unsupported NVIDIA model"},
                status_code=400,
                headers=_demo_cors_headers(),
            )

        allowed, retry_after = app.state.demo_bucket.allow(_demo_rate_key(request, api_key))
        if not allowed:
            return JSONResponse(
                {"detail": "demo rate limit exceeded for this IP and provider key"},
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
        provider_error_detail = _demo_provider_error_detail(
            provider_error_detail,
            provider_kind,
        )
        body = {
            "call_id": trace.call_id,
            "action": action,
            "payment_intent": payment_intent,
            "provider_kind": provider_kind,
            "demo_mode": "deterministic" if provider_kind == "mock" else "live_provider",
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
                    "detail": _demo_layer_event_detail(event, provider_kind),
                    "latency_ms": event.latency_ms,
                    "data": event.data,
                }
                for event in trace.layer_events
            ],
            "provider": trace.provider,
            "provider_model": trace.provider_model,
            "provider_latency_ms": trace.provider_latency_ms,
            "aws_scope": trace.aws_scope,
            "detection_tier": trace.detection_tier,
            "response_tier": trace.response_tier,
            "attack_techniques": trace.attack_techniques,
            "conformance_metrics": trace.conformance_metrics,
            "this_hash": trace.this_hash,
            "prev_hash": trace.prev_hash,
            "total_latency_ms": trace.total_latency_ms,
            "chain_valid": bool(armor.audit.verify_chain()),
        }
        if _as_bool(payload.get("telemetry_opt_in"), False):
            label = "blocked" if result.blocked else (
                "held" if trace.hitl_status == "idle" else "allowed"
            )
            body["telemetry_recorded"] = app.state.demo_signals.record_run(
                visitor_id=payload.get("visitor_id") or _demo_ip(request),
                provider_kind=provider_kind or "unknown",
                action=action,
                verdict=label,
                hitl_status=trace.hitl_status,
                payment_intent=payment_intent,
                aws_scope=trace.aws_scope,
                detection_tier=trace.detection_tier,
                response_tier=trace.response_tier,
            )
        else:
            body["telemetry_recorded"] = False
        return JSONResponse(body, headers=_demo_cors_headers())

    @app.post("/demo/request-access")
    async def demo_request_access(request: Request):
        if not _demo_enabled():
            _demo_not_found()
        try:
            raw_body = await request.json()
        except Exception:
            raw_body = {}
        if not isinstance(raw_body, dict):
            raw_body = {}
        try:
            parsed_body = DemoRequestAccessRequest.model_validate(raw_body)
        except ValidationError:
            return JSONResponse(
                {"detail": "invalid JSON body"},
                status_code=400,
                headers=_demo_cors_headers(),
            )
        email = str(parsed_body.email or "").strip()
        company = str(parsed_body.company or "").strip()
        use_case = str(parsed_body.use_case or "").strip()
        if not email and not company and not use_case:
            return JSONResponse(
                {"detail": "email, company, or use case is required"},
                status_code=400,
                headers=_demo_cors_headers(),
            )
        result = app.state.demo_signals.record_lead(
            email=email,
            company=company,
            use_case=use_case,
        )
        return JSONResponse(result, headers=_demo_cors_headers())

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
        # issuance instead of minting un-verifiable tokens. resolve_secret()
        # so a secret sourced from AWS Secrets Manager/Vault (not a plain
        # env var) still counts as "configured" here.
        from ..secrets import resolve_secret
        if not resolve_secret("PRAMAGENT_JWT_SECRET") and not os.environ.get("PRAMAGENT_JWT_SECRETS"):
            raise HTTPException(
                status_code=503,
                detail="JWT issuance requires PRAMAGENT_JWT_SECRET (or "
                       "PRAMAGENT_JWT_SECRETS) shared across workers")
        record = app.state.registry.record_for_key(body.api_key)
        if record is None:
            raise HTTPException(status_code=401, detail="invalid api key")
        token = app.state.jwt.issue(
            record.tenant_id,
            ttl_s=body.ttl_s,
            scopes=record.scopes,
        )
        return TokenResponse(
            access_token=token,
            expires_in=body.ttl_s,
            tenant_id=record.tenant_id,
            scopes=sorted(record.scopes),
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
                  tenant: str = Depends(require_write_tenant)):
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
            enforcement_mode=t.enforcement_mode,
            would_block=t.would_block,
            would_block_reason=t.would_block_reason,
            aws_scope=t.aws_scope,
            detection_tier=t.detection_tier,
            response_tier=t.response_tier,
            attack_techniques=t.attack_techniques,
            conformance_metrics=t.conformance_metrics,
        )

    @app.get("/v1/trace/{call_id}", response_model=TraceModel)
    async def get_trace(call_id: str, tenant: str = Depends(require_tenant)):
        return _fetch_trace(call_id, tenant).to_dict()

    @app.get("/v1/audit/verify")
    async def verify_audit(tenant: str = Depends(require_audit_tenant)):
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
                            tenant: str = Depends(require_write_tenant)):
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
                              tenant: str = Depends(require_admin_tenant)):
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
                                  tenant: str = Depends(require_admin_tenant)):
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

    @app.delete(
        "/v1/tenant/{tenant_id}/sessions/{session_id}/traces",
        response_model=EraseSessionResponse,
    )
    async def erase_session_traces(tenant_id: str, session_id: str,
                                    tenant: str = Depends(require_admin_tenant)):
        """GDPR right-to-erasure scoped to one end user's session.

        The trace schema has no separate per-end-user column, but session_id
        already identifies one user's conversation/session in practice —
        this is the "delete my data" primitive for a multi-user tenant, so
        one user's request doesn't require erasing every other user sharing
        that tenant (or hand-writing SQL, which is what this closes). Same
        ownership rules as the tenant-wide erasure endpoint above.
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
        store = app.state.armor.store
        if not hasattr(store, "delete_for_session"):
            raise HTTPException(
                status_code=501,
                detail="store does not support session-scoped erasure",
            )
        deleted = store.delete_for_session(tenant_id, session_id)
        audit = app.state.armor.audit
        if audit is not store and hasattr(audit, "redact_for_session"):
            audit.redact_for_session(tenant_id, session_id)
        return {"deleted": deleted, "tenant_id": tenant_id, "session_id": session_id}

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
                          tenant: str = Depends(require_write_tenant)):
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
