"""
Pramagent Admin Dashboard
=========================
FastAPI + HTMX. No build step, no npm.

Authentication
--------------
Every request must carry one of:
  - Header  X-API-Key: <PRAMAGENT_DASHBOARD_KEY>
  - Cookie  pramagent_session=<signed JWT>  (set after /login)

JWT payload: {"sub": "<username>", "tenant": "<tenant_id_or_*>", "exp": ...}

If tenant == "*" the user sees all tenants (super-admin).
Otherwise traces, metrics, and approvals are scoped to that tenant only.

Set PRAMAGENT_DASHBOARD_KEY and PRAMAGENT_JWT_SECRET in the environment (or docker-compose).
To enable all-tenant access, set both PRAMAGENT_DASHBOARD_TENANT=* and
PRAMAGENT_DASHBOARD_ALLOW_SUPER_ADMIN=true.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import time
import uuid
from pathlib import Path
from typing import Optional
from urllib.parse import quote_plus

import httpx
from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pramagent.dashboard_auth import (
    DashboardAuthError,
    DashboardUser,
    DashboardUserStore,
    build_dashboard_user_store_from_env,
)


def _normalize_dashboard_tenant(raw_tenant: str, allow_super_admin: bool) -> str:
    """Require an explicit opt-in before the dashboard can see every tenant."""
    if raw_tenant == "*":
        return "*" if allow_super_admin else "default"
    return raw_tenant or "default"


_DEFAULT_JWT_SECRET = "change-me-in-production"  # nosec B105 — sentinel, refused at startup

from pramagent.secrets import resolve_secret

# resolve_secret() falls back to AWS Secrets Manager/Vault when
# <NAME>_AWS_SECRET_ID / <NAME>_VAULT_PATH is set, otherwise behaves exactly
# like plain os.environ.get() — no change for existing env-var deployments.
PRAMAGENT_API_URL       = os.environ.get("PRAMAGENT_API_URL", "http://localhost:8080")
PRAMAGENT_API_KEY       = resolve_secret("PRAMAGENT_API_KEY")
PRAMAGENT_DASHBOARD_KEY = resolve_secret("PRAMAGENT_DASHBOARD_KEY", PRAMAGENT_API_KEY)  # shared key for browser
PRAMAGENT_JWT_SECRET    = resolve_secret("PRAMAGENT_JWT_SECRET", _DEFAULT_JWT_SECRET)
PRAMAGENT_DASHBOARD_ALLOW_SUPER_ADMIN = os.environ.get(
    "PRAMAGENT_DASHBOARD_ALLOW_SUPER_ADMIN", "false"
).lower() in {"1", "true", "yes", "on"}
# The shared-key LOGIN FORM fallback (password field == PRAMAGENT_DASHBOARD_KEY)
# is a single bearer secret that logs anyone who knows it in as an admin
# session — a de facto backdoor alongside the per-user bcrypt store. Off by
# default; the X-API-Key header path (a separate, documented CLI/curl
# mechanism, not a browser login) is unaffected by this flag.
PRAMAGENT_DASHBOARD_ALLOW_SHARED_KEY_LOGIN = os.environ.get(
    "PRAMAGENT_DASHBOARD_ALLOW_SHARED_KEY_LOGIN", "false"
).lower() in {"1", "true", "yes", "on"}
_PRAMAGENT_DASHBOARD_TENANT_RAW = os.environ.get("PRAMAGENT_DASHBOARD_TENANT", "default")
PRAMAGENT_DASHBOARD_TENANT = _normalize_dashboard_tenant(
    _PRAMAGENT_DASHBOARD_TENANT_RAW,
    PRAMAGENT_DASHBOARD_ALLOW_SUPER_ADMIN,
)
# Defaults to true: session/CSRF cookies require HTTPS unless an operator
# explicitly opts out (e.g. plain-http local dev). Chrome/Firefox already
# treat http://localhost as a trustworthy origin for Secure cookies, so this
# does not break the common local-dev path.
PRAMAGENT_DASHBOARD_SECURE_COOKIE = os.environ.get(
    "PRAMAGENT_DASHBOARD_SECURE_COOKIE", "true"
).lower() in {"1", "true", "yes", "on"}
SESSION_TTL_S    = int(os.environ.get("PRAMAGENT_SESSION_TTL_S", "3600"))
PRAMAGENT_DASHBOARD_REDIS_URL = os.environ.get(
    "PRAMAGENT_DASHBOARD_REDIS_URL",
    os.environ.get("PRAMAGENT_REDIS_URL", ""),
)
PRAMAGENT_DASHBOARD_SIGNUP_ENABLED = os.environ.get(
    "PRAMAGENT_DASHBOARD_SIGNUP_ENABLED", "true"
).lower() in {"1", "true", "yes", "on"}
PRAMAGENT_DASHBOARD_PASSWORD_RESET_ENABLED = os.environ.get(
    "PRAMAGENT_DASHBOARD_PASSWORD_RESET_ENABLED", "true"
).lower() in {"1", "true", "yes", "on"}
PRAMAGENT_DASHBOARD_RESET_SHOW_TOKEN = os.environ.get(
    "PRAMAGENT_DASHBOARD_RESET_SHOW_TOKEN", "false"
).lower() in {"1", "true", "yes", "on"}
PRAMAGENT_DASHBOARD_RESET_TOKEN_TTL_S = int(os.environ.get(
    "PRAMAGENT_DASHBOARD_RESET_TOKEN_TTL_S", "900"
))
PRAMAGENT_DASHBOARD_CSRF_TTL_S = int(os.environ.get(
    "PRAMAGENT_DASHBOARD_CSRF_TTL_S", "3600"
))
PRAMAGENT_DASHBOARD_STATS_TRACE_LIMIT = max(
    5,
    min(500, int(os.environ.get("PRAMAGENT_DASHBOARD_STATS_TRACE_LIMIT", "100"))),
)
PRAMAGENT_DASHBOARD_DEFAULT_ROLE = os.environ.get(
    "PRAMAGENT_DASHBOARD_DEFAULT_ROLE", "viewer"
)
PRAMAGENT_DASHBOARD_SIGNUP_TENANT = _normalize_dashboard_tenant(
    os.environ.get("PRAMAGENT_DASHBOARD_SIGNUP_TENANT", PRAMAGENT_DASHBOARD_TENANT),
    False,
)

def validate_dashboard_config() -> None:
    """Refuse to serve with a missing or well-known JWT secret.

    Uses the shared denylist from ``pramagent.security`` so EVERY published
    placeholder spelling (hyphenated, underscored, "changeme", …) is refused —
    the previous equality check only caught the hyphenated variant, letting
    the repo's own ``change_me_in_production`` example value sail through
    (P0-2 / T1-1). The JWT secret signs every session cookie, so a known
    secret means anyone can forge a super-admin (tenant "*") session.
    """
    from pramagent.security import assert_strong_secret
    assert_strong_secret("PRAMAGENT_JWT_SECRET", PRAMAGENT_JWT_SECRET)
    if PRAMAGENT_DASHBOARD_ALLOW_SHARED_KEY_LOGIN:
        log.warning(
            "PRAMAGENT_DASHBOARD_ALLOW_SHARED_KEY_LOGIN=1: the browser login "
            "form accepts PRAMAGENT_DASHBOARD_KEY as a password for ANY "
            "username, logging that person in as an admin session not tied "
            "to a real account. Meant for single-team alpha pilots only — "
            "configure a real dashboard user store instead for anything else."
        )


from contextlib import asynccontextmanager


@asynccontextmanager
async def _lifespan(app_: FastAPI):
    # lifespan replaces the deprecated @app.on_event("startup") hook (P3-3)
    validate_dashboard_config()
    yield


app = FastAPI(title="Pramagent Dashboard", docs_url=None, redoc_url=None,
              lifespan=_lifespan)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.mount(
    "/static",
    StaticFiles(directory=str(Path(__file__).parent / "static")),
    name="static",
)
log = logging.getLogger("pramagent.dashboard")


def _build_user_store() -> DashboardUserStore | None:
    try:
        store = build_dashboard_user_store_from_env()
        if store is not None:
            return store
        default_path = os.environ.get(
            "PRAMAGENT_DASHBOARD_LOCAL_USERS_PATH",
            ".pramagent/dashboard-users.db",
        )
        if default_path:
            from pramagent.dashboard_auth import SQLiteDashboardUserStore

            return SQLiteDashboardUserStore(default_path)
        return None
    except Exception as exc:
        log.warning("dashboard user store unavailable; shared-key auth remains active: %s", exc)
        return None


_user_store = _build_user_store()

_NO_STORE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0, private",
    "Pragma": "no-cache",
    "Expires": "0",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
}
_PREAUTH_CSRF_COOKIE = "pramagent_csrf"


def _apply_security_headers(response: Response) -> Response:
    for key, value in _NO_STORE_HEADERS.items():
        response.headers[key] = value
    return response


@app.middleware("http")
async def no_store_dashboard_pages(request: Request, call_next):
    response = await call_next(request)
    if request.url.path != "/health":
        _apply_security_headers(response)
    return response


# ── minimal JWT (HS256, no external deps) ────────────────────────────────────

import base64, struct

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _sign(payload: dict) -> str:
    header  = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    body    = _b64url(json.dumps(payload).encode())
    signing_input = f"{header}.{body}".encode()
    sig = hmac.new(PRAMAGENT_JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url(sig)}"

def _verify(token: str, *, check_revocation: bool = True) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        signing_input = f"{header}.{body}".encode()
        expected = _b64url(
            hmac.new(PRAMAGENT_JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        )
        if not hmac.compare_digest(expected, sig):
            return None
        # decode payload
        padded = body + "=" * (4 - len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if payload.get("exp", 0) < time.time():
            return None
        if check_revocation and payload.get("jti") and _is_session_revoked(payload["jti"]):
            return None
        return payload
    except Exception:
        return None


# ── auth dependency ───────────────────────────────────────────────────────────

class AuthContext:
    def __init__(
        self,
        username: str,
        tenant: str,
        *,
        csrf_token: str = "",
        auth_method: str = "cookie",
        role: str = "admin",
        user_id: str = "",
    ):
        self.username = username
        self.tenant   = tenant          # "*" = all tenants
        self.csrf_token = csrf_token
        self.auth_method = auth_method
        self.role = role
        self.user_id = user_id
    def scope(self, tenant_id: str) -> bool:
        return self.tenant == "*" or self.tenant == tenant_id


def _get_auth(request: Request) -> Optional[AuthContext]:
    # 1. X-API-Key header (CLI / curl usage)
    key = request.headers.get("X-API-Key", "")
    if key and PRAMAGENT_DASHBOARD_KEY and hmac.compare_digest(key, PRAMAGENT_DASHBOARD_KEY):
        return AuthContext("api_key_user", PRAMAGENT_DASHBOARD_TENANT, auth_method="api_key")

    # 2. Cookie session JWT
    token = request.cookies.get("pramagent_session", "")
    if token:
        payload = _verify(token)
        if payload:
            return AuthContext(
                payload.get("sub", ""),
                payload.get("tenant", "*"),
                csrf_token=payload.get("csrf", ""),
                auth_method="cookie",
                role=payload.get("role", "admin"),
                user_id=payload.get("uid", ""),
            )

    return None


def require_auth(request: Request) -> AuthContext:
    ctx = _get_auth(request)
    if ctx is None:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return ctx


def _template_context(ctx: AuthContext, **values):
    base = {
        "user": ctx.username,
        "tenant": ctx.tenant,
        "role": ctx.role,
        "csrf_token": ctx.csrf_token,
    }
    base.update(values)
    return base


def _sign_csrf_body(body: str) -> str:
    return hmac.new(PRAMAGENT_JWT_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()


def _new_preauth_csrf() -> str:
    body = f"{int(time.time())}.{secrets.token_urlsafe(32)}"
    return f"{body}.{_sign_csrf_body(body)}"


def _valid_preauth_csrf(token: str) -> bool:
    try:
        ts, nonce, sig = token.split(".", 2)
        body = f"{ts}.{nonce}"
        if not hmac.compare_digest(_sign_csrf_body(body), sig):
            return False
        issued_at = int(ts)
    except Exception:
        return False
    return 0 <= time.time() - issued_at <= PRAMAGENT_DASHBOARD_CSRF_TTL_S


def _set_preauth_csrf_cookie(response: Response, token: str) -> Response:
    response.set_cookie(
        _PREAUTH_CSRF_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=PRAMAGENT_DASHBOARD_SECURE_COOKIE,
        max_age=PRAMAGENT_DASHBOARD_CSRF_TTL_S,
        path="/",
    )
    return response


def _expire_preauth_csrf_cookie(response: Response) -> Response:
    response.set_cookie(
        _PREAUTH_CSRF_COOKIE,
        "",
        max_age=0,
        expires=0,
        httponly=True,
        samesite="lax",
        secure=PRAMAGENT_DASHBOARD_SECURE_COOKIE,
        path="/",
    )
    return response


def _preauth_template_response(request: Request, template: str, context: dict) -> Response:
    token = request.cookies.get(_PREAUTH_CSRF_COOKIE, "")
    if not _valid_preauth_csrf(token):
        token = _new_preauth_csrf()
    body = dict(context)
    body["csrf_token"] = token
    response = templates.TemplateResponse(request, template, body)
    return _set_preauth_csrf_cookie(response, token)


def require_preauth_csrf(request: Request, supplied: str = "") -> None:
    cookie_token = request.cookies.get(_PREAUTH_CSRF_COOKIE, "")
    if not supplied or not _valid_preauth_csrf(supplied):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")
    if cookie_token and _valid_preauth_csrf(cookie_token):
        if hmac.compare_digest(supplied, cookie_token):
            return
        # Multiple open pre-auth tabs can rotate the cookie while an older
        # signed form token is still within its TTL. The form token is already
        # HMAC-signed and embedded in a same-origin page, so accept it rather
        # than failing legitimate login/signup/reset submissions.
        return


def require_csrf(request: Request, ctx: AuthContext, supplied: str = "") -> None:
    """Require a session-bound CSRF token for cookie-authenticated POSTs."""
    if ctx.auth_method != "cookie":
        return
    token = supplied or request.headers.get("X-CSRF-Token", "")
    if not token:
        token = request.query_params.get("csrf_token", "")
    if not token or not ctx.csrf_token or not hmac.compare_digest(token, ctx.csrf_token):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")


# ── rate limit (Redis-backed when configured, in-process fallback) ────────────

_rl_state: dict[str, tuple[float, float]] = {}  # ip -> (tokens, last_refill)
_revoked_sessions: dict[str, float] = {}        # dashboard session id -> exp
_RL_CAPACITY    = float(os.environ.get("PRAMAGENT_DASHBOARD_RL_CAPACITY", "60"))
_RL_REFILL_S    = float(os.environ.get("PRAMAGENT_DASHBOARD_RL_REFILL", "60"))  # tokens/minute
_REDIS_RETRY_S  = float(os.environ.get("PRAMAGENT_DASHBOARD_REDIS_RETRY_S", "30"))
_REDIS_TIMEOUT_S = float(os.environ.get("PRAMAGENT_DASHBOARD_REDIS_TIMEOUT_S", "0.2"))
_redis_client = None
_redis_unavailable_until = 0.0


def _dashboard_redis():
    global _redis_client, _redis_unavailable_until
    if not PRAMAGENT_DASHBOARD_REDIS_URL:
        return None
    if _redis_client is not None:
        return _redis_client
    now = time.monotonic()
    if now < _redis_unavailable_until:
        return None
    try:
        import redis  # type: ignore
        _redis_client = redis.Redis.from_url(
            PRAMAGENT_DASHBOARD_REDIS_URL,
            decode_responses=True,
            socket_timeout=_REDIS_TIMEOUT_S,
            socket_connect_timeout=_REDIS_TIMEOUT_S,
        )
        _redis_client.ping()
        return _redis_client
    except Exception as exc:
        log.warning("dashboard redis rate limit unavailable; using local bucket: %s", exc)
        _redis_client = None
        _redis_unavailable_until = now + _REDIS_RETRY_S
        return None


def _redis_rate_limit(key: str) -> bool:
    client = _dashboard_redis()
    if client is None:
        return False
    now = time.monotonic()
    redis_key = f"pramagent:dashboard:rl:{key}"
    raw = client.get(redis_key)
    if raw:
        try:
            tokens, last = json.loads(raw)
            tokens = float(tokens)
            last = float(last)
        except Exception:
            tokens, last = _RL_CAPACITY, now
    else:
        tokens, last = _RL_CAPACITY, now
    tokens = min(_RL_CAPACITY, tokens + (now - last) * (_RL_CAPACITY / _RL_REFILL_S))
    if tokens < 1:
        client.set(redis_key, json.dumps([tokens, now]), ex=max(1, int(_RL_REFILL_S * 2)))
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    client.set(redis_key, json.dumps([tokens - 1, now]), ex=max(1, int(_RL_REFILL_S * 2)))
    return True


def _is_session_revoked(jti: str) -> bool:
    client = _dashboard_redis()
    if client is not None:
        try:
            return bool(client.get(f"pramagent:dashboard:revoked:{jti}"))
        except Exception as exc:
            log.warning("dashboard redis session revocation check failed open to local store: %s", exc)

    now = time.time()
    expired = [key for key, exp in _revoked_sessions.items() if exp < now]
    for key in expired:
        _revoked_sessions.pop(key, None)
    return jti in _revoked_sessions


def _revoke_session(jti: str, exp: int | float) -> None:
    ttl = max(1, int(exp - time.time()))
    client = _dashboard_redis()
    if client is not None:
        try:
            client.set(f"pramagent:dashboard:revoked:{jti}", "1", ex=ttl)
            return
        except Exception as exc:
            log.warning("dashboard redis session revocation failed open to local store: %s", exc)
    _revoked_sessions[jti] = float(exp)


def _rate_limit(request: Request) -> None:
    ip = request.client.host if request.client else "unknown"
    try:
        if _redis_rate_limit(ip):
            return
    except HTTPException:
        raise
    except Exception as exc:
        log.warning("dashboard redis rate limit failed open to local bucket: %s", exc)
    now = time.monotonic()
    tokens, last = _rl_state.get(ip, (_RL_CAPACITY, now))
    tokens = min(_RL_CAPACITY, tokens + (now - last) * (_RL_CAPACITY / _RL_REFILL_S))
    if tokens < 1:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    _rl_state[ip] = (tokens - 1, now)


# ── API proxy helpers ─────────────────────────────────────────────────────────

def _upstream_headers() -> dict:
    if not PRAMAGENT_API_KEY:
        return {}
    return {
        "Authorization": f"Bearer {PRAMAGENT_API_KEY}",
        "X-API-Key": PRAMAGENT_API_KEY,
    }


async def _get(path: str, params: Optional[dict] = None) -> dict | list:
    async with httpx.AsyncClient(
        base_url=PRAMAGENT_API_URL,
        timeout=10.0,
        trust_env=False,
    ) as client:
        return await _get_with_client(client, path, params)


async def _get_with_client(
    client: httpx.AsyncClient,
    path: str,
    params: Optional[dict] = None,
) -> dict | list:
    r = await client.get(path, headers=_upstream_headers(), params=params or {})
    r.raise_for_status()
    return r.json()


async def _post(path: str, json_body: dict) -> dict:
    async with httpx.AsyncClient(
        base_url=PRAMAGENT_API_URL,
        timeout=10.0,
        trust_env=False,
    ) as client:
        r = await client.post(path, headers=_upstream_headers(), json=json_body)
        r.raise_for_status()
        return r.json()


def _filter_by_tenant(items: list, ctx: AuthContext) -> list:
    if ctx.tenant == "*":
        return items
    return [t for t in items if t.get("tenant_id") == ctx.tenant]


def _event_value(event, key: str, default=""):
    if isinstance(event, dict):
        return event.get(key, default)
    return getattr(event, key, default)


def _trace_hitl_wait_ms(trace: dict) -> float:
    wait = 0.0
    for event in trace.get("layer_events") or []:
        if str(_event_value(event, "layer", "")).lower() == "hitllayer":
            wait += float(_event_value(event, "latency_ms", 0) or 0)
    return wait


def _trace_engine_latency_ms(trace: dict) -> float:
    if trace.get("engine_latency_ms") is not None:
        return float(trace.get("engine_latency_ms") or 0)
    total = float(trace.get("total_latency_ms") or 0)
    return max(0.0, total - _trace_hitl_wait_ms(trace))


def _decorate_trace_rows(items: list) -> list:
    rows = []
    for item in items:
        trace = dict(item)
        trace["hitl_wait_ms"] = _trace_hitl_wait_ms(trace)
        trace["engine_latency_ms"] = _trace_engine_latency_ms(trace)
        rows.append(trace)
    return rows


def _normalize_metrics(metrics: dict, traces: list | None = None) -> dict:
    """Return dashboard-ready metrics that do not contradict persisted traces.

    The sidecar's ObservabilityLayer is intentionally in-process; after an API
    restart it can report only calls since boot, while the trace browser shows
    persisted history. The dashboard reconciles the summary cards from the same
    trace rows it displays so a BLOCKED trace cannot sit under a 0.0% block
    rate.
    """
    data = dict(metrics or {})

    if "block_rate_pct" not in data:
        data["block_rate_pct"] = float(data.get("block_rate", 0) or 0) * 100

    if traces is not None:
        scoped = list(traces)
        total = len(scoped)
        blocked = sum(1 for item in scoped if item.get("blocked"))
        hitl_holds = sum(
            1 for item in scoped
            if item.get("hitl_status") in {"idle", "denied", "approved"}
        )
        if total:
            data["total_calls"] = total
            data["blocked_calls"] = blocked
            data["hitl_holds"] = hitl_holds
            data["block_rate"] = blocked / total
            data["block_rate_pct"] = (blocked / total) * 100
            latencies = sorted(
                _trace_engine_latency_ms(item)
                for item in scoped
            )
            if latencies:
                p50_index = min(int(0.50 * len(latencies)), len(latencies) - 1)
                p95_index = min(int(0.95 * len(latencies)), len(latencies) - 1)
                data["p50_latency_ms"] = latencies[p50_index]
                data["p95_latency_ms"] = latencies[p95_index]
                data["p50_engine_latency_ms"] = latencies[p50_index]
                data["p95_engine_latency_ms"] = latencies[p95_index]
            data["total_cost_usd"] = sum(
                float(item.get("provider_cost_usd") or 0)
                for item in scoped
            )

    return data


async def _dashboard_metrics_and_traces(
    ctx: AuthContext,
    trace_params: Optional[dict] = None,
) -> tuple[dict, list]:
    params = {"limit": PRAMAGENT_DASHBOARD_STATS_TRACE_LIMIT}
    if trace_params:
        params.update(trace_params)
    metrics_result, traces_result = await asyncio.gather(
        _get("/metrics"),
        _get("/traces", params),
        return_exceptions=True,
    )

    metrics = (
        {"error": str(metrics_result)}
        if isinstance(metrics_result, Exception)
        else metrics_result
    )
    if not isinstance(metrics, dict):
        metrics = {"error": "Unexpected metrics response"}

    if isinstance(traces_result, Exception):
        return _normalize_metrics(metrics), []
    items = traces_result if isinstance(traces_result, list) else traces_result.get("items", [])
    traces = _decorate_trace_rows(_filter_by_tenant(items, ctx))
    return _normalize_metrics(metrics, traces), traces


_APPROVER_ROLES = {"approver", "admin"}


def _require_approver_role(ctx: AuthContext) -> None:
    """A3: the dashboard role model was defined (viewer/approver/auditor/
    admin) but never enforced — approve/deny gated only on auth + tenant +
    CSRF, so a viewer or auditor could approve consequential actions. Only
    approver/admin may decide."""
    if ctx.role not in _APPROVER_ROLES:
        raise HTTPException(
            status_code=403,
            detail="Your role is not permitted to approve or deny requests",
        )


async def _require_pending_approval_scope(request_id: str, ctx: AuthContext) -> None:
    """Authorize approve/deny against the dashboard tenant scope."""
    if ctx.tenant == "*":
        return
    try:
        data = await _get("/hitl/pending")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    items = data if isinstance(data, list) else data.get("items", [])
    for item in items:
        rid = item.get("request_id") or item.get("id")
        if rid == request_id:
            context = item.get("context") or {}
            tenant_id = item.get("tenant_id") or context.get("tenant_id") or context.get("tenant") or ""
            if ctx.scope(tenant_id):
                return
            raise HTTPException(status_code=403, detail="Access denied")
    raise HTTPException(status_code=404, detail="Approval request not found")


# ── health (no auth) ──────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "ts": time.time()}


# ── login / logout ────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    return _preauth_template_response(request, "login.html", {
        "error": error,
        "signup_enabled": PRAMAGENT_DASHBOARD_SIGNUP_ENABLED and _user_store is not None,
        "password_reset_enabled": PRAMAGENT_DASHBOARD_PASSWORD_RESET_ENABLED and _user_store is not None,
    })


def _session_response(user: DashboardUser | None, username: str = "") -> RedirectResponse:
    if user is not None:
        subject = user.username
        tenant = user.tenant_id
        role = user.role
        user_id = user.id
    else:
        subject = username
        tenant = PRAMAGENT_DASHBOARD_TENANT
        role = "admin"
        user_id = ""

    payload = {
        "sub": subject,
        "tenant": tenant,
        "role": role,
        "uid": user_id,
        "jti": str(uuid.uuid4()),
        "csrf": secrets.token_urlsafe(32),
        "iat": int(time.time()),
        "exp": int(time.time()) + SESSION_TTL_S,
    }
    token = _sign(payload)
    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie(
        "pramagent_session", token,
        httponly=True, samesite="lax", secure=PRAMAGENT_DASHBOARD_SECURE_COOKIE,
        max_age=SESSION_TTL_S,
    )
    _expire_preauth_csrf_cookie(resp)
    return resp


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    _rl=Depends(_rate_limit),
):
    require_preauth_csrf(request, csrf_token)
    if _user_store is not None:
        user = _user_store.authenticate(username, password)
        if user is not None:
            return _session_response(user)

    # Fallback: password == PRAMAGENT_DASHBOARD_KEY (hashed compare). Off
    # unless explicitly enabled — anyone holding the shared key otherwise
    # gets an admin browser session, not just the documented X-API-Key
    # header path this flag does not affect.
    if not PRAMAGENT_DASHBOARD_ALLOW_SHARED_KEY_LOGIN:
        return RedirectResponse("/login?error=Invalid+credentials", status_code=302)
    if not PRAMAGENT_DASHBOARD_KEY or not hmac.compare_digest(
        hashlib.sha256(password.encode()).hexdigest(),
        hashlib.sha256(PRAMAGENT_DASHBOARD_KEY.encode()).hexdigest(),
    ):
        return RedirectResponse("/login?error=Invalid+credentials", status_code=302)

    log.warning(
        "dashboard login via shared-key fallback (PRAMAGENT_DASHBOARD_ALLOW_SHARED_KEY_LOGIN) "
        "for username=%r — this session is not tied to a specific user account",
        username,
    )
    # Scope the session from config. Use "*" only for a deliberate super-admin.
    return _session_response(None, username=username)


def _require_user_store() -> DashboardUserStore:
    if _user_store is None:
        raise HTTPException(status_code=404, detail="Dashboard user store is not configured")
    return _user_store


@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request, error: str = ""):
    if not PRAMAGENT_DASHBOARD_SIGNUP_ENABLED:
        raise HTTPException(status_code=404, detail="Signup is disabled")
    _require_user_store()
    return _preauth_template_response(request, "signup.html", {
        "error": error,
        "tenant": PRAMAGENT_DASHBOARD_SIGNUP_TENANT,
    })


@app.post("/signup")
async def signup(
    request: Request,
    email: str = Form(""),
    phone: str = Form(""),
    csrf_token: str = Form(""),
    _rl=Depends(_rate_limit),
):
    require_preauth_csrf(request, csrf_token)
    if not PRAMAGENT_DASHBOARD_SIGNUP_ENABLED:
        raise HTTPException(status_code=404, detail="Signup is disabled")
    store = _require_user_store()
    try:
        issue = store.create_user_with_key(
            email=email,
            phone=phone,
            tenant_id=PRAMAGENT_DASHBOARD_SIGNUP_TENANT,
            role=PRAMAGENT_DASHBOARD_DEFAULT_ROLE,
        )
    except DashboardAuthError as exc:
        return RedirectResponse(f"/signup?error={quote_plus(str(exc))}", status_code=302)
    return templates.TemplateResponse(request, "key_issued.html", {
        "title": "Dashboard key generated",
        "message": "Save this key now. Pramagent stores only a bcrypt hash and cannot show it again.",
        "dashboard_key": issue.key,
        "identity": issue.user.email or issue.user.phone,
        "tenant": issue.user.tenant_id,
    })


@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request, message: str = "", error: str = ""):
    if not PRAMAGENT_DASHBOARD_PASSWORD_RESET_ENABLED:
        raise HTTPException(status_code=404, detail="Password reset is disabled")
    _require_user_store()
    return _preauth_template_response(request, "forgot_password.html", {
        "message": message,
        "error": error,
    })


@app.post("/forgot-password", response_class=HTMLResponse)
async def forgot_password(
    request: Request,
    identity: str = Form(...),
    csrf_token: str = Form(""),
    _rl=Depends(_rate_limit),
):
    require_preauth_csrf(request, csrf_token)
    if not PRAMAGENT_DASHBOARD_PASSWORD_RESET_ENABLED:
        raise HTTPException(status_code=404, detail="Password reset is disabled")
    store = _require_user_store()
    token = store.create_reset_token(identity, ttl_s=PRAMAGENT_DASHBOARD_RESET_TOKEN_TTL_S)
    context = {
        "message": "If that account exists, a verification link has been prepared.",
        "error": "",
    }
    if token and PRAMAGENT_DASHBOARD_RESET_SHOW_TOKEN:
        context["reset_token"] = token
    return _preauth_template_response(request, "forgot_password.html", context)


@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request, token: str = "", error: str = ""):
    if not PRAMAGENT_DASHBOARD_PASSWORD_RESET_ENABLED:
        raise HTTPException(status_code=404, detail="Password reset is disabled")
    _require_user_store()
    return _preauth_template_response(request, "reset_password.html", {
        "token": token,
        "error": error,
        "message": "",
    })


@app.post("/reset-password", response_class=HTMLResponse)
async def reset_password(
    request: Request,
    token: str = Form(...),
    csrf_token: str = Form(""),
    _rl=Depends(_rate_limit),
):
    require_preauth_csrf(request, csrf_token)
    if not PRAMAGENT_DASHBOARD_PASSWORD_RESET_ENABLED:
        raise HTTPException(status_code=404, detail="Password reset is disabled")
    store = _require_user_store()
    issue = store.regenerate_key(token)
    if not issue:
        return _preauth_template_response(request, "reset_password.html", {
            "token": token,
            "error": "Verification token is invalid or expired",
            "message": "",
        })
    return templates.TemplateResponse(request, "key_issued.html", {
        "title": "New dashboard key generated",
        "message": "Your old key has been replaced. Save this new key now.",
        "dashboard_key": issue.key,
        "identity": issue.user.email or issue.user.phone,
        "tenant": issue.user.tenant_id,
    })


def _expire_session_cookie(resp: Response) -> Response:
    resp.set_cookie(
        "pramagent_session",
        "",
        max_age=0,
        expires=0,
        path="/",
        httponly=True,
        samesite="lax",
        secure=PRAMAGENT_DASHBOARD_SECURE_COOKIE,
    )
    return resp


def _logout_response(request: Request) -> RedirectResponse:
    token = request.cookies.get("pramagent_session", "")
    if token:
        payload = _verify(token, check_revocation=False)
        if payload and payload.get("jti"):
            _revoke_session(payload["jti"], payload.get("exp", time.time() + SESSION_TTL_S))
    resp = RedirectResponse("/login", status_code=303)
    _expire_session_cookie(resp)
    return resp


@app.post("/logout")
async def logout(
    request: Request,
    csrf_token: str = Form(""),
    ctx: AuthContext = Depends(require_auth),
):
    require_csrf(request, ctx, supplied=csrf_token)
    return _logout_response(request)


# ── overview ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def overview(
    request: Request,
    ctx: AuthContext = Depends(require_auth),
    _rl=Depends(_rate_limit),
):
    metrics, scoped_traces = await _dashboard_metrics_and_traces(ctx)
    return templates.TemplateResponse(request, "overview.html", _template_context(
        ctx,
        metrics=metrics,
        recent_traces=scoped_traces[-5:],
        api_url=PRAMAGENT_API_URL,
    ))


# ── traces ────────────────────────────────────────────────────────────────────

@app.get("/traces", response_class=HTMLResponse)
async def trace_browser(
    request: Request,
    tenant_id: str = "",
    session_id: str = "",
    blocked: str = "",
    limit: int = 50,
    ctx: AuthContext = Depends(require_auth),
    _rl=Depends(_rate_limit),
):
    # Enforce tenant scope from JWT
    effective_tenant = tenant_id if ctx.tenant == "*" else ctx.tenant
    params = {"limit": limit}
    if effective_tenant:
        params["tenant_id"] = effective_tenant
    if session_id:
        params["session_id"] = session_id
    if blocked:
        params["blocked"] = blocked
    try:
        data = await _get("/traces", params)
    except Exception as exc:
        data = {"items": [], "error": str(exc)}
    traces = data if isinstance(data, list) else data.get("items", [])
    traces = _decorate_trace_rows(_filter_by_tenant(traces, ctx))
    return templates.TemplateResponse(request, "traces.html", _template_context(
        ctx,
        traces=traces,
        tenant_id=effective_tenant,
        session_id=session_id,
        blocked=blocked,
    ))


@app.get("/traces/{trace_id}", response_class=HTMLResponse)
async def trace_detail(
    request: Request,
    trace_id: str,
    ctx: AuthContext = Depends(require_auth),
    _rl=Depends(_rate_limit),
):
    try:
        trace = await _get(f"/traces/{trace_id}")
    except httpx.HTTPStatusError:
        raise HTTPException(status_code=404, detail="Trace not found")
    # Tenant scope check
    if not ctx.scope(trace.get("tenant_id", "")):
        raise HTTPException(status_code=403, detail="Access denied")
    trace = _decorate_trace_rows([trace])[0]
    return templates.TemplateResponse(request, "trace_detail.html", _template_context(ctx, trace=trace))


# ── approvals ─────────────────────────────────────────────────────────────────

@app.get("/approvals", response_class=HTMLResponse)
async def approvals(
    request: Request,
    ctx: AuthContext = Depends(require_auth),
    _rl=Depends(_rate_limit),
):
    try:
        data = await _get("/hitl/pending")
    except Exception as exc:
        data = {"items": [], "error": str(exc)}
    items = data if isinstance(data, list) else data.get("items", [])
    return templates.TemplateResponse(request, "approvals.html", _template_context(
        ctx,
        approvals=_filter_by_tenant(items, ctx),
    ))


@app.post("/approvals/{request_id}/approve", response_class=HTMLResponse)
async def approve(
    request: Request,
    request_id: str,
    ctx: AuthContext = Depends(require_auth),
):
    require_csrf(request, ctx)
    try:
        _require_approver_role(ctx)
        await _require_pending_approval_scope(request_id, ctx)
        await _post(f"/hitl/{request_id}/decide", {"approved": True})
        msg, cls = "Approved", "badge-ok"
    except Exception as exc:
        msg, cls = f"Error: {exc}", "badge-block"
    # Upstream error bodies can carry markup — escape before rendering (T2-1)
    return HTMLResponse(f'<span class="badge {cls}">{html.escape(msg)}</span>')


@app.post("/approvals/{request_id}/deny", response_class=HTMLResponse)
async def deny(
    request: Request,
    request_id: str,
    ctx: AuthContext = Depends(require_auth),
):
    require_csrf(request, ctx)
    try:
        _require_approver_role(ctx)
        await _require_pending_approval_scope(request_id, ctx)
        await _post(f"/hitl/{request_id}/decide", {"approved": False})
        msg, cls = "Denied", "badge-block"
    except Exception as exc:
        msg, cls = f"Error: {exc}", "badge-block"
    # Upstream error bodies can carry markup — escape before rendering (T2-1)
    return HTMLResponse(f'<span class="badge {cls}">{html.escape(msg)}</span>')


# ── metrics ───────────────────────────────────────────────────────────────────

@app.get("/metrics", response_class=HTMLResponse)
async def metrics_page(
    request: Request,
    ctx: AuthContext = Depends(require_auth),
    _rl=Depends(_rate_limit),
):
    data, _ = await _dashboard_metrics_and_traces(ctx)
    return templates.TemplateResponse(request, "metrics.html", _template_context(ctx, metrics=data))


@app.get("/usage", response_class=HTMLResponse)
async def usage_page(
    request: Request,
    tenant_id: str = "",
    ctx: AuthContext = Depends(require_auth),
    _rl=Depends(_rate_limit),
):
    effective_tenant = tenant_id if ctx.tenant == "*" else ctx.tenant
    if not effective_tenant:
        effective_tenant = "default"
    try:
        usage = await _get("/usage", {"tenant_id": effective_tenant})
    except Exception as exc:
        usage = {"error": str(exc)}
    metrics, _ = await _dashboard_metrics_and_traces(ctx, {"tenant_id": effective_tenant})
    return templates.TemplateResponse(request, "usage.html", _template_context(
        ctx,
        usage=usage,
        metrics=metrics,
        tenant_id=effective_tenant,
    ))


@app.get("/metrics/fragment", response_class=HTMLResponse)
async def metrics_fragment(
    request: Request,
    ctx: AuthContext = Depends(require_auth),
):
    data, _ = await _dashboard_metrics_and_traces(ctx)
    return templates.TemplateResponse(request, "metrics_fragment.html", _template_context(ctx, metrics=data))


@app.get("/audit/verify", response_class=HTMLResponse)
async def audit_verify_page(
    request: Request,
    ctx: AuthContext = Depends(require_auth),
    _rl=Depends(_rate_limit),
):
    started = time.perf_counter()
    try:
        data = await _get("/v1/audit/verify")
        if not isinstance(data, dict):
            data = {"chain_valid": False, "error": "Unexpected audit response"}
    except Exception as exc:
        data = {"chain_valid": False, "error": str(exc)}
    data["verify_latency_ms"] = (time.perf_counter() - started) * 1000
    return templates.TemplateResponse(
        request,
        "audit_verify.html",
        _template_context(ctx, audit=data),
    )


# ── export ────────────────────────────────────────────────────────────────────

@app.get("/export/traces.csv")
async def export_csv(
    request: Request,
    ctx: AuthContext = Depends(require_auth),
    _rl=Depends(_rate_limit),
):
    """Export trace list as CSV for compliance."""
    import csv, io

    def csv_value(value):
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            value = json.dumps(value, sort_keys=True)
        if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t"):
            return "'" + value          # neutralize spreadsheet formulas (T2-1)
        return value

    params: dict = {"limit": 10000}
    if ctx.tenant != "*":
        params["tenant_id"] = ctx.tenant
    try:
        data = await _get("/traces", params)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    traces = data if isinstance(data, list) else data.get("items", [])
    traces = _filter_by_tenant(traces, ctx)

    buf = io.StringIO()
    fieldnames = [
        "created_at",
        "call_id",
        "this_hash",
        "prev_hash",
        "tenant_id",
        "session_id",
        "action",
        "input_text",
        "output_text",
        "blocked",
        "block_reason",
        "pre_verdict",
        "post_verdict",
        "hitl_status",
        "provider",
        "provider_model",
        "provider_cost_usd",
        "total_latency_ms",
    ]
    w = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for t in traces:
        w.writerow({field: csv_value(t.get(field)) for field in fieldnames})
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="pramagent_traces.csv"',
            "Cache-Control": _NO_STORE_HEADERS["Cache-Control"],
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )
