"""Slack-backed human approval adapter.

In single-process deployments the default InProcessBackend works fine.
For multi-worker / multi-instance production deployments, pass a RedisBackend
so approval callbacks can land on any worker::

    from pramagent.backends import RedisBackend
    from pramagent.hitl.slack import SlackApprovalRegistry

    backend  = RedisBackend.from_url(os.environ["REDIS_URL"])
    registry = SlackApprovalRegistry(backend=backend)

The registry interface is identical regardless of backend.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from ..security import validate_http_url


# F2: Slack broadcast / mention tokens. Stripped from untrusted text before
# escaping so an attacker-controlled action/tenant/preview cannot ping a whole
# channel (@channel/@here) or a user via the approval card.
_SLACK_BROADCAST_RE = re.compile(
    r"<!(?:channel|here|everyone)>|<@[A-Za-z0-9]+>", re.IGNORECASE)


def escape_slack_mrkdwn(text: str) -> str:
    """Neutralize Slack mrkdwn control characters and broadcast/mention tokens
    in untrusted text (tool output preview, action, tenant), so a crafted value
    cannot inject formatting, break out of a code span, or notify a channel
    when the approval card renders (F2). Per Slack's guidance the three chars
    &, <, > are the only ones that must be HTML-escaped in message text;
    backticks are dropped so a value cannot escape an enclosing code span."""
    text = _SLACK_BROADCAST_RE.sub("", text)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("`", "'")


log = logging.getLogger(__name__)


def verify_slack_signature(signing_secret: str, *,
                           timestamp: str, body: bytes,
                           signature: str,
                           max_skew_s: int = 300) -> bool:
    """Verify a Slack request signature per
    https://api.slack.com/authentication/verifying-requests-from-slack.

    Returns True iff the signature matches AND the timestamp is within
    ``max_skew_s`` of now. Replay protection comes from rejecting old
    timestamps.

    Parameters
    ----------
    signing_secret : str
        ``Slack App > Basic Info > Signing Secret``.
    timestamp : str
        Value of the ``X-Slack-Request-Timestamp`` header.
    body : bytes
        Raw request body (must be the bytes exactly as Slack sent them).
    signature : str
        Value of the ``X-Slack-Signature`` header (begins with ``v0=``).
    max_skew_s : int
        Reject timestamps older than this. Default 5 minutes (Slack's recommendation).
    """
    if not signing_secret or not timestamp or not signature:
        return False
    try:
        ts_int = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(time.time() - ts_int) > max_skew_s:
        return False
    if isinstance(body, str):
        body = body.encode("utf-8")
    basestring = f"v0:{timestamp}:".encode("utf-8") + body
    digest = hmac.new(
        signing_secret.encode("utf-8"), basestring, hashlib.sha256
    ).hexdigest()
    expected = f"v0={digest}"
    return hmac.compare_digest(expected, signature)


class SlackApprovalError(RuntimeError):
    pass


@dataclass
class PendingApproval:
    request_id: str
    action: str
    context: dict[str, Any]
    created_at: float = field(default_factory=time.time)
    decision: Optional[bool] = None
    # A4: who approved/denied. Empty until decide() records it.
    decided_by: str = ""
    # Only used by InProcessBackend path — RedisBackend uses its own wait()
    event: asyncio.Event = field(default_factory=asyncio.Event)


class SlackMessageClient(Protocol):
    async def post_approval(
        self,
        *,
        channel: str,
        request_id: str,
        action: str,
        context: dict[str, Any],
        public_url: str,
    ) -> Optional[dict[str, Any]]:
        ...

    async def update_message(
        self,
        *,
        channel: str,
        ts: str,
        text: str,
        blocks: list[dict[str, Any]],
    ) -> None:
        ...


class SlackApprovalRegistry:
    """Tracks pending approval requests.

    Backed by an AbstractBackend (in-process by default, Redis for prod).
    """

    def __init__(self, backend: Optional[Any] = None) -> None:
        from ..backends import InProcessBackend
        self._backend = backend or InProcessBackend()
        # in-process fallback for legacy callers that rely on PendingApproval objects
        self._pending: dict[str, PendingApproval] = {}

    def create(self, action: str, context: dict[str, Any]) -> PendingApproval:
        request = PendingApproval(
            request_id=str(uuid.uuid4()),
            action=action,
            context=dict(context),
        )
        self._pending[request.request_id] = request
        # also write to backend so other workers can resolve it
        self._backend.set(
            f"hitl:{request.request_id}",
            {"action": action, "context": context, "created_at": request.created_at},
            ttl_s=3600,
        )
        return request

    async def wait(self, request_id: str, *, timeout_s: float = 300.0) -> Optional[bool]:
        # Try the distributed backend first (works across workers).
        val = await self._backend.wait(f"hitl:decision:{request_id}", timeout_s=timeout_s)
        if val is not None:
            return bool(val)
        # Fall back to in-process event for single-process use.
        request = self._pending.get(request_id)
        if request is None:
            return None
        try:
            await asyncio.wait_for(request.event.wait(), timeout=timeout_s)
        except asyncio.TimeoutError:
            return None
        return request.decision

    def decide(self, request_id: str, approved: bool,
               *, decided_by: str = "") -> bool:
        # "Found" means this process knows the request OR the shared backend
        # still holds it (created by another worker). An unknown/expired id
        # now genuinely reports not-found, so the Slack "expired" reply path
        # is reachable (P3-10).
        known_in_backend = False
        try:
            known_in_backend = self._backend.get(f"hitl:{request_id}") is not None
        except Exception:
            known_in_backend = False
        # A4: persist WHO decided, cross-worker, alongside the decision signal
        # so the audit trail records the approver identity, not just the
        # boolean outcome. Best-effort — never let recording the actor block
        # the decision itself.
        if decided_by:
            try:
                self._backend.set(f"hitl:decided_by:{request_id}",
                                  {"decided_by": decided_by}, ttl_s=3600)
            except Exception as exc:
                log.warning("could not persist approver identity for %s: %s",
                            request_id, exc)
        # Signal via backend (visible to all workers; harmless for unknown ids).
        self._backend.signal(f"hitl:decision:{request_id}", int(approved))
        self._backend.delete(f"hitl:{request_id}")
        # Also resolve in-process for same-process callbacks.
        request = self._pending.get(request_id)
        if request is not None:
            request.decision = approved
            request.decided_by = decided_by
            request.event.set()
            return True
        return known_in_backend

    def discard(self, request_id: str) -> None:
        self._pending.pop(request_id, None)
        self._backend.delete(f"hitl:{request_id}")


class HTTPSlackMessageClient:
    """Minimal Slack Web API client using the standard library."""

    def __init__(self, bot_token: str):
        self.bot_token = bot_token

    async def post_approval(
        self,
        *,
        channel: str,
        request_id: str,
        action: str,
        context: dict[str, Any],
        public_url: str,
    ) -> Optional[dict[str, Any]]:
        return await asyncio.to_thread(
            self._post_approval_sync,
            channel=channel,
            request_id=request_id,
            action=action,
            context=context,
            public_url=public_url,
        )

    async def update_message(
        self,
        *,
        channel: str,
        ts: str,
        text: str,
        blocks: list[dict[str, Any]],
    ) -> None:
        await asyncio.to_thread(
            self._update_message_sync,
            channel=channel,
            ts=ts,
            text=text,
            blocks=blocks,
        )

    def _post_approval_sync(
        self,
        *,
        channel: str,
        request_id: str,
        action: str,
        context: dict[str, Any],
        public_url: str,
    ) -> dict[str, Any]:
        # F2: every value below is interpolated into Slack mrkdwn; escape the
        # untrusted ones (action label, tenant, and especially the free-text
        # output preview) so they cannot inject formatting or channel pings.
        action = escape_slack_mrkdwn(str(action))
        tenant = escape_slack_mrkdwn(str(context.get("tenant", "unknown")))
        preview = escape_slack_mrkdwn(str(context.get("output_preview", ""))[:240])
        body = {
            "channel": channel,
            "text": f"Pramagent approval requested for {action}",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Pramagent approval requested*\n"
                            f"*Action:* `{action}`\n"
                            f"*Tenant:* `{tenant}`\n"
                            f"*Preview:* {preview or '_empty_'}"
                        ),
                    },
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Approve"},
                            "style": "primary",
                            "action_id": "pramagent_approve",
                            "value": request_id,
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Deny"},
                            "style": "danger",
                            "action_id": "pramagent_deny",
                            "value": request_id,
                        },
                    ],
                },
            ],
        }
        data = json.dumps(body).encode("utf-8")
        url = validate_http_url("https://slack.com/api/chat.postMessage", context="Slack API URL")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.bot_token}",
                "Content-Type": "application/json; charset=utf-8",
            },
            method="POST",
        )
        try:
            # Slack API URL is validated immediately above.
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError) as exc:
            raise SlackApprovalError(f"failed to post Slack approval: {exc}") from exc
        if not payload.get("ok"):
            raise SlackApprovalError(
                f"Slack rejected approval message: {payload.get('error', 'unknown_error')}"
            )
        return payload

    def _update_message_sync(
        self,
        *,
        channel: str,
        ts: str,
        text: str,
        blocks: list[dict[str, Any]],
    ) -> None:
        body = {
            "channel": channel,
            "ts": ts,
            "text": text,
            "blocks": blocks,
        }
        data = json.dumps(body).encode("utf-8")
        url = validate_http_url("https://slack.com/api/chat.update", context="Slack API URL")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.bot_token}",
                "Content-Type": "application/json; charset=utf-8",
            },
            method="POST",
        )
        try:
            # Slack API URL is validated immediately above.
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError) as exc:
            raise SlackApprovalError(f"failed to update Slack approval: {exc}") from exc
        if not payload.get("ok"):
            raise SlackApprovalError(
                f"Slack rejected approval update: {payload.get('error', 'unknown_error')}"
            )


class SlackHITLApprover:
    """Async callable compatible with HITLLayer's approver hook."""

    def __init__(
        self,
        *,
        bot_token: str,
        channel_id: str,
        signing_secret: str,
        public_url: str,
        registry: Optional[SlackApprovalRegistry] = None,
        client: Optional[SlackMessageClient] = None,
    ):
        self.channel_id = channel_id
        self.signing_secret = signing_secret
        self.public_url = public_url.rstrip("/")
        self.registry = registry or SlackApprovalRegistry()
        self.client = client or HTTPSlackMessageClient(bot_token)
        self.last_error: str = ""
        self._message_refs: dict[str, tuple[str, str]] = {}

    async def __call__(self, action: str, context: dict[str, Any]) -> Optional[bool]:
        request = self.registry.create(action, context)
        try:
            try:
                posted = await self.client.post_approval(
                    channel=self.channel_id,
                    request_id=request.request_id,
                    action=action,
                    context=context,
                    public_url=self.public_url,
                )
                if isinstance(posted, dict) and posted.get("ts"):
                    self._message_refs[request.request_id] = (
                        str(posted.get("channel") or self.channel_id),
                        str(posted["ts"]),
                    )
            except SlackApprovalError as exc:
                self.last_error = str(exc)
                log.warning("Slack HITL approval post failed: %s", exc)
                return None
            self.last_error = ""
            return await self.registry.wait(request.request_id)
        finally:
            self.registry.discard(request.request_id)

    def handle_action_payload(self, payload: dict[str, Any]) -> tuple[bool, str]:
        actions = payload.get("actions") or []
        if not actions:
            raise SlackApprovalError("Slack payload did not include an action")
        action = actions[0]
        request_id = action.get("value")
        action_id = action.get("action_id")
        if not request_id:
            raise SlackApprovalError("Slack action did not include a request id")
        if action_id == "pramagent_approve":
            approved = True
        elif action_id == "pramagent_deny":
            approved = False
        else:
            raise SlackApprovalError(f"unknown Slack action: {action_id}")
        # A4: record the Slack user who clicked, so the audit trail attributes
        # the approval to a person, not just "someone on Slack".
        user = payload.get("user") or {}
        actor = str(user.get("username") or user.get("name") or user.get("id") or "")
        decided_by = f"slack:{actor}" if actor else "slack:unknown"
        found = self.registry.decide(request_id, approved, decided_by=decided_by)
        return found, "approved" if approved else "denied"

    async def update_original_message(self, payload: dict[str, Any], status: str, *, found: bool) -> None:
        """Remove approval buttons from the original Slack message.

        Returning ``replace_original`` is not reliable across all Slack clients
        and Block Kit interaction paths. ``chat.update`` directly edits the
        message that contained the clicked button.
        """
        response = slack_decision_response(status, found=found)
        channel = (
            (payload.get("channel") or {}).get("id")
            or (payload.get("container") or {}).get("channel_id")
        )
        message_ts = (
            ((payload.get("message") or {}).get("ts"))
            or (payload.get("container") or {}).get("message_ts")
        )
        request_id = ((payload.get("actions") or [{}])[0] or {}).get("value")
        if request_id and (not channel or not message_ts):
            ref = self._message_refs.get(request_id)
            if ref:
                channel, message_ts = ref
        if not channel or not message_ts:
            self.last_error = "Slack action payload did not include channel/message timestamp"
            log.warning(self.last_error)
            return
        update = getattr(self.client, "update_message", None)
        if update is None:
            self.last_error = "Slack client does not support message updates"
            log.warning(self.last_error)
            return
        try:
            await update(
                channel=channel,
                ts=message_ts,
                text=response["text"],
                blocks=response["blocks"],
            )
            if request_id:
                self._message_refs.pop(request_id, None)
            self.last_error = ""
        except SlackApprovalError as exc:
            self.last_error = str(exc)
            log.warning("Slack HITL approval update failed: %s", exc)


def slack_decision_response(status: str, *, found: bool = True) -> dict[str, Any]:
    """Build a Slack interactive-response body that removes stale buttons.

    Slack keeps interactive button blocks visible unless the callback returns a
    replacement message or separately calls chat.update. Returning
    replace_original is the fastest reliable acknowledgement path.
    """
    if not found:
        return {
            "replace_original": True,
            "text": "Pramagent approval request expired.",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Pramagent approval expired*\nThis request is no longer pending.",
                    },
                }
            ],
        }

    label = "Approved" if status == "approved" else "Denied"
    return {
        "replace_original": True,
        "text": f"Pramagent request {status}.",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Pramagent request {label.lower()}*\nDecision recorded. Action: `{status}`.",
                },
            }
        ],
    }


def verify_slack_signature(
    *,
    signing_secret: str,
    timestamp: str,
    body: bytes,
    signature: str,
    tolerance_s: int = 300,
) -> bool:
    """Validate Slack's v0 request signature."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(time.time() - ts) > tolerance_s:
        return False
    base = b"v0:" + str(ts).encode("ascii") + b":" + body
    expected = "v0=" + hmac.new(
        signing_secret.encode("utf-8"), base, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature or "")
