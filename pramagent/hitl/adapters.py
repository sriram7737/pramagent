"""
pramagent.hitl.adapters
=======================
Notification + approval adapters for the HITL layer. Each adapter is an async
callable ``(action: str, context: dict) -> Optional[bool]`` compatible with
HITLLayer / HITLWorkflowLayer's ``approver`` hook, OR a fire-and-forget
notifier used to *alert* humans while another channel collects the decision.

Adapters here
-------------
WebhookApprover
    POSTs the approval request to an arbitrary HTTPS endpoint and (optionally)
    polls a decision endpoint. Useful for custom internal tools. Fail-closed:
    a delivery error returns None (idle), never an implicit approve.

EmailNotifier
    Sends an approval-request email via SMTP. Notify-only by default (returns
    None) — pair it with a SlackApprovalRegistry or WebhookApprover to collect
    the actual decision. Stdlib smtplib, no third-party deps.

PagerDutyNotifier
    Triggers a PagerDuty Events API v2 alert for high-severity actions. Notify
    -only (returns None). For on-call escalation, not decision collection.

CompositeApprover
    Fans an approval request to several notifiers (alerting) while delegating
    the *decision* to one authoritative approver. This is the production
    pattern: alert PagerDuty + email, decide via Slack.

All network I/O uses the stdlib (urllib / smtplib) wrapped in asyncio.to_thread
so the event loop is never blocked, and every adapter degrades gracefully.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import smtplib
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any, Awaitable, Callable, Optional

from ..security import validate_http_url

log = logging.getLogger(__name__)

ApproverCallable = Callable[[str, dict], Awaitable[Optional[bool]]]


class AdapterError(RuntimeError):
    pass


# webhook approver
class WebhookApprover:
    """POST the request to a webhook; optionally poll for the decision.

    Parameters
    ----------
    notify_url : str
        Endpoint that receives the JSON approval request on every gate().
    decision_url : str, optional
        If set, WebhookApprover polls this URL (GET ``{decision_url}?id=<id>``)
        until it returns ``{"decision": "approve"|"deny"}`` or the timeout
        elapses. If unset, the adapter is notify-only and returns None.
    timeout_s, poll_interval_s : float
        Polling controls.
    headers : dict
        Extra HTTP headers (auth tokens etc.).
    """

    def __init__(
        self,
        notify_url: str,
        *,
        decision_url: Optional[str] = None,
        timeout_s: float = 300.0,
        poll_interval_s: float = 2.0,
        headers: Optional[dict] = None,
    ) -> None:
        self.notify_url = notify_url
        self.decision_url = decision_url
        self.timeout_s = timeout_s
        self.poll_interval_s = poll_interval_s
        self.headers = headers or {}
        self.last_error: str = ""

    def _post(self, url: str, payload: dict) -> dict:
        url = validate_http_url(
            url,
            allow_http_localhost=True,
            context="WebhookApprover URL",
        )
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json", **self.headers},
        )
        # Webhook URL is validated immediately above.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            body = resp.read().decode("utf-8")
        return json.loads(body) if body.strip() else {}

    def _get(self, url: str) -> dict:
        url = validate_http_url(
            url,
            allow_http_localhost=True,
            context="WebhookApprover decision URL",
        )
        req = urllib.request.Request(url, method="GET", headers=self.headers)
        # Webhook URL is validated immediately above.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            body = resp.read().decode("utf-8")
        return json.loads(body) if body.strip() else {}

    async def __call__(self, action: str, context: dict) -> Optional[bool]:
        request_id = str(context.get("request_id") or int(time.time() * 1000))
        payload = {"request_id": request_id, "action": action, "context": context}
        try:
            await asyncio.to_thread(self._post, self.notify_url, payload)
            self.last_error = ""
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.last_error = str(exc)
            log.warning("WebhookApprover notify failed: %s", exc)
            return None  # fail-closed

        if not self.decision_url:
            return None  # notify-only

        deadline = time.monotonic() + self.timeout_s
        while time.monotonic() < deadline:
            try:
                resp = await asyncio.to_thread(
                    self._get, f"{self.decision_url}?id={request_id}")
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                self.last_error = str(exc)
                resp = {}
            decision = str(resp.get("decision", "")).lower()
            if decision in ("approve", "approved", "true", "yes"):
                return True
            if decision in ("deny", "denied", "false", "no"):
                return False
            await asyncio.sleep(self.poll_interval_s)
        return None  # timeout → idle


# email notifier
@dataclass
class SMTPConfig:
    host: str
    port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True
    from_addr: str = "pramagent@localhost"


class EmailNotifier:
    """Send an approval-request email. Notify-only (returns None).

    Pair with a decision-collecting approver via CompositeApprover.
    """

    def __init__(self, smtp: SMTPConfig, to_addrs: list[str]) -> None:
        self.smtp = smtp
        self.to_addrs = to_addrs
        self.last_error: str = ""

    def _send(self, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.smtp.from_addr
        msg["To"] = ", ".join(self.to_addrs)
        msg.set_content(body)
        with smtplib.SMTP(self.smtp.host, self.smtp.port, timeout=10) as s:
            if self.smtp.use_tls:
                s.starttls()
            if self.smtp.username:
                s.login(self.smtp.username, self.smtp.password)
            s.send_message(msg)

    async def __call__(self, action: str, context: dict) -> Optional[bool]:
        tenant = context.get("tenant", "unknown")
        preview = str(context.get("output_preview", ""))[:300]
        subject = f"[Pramagent] Approval needed: {action} (tenant={tenant})"
        body = (
            f"A Pramagent agent action requires human approval.\n\n"
            f"Action:  {action}\n"
            f"Tenant:  {tenant}\n"
            f"Preview: {preview}\n\n"
            f"Approve or deny via your configured Pramagent approval channel."
        )
        try:
            await asyncio.to_thread(self._send, subject, body)
            self.last_error = ""
        except (smtplib.SMTPException, OSError) as exc:
            self.last_error = str(exc)
            log.warning("EmailNotifier send failed: %s", exc)
        return None  # notify-only


# pagerduty notifier
class PagerDutyNotifier:
    """Trigger a PagerDuty Events API v2 alert. Notify-only (returns None)."""

    _EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, routing_key: str, *, severity: str = "warning",
                 source: str = "pramagent") -> None:
        self.routing_key = routing_key
        self.severity = severity
        self.source = source
        self.last_error: str = ""

    def _trigger(self, action: str, context: dict) -> None:
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"Pramagent approval needed: {action}",
                "source": self.source,
                "severity": self.severity,
                "custom_details": context,
            },
        }
        data = json.dumps(payload).encode("utf-8")
        url = validate_http_url(self._EVENTS_URL, context="PagerDuty Events URL")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        # PagerDuty URL is validated immediately above.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            resp.read()

    async def __call__(self, action: str, context: dict) -> Optional[bool]:
        try:
            await asyncio.to_thread(self._trigger, action, context)
            self.last_error = ""
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.last_error = str(exc)
            log.warning("PagerDutyNotifier trigger failed: %s", exc)
        return None  # notify-only


# composite approver
class ServiceNowNotifier:
    """Create a ServiceNow record for an approval escalation.

    This adapter is notify-only: it creates an incident/task record and returns
    None so the HITL layer waits for the configured decision channel.
    """

    def __init__(
        self,
        instance_url: str,
        *,
        username: str = "",
        password: str = "",
        bearer_token: str = "",
        table: str = "incident",
        category: str = "software",
        urgency: str = "2",
        impact: str = "2",
        assignment_group: str = "",
        timeout_s: float = 10.0,
        extra_fields: Optional[dict[str, Any]] = None,
    ) -> None:
        self.instance_url = instance_url.rstrip("/")
        self.username = username
        self.password = password
        self.bearer_token = bearer_token
        self.table = table.strip("/") or "incident"
        self.category = category
        self.urgency = urgency
        self.impact = impact
        self.assignment_group = assignment_group
        self.timeout_s = timeout_s
        self.extra_fields = dict(extra_fields or {})
        self.last_error: str = ""

    @property
    def endpoint(self) -> str:
        return f"{self.instance_url}/api/now/table/{self.table}"

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        elif self.username or self.password:
            raw = f"{self.username}:{self.password}".encode("utf-8")
            headers["Authorization"] = (
                "Basic " + base64.b64encode(raw).decode("ascii")
            )
        return headers

    def _payload(self, action: str, context: dict) -> dict[str, Any]:
        tenant = context.get("tenant") or context.get("tenant_id") or "unknown"
        request_id = context.get("request_id") or context.get("call_id") or ""
        preview = str(context.get("output_preview") or context.get("preview") or "")[:500]
        details = json.dumps(context, sort_keys=True, default=str)[:4000]
        payload: dict[str, Any] = {
            "short_description": f"Pramagent approval needed: {action}",
            "description": (
                "A Pramagent-protected agent action requires human approval.\n\n"
                f"Action: {action}\n"
                f"Tenant: {tenant}\n"
                f"Request ID: {request_id}\n"
                f"Preview: {preview}\n\n"
                f"Context JSON:\n{details}"
            ),
            "category": self.category,
            "urgency": self.urgency,
            "impact": self.impact,
        }
        if self.assignment_group:
            payload["assignment_group"] = self.assignment_group
        payload.update(self.extra_fields)
        return payload

    def _create_record(self, action: str, context: dict) -> dict:
        data = json.dumps(self._payload(action, context)).encode("utf-8")
        endpoint = validate_http_url(self.endpoint, context="ServiceNow endpoint")
        req = urllib.request.Request(
            endpoint,
            data=data,
            method="POST",
            headers=self._headers(),
        )
        # ServiceNow URL is validated immediately above.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:  # nosec B310
            body = resp.read().decode("utf-8")
            if getattr(resp, "status", 200) >= 400:
                raise AdapterError(f"ServiceNow returned HTTP {resp.status}")
        return json.loads(body) if body.strip() else {}

    async def __call__(self, action: str, context: dict) -> Optional[bool]:
        try:
            await asyncio.to_thread(self._create_record, action, context)
            self.last_error = ""
        except (AdapterError, urllib.error.URLError, TimeoutError, OSError) as exc:
            self.last_error = str(exc)
            log.warning("ServiceNowNotifier create failed: %s", exc)
        return None  # notify-only


class CompositeApprover:
    """Alert via N notifiers, collect the decision from one authoritative approver.

    The production pattern: page PagerDuty + email the team (notify), while the
    actual approve/deny comes back through Slack (decide).

    Example::

        approver = CompositeApprover(
            notifiers=[PagerDutyNotifier(rk), EmailNotifier(smtp, ["sec@co"])],
            decider=slack_approver,
        )
    """

    def __init__(
        self,
        *,
        notifiers: Optional[list[ApproverCallable]] = None,
        decider: Optional[ApproverCallable] = None,
    ) -> None:
        self.notifiers = notifiers or []
        self.decider = decider

    async def __call__(self, action: str, context: dict) -> Optional[bool]:
        # Fire all notifiers concurrently; ignore their (None) return values.
        if self.notifiers:
            await asyncio.gather(
                *[n(action, context) for n in self.notifiers],
                return_exceptions=True,
            )
        if self.decider is None:
            return None
        return await self.decider(action, context)
