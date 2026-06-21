"""
pramagent.layers
================
Trust layers. Each layer is small, single-responsibility, and independently
testable.

Layers shipped here:

    ComplianceLayer    - PII detection + redaction (context-guarded patterns)
    SafetyLayer        - pre/post classifier + deterministic rule engine
    ReliabilityLayer   - semaphore-bounded concurrency + timeout + circuit breaker
    HITLLayer          - propose-and-wait gateway; idle on silence
    ToolGuardLayer     - deterministic pre-execution tool-call policy checks
    IsolationLayer     - tenant-scoped memory + injection heuristics + size limits
                         (see pramagent.layers.isolation)
    ObservabilityLayer - call counters, block rate, p50/p95 latency
                         (see pramagent.layers.observability)

RCAEngine is in pramagent.rca; the audit chain is in pramagent.audit.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

from ..types import HITLStatus, RuleResult, Verdict

# Real implementations live in their own modules to keep this file small.
from .isolation import (IsolationLayer, IsolationViolation, InputTooLarge,
                        InjectionSuspected)
from .observability import ObservabilityLayer
from .tool_guard import ToolDecision, ToolGuardLayer, ToolPolicy

log = logging.getLogger(__name__)



# ───────────────────────────── ComplianceLayer ─────────────────────────────
class ComplianceLayer:
    """
    Detects and redacts PII before it reaches any LLM.

    Two pattern classes:

      * DEFAULT_PATTERNS  -- high-precision shapes (email, SSN, IBAN, …). The
        shape itself is distinctive, so the whole match is redacted wherever it
        appears.

      * DEFAULT_CONTEXTUAL -- ambiguous shapes (a bare 9-digit number, an ISO
        date). These are redacted ONLY when a context keyword appears within
        CONTEXT_WINDOW characters. This matters: a naive `\\d{9}` redacts every
        order id, and a naive ISO-date pattern redacts every event timestamp --
        a SILENT failure that quietly degrades agent quality without any error.
        Requiring nearby context keeps recall on real PII while eliminating the
        false positives.

    Both sets are fully overridable via the constructor.
    """

    DEFAULT_PATTERNS = {
        "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
        # National Provider Identifier: distinctive only when the NPI context
        # marker is present. It must run before the generic phone pattern, or
        # the 10 digits in "NPI 1234567890" look like a phone number.
        "npi": r"\bNPI[-:#\s]*(?:\d[\s-]?){10}\b",
        "phone": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "account": r"\bacct[-_ ]?\d{6,}\b",
        "iban": r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",   # distinctive enough to keep
        # HIPAA identifiers (SEC-2026-06-15 H-1). The literal "MRN" prefix makes
        # a medical record number distinctive enough to redact wherever it
        # appears, like SSN/IBAN.
        "mrn": r"\bMRN[-:\s]*\d{4,}\b",
    }

    # label -> (value_pattern, [context_keywords])
    DEFAULT_CONTEXTUAL = {
        "routing_number": (r"\b\d{9}\b", ["routing", "aba", "rtn"]),
        "dob": (r"\b\d{4}-\d{2}-\d{2}\b", ["dob", "d.o.b", "birth", "born"]),
        # Insurance member / payer IDs (SEC-2026-06-15 H-1). The dash-separated
        # alpha-numeric shape ("BCB-992341") is the precision lever — without
        # requiring a nearby insurance keyword, a bare LETTERS-DIGITS token
        # would eat SKUs and order codes. Redact only when both are present.
        "insurance_id": (
            r"\b[A-Za-z]{2,4}-\d{5,}\b",
            ["insurance", "policy", "subscriber", "payer", "member",
             "bcbs", "health plan", "group number"],
        ),
    }

    CONTEXT_WINDOW = 32  # chars on each side of a candidate to scan for a keyword

    # Bounded candidate window around each "@" (SEC-2026-06-11-01): up to 64
    # chars of local part before it, up to 255 chars of domain after it (the
    # RFC 5321 limits). The email pattern itself only ever runs inside these
    # windows, so its cost is independent of total input length.
    _EMAIL_WINDOW = re.compile(r".{0,64}@.{0,255}")

    def __init__(self, standards: list[str] | None = None,
                 patterns: dict[str, str] | None = None,
                 contextual_patterns: dict[str, tuple[str, list[str]]] | None = None,
                 enabled: bool = True):
        self.standards = standards or ["GDPR", "HIPAA"]
        self.patterns = {k: re.compile(v, re.IGNORECASE)
                         for k, v in (patterns or self.DEFAULT_PATTERNS).items()}
        ctx = contextual_patterns if contextual_patterns is not None else self.DEFAULT_CONTEXTUAL
        self.contextual_patterns = {
            k: (re.compile(p, re.IGNORECASE), [kw.lower() for kw in kws])
            for k, (p, kws) in ctx.items()
        }
        self.enabled = enabled

    def scrub(self, text: str) -> tuple[str, list[str]]:
        if not self.enabled:
            return text, []
        redactions: list[str] = []
        out = text

        # 1) high-precision patterns: redact the whole match wherever it appears
        for label, rx in self.patterns.items():
            def _sub(m, _label=label):
                redactions.append(_label)
                return f"[REDACTED:{_label.upper()}]"
            if label == "email":
                # The email pattern has superlinear no-match behaviour on long
                # alphabetic input (SEC-2026-06-11-01) — route it through the
                # bounded two-phase handler instead of a full-text sub().
                out = self._scrub_email(out, rx, _sub)
            else:
                out = rx.sub(_sub, out)

        # 2) contextual patterns: redact only when a context keyword is nearby
        for label, (rx, keywords) in self.contextual_patterns.items():
            src = out  # stable snapshot; re.sub scans this and returns a new string
            def _ctx(m, _label=label, _kw=keywords, _src=src):
                s, e = m.start(), m.end()
                window = _src[max(0, s - self.CONTEXT_WINDOW): e + self.CONTEXT_WINDOW].lower()
                if any(k in window for k in _kw):
                    redactions.append(_label)
                    return f"[REDACTED:{_label.upper()}]"
                return m.group(0)
            out = rx.sub(_ctx, src)

        return out, redactions

    def _scrub_email(self, text: str, rx: re.Pattern, sub_fn) -> str:
        """Bounded, linear email scrubbing (SEC-2026-06-11-01).

        The naive full-text email sub() is superlinear when nothing matches:
        on long alphabetic input the local-part class consumes to end-of-string
        and backtracks at every start position (16 KiB took ~1.3 s; 256 KiB
        never finished). Two phases keep it linear:

          Phase 1: O(n) pre-scan — an email requires "@", so no "@" means the
                   pattern can be skipped entirely with zero regex work.
          Phase 2: run the email pattern only inside bounded windows around
                   each "@" (_EMAIL_WINDOW), so per-window cost is constant.
        """
        if "@" not in text:
            return text
        pieces: list[str] = []
        last = 0
        for m in self._EMAIL_WINDOW.finditer(text):
            pieces.append(text[last:m.start()])
            pieces.append(rx.sub(sub_fn, m.group()))
            last = m.end()
        pieces.append(text[last:])
        return "".join(pieces)


# ─────────────────────────────── SafetyLayer ───────────────────────────────
@dataclass
class Rule:
    """
    A single deterministic rule. `fn` receives the text and returns True if the
    rule fires. When a rule fires its `action` is applied. Rules sit OUTSIDE the
    model and cannot be overridden by model output -- that is the whole point.
    """
    rule_id: str
    action: Verdict
    pattern: Optional[str] = None
    fn: Optional[Callable[[str], bool]] = None
    detail: str = ""
    _rx: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def __post_init__(self):
        if self.pattern:
            self._rx = re.compile(self.pattern, re.IGNORECASE)

    def evaluate(self, text: str) -> RuleResult:
        fired = False
        if self._rx is not None:
            fired = bool(self._rx.search(text))
        elif self.fn is not None:
            try:
                fired = bool(self.fn(text))
            except Exception as exc:
                log.warning(
                    "safety rule %s failed closed: %s",
                    self.rule_id,
                    exc,
                    exc_info=True,
                )
                return RuleResult(
                    rule_id=self.rule_id,
                    fired=True,
                    action=Verdict.BLOCK,
                    detail=f"rule evaluation error: {type(exc).__name__}",
                )
        return RuleResult(rule_id=self.rule_id, fired=fired,
                          action=self.action if fired else Verdict.ALLOW,
                          detail=self.detail if fired else "")


_UNSET = object()


class SafetyLayer:
    """
    Two-pass safety. `pre()` screens input; `post()` screens output. A classifier
    callable can be supplied for ML-based screening; the deterministic rule engine
    always runs and has final veto authority (BLOCK > ESCALATE > REDACT > ALLOW).
    """

    _PRECEDENCE = {Verdict.BLOCK: 3, Verdict.ESCALATE: 2, Verdict.REDACT: 1, Verdict.ALLOW: 0}

    def __init__(self, rules: list[Rule] | None = None,
                 classifier: Optional[Callable[[str], Verdict]] = None,
                 post_rules: list[Rule] | None = None,
                 post_classifier=_UNSET):
        self.rules = rules or []
        self.classifier = classifier
        self.post_rules = self.rules if post_rules is None else post_rules
        self.post_classifier = self.classifier if post_classifier is _UNSET else post_classifier

    def _combine(self, results: list[RuleResult], clf: Optional[Verdict]) -> Verdict:
        verdicts = [r.action for r in results if r.fired]
        if clf is not None:
            verdicts.append(clf)
        if not verdicts:
            return Verdict.ALLOW
        return max(verdicts, key=lambda v: self._PRECEDENCE[v])

    def _evaluate_with(
        self,
        text: str,
        rules: list[Rule],
        classifier: Optional[Callable[[str], Verdict]],
        *,
        phase: str = "pre",
    ) -> tuple[Verdict, list[RuleResult]]:
        results: list[RuleResult] = []
        for r in rules:
            try:
                results.append(r.evaluate(text))
            except Exception as exc:
                # Defensive wrapper for custom Rule subclasses: a broken
                # customer rule must fail closed, not turn the request into a
                # 500 or silently disappear from the audit trace.
                rule_id = getattr(r, "rule_id", "<unknown>")
                log.warning(
                    "safety rule %s failed closed: %s",
                    rule_id,
                    exc,
                    exc_info=True,
                )
                results.append(RuleResult(
                    rule_id=rule_id,
                    fired=True,
                    action=Verdict.BLOCK,
                    detail=f"rule evaluation error: {type(exc).__name__}",
                ))
        clf = None
        if classifier:
            try:
                clf = classifier(text)
            except Exception as exc:
                log.warning(
                    "safety classifier failed closed during %s pass: %s",
                    phase,
                    exc,
                    exc_info=True,
                )
                clf = Verdict.BLOCK
                results.append(RuleResult(
                    rule_id=f"classifier.{phase}.error",
                    fired=True,
                    action=Verdict.BLOCK,
                    detail=f"safety classifier error: {type(exc).__name__}",
                ))
        if clf is not None:
            # Record the classifier verdict as a rule result: RCA replay
            # re-derives the verdict from rules_evaluated alone, so every
            # input to the combined verdict must appear in that list.
            if not any(r.rule_id == f"classifier.{phase}.error" for r in results):
                results.append(RuleResult(
                    rule_id=f"classifier.{phase}",
                    fired=clf != Verdict.ALLOW,
                    action=clf if clf != Verdict.ALLOW else Verdict.ALLOW,
                    detail="safety classifier verdict" if clf != Verdict.ALLOW else "",
                ))
        for r in results:
            r.phase = phase
        return self._combine(results, clf), results

    def evaluate(self, text: str) -> tuple[Verdict, list[RuleResult]]:
        return self._evaluate_with(text, self.rules, self.classifier, phase="pre")

    pre = evaluate

    def post(self, text: str) -> tuple[Verdict, list[RuleResult]]:
        return self._evaluate_with(text, self.post_rules, self.post_classifier,
                                   phase="post")


# ───────────────────────────── ReliabilityLayer ────────────────────────────
class CircuitOpenError(RuntimeError):
    pass


class ReliabilityLayer:
    """
    Semaphore-bounded concurrency + per-call timeout + circuit breaker. When the
    system is saturated or the breaker is open, callers get a controlled failure
    or a safe default -- never an unbounded hang or a crash.
    """

    def __init__(self, max_concurrent: int = 10, timeout_s: float = 30.0,
                 breaker_threshold: int = 5, breaker_cooldown_s: float = 30.0):
        self._sem = asyncio.Semaphore(max_concurrent)
        self.timeout_s = timeout_s
        self.breaker_threshold = breaker_threshold
        self.breaker_cooldown_s = breaker_cooldown_s
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self.max_concurrent = max_concurrent

    def _breaker_open(self) -> bool:
        if self._opened_at is None:
            return False
        if time.time() - self._opened_at >= self.breaker_cooldown_s:
            # half-open: allow a trial call
            self._opened_at = None
            self._consecutive_failures = 0
            return False
        return True

    async def guard(self, coro_factory: Callable[[], Awaitable]):
        if self._breaker_open():
            raise CircuitOpenError("circuit breaker is open")
        async with self._sem:
            try:
                result = await asyncio.wait_for(coro_factory(), timeout=self.timeout_s)
                self._consecutive_failures = 0
                return result
            except Exception:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.breaker_threshold:
                    self._opened_at = time.time()
                raise


# ──────────────────────────────── HITLLayer ────────────────────────────────
class HITLLayer:
    """
    Human-in-the-loop gateway. For actions classified as consequential, the agent
    proposes and WAITS. The hard invariant: on timeout it returns IDLE and the
    action is NOT taken. Silence is never consent.

    Two modes::

        # Ephemeral mode — the approver coroutine returns True/False/None
        hitl = HITLLayer(require_approval_for=["wire_transfer"], approver=fn)

        # Persistent mode — requests survive process restarts. Any process
        # holding the same store can approve/deny a queued request.
        from pramagent.queue import PostgresHITLQueue
        hitl = HITLLayer(
            require_approval_for=["wire_transfer"],
            store=PostgresHITLQueue(dsn=os.environ["DATABASE_URL"]),
            timeout_s=None,  # wait forever
        )

    When ``store`` is set, ``gate()`` enqueues the request and polls the store
    until a decision is recorded or the timeout (if any) elapses. A side
    channel — Slack handler, admin CLI, web dashboard — calls
    ``store.decide(request_id, approved=...)`` and the waiter unblocks.
    """

    def __init__(self, require_approval_for: list[str] | None = None,
                 timeout_s: Optional[float] = 300.0,
                 approver: Optional[Callable[[str, dict], Awaitable[Optional[bool]]]] = None,
                 store=None,
                 poll_interval_s: float = 1.0,
                 on_enqueue: Optional[Callable[[str, str, dict], Awaitable[None]]] = None):
        self.require_approval_for = set(require_approval_for or [])
        self.timeout_s = timeout_s
        self.approver = approver
        self.store = store
        self.poll_interval_s = max(0.05, float(poll_interval_s))
        self.on_enqueue = on_enqueue  # notification hook (Slack, email, etc.)
        # Operational counter (P3-11): a notification outage leaves queued
        # approvals invisible to humans until timeout — surface it as a
        # number ops can alert on, not only a log line.
        self.enqueue_notify_failures = 0

    def is_consequential(self, action: str) -> bool:
        return action in self.require_approval_for

    async def gate(self, action: str, context: dict) -> HITLStatus:
        if not self.is_consequential(action):
            return HITLStatus.AUTO
        return await self.propose(action, context)

    async def propose(self, action: str, context: dict) -> HITLStatus:
        """Require human approval for `action` regardless of whether it is in
        require_approval_for. The pipeline calls this when ToolGuard returns
        ESCALATE — the tool decision itself already established that approval
        is required. Same invariant as gate(): silence is never consent."""
        # Persistent path: enqueue + poll the store.
        if self.store is not None:
            return await self._gate_persistent(action, context)

        # Ephemeral path: original behaviour.
        if self.approver is None:
            return HITLStatus.IDLE
        try:
            timeout = self.timeout_s if self.timeout_s is not None else 300.0
            answer = await asyncio.wait_for(
                self.approver(action, context), timeout=timeout)
        except asyncio.TimeoutError:
            return HITLStatus.IDLE
        if answer is True:
            return HITLStatus.APPROVED
        if answer is False:
            return HITLStatus.DENIED
        return HITLStatus.IDLE

    async def _gate_persistent(self, action: str, context: dict) -> HITLStatus:
        # Local import to avoid a hard package dependency at import time.
        from ..queue.base import QueuedRequest, RequestStatus

        req = QueuedRequest.new(action, context,
                                tenant_id=str(context.get("tenant") or context.get("tenant_id") or "default"))
        self.store.enqueue(req)

        # Fire-and-forget notification (so a Slack DM is sent per request, etc.).
        if self.on_enqueue is not None:
            try:
                await self.on_enqueue(req.request_id, action, context)
            except Exception as exc:
                self.enqueue_notify_failures += 1
                log.warning(
                    "HITL enqueue notification failed for request %s "
                    "(failure #%d): %s",
                    req.request_id,
                    self.enqueue_notify_failures,
                    exc,
                )

        deadline = (time.time() + self.timeout_s) if self.timeout_s else None

        while True:
            row = self.store.get(req.request_id)
            if row is not None and row.status != RequestStatus.PENDING.value:
                if row.status == RequestStatus.APPROVED.value:
                    return HITLStatus.APPROVED
                if row.status == RequestStatus.DENIED.value:
                    return HITLStatus.DENIED
                return HITLStatus.IDLE  # EXPIRED or anything unexpected

            # Ephemeral approver still works alongside the queue, for backends
            # that push (e.g. Slack approver writes back to the store directly).
            if self.approver is not None:
                try:
                    answer = await asyncio.wait_for(
                        self.approver(action, context),
                        timeout=self.poll_interval_s,
                    )
                    if answer is True:
                        self.store.decide(req.request_id, approved=True,
                                          decided_by="approver")
                        return HITLStatus.APPROVED
                    if answer is False:
                        self.store.decide(req.request_id, approved=False,
                                          decided_by="approver")
                        return HITLStatus.DENIED
                except asyncio.TimeoutError:
                    pass  # keep polling the store

            if deadline is not None and time.time() >= deadline:
                self.store.expire(req.request_id)
                return HITLStatus.IDLE

            await asyncio.sleep(self.poll_interval_s)
