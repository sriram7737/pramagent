"""
pramagent.layers.isolation
==========================
Real isolation primitives. Three defenses:

  1. Tenant-scoped memory backed by an AbstractBackend (in-process default,
     Redis for multi-worker deployments). Writing to tenant A does not bleed
     into tenant B; cross-scope reads raise IsolationViolation.

  2. Injection heuristics. Scans inbound prompts for common instruction-override
     and exfiltration patterns, authority/developer framing, and translation/
     indirection wrappers. Base64-looking tokens are decoded and the decoded
     text is scanned too, so encoding an attack does not bypass the patterns
     (SEC-2026-06-11-02). These are heuristics, not a complete defense.
     An ML classifier hook is provided for layering stronger detection.

  3. Hard size limits. Input and output bytes are capped per call to prevent
     trivial DoS and bound LLM costs. Configurable per deployment.

What this layer does NOT claim to do
-------------------------------------
It does not defend against a determined attacker with novel injection prompts.
Real defense requires fine-tuned classifiers, provenance tracking on tool
outputs, and runtime constraints on the model action space.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Callable, Optional


class IsolationViolation(Exception):
    """Raised when a request crosses tenant or session boundaries."""


class InputTooLarge(Exception):
    """Raised when an input exceeds the configured byte limit."""


class InjectionSuspected(Exception):
    """Raised when injection heuristics fire on the input. Heuristic, not proof."""


_INJECTION_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("instruction_override",
     re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)",
                re.IGNORECASE),
     "classic prompt-injection override"),
    ("role_hijack",
     re.compile(
         r"(?m)^\s*(#{1,6}\s*)?(system|assistant|developer|tool|function)\s*"
         r"(message|prompt|instructions?|role|turn)?\s*[:>\-=]\s*.{0,120}"
         r"\b(ignore|override|bypass|reveal|leak|comply|new\s+directive|you\s+(are|must|will))\b",
         re.IGNORECASE | re.DOTALL,
     ),
     "attempt to inject a fake role/turn header"),
    ("disregard_safety",
     re.compile(r"(disregard|bypass|ignore|override)\s+(your\s+)?(safety|guidelines?|rules?|polic(?:y|ies))",
                re.IGNORECASE),
     "explicit safety bypass request"),
    ("data_exfiltration",
     re.compile(r"(dump|print|reveal|show|leak|exfiltrate)\s+(all\s+|the\s+)?(memory|secrets?|keys?|tokens?|env(ironment)?|database|users?)",
                re.IGNORECASE),
     "request to reveal internal state or secrets"),
    ("sensitive_admin_exfiltration",
     re.compile(
         r"\b(as\s+an\s+admin|administrator|admin|root|superuser)\b"
         r".{0,120}\b(generate|show|reveal|export|return|dump|print)\b"
         r".{0,120}\b(sensitive\s+)?(system\s+)?(logs?|audit\s+logs?|credentials?|secrets?|private\s+data)\b|"
         r"\b(as\s+an\s+admin|administrator|admin|root|superuser)\b"
         r".{0,140}\b(elevated|admin(?:istrative)?|root|superuser)\s+(privileges?|access|permissions?)\b"
         r".{0,140}\b(access|read|open|retrieve|return|export|download|copy|show|reveal)\b"
         r".{0,140}\b(confidential|sensitive|private|protected)\s+(?:\w+\s+){0,3}(data|files?|records?|documents?)\b|"
         r"\b(admin|administrator|root|superuser)\s+privileges?\b"
         r".{0,140}\b(access|read|open|retrieve|return|export|download|copy)\b"
         r".{0,140}\b(confidential|sensitive|private|protected)\s+(?:\w+\s+){0,3}(data|files?|records?|documents?)\b|"
         r"\brole\s*:\s*['\"]?(administrative_access|admin|administrator|root|superuser|system)['\"]?\b"
         r".{0,140}\b(sensitive\s+)?(system\s+)?(logs?|audit\s+logs?|credentials?|secrets?|private\s+data)\b",
         re.IGNORECASE | re.DOTALL,
     ),
     "attempt to use privileged role context to reveal sensitive operational data"),
    ("sensitive_data_elicitation",
     re.compile(
         r"\b(as\s+an\s+expert|security\s+advisor|trusted\s+advisor|advisor)\b"
         r".{0,140}\b(recommend|advise|instruct|ask|tell)\b"
         r".{0,80}\b(shar(?:e|es|ing)|send(?:s|ing)?|upload(?:s|ing)?|provid(?:e|es|ing)|disclos(?:e|es|ing)|return(?:s|ing)?)\b"
         r".{0,120}\b(sensitive\s+data|passwords?|personal\s+information|credentials?|secrets?|private\s+data)\b",
         re.IGNORECASE | re.DOTALL,
     ),
     "attempt to elicit sensitive data under a trusted-advisor role"),
    ("pretend_you_are",
     re.compile(
         r"(pretend|act|behave|roleplay)\s+"
         r"(?:(?:as|like)\s+(?:if\s+)?)?"
         r"(?:you\s+are\s+|you\'re\s+)?"
         r"(?:an?\s+)?"
         r"(unrestricted|uncensored|jailbroken|dan\b)",
         re.IGNORECASE),
     "jailbreak persona request"),
    ("encoded_payload",
     re.compile(r"\b(decode|execute|run)\s+(this\s+)?(base64|hex|rot13|payload)",
                re.IGNORECASE),
     "request to decode/run obfuscated payload"),
    ("delimiter_break",
     re.compile(r"(```\s*end\s+of\s+prompt|<\|im_end\|>|<\|endoftext\|>|---\s*new\s+prompt)",
                re.IGNORECASE),
     "attempt to inject a chat-template delimiter"),
    # ── SEC-2026-06-15-01: fake "emergency override" framing ────────────────
    # Red-team proved a bypass that frames the request as activating a system
    # emergency/maintenance override ("this is a test of the emergency override
    # system") and then asks to disable content filters. The classic
    # disregard_safety pattern misses it: the verb is "disable"/"activate" (not
    # ignore/override) and the target is "content filters" (not safety/rules).
    ("emergency_override",
     re.compile(
         r"\b(emergency|maintenance|activate|enable|trigger|initiate|engage)\b"
         r"[\s\S]{0,40}\b(override|bypass|sudo|godmode|god\s+mode|"
         r"unrestricted\s+mode)\b",
         re.IGNORECASE),
     "fake emergency/override-mode activation attempt"),
    ("disable_safety_controls",
     re.compile(
         r"\b(disable|deactivate|turn\s+off|switch\s+off|suspend|bypass)\b"
         r"[\s\S]{0,40}\b((content\s+)?filters?|content\s+moderation|"
         r"guardrails?|safeguards?|safety\s+(filters?|checks?|controls?|guidelines?))\b",
         re.IGNORECASE),
     "request to disable safety/content controls"),
]

# ── SEC-2026-06-11-02: authority framing + indirection wrappers ────────────
# Security testing proved bypasses that claim a privileged role ("as a
# developer ...") or wrap the override in an innocuous task ("translate to
# French: ignore ..."). Kept as raw strings so deployments can extend them.
AUTHORITY_FRAMING_PATTERNS: list[str] = [
    r"\bas\s+an?\s+(developer|admin(?:istrator)?|system|operator|tester)\b",
    r"\b(reveal|show|display|print|output|give\s+me)\s+(?:me\s+)?"
    r"(?:the\s+|your\s+)?(system\s+prompt|instructions?|rules?|config(?:uration)?)\b",
    r"\bfor\s+(testing|debug|development)\s+(purposes?|only)\b",
    r"\bthis\s+is\s+a\s+(test|debug|dev)\s+(environment|mode|session)\b",
    r"\bi\s+(work|am)\s+(at|for|with)\s+(anthropic|openai|the\s+company)\b",
]

INDIRECTION_PATTERNS: list[str] = [
    r"translate\s+to\s+\w+\s*:\s*.*(ignore|bypass|disable|override)",
    r"(summarize|paraphrase|rewrite)\s+.*\s+(ignore|bypass|override)\s+",
    r"in\s+(french|spanish|german|chinese|arabic)\s*[,:]\s*(ignore|bypass)",
    r"what\s+would\s+(you|an\s+ai)\s+say\s+if\s+(there\s+were\s+no|without)"
    r"\s+(rules|restrictions|filters)",
]

_INJECTION_PATTERNS += [
    ("authority_framing", re.compile(p, re.IGNORECASE),
     "authority/developer framing to claim privileged access")
    for p in AUTHORITY_FRAMING_PATTERNS
] + [
    ("indirection_wrapper", re.compile(p, re.IGNORECASE),
     "translation/indirection wrapper around an override request")
    for p in INDIRECTION_PATTERNS
]

# Base64-looking runs worth decode-and-scanning (20+ chars of b64 alphabet).
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


class IsolationLayer:
    """
    Tenant-scoped memory + injection heuristics + size limits.

    Configuration
    -------------
    max_input_bytes   : cap on input prompt size (default 64 KiB)
    max_output_bytes  : cap on output text size (default 64 KiB)
    block_on_injection: True (default) raises InjectionSuspected on a hit;
                        False just records the hits in trace metadata.
    classifier        : optional callable(text) -> bool; True = malicious.
    backend           : AbstractBackend for tenant memory. Defaults to
                        InProcessBackend. Pass RedisBackend for multi-worker.
    memory_ttl_s      : TTL for memory entries in seconds (default 3600).
    """

    def __init__(
        self,
        max_input_bytes: int = 64 * 1024,
        max_output_bytes: int = 64 * 1024,
        block_on_injection: bool = True,
        classifier: Optional[Callable[[str], bool]] = None,
        backend=None,
        memory_ttl_s: int = 3600,
    ) -> None:
        self.max_input_bytes = max_input_bytes
        self.max_output_bytes = max_output_bytes
        self.block_on_injection = block_on_injection
        self.classifier = classifier
        self.memory_ttl_s = memory_ttl_s
        if backend is None:
            from ..backends import InProcessBackend
            backend = InProcessBackend()
        self._backend = backend

    @staticmethod
    def _scope_key(tenant_id: str, session_id: str) -> str:
        return f"{tenant_id}:{session_id}"

    def memory_for(self, tenant_id: str, session_id: str) -> list[str]:
        """Return a copy of this scope\'s memory."""
        return self._backend.memory_get(self._scope_key(tenant_id, session_id))

    def memory_append(self, tenant_id: str, session_id: str, item: str) -> None:
        """Append an item to scope memory (safe for multi-worker)."""
        self._backend.memory_append(self._scope_key(tenant_id, session_id), item)

    def assert_scope(self, tenant_id: str, session_id: str,
                     expected_tenant: str, expected_session: str) -> None:
        if tenant_id != expected_tenant or session_id != expected_session:
            raise IsolationViolation(
                f"scope mismatch: got ({tenant_id},{session_id}) "
                f"expected ({expected_tenant},{expected_session})"
            )

    def clear_scope(self, tenant_id: str, session_id: str) -> None:
        self._backend.memory_clear(self._scope_key(tenant_id, session_id))

    def check_input_size(self, text: str) -> None:
        size = len(text.encode("utf-8"))
        if size > self.max_input_bytes:
            raise InputTooLarge(
                f"input is {size} bytes; limit is {self.max_input_bytes}"
            )

    def truncate_output(self, text: str) -> tuple[str, bool]:
        b = text.encode("utf-8")
        if len(b) <= self.max_output_bytes:
            return text, False
        return b[: self.max_output_bytes].decode("utf-8", errors="ignore"), True

    def scan_for_injection(self, text: str) -> list[dict]:
        """Return hits for every heuristic that fires. Empty = no match (not safe)."""
        hits = []
        for pid, rx, detail in _INJECTION_PATTERNS:
            if rx.search(text):
                hits.append({"pattern_id": pid, "detail": detail})
        return hits

    def _decode_b64_tokens(self, text: str) -> str:
        """Extract and decode base64 tokens, append decoded text for scanning.

        SEC-2026-06-11-02: a base64-encoded payload sails past plain-text
        heuristics ("SWdub3JlIGFsbCBydWxlcw==" is "Ignore all rules"). Decoded
        tokens that look like real text (printable, more than 8 chars) are
        appended so every existing heuristic also sees the decoded form.
        Tokens that fail to decode or decode to binary noise are ignored.
        """
        extras: list[str] = []
        for match in _B64_TOKEN.finditer(text):
            try:
                decoded = base64.b64decode(match.group(), validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if decoded.isprintable() and len(decoded) > 8:
                extras.append(decoded)
        if extras:
            return text + " [DECODED: " + " | ".join(extras) + "]"
        return text

    async def evaluate_input(self, text: str, *, tenant_id: str,
                             session_id: str) -> dict:
        """Run all checks on an inbound prompt. Raises on hard violations."""
        self.check_input_size(text)

        # Heuristics and the optional classifier both scan the augmented text
        # (original + decoded base64 tokens) so encoding is not a bypass.
        scan_text = self._decode_b64_tokens(text)
        hits = self.scan_for_injection(scan_text)
        classifier_verdict: Optional[bool] = None
        if self.classifier is not None:
            classifier_verdict = bool(self.classifier(scan_text))

        suspected = bool(hits) or (classifier_verdict is True)
        if suspected and self.block_on_injection:
            reasons = [h["pattern_id"] for h in hits]
            if classifier_verdict:
                reasons.append("classifier")
            raise InjectionSuspected(",".join(reasons) or "classifier")

        return {
            "scope": f"{tenant_id}:{session_id}",
            "injection_hits": hits,
            "classifier_flagged": classifier_verdict,
            "input_bytes": len(text.encode("utf-8")),
        }
