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

from ..types import Provenance


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
     re.compile(
         r"(```\s*end\s+of\s+prompt|<\|im_end\|>|<\|endoftext\|>|"
         r"<\|(system|developer|user|assistant)\|>|"
         r"<\|im_start\|>\s*(system|developer|user|assistant)|"
         r"\[INST\]|<<SYS>>|<</SYS>>|---\s*new\s+prompt)",
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
         r"\b(SYSTEM\s+ALERT|PRIORITY\s+OVERRIDE|MAINTENANCE\s+MODE\s+ACTIVE)\b|"
         r"\b(activate|enable|trigger|initiate|engage)\s+(?:the\s+)?"
         r"(override|bypass)\b[\s\S]{0,100}"
         r"\b(unrestricted|filters?|restrictions?|safety|proceed|full\s+output)\b|"
         r"\b(emergency|maintenance)\b[\s\S]{0,70}"
         r"\b(override|bypass|maintenance\s+mode|unrestricted\s+mode|protocol)\b"
         r"[\s\S]{0,140}\b(OVERRIDE_ACCEPTED|disable|disabled|suspend(?:ed)?|"
         r"restrictions?|filters?|full\s+output|proceed|acknowledge)\b|"
         r"\b(all\s+standard\s+restrictions|safety\s+systems)\b"
         r"[\s\S]{0,100}\b(suspend(?:ed)?|disabled|maintenance\s+mode|OVERRIDE_ACCEPTED)\b",
         re.IGNORECASE),
     "fake emergency/override-mode activation attempt"),
    ("disable_safety_controls",
     re.compile(
         r"\b(disable|deactivate|turn\s+off|switch\s+off|suspend|bypass)\b"
         r"[\s\S]{0,40}\b((content\s+)?filters?|content\s+moderation|"
         r"guardrails?|safeguards?|safety\s+(filters?|checks?|controls?|guidelines?))\b",
         re.IGNORECASE),
     "request to disable safety/content controls"),
    # ── SEC-2026-06-15-02: encoded-payload framing + override tokens ─────────
    # The decoded forms of base64/hex/unicode payloads are appended by
    # _augment_decoded and scanned by every heuristic above, so an encoded
    # "ignore all previous instructions" is caught by instruction_override.
    # These two add coverage for the *framing* (so the intent is flagged even
    # if a payload fails to decode) and for the language-independent override
    # token a translated jailbreak asks the model to emit.
    ("encoded_payload_framing",
     re.compile(
         r"\b(hex|unicode|base64|rot13|gzip|binary|ascii)[\s\-+]*"
         r"(encoded|encod(?:ing)?|payload|string|sequence|blob)\b"
         r"[\s\S]{0,80}\b(decode|decipher|interpret|unescape|execute|action|"
         r"run|process|apply)\b|"
         r"\b(decode|decipher|interpret|unescape)\b[\s\S]{0,40}"
         r"\b(hex|unicode|base64|rot13|gzip)\b",
         re.IGNORECASE),
     "framing that asks the model to decode and act on an encoded payload"),
    ("override_confirmation_token",
     re.compile(
         r"\bOVERRIDE[_\s]?(ACCEPTED|OK|CONFIRMED|GRANTED|ENABLED)\b|"
         r"\b(FILTERS?\s+DISABLED|UNRESTRICTED\s+MODE\s+(ON|ACTIVE|ACTIVATED))\b",
         re.IGNORECASE),
     "prompt asks the model to emit an override-confirmation token"),
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

# ── SEC-2026-06-15-02: targeted non-English instruction-override phrases ─────
# Red-team proved fr/es/de/hi "ignore all previous instructions" variants slip
# past the English-first heuristics AND the keyword classifier (the demo forces
# keyword-only, so the multilingual embedding exemplars never load). This is
# targeted coverage for the proven languages, NOT full multilingual support —
# the scalable fix is wiring the embedding classifier. See
# docs/IMPLEMENTATION_STATUS.md; the output post-check is the backstop.
MULTILINGUAL_OVERRIDE_PATTERNS: list[str] = [
    r"ignor(?:ez|er)\s+toutes\s+les\s+instructions\s+pr[ée]c[ée]dentes",      # fr
    r"ignor(?:a|ar)\s+todas\s+las\s+instrucciones\s+(?:anteriores|previas)",  # es
    r"ignoriere?\s+alle\s+(?:vorherigen|bisherigen)\s+anweisungen",           # de
    r"(asistente|assistant)\s+sin\s+restricciones",                          # es
    r"\b(uneingeschr[äa]nkt|wartungsmodus)\b",                                # de
    r"पिछले\s+निर्देश",                                                       # hi: previous instructions
    r"निर्देश(?:ों)?\s+को\s+अनदेखा",                                          # hi: ignore instructions
    r"असीमित\s+AI",                                                          # hi: unlimited AI
]

_INJECTION_PATTERNS += [
    ("multilingual_override", re.compile(p, re.IGNORECASE),
     "non-English instruction-override phrase")
    for p in MULTILINGUAL_OVERRIDE_PATTERNS
]

# Encoded runs worth decode-and-scanning. base64 (20+ b64 chars), hex (8+ byte
# pairs, whitespace allowed between them), and \uXXXX escape runs (4+).
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}\s*){8,}")
_UNICODE_ESCAPE_RUN = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")


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
        classifier: Optional[Callable] = None,
        backend=None,
        memory_ttl_s: int = 3600,
        untrusted_threshold_multiplier: float = 0.85,
    ) -> None:
        self.max_input_bytes = max_input_bytes
        self.max_output_bytes = max_output_bytes
        self.block_on_injection = block_on_injection
        self.classifier = classifier
        self.memory_ttl_s = memory_ttl_s
        # For untrusted provenance (tool_output, retrieved), the classifier
        # threshold is multiplied by this factor to be more aggressive.
        self.untrusted_threshold_multiplier = untrusted_threshold_multiplier
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

    def _augment_decoded(self, text: str) -> str:
        """Decode base64 / hex / ``\\uXXXX`` runs and append the decoded text so
        every heuristic and the classifier also see the decoded form.

        Encoding an attack is therefore not a bypass: "SWdub3Jl..." (base64),
        "69676e6f7265..." (hex), and "\\u0069\\u0067..." (unicode escapes) all
        decode to "ignore ..." and are then caught by instruction_override
        (SEC-2026-06-11-02 base64; SEC-2026-06-15-02 hex + unicode).

        Only printable decodes longer than 8 chars are appended. Binary noise —
        hashes, ids, gzip frames — decodes to non-text and is dropped, so this
        does NOT over-block legitimate hex/base64 data: a payload is only ever
        flagged when its *decoded* form itself matches an injection heuristic.
        """
        extras: list[str] = []

        for match in _B64_TOKEN.finditer(text):
            try:
                decoded = base64.b64decode(match.group(), validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if decoded.isprintable() and len(decoded) > 8:
                extras.append(decoded)

        for match in _HEX_RUN.finditer(text):
            blob = re.sub(r"\s+", "", match.group())
            if len(blob) % 2:
                blob = blob[:-1]
            try:
                decoded = bytes.fromhex(blob).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if decoded.isprintable() and len(decoded) > 8:
                extras.append(decoded)

        for match in _UNICODE_ESCAPE_RUN.finditer(text):
            decoded = re.sub(r"\\u([0-9a-fA-F]{4})",
                             lambda m: chr(int(m.group(1), 16)), match.group())
            if decoded.isprintable() and len(decoded) > 8:
                extras.append(decoded)

        if extras:
            return text + " [DECODED: " + " | ".join(extras) + "]"
        return text

    async def evaluate_input(self, text: str, *, tenant_id: str,
                             session_id: str,
                             provenance: Provenance = Provenance.USER) -> dict:
        """Run all checks on an inbound prompt. Raises on hard violations.

        Parameters
        ----------
        provenance : Provenance
            Source trust level. TOOL_OUTPUT and RETRIEVED trigger more
            aggressive scanning (lower effective threshold) because they
            are the primary vector for indirect prompt injection.
        """
        self.check_input_size(text)

        # Heuristics and the optional classifier both scan the augmented text
        # (original + decoded base64/hex/unicode tokens) so encoding is not a
        # bypass.
        scan_text = self._augment_decoded(text)
        hits = self.scan_for_injection(scan_text)

        # Classifier path — extracts structured verdict when available
        classifier_flagged: Optional[bool] = None
        classifier_meta: dict = {}
        if self.classifier is not None:
            raw_verdict = self.classifier(scan_text)
            # Support both InjectionVerdict (structured) and plain bool
            if hasattr(raw_verdict, "flagged"):
                classifier_flagged = raw_verdict.flagged
                threshold = getattr(raw_verdict, "threshold", None)
                classifier_meta = {
                    "layer": getattr(raw_verdict, "layer", "unknown"),
                    "score": getattr(raw_verdict, "score", 0.0),
                    "threshold": threshold,
                    "matched_exemplar": getattr(raw_verdict, "matched_exemplar", None),
                    "matched_pattern": getattr(raw_verdict, "matched_pattern", None),
                }
                # For untrusted provenance, apply stricter evaluation:
                # if the score is close to threshold but below it, flag anyway
                if (not classifier_flagged
                        and provenance in (Provenance.TOOL_OUTPUT, Provenance.RETRIEVED)
                        and hasattr(raw_verdict, "score")):
                    threshold_hit = self._passes_untrusted_threshold(raw_verdict)
                    if threshold_hit is not None:
                        classifier_flagged = True
                        classifier_meta.update({
                            "provenance_escalated": True,
                            "provenance_threshold_multiplier": self.untrusted_threshold_multiplier,
                            **threshold_hit,
                        })
            else:
                classifier_flagged = bool(raw_verdict)

        suspected = bool(hits) or (classifier_flagged is True)

        # For untrusted provenance, always enforce blocking even if
        # block_on_injection is False
        should_block = self.block_on_injection or provenance in (
            Provenance.TOOL_OUTPUT, Provenance.RETRIEVED
        )

        if suspected and should_block:
            reasons = [h["pattern_id"] for h in hits]
            if classifier_flagged:
                layer_info = classifier_meta.get("layer", "classifier")
                score_info = classifier_meta.get("score", 0.0)
                reasons.append(f"classifier({layer_info}:score={score_info:.2f})")
            raise InjectionSuspected(",".join(reasons) or "classifier")

        return {
            "scope": f"{tenant_id}:{session_id}",
            "provenance": provenance.value,
            "injection_hits": hits,
            "classifier_flagged": classifier_flagged,
            "classifier_meta": classifier_meta,
            "input_bytes": len(text.encode("utf-8")),
        }

    def _passes_untrusted_threshold(self, verdict: object) -> Optional[dict]:
        """Return metadata when an untrusted-source score crosses a stricter threshold.

        Score-based classifiers carry their own decision threshold. For tool
        output and retrieved text, Pramagent lowers that threshold instead of
        comparing to a hard-coded score. Ensemble verdicts may include per-layer
        scores in ``details["ensemble_layers"]``; those are checked too so a
        near-miss in one layer is still visible to provenance policy.
        """

        def check(score: object, threshold: object, layer: str) -> Optional[dict]:
            if score is None or threshold is None:
                return None
            try:
                score_f = float(score)
                threshold_f = float(threshold)
            except (TypeError, ValueError):
                return None
            if threshold_f <= 0.0:
                return None
            effective_threshold = threshold_f * self.untrusted_threshold_multiplier
            if score_f >= effective_threshold:
                return {
                    "provenance_layer": layer,
                    "provenance_score": score_f,
                    "provenance_effective_threshold": effective_threshold,
                    "provenance_base_threshold": threshold_f,
                }
            return None

        top_hit = check(
            getattr(verdict, "score", None),
            getattr(verdict, "threshold", None),
            getattr(verdict, "layer", "classifier"),
        )
        if top_hit is not None:
            return top_hit

        details = getattr(verdict, "details", {}) or {}
        layers = details.get("ensemble_layers", {}) if isinstance(details, dict) else {}
        if not isinstance(layers, dict):
            return None
        for layer, item in layers.items():
            if not isinstance(item, dict):
                continue
            hit = check(item.get("score"), item.get("threshold"), str(layer))
            if hit is not None:
                return hit
        return None
