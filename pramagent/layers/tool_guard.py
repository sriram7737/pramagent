"""
pramagent.layers.tool_guard
============================
Deterministic tool-call safety. Five layers of defense:

1. Policy allow-list
   Tool must be explicitly registered. Unregistered calls blocked by default.
   Per-tool tenant allow-list and action allow-list enforced.

2. Argument validation — full JSON Schema engine
   Type, required, properties, additionalProperties, enum, minimum/maximum,
   exclusiveMinimum/exclusiveMaximum, minLength/maxLength, pattern,
   minItems/maxItems, items, oneOf, anyOf, allOf, if/then/else, $defs/$ref,
   format (date-time, email, uri, uuid, ipv4, ipv6).

3. Argument injection scanning
   Deep recursive scan of every string argument value. Blocks SQL injection,
   shell injection, path traversal, template injection, SSRF targets.

4. Output validation
   Call validate_output() after the tool executes. Checks output_schema,
   enforces max_output_bytes, scans for exfiltration markers (AWS keys,
   private keys, JWTs, generic secrets), records a provenance entry.

5. Tool-chain detection
   Tracks the side-effect sequence within each (tenant, session). Detects
   known dangerous chains (read→exfil, read→payment, bulk-write, privilege
   escalation, write→destructive). Escalates rather than blindly blocks —
   humans confirm, machines flag.

Side-effect taxonomy (severity order, lowest to highest)
---------------------------------------------------------
  read            — read-only; no state change
  compute         — CPU/memory use; no external state
  write           — mutates internal state
  config_change   — modifies system configuration
  external_message— sends data outside the system
  payment         — financial transaction
  destructive     — deletes or overwrites data irreversibly

Higher-severity side effects get stricter treatment in chain detection.

All decisions recorded in an append-only audit log (per-instance).
"""
from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from jsonschema import Draft202012Validator, FormatChecker
    from jsonschema.exceptions import SchemaError
except ImportError:  # pragma: no cover - dependency is declared, fallback is legacy
    Draft202012Validator = None
    FormatChecker = None
    SchemaError = Exception

from ..types import Verdict

log = logging.getLogger(__name__)


class ToolGuardError(ValueError):
    pass


class _BackendUnavailable(RuntimeError):
    """Internal: a configured ToolGuard backend (Redis) failed while reading a
    session counter or chain history. When fail_open is False, evaluate()
    turns this into a BLOCK rather than silently under-counting via
    per-process memory (E2)."""


# ── side-effect taxonomy ──────────────────────────────────────────────────────

class SideEffect:
    """Ordered severity levels. Higher = more dangerous."""
    READ             = "read"
    COMPUTE          = "compute"
    WRITE            = "write"
    CONFIG_CHANGE    = "config_change"
    EXTERNAL_MESSAGE = "external_message"
    PAYMENT          = "payment"
    DESTRUCTIVE      = "destructive"

    _ORDER = [READ, COMPUTE, WRITE, CONFIG_CHANGE, EXTERNAL_MESSAGE, PAYMENT, DESTRUCTIVE]

    @classmethod
    def severity(cls, effect: str) -> int:
        try:
            return cls._ORDER.index(effect)
        except ValueError:
            return 1   # unknown → treat as compute

    @classmethod
    def is_at_least(cls, effect: str, threshold: str) -> bool:
        return cls.severity(effect) >= cls.severity(threshold)


# ── argument injection patterns ───────────────────────────────────────────────
#
# SEC-2026-07-10: sql_injection and shell_injection used to fire on bare
# punctuation alone (a lone "--", ";", or "|" next to a letter), which is
# indistinguishable from ordinary prose dashes, semicolons in sentences,
# piped shell commands, and regex alternation. Split each into the same
# two-tier design ComplianceLayer already uses for PII (pramagent/layers/
# __init__.py): a HIGH-PRECISION set (distinctive shapes -- real SQL
# keyword phrases, boolean-tautology SQLi, backtick/$() shell substitution,
# sh -c/bash -c invocation) that fires unconditionally, and a CONTEXTUAL set
# (ambiguous punctuation) that only fires when a genuine SQL/shell keyword
# appears within a bounded window of the punctuation -- mirroring
# ComplianceLayer.scrub()'s candidate-regex-plus-nearby-keyword check.
#
# ISSUE-14 follow-up: two entries in the unconditional set were themselves
# ordinary, benign shapes rather than distinctive attack signatures -- a
# schema-DDL statement Claude Code writes on request, and a loopback
# address Claude Code binds/connects to on request, both being extremely
# common in legitimate coding-assistant tool calls. Both were demoted to
# the contextual set below, gated on a nearby signal that actually
# indicates the attack shape (a stacked-query break-out marker, or an
# outbound-fetch verb) instead of the bare keyword/address alone.

_ARG_INJECTION_WINDOW = 40  # chars scanned on each side of contextual punctuation

_ARG_INJECTION: list[tuple[str, re.Pattern, str]] = [
    ("sql_injection",
     re.compile(
         r"(\bxp_\w+|exec\s*\(|drop\s+table|union\s+select|insert\s+into"
         r"|delete\s+from|truncate\s+table|alter\s+table"
         r"|sleep\s*\(\d+\)|benchmark\s*\("
         # boolean-tautology SQLi ('1'='1', OR 1=1, '='): the tautology
         # shape itself is the distinctive marker, no keyword needed.
         r"|'\s*(?:or|and)\s*'.*?'\s*=\s*'|\b(?:or|and)\s+\d+\s*=\s*\d+\b"
         r"|'\s*=\s*')",
         re.IGNORECASE),
     "SQL injection pattern in argument"),
    ("shell_injection",
     re.compile(
         r"(\$\(|\bsh\s+-c\b|\bbash\s+-c\b|\beval\s*\(|\bexec\s*\()",
         re.IGNORECASE),
     "shell injection pattern in argument"),
    ("path_traversal",
     re.compile(
         r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f"
         r"|/etc/passwd|/etc/shadow|/proc/self|/sys/)",
         re.IGNORECASE),
     "path traversal pattern in argument"),
    ("ssrf_attempt",
     re.compile(
         r"(169\.254\.169\.254|metadata\.google\.internal"
         r"|file://|gopher://|dict://|sftp://|ldap://|tftp://)",
         re.IGNORECASE),
     "SSRF target in argument"),
    ("xxe_attempt",
     re.compile(r"<!ENTITY\s|<!DOCTYPE\s.*\[", re.IGNORECASE),
     "XML External Entity attempt in argument"),
]

# Contextual counterparts of sql_injection/shell_injection: the punctuation
# alone is ambiguous (see the design note above _ARG_INJECTION), so each
# entry pairs a candidate regex with a keyword list and only reports a
# finding when a keyword appears within _ARG_INJECTION_WINDOW chars of the
# match. Same pattern_id as the high-precision entry above, since this is
# the same underlying concern at lower confidence, not a different category.
#
# Each entry's last element is a window direction: "before"/"after" search
# only that side of the punctuation match, "any" (the default used by most
# entries) searches both.
#
# The original single sql_injection separator entry matched "--"/";"/"/*"/
# "*/" as one alternation with a symmetric window. That also matched an
# ORDINARY complete statement's own keyword sitting right before its own
# closing ";" (e.g. "UPDATE x SET y WHERE z;" -- not an attack, just a
# normal terminated statement) (ISSUE-14). Split into two entries by how
# strong a signal each punctuation shape actually is:
#   - a SQL comment marker ("--", "/*", "*/") near a SQL keyword is a
#     strong signal on its own, symmetric window -- "commenting out the
#     rest of the query" is the classic injection technique, and comment
#     markers essentially never appear near SQL keywords in ordinary prose
#     or in a complete, uncommented statement.
#   - a bare ";" is a much weaker signal (it terminates EVERY complete SQL
#     statement), so it only counts when a keyword follows it -- the
#     stacked-query shape ("...; DROP TABLE ...") -- not when a keyword
#     merely precedes it as part of the very statement it's terminating.
_ARG_INJECTION_CONTEXTUAL: list[tuple[str, re.Pattern, list[str], str, str]] = [
    # A common English preposition (as in "differences X this", "aside X
    # that") was intentionally dropped from the keyword list below: it
    # false-positived constantly whenever it landed near a dash-style prose
    # separator or a markdown heading underline. select/where/table/etc.
    # alone already cover the real SQL shape without it.
    ("sql_injection",
     re.compile(r"(--|/\*|\*/)"),
     ["select", "insert", "update", "delete", "drop", "union",
      "where", "table", "database", "index", "view", "trigger", "exec"],
     "SQL comment marker near a SQL keyword",
     "any"),
    ("sql_injection",
     re.compile(r";"),
     # LOW-1: index/view/trigger were missing here, so a stacked query
     # breaking out to run "CREATE INDEX ..." / "CREATE VIEW ..." /
     # "CREATE TRIGGER ..." after a separator slipped past, unlike the
     # table/database DDL shapes that were kept.
     ["select", "insert", "update", "delete", "drop", "union",
      "where", "table", "database", "index", "view", "trigger", "exec"],
     "stacked SQL statement after a statement separator",
     "after"),
    # The classic auth-bypass shape ("admin' --") has no SQL keyword at
    # all -- it just closes a string literal and comments out the rest of
    # the query. A bare quote-then-comment-marker is still too ambiguous on
    # its own (ordinary quoted dialogue uses "word." -- like this too), so
    # this narrows to login/credential-field context instead of a SQL
    # keyword, matching the actual attack scenario. The credential keyword
    # sits BEFORE the quote-then-comment shape in the real attack pattern
    # ("admin' --"), so this window stays symmetric ("any") rather than
    # after-only.
    ("sql_injection",
     re.compile(r"""['"]\s*(?:--|;)"""),
     ["admin", "login", "password", "username", "user=", "pwd", "auth"],
     "quote-then-comment auth-bypass shape near a login/credential field",
     "any"),
    ("shell_injection",
     re.compile(r"(\|\s*\w|&&|\|\||;\s*\w+\b|>\s*/|>>\s*/)"),
     ["curl", "wget", "netcat", " nc ", "chmod 777", "rm -rf",
      "/etc/passwd", "/etc/shadow", "base64 -d", "0.0.0.0", "/dev/tcp"],  # nosec B104
     "shell chaining/redirection near a known dangerous command",
     "any"),
    # Demoted from the unconditional list above (SEC hardening pass): the
    # bare shape matches ANY JS/TS template literal or Ruby interpolation,
    # which is ordinary code, not an attack. Real template/SSTI injection
    # payloads reference a sandbox-escape target, not just any expression.
    ("template_injection",
     re.compile(r"(\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}|#\{.*?\}|\{#.*?#\})", re.DOTALL),
     ["config", "__class__", "__globals__", "__init__", "__mro__",
      "__subclasses__", "self.", "request.", "os.", "subprocess",
      "import", "eval", "exec", "system", "popen", "getattr"],
     "template syntax near a sandbox-escape keyword",
     "any"),
    # Demoted from the unconditional ssrf_attempt list (ISSUE-14): a bare
    # loopback address (bind syntax, a local dev-server URL, a test fixture
    # connecting to its own service) has no attack signal on its own. The
    # real SSRF-bypass shape is a tool call fetching a caller-controlled
    # URL that unexpectedly resolves to loopback/internal instead of the
    # intended external host, so this requires an outbound-request verb or
    # scheme nearby -- which a bare bind() call won't have.
    ("ssrf_attempt",
     re.compile(r"(localhost|\b127\.0\.0\.\d{1,3}\b|\b0\.0\.0\.0\b|::1)", re.IGNORECASE),
     # Bare "connect" was dropped: it's an ordinary English verb ("connect
     # to localhost for the test fixture") as often as it's code, unlike
     # the function-call/scheme shapes below.
     ["fetch", "curl", "wget", "http://", "https://", "requests.get",
      "requests.post", "urlopen", "axios", ".get(", ".post("],
     "loopback address near an outbound fetch/request call",
     "any"),
]




def _keyword_present(window, keyword):
    """Whole-word match for plain alphanumeric keywords so a short keyword
    does not match inside an ordinary longer word that happens to contain
    it as a substring. Falls back to substring match for keywords that
    already contain spaces or special characters (already distinctive
    enough on their own; a plain word-boundary check does not work cleanly
    around non-word characters)."""
    if keyword.isalnum():
        return re.search(rf"\b{re.escape(keyword)}\b", window) is not None
    return keyword in window


# Fields conventionally used for prose or documentation content rather than
# a literal command to run (mirrors the field-name convention in
# scripts/claude_code_hook.py and scripts/gemini_cli_hook.py). A markdown
# code span or a JS/Ruby template literal is completely ordinary content in
# these fields; the backtick shape alone is not a meaningful signal there
# the way it is in a field actually named "command".
_BACKTICK_PRONE_FIELDS = {"content", "pattern", "instruction", "new_string", "old_string", "text", "description"}

_BACKTICK_PAIR = re.compile(r"`[^`]*`")

# The blocked payload literals include bind-looking strings, but they are
# match targets, not sockets opened by this code.
_BACKTICK_DANGEROUS_KEYWORDS = ['curl', 'wget', 'netcat', ' nc ', 'chmod 777', 'rm -rf', '/etc/passwd', '/etc/shadow', 'base64 -d', '0.0.0.0', '/dev/tcp', 'sh -c', 'bash -c', 'eval(', 'exec(']  # nosec B104


def _field_name(path):
    """Last dict-key segment of a scan path, ignoring any trailing
    list-index segment. Used only to decide whether the backtick check
    below should require a dangerous keyword nearby."""
    tail = path.rsplit(".", 1)[-1]
    return tail.split("[", 1)[0]


def _backtick_hits(text, field):
    """Backtick command substitution: unconditional for fields that
    plausibly hold an actual command (the pre-hardening-pass behavior),
    keyword-gated for fields conventionally used for prose or code
    documentation. See _BACKTICK_PRONE_FIELDS above."""
    hits = []
    prose_field = field in _BACKTICK_PRONE_FIELDS
    for m in _BACKTICK_PAIR.finditer(text):
        if not prose_field:
            hits.append({"pattern_id": "shell_injection",
                         "detail": "backtick command substitution in argument"})
            break
        s, e = m.start(), m.end()
        window = text[max(0, s - _ARG_INJECTION_WINDOW): e + _ARG_INJECTION_WINDOW].lower()
        if any(_keyword_present(window, k) for k in _BACKTICK_DANGEROUS_KEYWORDS):
            hits.append({"pattern_id": "shell_injection",
                         "detail": "backtick command substitution near a known dangerous command"})
            break
    return hits


def _contextual_arg_injection_hits(text: str) -> list[dict]:
    """Same window-then-keyword-check design as ComplianceLayer.scrub()'s
    contextual patterns: a candidate match only counts when a real keyword
    is nearby, not on the punctuation shape alone. `direction` restricts
    which side of the match is searched — see the design note above
    _ARG_INJECTION_CONTEXTUAL for why the SQL-separator entry is after-only."""
    findings: list[dict] = []
    for pid, rx, keywords, detail, direction in _ARG_INJECTION_CONTEXTUAL:
        for m in rx.finditer(text):
            s, e = m.start(), m.end()
            if direction == "after":
                window = text[e: e + _ARG_INJECTION_WINDOW].lower()
            elif direction == "before":
                window = text[max(0, s - _ARG_INJECTION_WINDOW): s].lower()
            else:
                # "any": the original symmetric window, including the
                # matched span itself -- some patterns (e.g. template
                # syntax) need to match a keyword sitting INSIDE the
                # match, not just outside it.
                window = text[max(0, s - _ARG_INJECTION_WINDOW): e + _ARG_INJECTION_WINDOW].lower()
            if any(_keyword_present(window, k) for k in keywords):
                findings.append({"pattern_id": pid, "detail": detail})
                break  # one contextual finding per pattern_id is enough
    return findings


# ── output exfiltration patterns ──────────────────────────────────────────────

_OUTPUT_EXFIL: list[tuple[str, re.Pattern, str]] = [
    ("aws_key",
     re.compile(r"AKIA[0-9A-Z]{16}"),
     "AWS access key in output"),
    ("aws_secret",
     re.compile(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*[A-Za-z0-9/+=]{40}"),
     "AWS secret key in output"),
    ("private_key_header",
     re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
     "private key material in output"),
    ("jwt_token",
     re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "JWT token in output"),
    ("github_pat",
     re.compile(r"(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{82})"),
     "GitHub personal access token in output"),
    ("generic_secret",
     re.compile(
         r"(?i)(password|passwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token"
         r"|client[_-]?secret)\s*[:=]\s*['\"]?\S{8,}",
     ),
     "probable secret value in output"),
    ("pem_block",
     re.compile(r"-----BEGIN CERTIFICATE-----"),
     "certificate material in output (may contain private info)"),
]

# ── dangerous tool chain patterns ─────────────────────────────────────────────

_DANGEROUS_CHAINS: list[tuple[str, list[str], str]] = [
    ("data_exfil",
     [SideEffect.READ, SideEffect.EXTERNAL_MESSAGE],
     "read then external_message — possible data exfiltration"),
    ("read_then_payment",
     [SideEffect.READ, SideEffect.PAYMENT],
     "read then payment — confirm deliberate intent"),
    ("multi_write",
     [SideEffect.WRITE, SideEffect.WRITE, SideEffect.WRITE],
     "three consecutive writes — bulk mutation, confirm intent"),
    ("escalating_privileges",
     [SideEffect.READ, SideEffect.WRITE, SideEffect.PAYMENT],
     "read → write → payment — high-risk privilege escalation chain"),
    ("config_then_destructive",
     [SideEffect.CONFIG_CHANGE, SideEffect.DESTRUCTIVE],
     "config change then destructive operation — elevated risk"),
    ("write_then_external",
     [SideEffect.WRITE, SideEffect.EXTERNAL_MESSAGE],
     "write then external_message — data leaving after mutation"),
    ("triple_external",
     [SideEffect.EXTERNAL_MESSAGE, SideEffect.EXTERNAL_MESSAGE, SideEffect.EXTERNAL_MESSAGE],
     "three consecutive external messages — possible bulk data leak"),
]

# ── provenance record ─────────────────────────────────────────────────────────

@dataclass
class OutputProvenance:
    """Tracks where a tool output came from and what was found in it."""
    tool_name: str
    tenant_id: str
    session_id: str
    ok: bool
    findings: list[dict]
    output_size_bytes: int
    validated_at: float = field(default_factory=time.time)
    schema_validated: bool = False

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "ok": self.ok,
            "findings": self.findings,
            "output_size_bytes": self.output_size_bytes,
            "validated_at": self.validated_at,
            "schema_validated": self.schema_validated,
        }


# ── policy ────────────────────────────────────────────────────────────────────

@dataclass
class ToolPolicy:
    """Configuration for one registered tool.

    Full JSON Schema is supported in both ``schema`` (argument validation)
    and ``output_schema`` (output validation). See validate_schema() for the
    complete list of supported keywords.
    """
    name: str
    schema: dict[str, Any]

    # Side-effect classification. Use SideEffect constants.
    side_effect: str = SideEffect.READ

    # Default verdict when all checks pass
    action: Verdict = Verdict.ALLOW

    # Tenant allow-list. None = all tenants allowed.
    allowed_tenants: Optional[set[str]] = None

    # Action-label allow-list. None = all actions allowed.
    allowed_actions: Optional[set[str]] = None

    # Per-(tenant, session) call limit. None = unlimited.
    max_calls_per_session: Optional[int] = None

    # Human-readable description
    detail: str = ""

    # Optional output schema (full JSON Schema supported)
    output_schema: Optional[dict[str, Any]] = None

    # Max output size in bytes (0 = no limit)
    max_output_bytes: int = 0

    # Skip argument injection scanning for this tool.
    # Only use for tools with their own strict input sanitization.
    skip_arg_injection_scan: bool = False

    # Require human approval if side_effect severity is at least this level.
    # None = use action field only.
    escalate_if_severity_gte: Optional[str] = None

    # Compiled jsonschema validators, built once at registration so evaluate()
    # never re-checks/rebuilds the schema per call (P2-3). Internal.
    _validator: Any = field(default=None, init=False, repr=False, compare=False)
    _output_validator: Any = field(default=None, init=False, repr=False, compare=False)


# ── decision ──────────────────────────────────────────────────────────────────

@dataclass
class ToolDecision:
    decision_id: str
    tool_name: str
    tenant_id: str
    session_id: str
    action_label: str
    verdict: Verdict
    reason: str
    side_effect: str
    injection_findings: list[dict] = field(default_factory=list)
    chain_context: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "tool_name": self.tool_name,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "action_label": self.action_label,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "side_effect": self.side_effect,
            "injection_findings": self.injection_findings,
            "chain_context": self.chain_context,
            "created_at": self.created_at,
        }


@dataclass
class OutputValidationResult:
    ok: bool
    reason: str
    findings: list[dict] = field(default_factory=list)
    provenance: Optional[OutputProvenance] = None


# ── full JSON Schema validator ────────────────────────────────────────────────

# format validators
_FORMAT_VALIDATORS: dict[str, re.Pattern] = {
    "date-time": re.compile(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$"),
    "date": re.compile(r"^\d{4}-\d{2}-\d{2}$"),
    "time": re.compile(r"^\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$"),
    "email": re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    "uri": re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://"),
    "uuid": re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE),
    "ipv4": re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"),
    "ipv6": re.compile(r"^[0-9a-fA-F:]+$"),
    "hostname": re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"),
}

_TYPE_MAP: dict[str, type | tuple] = {
    "string":  str,
    "integer": int,
    "number":  (int, float),
    "boolean": bool,
    "array":   list,
    "object":  dict,
    "null":    type(None),
}


def compile_schema_validator(schema: dict[str, Any]):
    """Compile a Draft 2020-12 validator once for reuse across calls (P2-3).

    Returns None when jsonschema is unavailable. Raises SchemaError for an
    invalid schema (callers that compile eagerly catch it and fall back to
    the per-call path, which reports the error in the decision reason)."""
    if Draft202012Validator is None:
        return None
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schema,
        format_checker=FormatChecker() if FormatChecker else None,
    )


def validate_schema(
    value: Any,
    schema: dict[str, Any],
    *,
    path: str = "$",
    defs: Optional[dict[str, Any]] = None,
    validator: Any = None,
    redact_values: bool = False,
) -> tuple[bool, str]:
    """Validate with JSON Schema Draft 2020-12.

    Returns the historical ``(ok, reason)`` tuple so ToolGuard callers do not
    need to know which validation engine is underneath. Pass a prebuilt
    ``validator`` (see compile_schema_validator) to skip the per-call
    check_schema + constructor cost. If jsonschema is not importable, the
    legacy in-module validator below is used as a fallback.

    redact_values=True omits the failing *instance* value from the returned
    reason, describing the failure by location + the constraint that failed.
    Callers that write the reason to the durable audit log MUST set this: the
    default jsonschema message embeds the raw value (e.g. a rejected SSN- or
    note-shaped argument), which the GDPR redaction fields did not scrub and
    which is not always PII-pattern-shaped (B1).
    """
    if Draft202012Validator is not None:
        try:
            if validator is None:
                validator = compile_schema_validator(schema)
            errors = sorted(validator.iter_errors(value), key=lambda e: list(e.absolute_path))
        except SchemaError as exc:
            message = getattr(exc, "message", str(exc))
            return False, f"{path}: invalid schema: {message}"
        except Exception as exc:
            return False, f"{path}: schema validation error: {exc}"
        if not errors:
            return True, ""
        err = errors[0]
        location = "$"
        for part in err.absolute_path:
            location += f"[{part}]" if isinstance(part, int) else f".{part}"
        if redact_values:
            return False, f"{location}: failed '{err.validator}' constraint"
        return False, f"{location}: {err.message}"

    # resolve $defs from root schema if not passed in
    if defs is None:
        defs = schema.get("$defs") or schema.get("definitions") or {}

    # $ref resolution (basic — local #/$defs/Name only)
    ref = schema.get("$ref")
    if ref:
        if ref.startswith("#/$defs/") or ref.startswith("#/definitions/"):
            def_name = ref.rsplit("/", 1)[-1]
            if def_name not in defs:
                return False, f"{path}: $ref '{ref}' not found in $defs"
            return validate_schema(value, defs[def_name], path=path, defs=defs)
        return False, f"{path}: unsupported $ref '{ref}' (only local $defs supported)"

    # type
    expected_types = schema.get("type")
    if expected_types is not None:
        if isinstance(expected_types, str):
            expected_types = [expected_types]
        type_ok = False
        for t in expected_types:
            py_type = _TYPE_MAP.get(t)
            if py_type is None:
                continue
            if isinstance(value, py_type):
                # JSON schema: integer must not be float
                if t == "integer" and isinstance(value, bool):
                    continue
                if t == "number" and isinstance(value, bool):
                    continue
                type_ok = True
                break
            # null special case
            if t == "null" and value is None:
                type_ok = True
                break
        if not type_ok:
            got = "null" if value is None else type(value).__name__
            return False, f"{path}: expected type {expected_types}, got {got}"

    # const
    if "const" in schema and value != schema["const"]:
        return False, f"{path}: must equal {schema['const']!r}"

    # enum
    if "enum" in schema and value not in schema["enum"]:
        return False, f"{path}: must be one of {schema['enum']}"

    # string keywords
    if isinstance(value, str):
        mn = schema.get("minLength")
        mx = schema.get("maxLength")
        if mn is not None and len(value) < mn:
            return False, f"{path}: string length {len(value)} < minLength {mn}"
        if mx is not None and len(value) > mx:
            return False, f"{path}: string length {len(value)} > maxLength {mx}"
        pat = schema.get("pattern")
        if pat is not None and not re.search(pat, value):
            return False, f"{path}: string does not match pattern {pat!r}"
        fmt = schema.get("format")
        if fmt and fmt in _FORMAT_VALIDATORS:
            if not _FORMAT_VALIDATORS[fmt].search(value):
                return False, f"{path}: string is not a valid {fmt}"

    # number keywords
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        def _n(k):
            return schema[k] if k in schema else None
        mn, mx = _n("minimum"), _n("maximum")
        exmn, exmx = _n("exclusiveMinimum"), _n("exclusiveMaximum")
        mo = _n("multipleOf")
        if mn is not None and value < mn:
            return False, f"{path}: {value} < minimum {mn}"
        if mx is not None and value > mx:
            return False, f"{path}: {value} > maximum {mx}"
        if exmn is not None and value <= exmn:
            return False, f"{path}: {value} <= exclusiveMinimum {exmn}"
        if exmx is not None and value >= exmx:
            return False, f"{path}: {value} >= exclusiveMaximum {exmx}"
        if mo is not None and (value % mo) != 0:
            return False, f"{path}: {value} is not a multiple of {mo}"

    # array keywords
    if isinstance(value, list):
        mn, mx = schema.get("minItems"), schema.get("maxItems")
        if mn is not None and len(value) < mn:
            return False, f"{path}: array length {len(value)} < minItems {mn}"
        if mx is not None and len(value) > mx:
            return False, f"{path}: array length {len(value)} > maxItems {mx}"
        if schema.get("uniqueItems") and len(value) != len(set(map(str, value))):
            return False, f"{path}: array items must be unique"
        # prefixItems (tuple validation)
        prefix = schema.get("prefixItems")
        if prefix:
            for i, (item, item_schema) in enumerate(zip(value, prefix)):
                ok, msg = validate_schema(item, item_schema, path=f"{path}[{i}]", defs=defs)
                if not ok:
                    return False, msg
            items_schema = schema.get("items")
            if items_schema is not None and len(value) > len(prefix):
                for i, item in enumerate(value[len(prefix):], start=len(prefix)):
                    ok, msg = validate_schema(item, items_schema, path=f"{path}[{i}]", defs=defs)
                    if not ok:
                        return False, msg
        else:
            items_schema = schema.get("items")
            if items_schema is not None:
                for i, item in enumerate(value):
                    ok, msg = validate_schema(item, items_schema, path=f"{path}[{i}]", defs=defs)
                    if not ok:
                        return False, msg
        contains = schema.get("contains")
        if contains:
            if not any(validate_schema(item, contains, path=f"{path}[?]", defs=defs)[0]
                       for item in value):
                return False, f"{path}: no item matches 'contains' schema"

    # object keywords
    if isinstance(value, dict):
        mn, mx = schema.get("minProperties"), schema.get("maxProperties")
        if mn is not None and len(value) < mn:
            return False, f"{path}: object has {len(value)} properties < minProperties {mn}"
        if mx is not None and len(value) > mx:
            return False, f"{path}: object has {len(value)} properties > maxProperties {mx}"
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                return False, f"{path}.{key}: required property missing"
        properties = schema.get("properties", {})
        for key, val in value.items():
            if key in properties:
                ok, msg = validate_schema(val, properties[key], path=f"{path}.{key}", defs=defs)
                if not ok:
                    return False, msg
        add_props = schema.get("additionalProperties")
        if add_props is False:
            extra = set(value.keys()) - set(properties.keys()) - set(
                schema.get("patternProperties", {}).keys())
            if extra:
                return False, f"{path}: additional properties not allowed: {sorted(extra)}"
        elif isinstance(add_props, dict):
            known = set(properties.keys())
            for key, val in value.items():
                if key not in known:
                    ok, msg = validate_schema(val, add_props, path=f"{path}.{key}", defs=defs)
                    if not ok:
                        return False, msg

    # composition keywords
    one_of = schema.get("oneOf")
    if one_of is not None:
        matching = [i for i, s in enumerate(one_of)
                    if validate_schema(value, s, path=path, defs=defs)[0]]
        if len(matching) != 1:
            return False, f"{path}: oneOf: exactly 1 schema must match, {len(matching)} matched"

    any_of = schema.get("anyOf")
    if any_of is not None:
        if not any(validate_schema(value, s, path=path, defs=defs)[0] for s in any_of):
            return False, f"{path}: anyOf: value must match at least one schema"

    all_of = schema.get("allOf")
    if all_of is not None:
        for i, s in enumerate(all_of):
            ok, msg = validate_schema(value, s, path=path, defs=defs)
            if not ok:
                return False, f"{path}: allOf[{i}]: {msg}"

    not_schema = schema.get("not")
    if not_schema is not None:
        ok, _ = validate_schema(value, not_schema, path=path, defs=defs)
        if ok:
            return False, f"{path}: value must NOT match 'not' schema"

    # if / then / else
    if_schema = schema.get("if")
    if if_schema is not None:
        cond_ok, _ = validate_schema(value, if_schema, path=path, defs=defs)
        branch = schema.get("then") if cond_ok else schema.get("else")
        if branch is not None:
            ok, msg = validate_schema(value, branch, path=path, defs=defs)
            if not ok:
                return False, msg

    return True, ""


# ── ToolGuardLayer ────────────────────────────────────────────────────────────

class ToolGuardLayer:
    """
    Deterministic, multi-layer tool-call safety guard.

    Usage::

        guard = ToolGuardLayer(policies=[
            ToolPolicy(
                name="query_db",
                side_effect=SideEffect.READ,
                action=Verdict.ALLOW,
                allowed_tenants={"acme"},
                schema={
                    "type": "object",
                    "required": ["sql"],
                    "properties": {
                        "sql": {"type": "string", "maxLength": 4096}
                    },
                    "additionalProperties": False,
                },
                output_schema={...},
                max_output_bytes=65536,
            )
        ])

        decision = guard.evaluate("query_db", args, tenant_id="acme", session_id="s1")
        if decision.verdict == Verdict.BLOCK:
            raise PermissionError(decision.reason)

        result = db.query(...)

        out = guard.validate_output("query_db", result, tenant_id="acme", session_id="s1")
        if not out.ok:
            raise ValueError(out.reason)
    """

    def __init__(
        self,
        policies: list[ToolPolicy] | None = None,
        default_verdict: Verdict = Verdict.BLOCK,
        chain_window: int = 10,
        judge: Optional[Any] = None,
        backend: Optional[Any] = None,
        chain_ttl_s: int = 300,
        fail_open: bool = False,
    ) -> None:
        self.policies: dict[str, ToolPolicy] = {}
        self.default_verdict = default_verdict
        self.chain_window = chain_window
        self.chain_ttl_s = chain_ttl_s
        self._backend = backend
        # E2: when a shared backend (Redis) IS configured but a call to it
        # fails, session-call-limit and chain-history counters used to fall
        # back silently to per-process in-memory state. Under multiple workers
        # that multiplies a session cap by the worker count (each worker counts
        # only the calls it saw), letting an attacker exceed the intended
        # limit during a backend blip. Default fail closed: a backend failure
        # BLOCKs the call instead. Set fail_open=True to prefer availability
        # (the old silent per-process fallback) where that trade is acceptable.
        self.fail_open = fail_open
        # Guards the in-memory chain history and call counters: evaluate()
        # may be called from multiple threads (sync API, thread-pool hosts).
        # NOTE: without a shared backend (Redis) this state is per-process —
        # chain detection and session call limits are only correct across
        # uvicorn workers when a Redis backend is configured.
        self._lock = threading.Lock()
        # (tenant_id, session_id) -> list of side_effects (bounded to chain_window)
        self._side_effect_history: dict[tuple[str, str], list[str]] = defaultdict(list)
        # per-(tenant, session, tool) -> (count, window_started); the window
        # resets after chain_ttl_s so keys cannot grow without bound (P2-2)
        self._call_counts: dict[tuple[str, str, str], tuple[int, float]] = {}
        # Bounded: appended on every run() since validate_output was wired
        # into the pipeline — unbounded lists leak linearly with traffic
        # (P2-2). Durable audit lives in the trace store, not here.
        self._provenance_log: deque[OutputProvenance] = deque(maxlen=10_000)
        self.audit_log: deque[ToolDecision] = deque(maxlen=10_000)
        # Optional LLMJudge: a semantic safety net consulted for
        # high-severity tools via evaluate_async(). It can only make a
        # decision STRICTER (ALLOW->ESCALATE/BLOCK), never looser.
        self.judge = judge
        for p in (policies or []):
            self.register(p)

    def register(self, policy: ToolPolicy) -> None:
        """Register a new tool policy at runtime.

        Validators are compiled once here, not per evaluate() call (P2-3).
        An invalid schema leaves the compiled validator unset; the per-call
        path then reports the schema error in the decision reason, exactly
        as before."""
        try:
            policy._validator = compile_schema_validator(policy.schema)
        except Exception:
            policy._validator = None
        if policy.output_schema is not None:
            try:
                policy._output_validator = compile_schema_validator(policy.output_schema)
            except Exception:
                policy._output_validator = None
        self.policies[policy.name] = policy

    @staticmethod
    def _scope_digest(*parts: str) -> str:
        blob = "\0".join(str(part) for part in parts).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def _backend_key(self, kind: str, *parts: str) -> str:
        return f"pramagent:toolguard:{kind}:{self._scope_digest(*parts)}"

    def _session_call_count(self, tenant_id: str, session_id: str, tool_name: str) -> int:
        key = (tenant_id, session_id, tool_name)
        if self._backend is not None:
            try:
                return int(self._backend.increment(
                    self._backend_key("calls", tenant_id, session_id, tool_name),
                    ttl_s=self.chain_ttl_s,
                ))
            except Exception as exc:
                if not self.fail_open:
                    # E2: don't silently under-count via per-process memory;
                    # let evaluate() fail the call closed.
                    raise _BackendUnavailable(
                        f"session call-count backend unavailable: {exc}") from exc
                log.warning("ToolGuard backend call count unavailable; falling back to memory: %s", exc)
        now = time.time()
        with self._lock:
            count, window_started = self._call_counts.get(key, (0, now))
            if now - window_started >= self.chain_ttl_s:
                # window elapsed: reset, mirroring the backend key TTL (P2-2)
                count, window_started = 0, now
            count += 1
            self._call_counts[key] = (count, window_started)
            return count

    def _append_side_effect(self, tenant_id: str, session_id: str,
                            side_effect: str) -> list[str]:
        """Append one side effect to the (tenant, session) chain history and
        return the updated window.

        Backend path: uses the backend's atomic history_append (Redis Lua
        RPUSH+LTRIM+EXPIRE) when available, so concurrent same-session calls
        on different workers never lose updates. Legacy backends without
        history_append fall back to load→append→store (non-atomic, logged).
        In-memory path: mutation under the lock."""
        if self._backend is not None:
            key = self._backend_key("history", tenant_id, session_id)
            try:
                if hasattr(self._backend, "history_append"):
                    return [str(item) for item in self._backend.history_append(
                        key, side_effect,
                        max_len=self.chain_window, ttl_s=self.chain_ttl_s)]
                log.warning(
                    "ToolGuard backend lacks atomic history_append; "
                    "using non-atomic load-append-store")
                raw = self._backend.get(key)
                history = ([str(item) for item in raw][-self.chain_window:]
                           if isinstance(raw, list) else [])
                history.append(side_effect)
                history = history[-self.chain_window:]
                self._backend.set(key, history, ttl_s=self.chain_ttl_s)
                return history
            except _BackendUnavailable:
                raise
            except Exception as exc:
                if not self.fail_open:
                    # E2: fail closed rather than losing cross-worker chain
                    # history to a per-process fallback.
                    raise _BackendUnavailable(
                        f"chain-history backend unavailable: {exc}") from exc
                log.warning("ToolGuard backend side-effect history unavailable; falling back to memory: %s", exc)
        with self._lock:
            history = self._side_effect_history[(tenant_id, session_id)]
            history.append(side_effect)
            del history[:-self.chain_window]
            return list(history)

    def _record(self, decision: ToolDecision) -> ToolDecision:
        self.audit_log.append(decision)
        return decision

    def _block(self, tool_name, tenant_id, session_id, action_label, reason,
               side_effect="unknown", **kwargs) -> ToolDecision:
        return self._record(ToolDecision(
            decision_id=str(uuid.uuid4()),
            tool_name=tool_name, tenant_id=tenant_id, session_id=session_id,
            action_label=action_label, verdict=Verdict.BLOCK,
            reason=reason, side_effect=side_effect, **kwargs,
        ))

    def _escalate(self, tool_name, tenant_id, session_id, action_label, reason,
                  side_effect="unknown", **kwargs) -> ToolDecision:
        return self._record(ToolDecision(
            decision_id=str(uuid.uuid4()),
            tool_name=tool_name, tenant_id=tenant_id, session_id=session_id,
            action_label=action_label, verdict=Verdict.ESCALATE,
            reason=reason, side_effect=side_effect, **kwargs,
        ))

    def evaluate(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        tenant_id: str = "default",
        session_id: str = "default",
        action_label: str = "tool_call",
    ) -> ToolDecision:
        """Evaluate a proposed tool call. Returns a ToolDecision.

        verdict == BLOCK   → must not execute
        verdict == ESCALATE → requires human approval before execution
        verdict == ALLOW   → cleared to execute
        """
        policy = self.policies.get(tool_name)

        # 1. Policy allow-list
        if policy is None:
            return self._block(tool_name, tenant_id, session_id, action_label,
                               f"tool '{tool_name}' is not registered")

        # 2. Tenant allow-list
        if policy.allowed_tenants is not None and tenant_id not in policy.allowed_tenants:
            return self._block(tool_name, tenant_id, session_id, action_label,
                               f"tenant '{tenant_id}' not in allowed_tenants for '{tool_name}'",
                               side_effect=policy.side_effect)

        # 3. Action allow-list
        if policy.allowed_actions is not None and action_label not in policy.allowed_actions:
            return self._block(tool_name, tenant_id, session_id, action_label,
                               f"action '{action_label}' is not allowed for '{tool_name}'",
                               side_effect=policy.side_effect)

        # 4. Argument schema validation (full JSON Schema, compiled once
        #    at registration — P2-3)
        # redact_values=True: this reason is written to the durable audit
        # log, so it must not carry the raw failing argument value (B1).
        ok, schema_reason = validate_schema(arguments, policy.schema,
                                            validator=policy._validator,
                                            redact_values=True)
        if not ok:
            return self._block(tool_name, tenant_id, session_id, action_label,
                               f"argument schema violation: {schema_reason}",
                               side_effect=policy.side_effect)

        # 5. Argument injection scanning
        injection_findings = []
        if not policy.skip_arg_injection_scan:
            injection_findings = scan_arguments_for_injection(arguments)
            if injection_findings:
                # The high-precision and contextual checks in
                # scan_arguments_for_injection can both report the same
                # pattern_id for one string (e.g. a keyword match and a
                # punctuation-near-keyword match) -- dedupe for display,
                # order preserved, findings themselves are untouched.
                seen_pids: list[str] = []
                for f in injection_findings:
                    if f["pattern_id"] not in seen_pids:
                        seen_pids.append(f["pattern_id"])
                pids = ", ".join(seen_pids)
                return self._block(tool_name, tenant_id, session_id, action_label,
                                   f"injection detected in arguments: {pids}",
                                   side_effect=policy.side_effect,
                                   injection_findings=injection_findings)

        # 6. Per-session call limit
        if policy.max_calls_per_session is not None:
            try:
                count = self._session_call_count(tenant_id, session_id, tool_name)
            except _BackendUnavailable as exc:
                return self._block(tool_name, tenant_id, session_id, action_label,
                                   f"session-limit backend unavailable; failing closed: {exc}",
                                   side_effect=policy.side_effect)
            if count > policy.max_calls_per_session:
                return self._block(tool_name, tenant_id, session_id, action_label,
                                   f"session call limit ({policy.max_calls_per_session}) exceeded",
                                   side_effect=policy.side_effect)

        # 7. Side-effect severity escalation
        if policy.escalate_if_severity_gte and SideEffect.is_at_least(
            policy.side_effect, policy.escalate_if_severity_gte
        ):
            return self._escalate(tool_name, tenant_id, session_id, action_label,
                                  f"side-effect '{policy.side_effect}' meets escalation threshold "
                                  f"(>= {policy.escalate_if_severity_gte})",
                                  side_effect=policy.side_effect)

        # 8. Tool-chain detection — record this call's side-effect atomically,
        # then check the returned window
        try:
            history = self._append_side_effect(tenant_id, session_id, policy.side_effect)
        except _BackendUnavailable as exc:
            return self._block(tool_name, tenant_id, session_id, action_label,
                               f"chain-history backend unavailable; failing closed: {exc}",
                               side_effect=policy.side_effect)

        chain_verdict, chain_reason, chain_ctx = detect_dangerous_chain(history)
        if chain_verdict == Verdict.ESCALATE:
            return self._escalate(tool_name, tenant_id, session_id, action_label,
                                  f"dangerous tool chain: {chain_reason}",
                                  side_effect=policy.side_effect,
                                  chain_context=chain_ctx)

        # 9. Policy action
        if policy.action == Verdict.BLOCK:
            return self._block(tool_name, tenant_id, session_id, action_label,
                               policy.detail or "blocked by policy",
                               side_effect=policy.side_effect)
        if policy.action == Verdict.ESCALATE:
            return self._escalate(tool_name, tenant_id, session_id, action_label,
                                  policy.detail or "escalated by policy",
                                  side_effect=policy.side_effect)

        return self._record(ToolDecision(
            decision_id=str(uuid.uuid4()),
            tool_name=tool_name, tenant_id=tenant_id, session_id=session_id,
            action_label=action_label, verdict=Verdict.ALLOW,
            reason="all checks passed", side_effect=policy.side_effect,
        ))

    async def evaluate_async(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        tenant_id: str = "default",
        session_id: str = "default",
        action_label: str = "tool_call",
    ) -> ToolDecision:
        """Async evaluate: run the deterministic checks, then (for high-severity
        tools) consult the optional LLMJudge as a semantic safety net.

        The judge can only tighten the verdict, never loosen it:
        final = max_severity(deterministic_verdict, judge_verdict).
        If no judge is configured this is equivalent to evaluate().
        """
        decision = self.evaluate(
            tool_name, arguments,
            tenant_id=tenant_id, session_id=session_id,
            action_label=action_label,
        )
        # Only consult the judge when the deterministic layer did not already
        # BLOCK, and the tool is registered (we know its side_effect).
        if self.judge is None or decision.verdict == Verdict.BLOCK:
            return decision
        policy = self.policies.get(tool_name)
        if policy is None:
            return decision
        try:
            jd = await self.judge.evaluate(
                tool_name, arguments,
                side_effect=policy.side_effect,
                tenant_id=tenant_id, session_id=session_id,
            )
        except Exception:
            # Judge failure must not loosen the deterministic verdict.
            return decision
        order = {Verdict.ALLOW: 0, Verdict.REDACT: 1, Verdict.ESCALATE: 2, Verdict.BLOCK: 3}
        if order.get(jd.verdict, 0) > order.get(decision.verdict, 0):
            tightened = ToolDecision(
                decision_id=decision.decision_id,
                tool_name=tool_name, tenant_id=tenant_id, session_id=session_id,
                action_label=action_label, verdict=jd.verdict,
                reason=f"LLM judge tightened: {jd.reason}",
                side_effect=decision.side_effect,
                injection_findings=decision.injection_findings,
                chain_context=decision.chain_context,
            )
            self.audit_log.append(tightened)
            return tightened
        return decision

    def validate_output(
        self,
        tool_name: str,
        output: Any,
        *,
        tenant_id: str = "default",
        session_id: str = "default",
    ) -> OutputValidationResult:
        """Validate a tool's return value. Call after the tool executes.

        Checks (in order):
        1. Output size limit (if configured in policy)
        2. Output schema (full JSON Schema)
        3. Exfiltration marker scan on string output
        Records a provenance entry regardless of outcome.
        """
        policy = self.policies.get(tool_name)

        output_text = str(output)
        output_bytes = len(output_text.encode("utf-8"))

        def _prov(ok, findings, schema_validated=False):
            p = OutputProvenance(
                tool_name=tool_name, tenant_id=tenant_id, session_id=session_id,
                ok=ok, findings=findings, output_size_bytes=output_bytes,
                schema_validated=schema_validated,
            )
            self._provenance_log.append(p)
            return p

        if policy is None:
            # Unknown tool: still scan for exfil markers
            findings = _scan_output_exfil(output_text)
            if findings:
                prov = _prov(False, findings)
                return OutputValidationResult(
                    ok=False,
                    reason=f"exfiltration markers in unregistered tool output: "
                           f"{', '.join(f['pattern_id'] for f in findings)}",
                    findings=findings, provenance=prov)
            prov = _prov(True, [])
            return OutputValidationResult(
                ok=True, reason="tool not registered; output exfil scan passed",
                provenance=prov)

        # Size limit
        if policy.max_output_bytes > 0 and output_bytes > policy.max_output_bytes:
            prov = _prov(False, [])
            return OutputValidationResult(
                ok=False,
                reason=f"tool output exceeds max_output_bytes ({output_bytes} > {policy.max_output_bytes})",
                provenance=prov)

        # Schema validation
        schema_ok = False
        if policy.output_schema is not None:
            # redact_values: an output schema violation would otherwise echo
            # the raw (possibly PHI-bearing) output value into the reason (B1).
            ok, reason = validate_schema(output, policy.output_schema,
                                         validator=policy._output_validator,
                                         redact_values=True)
            if not ok:
                prov = _prov(False, [])
                return OutputValidationResult(
                    ok=False, reason=f"output schema violation: {reason}", provenance=prov)
            schema_ok = True

        # Exfiltration scan
        findings = _scan_output_exfil(output_text)
        if findings:
            prov = _prov(False, findings, schema_validated=schema_ok)
            return OutputValidationResult(
                ok=False,
                reason=f"possible sensitive data in tool output: "
                       f"{', '.join(f['pattern_id'] for f in findings)}",
                findings=findings, provenance=prov)

        prov = _prov(True, [], schema_validated=schema_ok)
        return OutputValidationResult(ok=True, reason="output validation passed", provenance=prov)

    def provenance_for(self, tenant_id: str, session_id: str) -> list[OutputProvenance]:
        """Return all provenance records for a (tenant, session) pair."""
        return [p for p in self._provenance_log
                if p.tenant_id == tenant_id and p.session_id == session_id]


def _scan_output_exfil(text: str) -> list[dict]:
    return [{"pattern_id": pid, "detail": detail}
            for pid, rx, detail in _OUTPUT_EXFIL if rx.search(text)]


# ── module-level helpers ──────────────────────────────────────────────────────

def scan_arguments_for_injection(arguments: Any, path: str = "$") -> list[dict]:
    """Recursively scan all string values in arguments for injection patterns.
    Returns a list of findings; empty means clean (not necessarily safe)."""
    findings: list[dict] = []
    if isinstance(arguments, str):
        for pid, rx, detail in _ARG_INJECTION:
            if rx.search(arguments):
                findings.append({"path": path, "pattern_id": pid, "detail": detail})
        for hit in _contextual_arg_injection_hits(arguments):
            findings.append({"path": path, **hit})
        for hit in _backtick_hits(arguments, _field_name(path)):
            findings.append({"path": path, **hit})
    elif isinstance(arguments, dict):
        for key, val in arguments.items():
            findings.extend(scan_arguments_for_injection(val, path=f"{path}.{key}"))
    elif isinstance(arguments, list):
        for idx, item in enumerate(arguments):
            findings.extend(scan_arguments_for_injection(item, path=f"{path}[{idx}]"))
    return findings


def detect_dangerous_chain(
    history: list[str],
    window: int = 0,
) -> tuple[Verdict, str, list[str]]:
    """Check whether the recent side-effect history matches a dangerous chain.
    Returns (verdict, reason, matching_history_slice)."""
    scope = history[-window:] if window > 0 else history
    for _name, pattern, reason in _DANGEROUS_CHAINS:
        n = len(pattern)
        if len(scope) >= n and scope[-n:] == pattern:
            return Verdict.ESCALATE, reason, list(scope[-n:])
    return Verdict.ALLOW, "", []
