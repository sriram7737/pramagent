#!/usr/bin/env python3
"""Gemini CLI BeforeTool hook -> Pramagent ToolGuardLayer.

Mirrors scripts/claude_code_hook.py's wiring (same ToolGuardLayer,
IsolationLayer, ComplianceLayer instances, same policy philosophy) for
Gemini CLI's BeforeTool hook event, which is Gemini CLI's equivalent of
Claude Code's PreToolUse. See docs/GEMINI_CLI_HOOK.md for the full contract
and the deliberate differences from the Claude Code hook.

Deliberate differences from scripts/claude_code_hook.py, each explained
where it happens below:
  1. Gemini CLI's hook stdout contract has no "ask" decision (only
     allow/deny/block) -- ESCALATE verdicts fail closed to deny instead
     of falling back to a human confirmation prompt, unless HITL is
     enabled and wired to a real approver.
  2. Any error in this script (bad JSON, an uncaught exception, an audit
     write failure) hard-blocks via exit code 2 instead of silently
     returning an empty/absent decision. Gemini CLI treats a non-0/non-2
     exit code as a non-fatal warning and lets the tool call proceed, so a
     crash here must not be allowed to fall through to that path.
  3. Every intercepted call is appended to a persistent, hash-chained
     audit log (pramagent.store.SQLiteStore, which implements the same
     AuditBackend protocol as pramagent.audit.HashChainBackend) so the
     chain survives across invocations -- each hook call is a fresh
     process, so an in-memory HashChainBackend would restart at genesis
     every time and never actually chain anything.

Install: see gemini_cli_hook.settings.json.example in this folder.
"""
from __future__ import annotations

import asyncio
import copy
import datetime
import json
import os
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from pramagent.layers.tool_guard import ToolGuardLayer, ToolPolicy, SideEffect
from pramagent.layers.isolation import IsolationLayer
from pramagent.layers import HITLLayer, ComplianceLayer
from pramagent.store import SQLiteStore
from pramagent.types import Verdict, HITLStatus

_COMPLIANCE = ComplianceLayer()  # PII/PHI regex scan, deterministic, no network/API calls

# block_on_injection=False: we want the hit list back so we can attribute a
# clear reason, not have it raise. The hook decides what to do with hits.
_ISOLATION = IsolationLayer(block_on_injection=False)

# Which tool_input fields carry free-text content worth scanning for
# injected instructions. "instruction" covers the replace tool's
# natural-language edit instruction field, which Claude Code's Edit tool
# has no equivalent of.
_SCANNABLE_FIELDS = ("command", "content", "new_string", "old_string", "pattern", "instruction")

# ── Audit chain ──────────────────────────────────────────────────────────
# File-backed so the hash chain survives across hook invocations: Gemini
# CLI runs this script as a brand-new process per tool call, so anything
# in-memory would restart at genesis every time and never actually link
# records together. SQLiteStore re-reads the chain head from disk under a
# write lock on every append, so this is also safe if Gemini CLI ever
# fires hooks for concurrent tool calls.
#
# Deliberately NOT constructed here at module import time: sqlite3.connect
# can raise (e.g. the target directory doesn't exist), and an exception
# raised during module import happens before main()'s try/except below
# ever runs, so it would crash with a generic, uncontrolled exit code
# instead of the deliberate sys.exit(2) hard-block. main() constructs it
# inside its own try block instead, so a failure here is handled exactly
# like any other hook failure.
_AUDIT_DB_PATH = os.environ.get(
    "PRAMAGENT_GEMINI_HOOK_AUDIT_DB",
    os.path.join(_REPO_ROOT, "pramagent_gemini_hook_audit.db"),
)


# ── HITL switch ──────────────────────────────────────────────────────────
# OFF by default, same as scripts/claude_code_hook.py. When off, ESCALATE
# verdicts deny (see (1) in the module docstring -- there is no "ask" to
# fall back to here). When PRAMAGENT_HOOK_ENABLE_HITL=1, ESCALATE instead
# routes through a real HITLLayer.gate() call. As wired below this is a
# stub with no approver/store configured, so it will simply wait out a
# short timeout and resolve to IDLE, which denies, every time. To make this
# actually useful, wire a real persistent store or approver callback
# before relying on this switch in practice.
_HITL_ENABLED = os.environ.get("PRAMAGENT_HOOK_ENABLE_HITL", "0") == "1"
_HITL_TIMEOUT_S = float(os.environ.get("PRAMAGENT_HOOK_HITL_TIMEOUT_S", "8"))

# Self-contained proof of invocation, independent of Gemini CLI's own
# verbose/debug output. Every call to this script appends one line here.
_LOG_PATH = os.path.join(_REPO_ROOT, "pramagent_gemini_hook.log")


def _log(*, tool_name: str, decision_summary: str) -> None:
    try:
        with open(_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(
                f"{datetime.datetime.now().isoformat()} "
                f"tool={tool_name} decision={decision_summary}\n"
            )
    except OSError:
        pass  # never let logging failure block a real tool decision


def _hitl_gate_sync(tool_name: str, tool_input: dict, reason: str) -> HITLStatus:
    hitl = HITLLayer(
        require_approval_for=[tool_name],
        timeout_s=_HITL_TIMEOUT_S,
        approver=None,   # no real approver wired yet, always times out to IDLE
        store=None,      # no persistent queue wired yet, see docstring above
    )
    return asyncio.run(hitl.propose(tool_name, {"reason": reason, "arguments": tool_input}))


def _decision_output(decision: str, reason: str) -> dict:
    """Shared shape for every non-silent verdict, in Gemini CLI's own
    BeforeTool stdout schema: a decision field (allow, deny, or block) plus
    a reason string.
    """
    return {"decision": decision, "reason": reason}


# ── Policy registration ─────────────────────────────────────────────────
# Tool names and parameter schemas are Gemini CLI's own built-in tool
# surface (confirmed against the google-gemini/gemini-cli docs/tools
# reference), not Claude Code's tool names -- registering the wrong names
# would mean every real Gemini CLI tool call gets denied as "not
# registered" by ToolGuardLayer's fail-closed default. Anything not
# registered here is still BLOCKed by default, deliberately: an
# unrecognized tool_name (e.g. a new host or connector tool) should not
# silently pass.
_GUARD = ToolGuardLayer()

_GUARD.register(ToolPolicy(
    name="run_shell_command",
    schema={
        "type": "object",
        "properties": {"command": {"type": "string"}},
        "required": ["command"],
    },
    side_effect=SideEffect.DESTRUCTIVE,
    escalate_if_severity_gte=SideEffect.WRITE,
    detail="Shell commands can delete or modify anything on disk. Escalate by default.",
))

_GUARD.register(ToolPolicy(
    name="write_file",
    schema={
        "type": "object",
        "properties": {"file_path": {"type": "string"}},
        "required": ["file_path"],
    },
    side_effect=SideEffect.WRITE,
))

_GUARD.register(ToolPolicy(
    name="replace",
    schema={
        "type": "object",
        "properties": {"file_path": {"type": "string"}},
        "required": ["file_path"],
    },
    side_effect=SideEffect.WRITE,
))

for _read_tool in ("read_file", "list_directory", "glob", "grep_search", "search_file_content"):
    _GUARD.register(ToolPolicy(
        name=_read_tool,
        schema={"type": "object"},
        side_effect=SideEffect.READ,
    ))


def _scan_tool_input_for_injection(tool_input: dict) -> list[dict]:
    hits = []
    for field in _SCANNABLE_FIELDS:
        value = tool_input.get(field)
        if isinstance(value, str) and value:
            hits.extend(_ISOLATION.scan_for_injection(value))
    return hits


def evaluate_event(event: dict) -> dict:
    """Pure decision logic: a parsed BeforeTool event in, the hook's JSON
    response out. No stdin/stdout/logging/audit side effects, so tests can
    call this directly. Returns {} for allow-no-comment (a non-BeforeTool
    event, or a clean ALLOW) -- an absent decision field means the same
    thing as an explicit allow in Gemini CLI's contract, but omitting it
    here keeps this function's return shape aligned with
    scripts/claude_code_hook.py's evaluate_event() for easy comparison.
    """
    if event.get("hook_event_name") != "BeforeTool":
        return {}

    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}
    session_id = event.get("session_id", "local")

    decision = _GUARD.evaluate(
        tool_name=tool_name,
        arguments=tool_input,
        tenant_id="gemini-cli-local",
        session_id=session_id,
        action_label="gemini_cli_tool_call",
    )

    if decision.verdict == Verdict.BLOCK:
        return _decision_output("deny", f"Pramagent ToolGuard: {decision.reason}")

    injection_hits = _scan_tool_input_for_injection(tool_input)
    if injection_hits:
        pattern_ids = ", ".join(h["pattern_id"] for h in injection_hits)
        reason = (
            f"Pramagent Isolation: possible prompt injection in "
            f"tool arguments ({pattern_ids}). Blocked -- Gemini CLI's hook "
            f"contract has no human-in-the-loop ask outcome, so this "
            f"fails closed rather than silently proceeding."
        )
        return _decision_output("deny", reason)

    pii_labels: list[str] = []
    for field in _SCANNABLE_FIELDS:
        value = tool_input.get(field)
        if isinstance(value, str) and value:
            _, redactions = _COMPLIANCE.scrub(value)
            pii_labels.extend(redactions)
    if pii_labels:
        labels = ", ".join(sorted(set(pii_labels)))
        reason = (
            f"Pramagent Compliance: possible PII/PHI in tool arguments "
            f"({labels}). Blocked pending review."
        )
        return _decision_output("deny", reason)

    if decision.verdict == Verdict.ESCALATE:
        if _HITL_ENABLED:
            status = _hitl_gate_sync(tool_name, tool_input, decision.reason)
            gemini_decision = "allow" if status == HITLStatus.APPROVED else "deny"
            reason = f"Pramagent HITL ({status.value}): {decision.reason}"
            return _decision_output(gemini_decision, reason)
        # No "ask" outcome exists in Gemini CLI's BeforeTool contract, so
        # an ESCALATE-worthy call fails closed to deny rather than
        # silently becoming an allow. Set PRAMAGENT_HOOK_ENABLE_HITL=1 and
        # wire a real approver/store to route these through HITLLayer
        # instead of a blanket deny.
        return _decision_output(
            "deny",
            f"Pramagent ToolGuard (escalate, no HITL wired): {decision.reason}",
        )

    return {}


def _decision_summary(output: dict) -> str:
    if not output:
        return "allow:clean"
    return f"{output.get('decision', 'allow')}:{output.get('reason', '')}"


def _record_audit_entry(audit: SQLiteStore, event: dict, output: dict) -> None:
    """Append one hash-chained record for every intercepted call,
    regardless of outcome -- allow, deny, or block alike. Uses SQLiteStore
    as the AuditBackend so the chain is durable across the fresh process
    each hook invocation runs in. Deliberately fails closed: if the audit
    write itself fails, the caller (main()) must treat that the same as
    any other unexpected error and hard-block, not silently allow a tool
    call that was never actually recorded."""
    payload = {
        "hook_event_name": "BeforeTool",
        "tool_name": event.get("tool_name", ""),
        "arguments": copy.deepcopy(event.get("tool_input", {}) or {}),
        "tenant_id": "gemini-cli-local",
        "session_id": event.get("session_id", "local"),
        "action_label": "gemini_cli_tool_call",
        "decision": output.get("decision", "allow") if output else "allow",
        "reason": output.get("reason", "") if output else "",
        "created_at": time.time(),
    }
    audit.append(payload)


def main() -> None:
    raw = sys.stdin.read()
    try:
        # Constructed here, inside the try block, not at module import
        # time: see the comment above _AUDIT_DB_PATH for why.
        audit = SQLiteStore(path=_AUDIT_DB_PATH)
        event = json.loads(raw) if raw else {}
        tool_name = event.get("tool_name", "?")
        output = evaluate_event(event)
        _record_audit_entry(audit, event, output)
    except Exception as exc:  # noqa: BLE001 -- deliberately broad: any
        # failure here (bad JSON, a layer raising, the audit store
        # failing to open or write) must hard-block, not fall through to
        # Gemini CLI's non-zero/non-2-exit-code-is-a-non-fatal-warning-
        # proceed-anyway behavior. See point (2) in the module docstring.
        sys.stderr.write(f"pramagent gemini_cli_hook failed closed: {exc}\n")
        _log(tool_name="<error>", decision_summary=f"deny:hook_error:{exc}")
        sys.exit(2)

    print(json.dumps(output))
    _log(tool_name=tool_name, decision_summary=_decision_summary(output))


if __name__ == "__main__":
    main()
