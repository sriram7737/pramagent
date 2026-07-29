#!/usr/bin/env python3
"""Claude Code PreToolUse hook -> Pramagent ToolGuardLayer.

Wires Claude Code's tool-call loop through Pramagent's guardrails: every
Bash/Write/Edit/Read/Grep/Glob call is evaluated by ToolGuardLayer before
Claude Code executes it. BLOCK denies the call, ESCALATE falls back to
Claude Code's normal human-confirmation prompt, ALLOW proceeds.

This runs Pramagent in-process (no server needed), which is fine for local
dev. For team-shared enforcement, point this at a running Pramagent API
instance's /v1/tools/check endpoint instead of importing the library
directly, so everyone shares one policy set and one audit trail.

Install: see claude_code_hook.settings.json.example in this folder.
"""
from __future__ import annotations

import asyncio
import datetime
import json
import os
import sys

from pramagent.layers.tool_guard import ToolGuardLayer, ToolPolicy, SideEffect
from pramagent.layers.isolation import IsolationLayer
from pramagent.layers import HITLLayer, ComplianceLayer
from pramagent.types import Verdict, HITLStatus

_COMPLIANCE = ComplianceLayer()  # PII/PHI regex scan, deterministic, no network/API calls

# block_on_injection=False: we want the hit list back so we can attribute a
# clear reason, not have it raise. The hook decides what to do with hits.
_ISOLATION = IsolationLayer(block_on_injection=False)

# Which tool_input fields actually carry free-text content worth scanning
# for injected instructions (as opposed to structural args like file paths).
_SCANNABLE_FIELDS = ("command", "content", "new_string", "old_string", "pattern")


def _scan_tool_input_for_injection(tool_input: dict) -> list[dict]:
    hits = []
    for field in _SCANNABLE_FIELDS:
        value = tool_input.get(field)
        if isinstance(value, str) and value:
            hits.extend(_ISOLATION.scan_for_injection(value))
    return hits


# ── HITL switch ──────────────────────────────────────────────────────────
# OFF by default. When off, an ESCALATE verdict just becomes Claude Code's
# own "ask" confirmation prompt (a human, you at the terminal, is already
# the approver in that path, so this isn't "no HITL". It's HITL via the
# terminal instead of via Pramagent's own queue).
#
# When PRAMAGENT_HOOK_ENABLE_HITL=1, ESCALATE verdicts instead route
# through a real HITLLayer.gate() call. IMPORTANT: as wired below this is
# a stub with no approver/store configured, so with no further setup it
# will simply wait out a short timeout and resolve to IDLE, which denies,
# every time. To make this actually useful, wire a real persistent store
# (e.g. PostgresHITLQueue, so a Slack/dashboard approval can unblock it) or
# a real approver callback before relying on this switch in practice.
_HITL_ENABLED = os.environ.get("PRAMAGENT_HOOK_ENABLE_HITL", "0") == "1"
_HITL_TIMEOUT_S = float(os.environ.get("PRAMAGENT_HOOK_HITL_TIMEOUT_S", "8"))

# Self-contained proof of invocation, independent of Claude Code's own
# verbose/debug output (which has, in practice, not reliably shown hook
# activity for every tool type). Every call to this script appends one
# line here, regardless of what Claude Code does or doesn't surface in its
# own logs.
_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pramagent_hook.log")


def _log(*, tool_name: str, decision_summary: str) -> None:
    """Append a plain-text audit line to _LOG_PATH: ground truth that
    doesn't depend on trusting Claude Code's own reporting."""
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


def _decision_output(permission_decision: str, reason: str) -> dict:
    """Shared shape for every non-silent verdict.

    permissionDecisionReason alone does not reliably surface in Claude
    Code UI for every tool type (confirmed via live testing against
    Write). additionalContext is the field that actually renders
    regardless of tool type, so both are set here.
    """
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission_decision,
            "permissionDecisionReason": reason,
        },
        "additionalContext": reason,
    }


# ── Policy registration ─────────────────────────────────────────────────
# Adjust these to taste. Anything not registered here is BLOCKed by
# ToolGuardLayer by default (fail-closed). That's deliberate: an
# unrecognized tool_name (e.g. a new host or connector tool) should not
# silently pass.
_GUARD = ToolGuardLayer()

_GUARD.register(ToolPolicy(
    name="Bash",
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
    name="Write",
    schema={
        "type": "object",
        "properties": {"file_path": {"type": "string"}},
        "required": ["file_path"],
    },
    side_effect=SideEffect.WRITE,
))

_GUARD.register(ToolPolicy(
    name="Edit",
    schema={
        "type": "object",
        "properties": {"file_path": {"type": "string"}},
        "required": ["file_path"],
    },
    side_effect=SideEffect.WRITE,
))

for _read_tool in ("Read", "Grep", "Glob"):
    _GUARD.register(ToolPolicy(
        name=_read_tool,
        schema={"type": "object"},
        side_effect=SideEffect.READ,
    ))


def evaluate_event(event: dict) -> dict:
    """Pure decision logic: a parsed PreToolUse event in, the hook's JSON
    response out. No stdin/stdout/logging side effects, so tests can call
    this directly instead of shelling out to the script.

    Returns {} for "say nothing, let Claude Code's own flow decide" (a
    non-PreToolUse event, or a clean ALLOW). Every other outcome is a dict
    shaped by _decision_output().
    """
    if event.get("hook_event_name") != "PreToolUse":
        return {}

    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}
    session_id = event.get("session_id", "local")

    decision = _GUARD.evaluate(
        tool_name=tool_name,
        arguments=tool_input,
        tenant_id="claude-code-local",
        session_id=session_id,
        action_label="claude_code_tool_call",
    )

    # ToolGuard's own verdict (tool execution attacks: dangerous shell/query
    # patterns, path/network exfiltration attempts, schema violations,
    # unregistered tools, chain/severity escalation).
    if decision.verdict == Verdict.BLOCK:
        return _decision_output("deny", f"Pramagent ToolGuard: {decision.reason}")

    # Separately, scan any free-text argument content for prompt-injection
    # phrasing (IsolationLayer). This catches the case where Claude Code
    # read something (a file, a page, a repo) containing hidden injected
    # instructions and is about to act on that content via a tool call.
    injection_hits = _scan_tool_input_for_injection(tool_input)
    if injection_hits:
        pattern_ids = ", ".join(h["pattern_id"] for h in injection_hits)
        reason = (
            f"Pramagent Isolation: possible prompt injection in "
            f"tool arguments ({pattern_ids}). Review before proceeding."
        )
        return _decision_output("ask", reason)

    # PII/PHI scan (ComplianceLayer). Deterministic regex, no LLM call.
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
            f"({labels}). Review before proceeding."
        )
        return _decision_output("ask", reason)

    if decision.verdict == Verdict.ESCALATE:
        if _HITL_ENABLED:
            status = _hitl_gate_sync(tool_name, tool_input, decision.reason)
            permission_decision = "allow" if status == HITLStatus.APPROVED else "deny"
            reason = f"Pramagent HITL ({status.value}): {decision.reason}"
            return _decision_output(permission_decision, reason)
        return _decision_output("ask", f"Pramagent ToolGuard: {decision.reason}")

    return {}


def _summarize(output: dict) -> str:
    """Reconstruct a short decision_summary string for the log file from
    evaluate_event()'s return value, so main() doesn't need to thread a
    separate summary string through every branch above."""
    hook_output = output.get("hookSpecificOutput")
    if not hook_output:
        return "allow:clean"
    return f"{hook_output.get('permissionDecision')}:{hook_output.get('permissionDecisionReason', '')}"


def main() -> None:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw else {}
        tool_name = event.get("tool_name", "?")
        output = evaluate_event(event)
    except Exception as exc:
        # Any failure here (bad JSON, a layer raising) must deny, not
        # silently return {} ("no opinion, use Claude Code's own default
        # flow"): that swallowed the failure with no visible signal that
        # Pramagent's own checks were skipped for this call.
        output = _decision_output(
            "deny", f"Pramagent hook error (failed closed): {exc}"
        )
        print(json.dumps(output))
        _log(tool_name="<error>", decision_summary=f"deny:hook_error:{exc}")
        return

    print(json.dumps(output))
    _log(tool_name=tool_name, decision_summary=_summarize(output))


if __name__ == "__main__":
    main()
