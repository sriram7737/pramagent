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

# Ensure the hook imports the pramagent package from the repo it lives in,
# not whatever build/site-packages copy happens to be importable for the
# interpreter that runs it (which may lag behind the repo). Mirrors the same
# guard in scripts/gemini_cli_hook.py.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from pramagent.hook_scan import scan_injection, scan_pii
from pramagent.hook_state import is_enabled as _hook_enabled
from pramagent.hook_state import get_policies as _central_policies
from pramagent.hook_state import tool_enabled as _tool_enabled
from pramagent.hook_state import tenant_tool_allowed as _tenant_tool_allowed
from pramagent.hook_state import targets_protected_path as _targets_protected_path

# Tenant this hook runs as. Operators running a coding agent on behalf of a
# specific tenant set PRAMAGENT_TENANT_ID; the admin console's per-tenant
# permissions are then enforced against it. Defaults to the local surface
# tenant, which is unmanaged by default (no restriction).
_TENANT_ID = os.environ.get("PRAMAGENT_TENANT_ID", "claude-code-local")
from pramagent.layers.tool_guard import ToolGuardLayer, ToolPolicy, SideEffect
from pramagent.layers.isolation import IsolationLayer
from pramagent.layers import HITLLayer, ComplianceLayer
from pramagent.types import Verdict, HITLStatus

_COMPLIANCE = ComplianceLayer()  # PII/PHI regex scan, deterministic, no network/API calls

# block_on_injection=False: we want the hit list back so we can attribute a
# clear reason, not have it raise. The hook decides what to do with hits.
_ISOLATION = IsolationLayer(block_on_injection=False)


# -- HITL switch ----------------------------------------------------------
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


# -- Policy registration -------------------------------------------------
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


def _apply_central_policy_overrides() -> None:
    """Merge any policies defined in the admin console over the built-in
    defaults (register() replaces by name, so a console policy overrides a
    same-named default and adds new tools). Each hook process is fresh, so this
    runs once per tool call  -  live edits take effect immediately. An individual
    invalid override is skipped, never allowed to crash the hook."""
    try:
        from pramagent.policies import tool_policy_from_dict
        for _policy in _central_policies() or []:
            try:
                _GUARD.register(tool_policy_from_dict(_policy))
            except Exception:
                continue
    except Exception:
        pass


_apply_central_policy_overrides()


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

    # Control-plane self-protection. A guarded tool call must never be able to
    # write the hook's own config or admin audit DB: those files govern the
    # guard itself, so a write to them could disable enforcement or silently
    # rewrite the policy set for every later call. Checked BEFORE the master
    # switch below, so a surface that a tampering write is trying to turn off
    # cannot skip this. Fail-safe: the config can only be changed through the
    # admin console, never by the constrained agent's own tool calls.
    protected_hit = _targets_protected_path(tool_name, tool_input)
    if protected_hit:
        return _decision_output(
            "deny",
            f"Pramagent hook self-protection: tool '{tool_name}' may not modify "
            f"the hook control plane ({protected_hit}). Change hook settings "
            f"through the admin console instead.")

    # Admin master switch: when this surface is disabled from the dashboard,
    # the hook no-ops to allow for the next call onward. Fail-safe  -  a missing
    # or corrupt state file leaves enforcement ON (see pramagent.hook_state).
    if not _hook_enabled("claude"):
        return {}

    # Per-tool master switch from the admin console: a tool switched off is
    # denied outright, regardless of its arguments.
    if not _tool_enabled(tool_name):
        return _decision_output(
            "deny", f"Pramagent hook admin: tool '{tool_name}' is disabled")

    # Per-tenant permission from the admin console: is this tenant allowed to
    # use this tool at all? Unmanaged tenants are unrestricted.
    if not _tenant_tool_allowed(_TENANT_ID, tool_name):
        return _decision_output(
            "deny",
            f"Pramagent hook admin: tenant '{_TENANT_ID}' is not permitted "
            f"to use tool '{tool_name}'")

    decision = _GUARD.evaluate(
        tool_name=tool_name,
        arguments=tool_input,
        tenant_id=_TENANT_ID,
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
    # phrasing over EVERY string argument (see pramagent.hook_scan: all
    # leaves, decoded runs included), not just a hardcoded field list  -  a
    # payload routed through any other field used to slip past this pass.
    injection_ids = scan_injection(tool_input, _ISOLATION)
    if injection_ids:
        pattern_ids = ", ".join(injection_ids)
        reason = (
            f"Pramagent Isolation: possible prompt injection in "
            f"tool arguments ({pattern_ids}). Review before proceeding."
        )
        return _decision_output("ask", reason)

    # PII/PHI scan (ComplianceLayer). Deterministic regex, no LLM call, same
    # all-leaves surface as the injection pass above.
    pii_labels = scan_pii(tool_input, _COMPLIANCE)
    if pii_labels:
        labels = ", ".join(pii_labels)
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
