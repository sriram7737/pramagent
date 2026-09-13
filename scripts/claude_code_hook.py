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

# Prefer the checkout beside this hook over an older installed package.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from pramagent.hook_scan import scan_injection, scan_pii
from pramagent.hook_state import is_enabled as _hook_enabled
from pramagent.hook_state import get_policies as _central_policies
from pramagent.hook_state import tool_enabled as _tool_enabled
from pramagent.hook_state import tenant_tool_allowed as _tenant_tool_allowed
from pramagent.hook_state import targets_protected_path as _targets_protected_path

# The local tenant is unrestricted until it is added to the admin console.
_TENANT_ID = os.environ.get("PRAMAGENT_TENANT_ID", "claude-code-local")
from pramagent.layers.tool_guard import ToolGuardLayer, ToolPolicy, SideEffect
from pramagent.layers.isolation import IsolationLayer
from pramagent.layers import HITLLayer, ComplianceLayer
from pramagent.types import Verdict, HITLStatus

_COMPLIANCE = ComplianceLayer()

# Return pattern IDs so the hook can explain its decision.
_ISOLATION = IsolationLayer(block_on_injection=False)


# HITL
# Without a configured HITL queue, Claude Code's native confirmation prompt
# handles escalations. Enabling this path without an approver times out closed.
_HITL_ENABLED = os.environ.get("PRAMAGENT_HOOK_ENABLE_HITL", "0") == "1"
_HITL_TIMEOUT_S = float(os.environ.get("PRAMAGENT_HOOK_HITL_TIMEOUT_S", "8"))

# Keep a local invocation log because host debug output is not authoritative.
_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pramagent_hook.log")


def _log(*, tool_name: str, decision_summary: str) -> None:
    """Append one local hook decision."""
    try:
        with open(_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(
                f"{datetime.datetime.now().isoformat()} "
                f"tool={tool_name} decision={decision_summary}\n"
            )
    except OSError:
        pass  # The policy decision must not depend on diagnostic logging.


def _hitl_gate_sync(tool_name: str, tool_input: dict, reason: str) -> HITLStatus:
    hitl = HITLLayer(
        require_approval_for=[tool_name],
        timeout_s=_HITL_TIMEOUT_S,
        approver=None,
        store=None,
    )
    return asyncio.run(hitl.propose(tool_name, {"reason": reason, "arguments": tool_input}))


def _decision_output(permission_decision: str, reason: str) -> dict:
    """Build the host response for a non-silent verdict.

    ``additionalContext`` keeps the reason visible for tools whose UI omits
    ``permissionDecisionReason``.
    """
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission_decision,
            "permissionDecisionReason": reason,
        },
        "additionalContext": reason,
    }


# Policy registration
# ToolGuard denies names that are not registered here.
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
    """Overlay valid admin policies on the built-in defaults."""
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
    """Evaluate one parsed PreToolUse event without I/O side effects."""
    if event.get("hook_event_name") != "PreToolUse":
        return {}

    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}
    session_id = event.get("session_id", "local")

    # Protect control-plane files before consulting the switch they contain.
    protected_hit = _targets_protected_path(tool_name, tool_input)
    if protected_hit:
        return _decision_output(
            "deny",
            f"Pramagent hook self-protection: tool '{tool_name}' may not modify "
            f"the hook control plane ({protected_hit}). Change hook settings "
            f"through the admin console instead.")

    # Missing or invalid state keeps enforcement enabled.
    if not _hook_enabled("claude"):
        return {}

    # A global tool disable takes precedence over its policy.
    if not _tool_enabled(tool_name):
        return _decision_output(
            "deny", f"Pramagent hook admin: tool '{tool_name}' is disabled")

    # Managed tenants are constrained by their allow and deny lists.
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

    # Structural policy failures are final.
    if decision.verdict == Verdict.BLOCK:
        return _decision_output("deny", f"Pramagent ToolGuard: {decision.reason}")

    # Scan every decoded string leaf, including content copied from tools.
    injection_ids = scan_injection(tool_input, _ISOLATION)
    if injection_ids:
        pattern_ids = ", ".join(injection_ids)
        reason = (
            f"Pramagent Isolation: possible prompt injection in "
            f"tool arguments ({pattern_ids}). Review before proceeding."
        )
        return _decision_output("ask", reason)

    # PII/PHI uses the same all-leaves traversal.
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
    """Return a compact decision label for the local log."""
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
        # Malformed input or an enforcement error must fail closed.
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
