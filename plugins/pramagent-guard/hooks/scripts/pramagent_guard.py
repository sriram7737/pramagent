#!/usr/bin/env python3
"""Pramagent Guard hook for Claude Code, Codex, and Grok-style agents.

The hook reads one tool-call event JSON object from stdin, evaluates the
proposed call with Pramagent ToolGuard policies from ``policies.json``, and
returns a hook decision JSON object on stdout.

This is a policy gate, not an OS sandbox. It can block, deny, or route a tool
call to the host agent's human-confirmation flow, but it does not isolate the
underlying process, filesystem, network, or credentials.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


TOOL_EVENTS = {"PreToolUse", "BeforeTool"}


def _plugin_root() -> Path:
    for name in (
        "PRAMAGENT_PLUGIN_ROOT",
        "CLAUDE_PLUGIN_ROOT",
        "PLUGIN_ROOT",
        "GROK_PLUGIN_ROOT",
    ):
        value = os.environ.get(name)
        if value:
            return Path(value).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def _event_name(event: dict[str, Any]) -> str:
    return str(event.get("hook_event_name") or event.get("hookEventName") or "")


def _tool_name(event: dict[str, Any]) -> str:
    return str(event.get("tool_name") or event.get("toolName") or "")


def _tool_input(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("tool_input")
    if value is None:
        value = event.get("toolInput")
    return value if isinstance(value, dict) else {}


def _session_id(event: dict[str, Any]) -> str:
    return str(event.get("session_id") or event.get("sessionId") or "local")


def _decision(
    permission: str, reason: str, event_name: str = "PreToolUse"
) -> dict[str, Any]:
    if event_name == "BeforeTool":
        # Gemini has no interactive ask result, so unresolved reviews deny.
        return {
            "decision": "allow" if permission == "allow" else "deny",
            "reason": reason,
        }
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,
            "permissionDecisionReason": reason,
        },
        "additionalContext": reason,
    }


def _no_op() -> dict[str, Any]:
    return {}


def _fail_decision(reason: str, event_name: str = "PreToolUse") -> dict[str, Any]:
    configured = os.environ.get("PRAMAGENT_GUARD_FAILURE_DECISION", "deny")
    permission = configured.strip().lower()
    if permission not in {"deny", "ask"}:
        permission = "deny"
    return _decision(permission, reason, event_name)


def _universal_deny(reason: str) -> dict[str, Any]:
    """Deny malformed input before the originating host can be identified."""
    output = _decision("deny", reason)
    output.update({"decision": "deny", "reason": reason})
    return output


def _escalate_decision() -> str:
    configured = os.environ.get("PRAMAGENT_HOOK_ESCALATE_DECISION")
    if configured:
        value = configured.strip().lower()
        if value in {"ask", "deny"}:
            return value

    # Codex historically treats "ask" less consistently than Claude Code.
    # Codex plugin hooks set PLUGIN_ROOT; Claude Code sets CLAUDE_PLUGIN_ROOT.
    if os.environ.get("PLUGIN_ROOT") and not os.environ.get("GROK_PLUGIN_ROOT"):
        return "deny"
    return "ask"


def evaluate_event(event: dict[str, Any]) -> dict[str, Any]:
    event_name = _event_name(event)
    if event_name not in TOOL_EVENTS:
        return _no_op()

    tool_name = _tool_name(event)
    tool_input = _tool_input(event)

    # Protect control-plane files before consulting the switch they contain.
    try:
        from pramagent.hook_state import targets_protected_path, targets_sensitive_path
        protected_hit = targets_protected_path(tool_name, tool_input)
        if protected_hit:
            return _decision(
                "deny",
                f"Pramagent hook self-protection: tool '{tool_name}' may not "
                f"modify the hook control plane ({protected_hit}). Change hook "
                f"settings through the admin console instead.",
                event_name,
            )
        sensitive_hit = targets_sensitive_path(tool_name, tool_input)
        if sensitive_hit:
            return _decision(
                "deny",
                f"Pramagent path policy: tool '{tool_name}' may not modify a "
                f"credential or system location ({sensitive_hit}).",
                event_name,
            )
    except Exception as exc:
        return _fail_decision(
            f"Pramagent Guard self-protection failed closed: {exc}", event_name
        )

    # Missing or invalid state keeps enforcement enabled.
    try:
        from pramagent.hook_state import is_enabled as _hook_enabled
        if not _hook_enabled("plugin"):
            return _no_op()
    except Exception:
        pass

    root = _plugin_root()
    policy_path = Path(
        os.environ.get("PRAMAGENT_GUARD_POLICY", root / "policies.json")
    )
    tenant_id = os.environ.get("PRAMAGENT_TENANT_ID", "local-dev")

    try:
        from pramagent.hook_scan import scan_injection, scan_pii, shell_command_risk
        from pramagent.hook_state import get_policies, tool_enabled, tenant_tool_allowed
        from pramagent.layers import ComplianceLayer
        from pramagent.layers.isolation import IsolationLayer
        from pramagent.policies import load_tool_guard, tool_policy_from_dict
        from pramagent.types import Verdict
    except Exception as exc:
        return _fail_decision(
            "Pramagent Guard failed closed: install Pramagent in this Python "
            f"environment (`pip install pramagent`). Import error: {exc}",
            event_name,
        )

    # Apply global tool and tenant permissions before policy evaluation.
    try:
        if not tool_enabled(tool_name):
            return _decision(
                "deny", f"Pramagent hook admin: tool '{tool_name}' is disabled",
                event_name)
        if not tenant_tool_allowed(tenant_id, tool_name):
            return _decision(
                "deny",
                f"Pramagent hook admin: tenant '{tenant_id}' is not permitted "
                f"to use tool '{tool_name}'", event_name)
    except Exception:
        pass  # fail-safe: unreadable switch -> enforce, don't silently allow

    try:
        guard = load_tool_guard(policy_path)
        # Merge admin-console policy overrides over the file-based defaults.
        for _policy in (get_policies() or []):
            try:
                guard.register(tool_policy_from_dict(_policy))
            except Exception:
                continue
        decision = guard.evaluate(
            tool_name,
            tool_input,
            tenant_id=tenant_id,
            session_id=_session_id(event),
            action_label="coding_agent_tool_call",
        )
    except Exception as exc:
        return _fail_decision(f"Pramagent Guard failed closed: {exc}", event_name)

    # Structural policy failures are final.
    if decision.verdict == Verdict.BLOCK:
        return _decision("deny", f"Pramagent ToolGuard: {decision.reason}", event_name)

    # Scan every decoded string leaf for injection and sensitive data. Hosts
    # without an interactive "ask" result deny escalations.
    try:
        isolation = IsolationLayer(block_on_injection=False)
        compliance = ComplianceLayer()
        injection_ids = scan_injection(tool_input, isolation)
        if injection_ids:
            return _decision(
                _escalate_decision(),
                "Pramagent Isolation: possible prompt injection in tool "
                f"arguments ({', '.join(injection_ids)}). Review before proceeding.",
                event_name,
            )
        pii_labels = scan_pii(tool_input, compliance)
        if pii_labels:
            return _decision(
                _escalate_decision(),
                "Pramagent Compliance: possible PII/PHI in tool arguments "
                f"({', '.join(pii_labels)}). Review before proceeding.",
                event_name,
            )
    except Exception as exc:
        return _fail_decision(
            f"Pramagent Guard content scan failed closed: {exc}", event_name
        )

    if tool_name in {"Bash", "PowerShell", "run_shell_command", "exec_command"}:
        command = tool_input.get("command", tool_input.get("cmd"))
        shell_risk, shell_reason = shell_command_risk(command)
        if shell_risk == "deny":
            return _decision(
                "deny", f"Pramagent shell policy: {shell_reason}.", event_name
            )
        if shell_risk == "allow":
            return _no_op()

    if decision.verdict == Verdict.ESCALATE:
        return _decision(
            _escalate_decision(),
            f"Pramagent ToolGuard escalation: {decision.reason}",
            event_name,
        )
    if decision.verdict == Verdict.ALLOW:
        return _no_op()
    return _decision(
        "deny", f"Pramagent ToolGuard unknown verdict: {decision.verdict}", event_name
    )


def main() -> int:
    try:
        raw = sys.stdin.read()
        event = json.loads(raw) if raw.strip() else {}
        if not isinstance(event, dict):
            raise ValueError("hook payload must be a JSON object")
    except Exception as exc:
        print(json.dumps(_universal_deny(f"Pramagent Guard failed closed: {exc}")))
        return 0

    print(json.dumps(evaluate_event(event), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
