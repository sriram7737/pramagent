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


def _decision(permission: str, reason: str) -> dict[str, Any]:
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


def _fail_decision(reason: str) -> dict[str, Any]:
    configured = os.environ.get("PRAMAGENT_GUARD_FAILURE_DECISION", "deny")
    permission = configured.strip().lower()
    if permission not in {"deny", "ask"}:
        permission = "deny"
    return _decision(permission, reason)


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
    if _event_name(event) not in TOOL_EVENTS:
        return _no_op()

    tool_name = _tool_name(event)
    tool_input = _tool_input(event)

    # Control-plane self-protection (see scripts/claude_code_hook.py). Refuse any
    # tool call that would write the hook's own config or admin audit DB, checked
    # BEFORE the master switch so a tampering write cannot disable this surface
    # and slip through. Fail-safe: if the check cannot be loaded, fall through to
    # the rest of enforcement rather than allowing.
    try:
        from pramagent.hook_state import targets_protected_path
        protected_hit = targets_protected_path(tool_name, tool_input)
        if protected_hit:
            return _decision(
                "deny",
                f"Pramagent hook self-protection: tool '{tool_name}' may not "
                f"modify the hook control plane ({protected_hit}). Change hook "
                f"settings through the admin console instead.")
    except Exception:
        pass

    # Admin master switch (fail-safe; see pramagent.hook_state). If the switch
    # cannot be read we enforce rather than assume disabled.
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
        from pramagent.hook_scan import scan_injection, scan_pii
        from pramagent.hook_state import get_policies, tool_enabled, tenant_tool_allowed
        from pramagent.layers import ComplianceLayer
        from pramagent.layers.isolation import IsolationLayer
        from pramagent.policies import load_tool_guard, tool_policy_from_dict
        from pramagent.types import Verdict
    except Exception as exc:
        return _fail_decision(
            "Pramagent Guard failed closed: install Pramagent in this Python "
            f"environment (`pip install pramagent`). Import error: {exc}"
        )

    # Per-tool master switch + per-tenant permission from the admin console.
    try:
        if not tool_enabled(tool_name):
            return _decision(
                "deny", f"Pramagent hook admin: tool '{tool_name}' is disabled")
        if not tenant_tool_allowed(tenant_id, tool_name):
            return _decision(
                "deny",
                f"Pramagent hook admin: tenant '{tenant_id}' is not permitted "
                f"to use tool '{tool_name}'")
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
        return _fail_decision(f"Pramagent Guard failed closed: {exc}")

    # Structural verdict first: a hard BLOCK short-circuits before the
    # heuristic content passes.
    if decision.verdict == Verdict.BLOCK:
        return _decision("deny", f"Pramagent ToolGuard: {decision.reason}")

    # Content passes the standalone scripts run but this plugin historically
    # omitted entirely (it ran only the structural ToolGuard evaluate  -  1 of
    # the 3 defenses): prompt-injection heuristics + PII/PHI scan over EVERY
    # string argument (see pramagent.hook_scan for why every leaf, decoded).
    # A finding maps to the host's escalate decision  -  "ask" on Claude Code,
    # "deny" where there is no ask  -  never a silent allow. Fails closed if the
    # scan itself raises.
    try:
        isolation = IsolationLayer(block_on_injection=False)
        compliance = ComplianceLayer()
        injection_ids = scan_injection(tool_input, isolation)
        if injection_ids:
            return _decision(
                _escalate_decision(),
                "Pramagent Isolation: possible prompt injection in tool "
                f"arguments ({', '.join(injection_ids)}). Review before proceeding.",
            )
        pii_labels = scan_pii(tool_input, compliance)
        if pii_labels:
            return _decision(
                _escalate_decision(),
                "Pramagent Compliance: possible PII/PHI in tool arguments "
                f"({', '.join(pii_labels)}). Review before proceeding.",
            )
    except Exception as exc:
        return _fail_decision(f"Pramagent Guard content scan failed closed: {exc}")

    if decision.verdict == Verdict.ESCALATE:
        return _decision(
            _escalate_decision(),
            f"Pramagent ToolGuard escalation: {decision.reason}",
        )
    if decision.verdict == Verdict.ALLOW:
        return _no_op()
    return _decision("deny", f"Pramagent ToolGuard unknown verdict: {decision.verdict}")


def main() -> int:
    try:
        raw = sys.stdin.read()
        event = json.loads(raw) if raw.strip() else {}
        if not isinstance(event, dict):
            raise ValueError("hook payload must be a JSON object")
    except Exception as exc:
        print(json.dumps(_fail_decision(f"Pramagent Guard failed closed: {exc}")))
        return 0

    print(json.dumps(evaluate_event(event), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
