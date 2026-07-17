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

    root = _plugin_root()
    policy_path = Path(
        os.environ.get("PRAMAGENT_GUARD_POLICY", root / "policies.json")
    )
    tenant_id = os.environ.get("PRAMAGENT_TENANT_ID", "local-dev")
    tool_name = _tool_name(event)
    tool_input = _tool_input(event)

    try:
        from pramagent.policies import load_tool_guard
        from pramagent.types import Verdict
    except Exception as exc:
        return _fail_decision(
            "Pramagent Guard failed closed: install Pramagent in this Python "
            f"environment (`pip install pramagent`). Import error: {exc}"
        )

    try:
        guard = load_tool_guard(policy_path)
        decision = guard.evaluate(
            tool_name,
            tool_input,
            tenant_id=tenant_id,
            session_id=_session_id(event),
            action_label="coding_agent_tool_call",
        )
    except Exception as exc:
        return _fail_decision(f"Pramagent Guard failed closed: {exc}")

    if decision.verdict == Verdict.ALLOW:
        return _no_op()
    if decision.verdict == Verdict.BLOCK:
        return _decision("deny", f"Pramagent ToolGuard: {decision.reason}")
    if decision.verdict == Verdict.ESCALATE:
        return _decision(
            _escalate_decision(),
            f"Pramagent ToolGuard escalation: {decision.reason}",
        )
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
