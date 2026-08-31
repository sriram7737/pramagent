#!/usr/bin/env python3
"""Codex PreToolUse hook -> Pramagent guardrails.

This is the Codex adapter for the same local policy idea as
scripts/claude_code_hook.py. Codex hooks currently support denying a tool
call or adding context; they do not support Claude Code's "ask" permission
decision. For that reason, Pramagent BLOCK/ESCALATE/Compliance/Isolation
findings are mapped to deny, while clean calls return {}.

Configured by .codex/hooks.json. Review/trust it with /hooks in Codex after
changing this file or the hook definition.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sys
from typing import Any

# Import pramagent from the repo this hook lives in, not a stale build/
# site-packages copy for whatever interpreter runs it. Mirrors gemini_cli_hook.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from pramagent.hook_scan import scan_injection, scan_pii
from pramagent.hook_state import is_enabled as _hook_enabled
from pramagent.hook_state import get_policies as _central_policies
from pramagent.hook_state import tool_enabled as _tool_enabled
from pramagent.hook_state import tenant_tool_allowed as _tenant_tool_allowed
from pramagent.hook_state import targets_protected_path as _targets_protected_path
from pramagent.layers import ComplianceLayer
from pramagent.layers.isolation import IsolationLayer
from pramagent.layers.tool_guard import SideEffect, ToolGuardLayer, ToolPolicy
from pramagent.types import Verdict


_TENANT_ID = os.environ.get("PRAMAGENT_TENANT_ID", "codex-local")
_ACTION_LABEL = "codex_pre_tool_use"
_LOG_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "pramagent_codex_hook.log")
)

_ALLOW_HIGH_RISK = os.environ.get("PRAMAGENT_CODEX_ALLOW_HIGH_RISK", "0") == "1"

_COMPLIANCE = ComplianceLayer()
_ISOLATION = IsolationLayer(block_on_injection=False)


def _command_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {"command": {"type": "string"}},
        "required": ["command"],
        "additionalProperties": True,
    }


def _object_schema() -> dict[str, Any]:
    return {"type": "object", "additionalProperties": True}


# Codex naturally makes many small edits in one turn. Keep ToolGuard's
# per-call validation and argument-injection scan, but disable multi-call
# chain escalation in this local adapter so the third normal apply_patch
# does not fail closed during ordinary coding.
_GUARD = ToolGuardLayer(chain_window=1)

# Codex tool names documented for hook matchers. Edit/Write are aliases for
# apply_patch in Codex matchers, but registering them keeps the adapter
# tolerant of older/newer payload shapes.
for _name in ("Bash", "PowerShell"):
    _GUARD.register(
        ToolPolicy(
            name=_name,
            schema=_command_schema(),
            side_effect=SideEffect.READ,
            detail="Local shell command screened by Pramagent.",
        )
    )

for _name in ("apply_patch", "Edit", "Write", "MultiEdit"):
    _GUARD.register(
        ToolPolicy(
            name=_name,
            schema=_object_schema(),
            side_effect=SideEffect.WRITE,
            detail="Local file edit screened by Pramagent.",
        )
    )

for _name in ("Read", "LS", "Grep", "Glob"):
    _GUARD.register(
        ToolPolicy(
            name=_name,
            schema=_object_schema(),
            side_effect=SideEffect.READ,
        )
    )


def _apply_central_policy_overrides() -> None:
    """Merge admin-console policies over the built-in defaults (see the same
    helper in scripts/claude_code_hook.py). Invalid overrides are skipped."""
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


_HIGH_RISK_SHELL: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"\brm\s+.*(?:-rf|-fr|--recursive|--force)", re.I),
        "recursive/forced rm command",
    ),
    (
        re.compile(r"\bRemove-Item\b.*(?:-Recurse|-Force|-r\b)", re.I),
        "recursive/forced Remove-Item command",
    ),
    (
        re.compile(r"\b(?:del|erase|rmdir|rd)\b.*(?:/s|/q)", re.I),
        "recursive Windows delete command",
    ),
    (
        re.compile(r"\bgit\s+reset\s+--hard\b|\bgit\s+clean\b.*-[^\s]*[fd]", re.I),
        "destructive git cleanup/reset command",
    ),
    (
        re.compile(r"\bgit\s+push\b|\bgh\s+release\b|\bnpm\s+publish\b|\btwine\s+upload\b", re.I),
        "external publish/push command",
    ),
    (
        re.compile(r"\b(?:railway\s+up|vercel\s+--prod|fly\s+deploy|firebase\s+deploy)\b", re.I),
        "production deploy command",
    ),
    (
        re.compile(r"\b(?:drop|truncate)\s+(?:table|database|schema)\b", re.I),
        "destructive database command",
    ),
]


def _canonical_tool_name(tool_name: str) -> str:
    if tool_name in {"Edit", "Write", "MultiEdit"}:
        return tool_name
    return tool_name


def _deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
            "additionalContext": reason,
        }
    }


def _log(tool_name: str, summary: str) -> None:
    try:
        with open(_LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(
                f"{_dt.datetime.now().isoformat()} "
                f"tool={tool_name or '?'} decision={summary}\n"
            )
    except OSError:
        pass


def _high_risk_shell_reason(tool_name: str, tool_input: dict[str, Any]) -> str | None:
    if tool_name not in {"Bash", "PowerShell"}:
        return None
    command = tool_input.get("command")
    if not isinstance(command, str):
        return None
    for pattern, reason in _HIGH_RISK_SHELL:
        if pattern.search(command):
            return reason
    return None


def _isolation_reason(tool_input: dict[str, Any]) -> str | None:
    # Delegates to the shared all-leaves, decode-aware scanner
    # (pramagent.hook_scan) so codex catches encoded payloads too, and so all
    # hook surfaces share one implementation.
    pattern_ids = scan_injection(tool_input, _ISOLATION)
    if not pattern_ids:
        return None
    return (
        "Pramagent Isolation: possible prompt injection in tool arguments "
        f"({', '.join(pattern_ids)})."
    )


def _compliance_reason(tool_input: dict[str, Any]) -> str | None:
    labels = scan_pii(tool_input, _COMPLIANCE)
    if not labels:
        return None
    return (
        "Pramagent Compliance: possible PII/PHI in tool arguments "
        f"({', '.join(labels)})."
    )


def evaluate_event(event: dict[str, Any]) -> dict[str, Any]:
    """Return the Codex hook response for one PreToolUse event."""
    event_name = event.get("hook_event_name") or event.get("hookEventName")
    if event_name and event_name != "PreToolUse":
        return {}

    tool_name = str(event.get("tool_name") or event.get("toolName") or "")
    if not tool_name:
        return {}

    raw_input = event.get("tool_input", event.get("toolInput", {}))
    tool_input = raw_input if isinstance(raw_input, dict) else {"value": raw_input}
    canonical_tool = _canonical_tool_name(tool_name)
    session_id = str(event.get("session_id") or event.get("sessionId") or "local")

    # Control-plane self-protection (see scripts/claude_code_hook.py). Refuse any
    # tool call that would write the hook's own config or admin audit DB, checked
    # BEFORE the master switch so a tampering write cannot disable the surface
    # and slip through.
    protected_hit = _targets_protected_path(canonical_tool, tool_input)
    if protected_hit:
        return _deny(
            f"Pramagent hook self-protection: tool '{canonical_tool}' may not "
            f"modify the hook control plane ({protected_hit}). Change hook "
            f"settings through the admin console instead.")

    # Admin master switch (fail-safe; see pramagent.hook_state).
    if not _hook_enabled("codex"):
        return {}

    # Per-tool master switch from the admin console: a disabled tool denies.
    if not _tool_enabled(canonical_tool):
        return _deny(f"Pramagent hook admin: tool '{canonical_tool}' is disabled")

    # Per-tenant permission from the admin console.
    if not _tenant_tool_allowed(_TENANT_ID, canonical_tool):
        return _deny(
            f"Pramagent hook admin: tenant '{_TENANT_ID}' is not permitted "
            f"to use tool '{canonical_tool}'")

    decision = _GUARD.evaluate(
        tool_name=canonical_tool,
        arguments=tool_input,
        tenant_id=_TENANT_ID,
        session_id=session_id,
        action_label=_ACTION_LABEL,
    )
    if decision.verdict == Verdict.BLOCK:
        return _deny(f"Pramagent ToolGuard: {decision.reason}")

    high_risk = _high_risk_shell_reason(canonical_tool, tool_input)
    if high_risk and not _ALLOW_HIGH_RISK:
        return _deny(
            "Pramagent shell policy: "
            f"{high_risk}. Set PRAMAGENT_CODEX_ALLOW_HIGH_RISK=1 only for a "
            "deliberate, supervised one-off run."
        )

    isolation = _isolation_reason(tool_input)
    if isolation:
        return _deny(isolation)

    compliance = _compliance_reason(tool_input)
    if compliance:
        return _deny(compliance)

    if decision.verdict == Verdict.ESCALATE:
        return _deny(
            "Pramagent ToolGuard: "
            f"{decision.reason}. Codex hooks do not support an ask decision, "
            "so escalation fails closed."
        )

    return {}


def _summary(output: dict[str, Any]) -> str:
    hook = output.get("hookSpecificOutput") if isinstance(output, dict) else None
    if not hook:
        return "allow:clean"
    return f"{hook.get('permissionDecision')}:{hook.get('permissionDecisionReason', '')}"


def main() -> None:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw else {}
        tool_name = str(event.get("tool_name") or event.get("toolName") or "?")
        output = evaluate_event(event if isinstance(event, dict) else {})
    except Exception as exc:
        output = _deny(f"Pramagent Codex hook error (failed closed): {exc}")
        print(json.dumps(output))
        _log("<error>", f"deny:hook_error:{exc}")
        return

    print(json.dumps(output))
    _log(tool_name, _summary(output))


if __name__ == "__main__":
    main()
