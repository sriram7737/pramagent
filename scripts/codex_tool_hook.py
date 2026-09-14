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
import sys
from typing import Any

# Prefer the checkout beside this hook over an older installed package.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from pramagent.hook_scan import scan_injection, scan_pii, shell_command_risk
from pramagent.hook_state import is_enabled as _hook_enabled
from pramagent.hook_state import get_policies as _central_policies
from pramagent.hook_state import tool_enabled as _tool_enabled
from pramagent.hook_state import tenant_tool_allowed as _tenant_tool_allowed
from pramagent.hook_state import targets_protected_path as _targets_protected_path
from pramagent.hook_state import targets_sensitive_path as _targets_sensitive_path
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
        "properties": {
            "command": {"type": "string"},
            "cmd": {"type": "string"},
            "workdir": {"type": "string"},
            "yield_time_ms": {"type": "integer", "minimum": 0},
            "max_output_tokens": {"type": "integer", "minimum": 0},
            "login": {"type": "boolean"},
            "shell": {"type": "string"},
            "tty": {"type": "boolean"},
            "justification": {"type": "string"},
            "prefix_rule": {"type": "array", "items": {"type": "string"}},
            "sandbox_permissions": {"type": "string"},
        },
        "anyOf": [{"required": ["command"]}, {"required": ["cmd"]}],
        "additionalProperties": False,
    }


def _object_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "file_path": {"type": "string"},
            "path": {"type": "string"},
            "content": {"type": "string"},
            "old_string": {"type": "string"},
            "new_string": {"type": "string"},
            "replace_all": {"type": "boolean"},
            "input": {"type": "string"},
            "patch": {"type": "string"},
            "pattern": {"type": "string"},
            "glob": {"type": "string"},
            "type": {"type": "string"},
            "offset": {"type": "integer", "minimum": 0},
            "limit": {"type": "integer", "minimum": 0},
            "pages": {"type": "string"},
            "output_mode": {"type": "string"},
            "head_limit": {"type": "integer", "minimum": 0},
            "multiline": {"type": "boolean"},
        },
        "additionalProperties": False,
    }


# Local coding sessions make many writes, so this adapter disables cumulative
# chain escalation while retaining per-call validation.
_GUARD = ToolGuardLayer(chain_window=1)

# Register current names plus older Edit/Write aliases.
for _name in ("Bash", "PowerShell", "exec_command", "run_shell_command"):
    _GUARD.register(
        ToolPolicy(
            name=_name,
            schema=_command_schema(),
            side_effect=SideEffect.DESTRUCTIVE,
            escalate_if_severity_gte=SideEffect.WRITE,
            detail="Shell commands are risk-tiered before execution.",
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


def _isolation_reason(tool_input: dict[str, Any]) -> str | None:
    # Use the shared decode-aware traversal for all string leaves.
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

    # Protect control-plane files before consulting the switch they contain.
    protected_hit = _targets_protected_path(canonical_tool, tool_input)
    if protected_hit:
        return _deny(
            f"Pramagent hook self-protection: tool '{canonical_tool}' may not "
            f"modify the hook control plane ({protected_hit}). Change hook "
            f"settings through the admin console instead.")

    sensitive_hit = _targets_sensitive_path(canonical_tool, tool_input)
    if sensitive_hit:
        return _deny(
            f"Pramagent path policy: tool '{canonical_tool}' may not modify a "
            f"credential or system location ({sensitive_hit}).")

    # Missing or invalid state keeps enforcement enabled.
    if not _hook_enabled("codex"):
        return {}

    # A global tool disable takes precedence over its policy.
    if not _tool_enabled(canonical_tool):
        return _deny(f"Pramagent hook admin: tool '{canonical_tool}' is disabled")

    # Managed tenants are constrained by their allow and deny lists.
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

    shell_tools = {"Bash", "PowerShell", "exec_command", "run_shell_command"}
    shell_risk = None
    shell_reason = ""
    if canonical_tool in shell_tools:
        command = tool_input.get("command", tool_input.get("cmd"))
        shell_risk, shell_reason = shell_command_risk(command)
        if shell_risk == "deny" and not _ALLOW_HIGH_RISK:
            return _deny(
                "Pramagent shell policy: "
                f"{shell_reason}. Set PRAMAGENT_CODEX_ALLOW_HIGH_RISK=1 only "
                "for a deliberate, supervised one-off run."
            )

    isolation = _isolation_reason(tool_input)
    if isolation:
        return _deny(isolation)

    compliance = _compliance_reason(tool_input)
    if compliance:
        return _deny(compliance)

    if shell_risk == "allow":
        return {}
    if shell_risk == "review":
        return _deny(f"Pramagent shell policy: {shell_reason}.")

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
