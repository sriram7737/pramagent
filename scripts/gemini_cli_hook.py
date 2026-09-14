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

from pramagent.hook_scan import scan_injection, scan_pii, shell_command_risk
from pramagent.hook_state import is_enabled as _hook_enabled
from pramagent.hook_state import get_policies as _central_policies
from pramagent.hook_state import tool_enabled as _tool_enabled
from pramagent.hook_state import tenant_tool_allowed as _tenant_tool_allowed
from pramagent.hook_state import targets_protected_path as _targets_protected_path
from pramagent.hook_state import targets_sensitive_path as _targets_sensitive_path

# The local tenant is unrestricted until it is managed in the console.
_TENANT_ID = os.environ.get("PRAMAGENT_TENANT_ID", "gemini-cli-local")
from pramagent.layers.tool_guard import ToolGuardLayer, ToolPolicy, SideEffect
from pramagent.layers.isolation import IsolationLayer
from pramagent.layers import HITLLayer, ComplianceLayer
from pramagent.store import SQLiteStore
from pramagent.types import Verdict, HITLStatus

_COMPLIANCE = ComplianceLayer()  # PII/PHI regex scan, deterministic, no network/API calls

# Return pattern IDs so the hook can explain its decision.
_ISOLATION = IsolationLayer(block_on_injection=False)

# Shared scanning covers every decoded string leaf in the tool arguments.

# Audit chain
# Gemini launches a new process per call, so use SQLite to retain one chain.
# Construct the store inside ``main`` so open failures follow the deny path.
_AUDIT_DB_PATH = os.environ.get(
    "PRAMAGENT_GEMINI_HOOK_AUDIT_DB",
    os.path.join(_REPO_ROOT, "pramagent_gemini_hook_audit.db"),
)


# HITL
# Gemini has no "ask" result, so escalation denies unless a real approver is
# wired. The placeholder HITL path also times out closed.
_HITL_ENABLED = os.environ.get("PRAMAGENT_HOOK_ENABLE_HITL", "0") == "1"
_HITL_TIMEOUT_S = float(os.environ.get("PRAMAGENT_HOOK_HITL_TIMEOUT_S", "8"))

# Keep a local invocation log independent of host debug output.
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


# These names follow Gemini CLI's built-in tool surface. Unknown names deny.
_GUARD = ToolGuardLayer()

def _schema(properties: dict, required: tuple[str, ...] = ()) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


_PATH = {"type": "string", "minLength": 1}
_TEXT = {"type": "string"}
_BOOL = {"type": "boolean"}
_INT = {"type": "integer", "minimum": 0}

_GUARD.register(ToolPolicy(
    name="run_shell_command",
    schema=_schema({
        "command": _TEXT,
        "description": _TEXT,
        "directory": _PATH,
        "is_background": _BOOL,
    }, ("command",)),
    side_effect=SideEffect.DESTRUCTIVE,
    escalate_if_severity_gte=SideEffect.WRITE,
    detail="Shell commands are risk-tiered before execution.",
))

_GUARD.register(ToolPolicy(
    name="write_file",
    schema=_schema({"file_path": _PATH, "content": _TEXT}, ("file_path", "content")),
    side_effect=SideEffect.WRITE,
))

_GUARD.register(ToolPolicy(
    name="replace",
    schema=_schema({
        "file_path": _PATH,
        "old_string": _TEXT,
        "new_string": _TEXT,
        "instruction": _TEXT,
        "expected_replacements": _INT,
    }, ("file_path",)),
    side_effect=SideEffect.WRITE,
))

_READ_SCHEMAS = {
    "read_file": _schema({"file_path": _PATH, "offset": _INT, "limit": _INT}, ("file_path",)),
    "list_directory": _schema({"path": _PATH, "ignore": {"type": "array", "items": _TEXT}}),
    "glob": _schema({"pattern": _TEXT, "path": _PATH}, ("pattern",)),
    "grep_search": _schema({
        "pattern": _TEXT, "path": _PATH, "glob": _TEXT,
        "case_sensitive": _BOOL, "max_results": _INT,
    }, ("pattern",)),
    "search_file_content": _schema({
        "pattern": _TEXT, "path": _PATH, "include": _TEXT,
        "case_sensitive": _BOOL, "max_results": _INT,
    }, ("pattern",)),
}
for _read_tool, _read_schema in _READ_SCHEMAS.items():
    _GUARD.register(ToolPolicy(
        name=_read_tool,
        schema=_read_schema,
        side_effect=SideEffect.READ,
    ))


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

    # Protect control-plane files before consulting the switch they contain.
    protected_hit = _targets_protected_path(tool_name, tool_input)
    if protected_hit:
        return _decision_output(
            "deny",
            f"Pramagent hook self-protection: tool '{tool_name}' may not modify "
            f"the hook control plane ({protected_hit}). Change hook settings "
            f"through the admin console instead.")

    sensitive_hit = _targets_sensitive_path(tool_name, tool_input)
    if sensitive_hit:
        return _decision_output(
            "deny",
            f"Pramagent path policy: tool '{tool_name}' may not modify a "
            f"credential or system location ({sensitive_hit}).")

    # Missing or invalid state keeps enforcement enabled.
    if not _hook_enabled("gemini"):
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
        action_label="gemini_cli_tool_call",
    )

    if decision.verdict == Verdict.BLOCK:
        return _decision_output("deny", f"Pramagent ToolGuard: {decision.reason}")

    injection_ids = scan_injection(tool_input, _ISOLATION)
    if injection_ids:
        pattern_ids = ", ".join(injection_ids)
        reason = (
            f"Pramagent Isolation: possible prompt injection in "
            f"tool arguments ({pattern_ids}). Blocked -- Gemini CLI's hook "
            f"contract has no human-in-the-loop ask outcome, so this "
            f"fails closed rather than silently proceeding."
        )
        return _decision_output("deny", reason)

    pii_labels = scan_pii(tool_input, _COMPLIANCE)
    if pii_labels:
        labels = ", ".join(pii_labels)
        reason = (
            f"Pramagent Compliance: possible PII/PHI in tool arguments "
            f"({labels}). Blocked pending review."
        )
        return _decision_output("deny", reason)

    if tool_name == "run_shell_command":
        shell_risk, shell_reason = shell_command_risk(tool_input.get("command"))
        if shell_risk == "deny":
            return _decision_output("deny", f"Pramagent shell policy: {shell_reason}.")
        if shell_risk == "allow":
            return {}

    if decision.verdict == Verdict.ESCALATE:
        if _HITL_ENABLED:
            status = _hitl_gate_sync(tool_name, tool_input, decision.reason)
            gemini_decision = "allow" if status == HITLStatus.APPROVED else "deny"
            reason = f"Pramagent HITL ({status.value}): {decision.reason}"
            return _decision_output(gemini_decision, reason)
        # Gemini has no interactive "ask" result, so unresolved escalation
        # must deny.
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
        # Store creation belongs inside the fail-closed boundary.
        audit = SQLiteStore(path=_AUDIT_DB_PATH)
        event = json.loads(raw) if raw else {}
        tool_name = event.get("tool_name", "?")
        output = evaluate_event(event)
        _record_audit_entry(audit, event, output)
    except Exception as exc:  # noqa: BLE001 -- deliberately broad: any
        # Exit 2 is Gemini's hard deny; other failures may be treated as warnings.
        sys.stderr.write(f"pramagent gemini_cli_hook failed closed: {exc}\n")
        _log(tool_name="<error>", decision_summary=f"deny:hook_error:{exc}")
        sys.exit(2)

    print(json.dumps(output))
    _log(tool_name=tool_name, decision_summary=_decision_summary(output))


if __name__ == "__main__":
    main()
