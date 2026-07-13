# Gemini CLI ToolGuard Hook

scripts/gemini_cli_hook.py wires Gemini CLI BeforeTool events through
Pramagent's ToolGuardLayer, IsolationLayer, and ComplianceLayer: the same
guardrail stack that scripts/claude_code_hook.py wires into Claude Code's
PreToolUse event.

The hook runs in-process, so it is meant for local development. For
team-shared enforcement, point a hook or wrapper at a shared Pramagent API
deployment so all developers use the same policy registry and audit trail.

## Install

From the repository root:

    python -m pip install -e .
    python -c "from pramagent.layers.tool_guard import ToolGuardLayer; print('ok')"

The committed example lives at:

    scripts/gemini_cli_hook.settings.json.example

Copy its contents into .gemini/settings.json (project-level) or
~/.gemini/settings.json (user-level). If Gemini CLI does not inherit your
shell PATH, replace "python" in the command value with the full Python
interpreter path from:

    (Get-Command python).Source

## Local Sanity Check

    '{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"ls -la"},"session_id":"test1"}' |
      python scripts\gemini_cli_hook.py

Expected result: a JSON decision with "decision":"deny" (see Current
Policy below for why there is no "ask" outcome in this hook's contract,
unlike Claude Code's).

Read-only tools such as read_file, list_directory, glob, grep_search, and
search_file_content return {} when their arguments match the expected
schema. Unknown tool names return "deny" whenever the hook is invoked for
them.

## Matcher Choices

The example matcher covers Gemini CLI's built-in local tools:

    run_shell_command|write_file|replace|read_file|list_directory|glob|grep_search|search_file_content

For strict fail-closed MCP experiments, change the matcher to a broad
regular expression such as ".*". With a broad matcher, any unregistered
tool name is denied by ToolGuardLayer instead of silently passing through.

## Current Policy

| Tool | Side effect | Hook behavior |
| --- | --- | --- |
| run_shell_command | destructive | escalates internally, then denies by default (no HITL wired) |
| write_file, replace | write | allow when schema, injection, and PII checks pass |
| read_file, list_directory, glob, grep_search, search_file_content | read | allow when schema and injection checks pass |
| unregistered tools | unknown | deny |

This hook is a guardrail and approval router. It is not an OS sandbox.

## Deliberate differences from the Claude Code hook

1. No "ask" outcome. Claude Code's PreToolUse hook contract has an "ask"
   permissionDecision that falls back to Claude Code's own human
   confirmation UI. Gemini CLI's BeforeTool contract only supports
   allow, deny, and block: there is no equivalent pass-through-to-a-human
   value. As a direct consequence, ToolGuard ESCALATE verdicts (for
   example a plain run_shell_command call with no injection or PII hit,
   but a side-effect severity at or above the escalation threshold) fail
   closed to deny by default, rather than becoming a human prompt. This
   is more restrictive than the Claude Code hook's default behavior for
   the equivalent case. Set PRAMAGENT_HOOK_ENABLE_HITL=1 and wire a real
   HITLLayer approver/store (see the module docstring in
   scripts/gemini_cli_hook.py) to route these through a real
   human-in-the-loop approval instead of a blanket deny.

2. Errors hard-block (exit code 2) instead of silently allowing. Gemini
   CLI's hook contract treats any exit code other than 0 or 2 as a
   non-fatal warning and lets the tool call proceed anyway. The Claude
   Code hook's main() catches a JSON parse error and returns an empty
   object (Claude Code's cue to use its own default flow), a soft
   failure mode. scripts/gemini_cli_hook.py instead wraps its entire body
   in one try/except and calls sys.exit(2) on any exception (bad stdin
   JSON, a layer raising, or an audit-write failure), so a bug in this
   script cannot silently degrade into an allow.

3. Hash-chained audit persistence. Neither scripts/claude_code_hook.py
   nor ToolGuardLayer.evaluate() itself writes to Pramagent's
   hash-chained audit backend (pramagent.audit.HashChainBackend, the
   AuditBackend protocol): only the full Pramagent.run() LLM-completion
   pipeline does, through Pramagent._finalize(). scripts/gemini_cli_hook.py
   closes that gap for tool-call interception by appending one record per
   intercepted call (tool name, arguments, verdict, reason, tenant and
   session id, timestamp) to a pramagent.store.SQLiteStore instance,
   which implements the same append/verify_chain AuditBackend protocol.
   SQLiteStore is used instead of a bare in-memory HashChainBackend
   because each hook invocation is a fresh process: an in-memory chain
   would restart at genesis every single call and never actually link
   anything. The default location is pramagent_gemini_hook_audit.db at
   the repo root; override with PRAMAGENT_GEMINI_HOOK_AUDIT_DB. Call
   SQLiteStore(path=...).verify_chain() to check the chain has not been
   tampered with.

## Known upstream limitation (Gemini CLI itself, not this hook)

In Gemini CLI's interactive mode, BeforeTool currently fires after its own
confirmation dialog is already shown to the user (a documented gap in
Gemini CLI itself, not something this hook can work around). In that
mode, this hook acts as a second, authoritative gate after the human sees
a prompt: a deny from this hook overrides an approval the user may have
already clicked. In non-interactive, auto_edit, or yolo approval modes,
where no human dialog appears at all, this hook is the only gate, so its
fail-closed defaults matter more there.
