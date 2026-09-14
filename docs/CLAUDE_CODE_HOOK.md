# Claude Code ToolGuard Hook

`scripts/claude_code_hook.py` wires Claude Code `PreToolUse` events through
Pramagent's `ToolGuardLayer`.

The hook runs in-process, so it is meant for local development. For team-shared
enforcement, point a hook or wrapper at a shared Pramagent API deployment so all
developers use the same policy registry and audit trail.

## Install

From the repository root:

```powershell
python -m pip install -e .
python -c "from pramagent.layers.tool_guard import ToolGuardLayer; print('ok')"
```

The committed example lives at:

```text
scripts/claude_code_hook.settings.json.example
```

Use its contents for `.claude/settings.json`. If Claude Code does not inherit
your shell `PATH`, replace `python` in the `command` value with the full Python
interpreter path from:

```powershell
(Get-Command python).Source
```

## Local Sanity Check

```powershell
'{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"},"session_id":"test1"}' |
  python scripts\claude_code_hook.py
```

Expected result: `{}` because `ls` is in the read-only shell tier. A command
such as `npm install` returns `"permissionDecision":"ask"`.

Read-only tools such as `Read`, `LS`, `Grep`, and `Glob` return `{}` when their
arguments match the expected schema. Unknown tool names return `"deny"` whenever
the hook is invoked for them.

## Matcher Choices

The example uses a strict matcher:

```text
.*
```

This sends every host tool through the hook. Any unregistered name is denied by
`ToolGuardLayer` instead of silently passing through.

## Current Policy

| Tool | Side effect | Hook behavior |
| --- | --- | --- |
| `Bash`, `PowerShell` | destructive | allow known read-only commands, deny destructive forms, ask otherwise |
| `Write`, `Edit`, `MultiEdit` | write | ask |
| `Read`, `LS`, `Grep`, `Glob` | read | allow when schema and injection checks pass |
| unregistered tools | unknown | deny |

This hook is a guardrail and approval router. It is not an OS sandbox.

## Integrity Check

Run the installation doctor after setup and after upgrades:

```powershell
pramagent hooks-doctor --repo-root C:\path\to\pramagent
pramagent hooks-doctor --repo-root C:\path\to\pramagent --strict
```

The command checks the fail-closed bootstrap wiring, approved SHA-256 hashes,
plugin manifest, signed control-plane state, and whether the current account can
rewrite runtime files in that source checkout. The PyPI package does not install
host configuration or plugin files. On Windows, a hash match detects modification
but does not prevent a same-user process from replacing the hook; use a separate
administrator-owned installation or restrictive ACLs for that stronger boundary.
