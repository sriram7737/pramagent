# Publishing Pramagent Guard Hooks

Pramagent Guard packages the same policy idea for multiple coding-agent hosts:
Claude Code, Codex, Grok Build, and other agents that expose a pre-tool-call
hook.

## Current publish target

The publishable plugin lives at:

```text
plugins/pramagent-guard/
```

It contains:

- `.codex-plugin/plugin.json` for Codex plugin discovery
- `.claude-plugin/plugin.json` for Claude-compatible plugin metadata
- `hooks/hooks.json` for PreToolUse/BeforeTool registration
- `hooks/scripts/pramagent_guard.py` for policy evaluation
- `policies.json` for starter ToolGuard policies

This is not an MCP implementation. It is a lifecycle hook that evaluates a
host-proposed tool call before execution.

## Claude Code

Claude Code supports command hooks on lifecycle events, including
`PreToolUse`. Plugin hooks are defined in `hooks/hooks.json`; enabled plugin
hooks merge with user and project hooks.

Recommended publish flow:

```bash
git add plugins/pramagent-guard .agents/plugins/marketplace.json docs/AGENT_HOOK_PUBLISHING.md
git commit -m "Add Pramagent Guard coding-agent plugin"
git push
```

Then install from the GitHub-hosted marketplace/plugin source and verify with:

```text
/plugins
/hooks
```

Use `claude --debug` and run a simple command to confirm the hook fires.

## Codex

Codex plugins are installable bundles discovered through marketplaces. This repo
ships a repo-local marketplace at:

```text
.agents/plugins/marketplace.json
```

The marketplace entry points at:

```text
./plugins/pramagent-guard
```

After pushing, add the repo as a marketplace source in Codex, install
`pramagent-guard`, then review and trust the hook in `/hooks`.

Codex plugin hooks pass `PLUGIN_ROOT` and `PLUGIN_DATA`; the guard script also
accepts Claude-compatible `CLAUDE_PLUGIN_ROOT` for portability.

## Grok Build / xAI

Grok Build plugins can include hooks. Grok discovers plugins from project and
user plugin folders, marketplace installs, explicit `--plugin-dir`, and
Claude-compatible plugin sources. Plugin hooks receive `GROK_PLUGIN_ROOT` and
`GROK_PLUGIN_DATA`.

Local test:

```bash
grok --plugin-dir plugins/pramagent-guard
```

Then open:

```text
/hooks
```

and trust the hook for the project.

## Other hosts

Any host can use the same script if it can send this event shape on stdin:

```json
{
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {"command": "ls -la"},
  "session_id": "local"
}
```

The script returns `{}` for allowed calls or a `hookSpecificOutput` decision
for blocked/escalated calls.

## Release checklist

1. Confirm `python -m pip install pramagent` works in a clean environment.
2. Run the smoke tests in `plugins/pramagent-guard/README.md`.
3. Run `python -m compileall -q plugins/pramagent-guard`.
4. Validate the Codex plugin manifest with the local plugin validator.
5. Push to GitHub.
6. In each host, install the plugin and open `/hooks` to trust it.

## Security posture

The plugin fails closed by default when:

- the hook payload is malformed;
- `pramagent` is not importable;
- `policies.json` is missing or invalid;
- ToolGuard evaluation raises.

Set `PRAMAGENT_GUARD_FAILURE_DECISION=ask` only if you prefer human review over
hard denial for hook-runtime errors.
