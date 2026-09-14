# Publishing Pramagent Guard Hooks

Pramagent Guard packages the same policy idea for multiple coding-agent hosts:
Claude Code, Codex, Gemini CLI, Grok Build, and other agents that expose a
pre-tool-call hook.

## Current publish target

The publishable plugin lives at:

```text
plugins/pramagent-guard/
```

It contains:

- `.codex-plugin/plugin.json` for Codex plugin discovery
- `.claude-plugin/plugin.json` for Claude-compatible plugin metadata
- `hooks/hooks.json` for Claude-compatible `PreToolUse` registration
- `hooks/codex_hooks.json` for Codex `PreToolUse` registration
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

From a terminal, the public marketplace can be installed directly:

```bash
claude plugin marketplace add sriram7737/pramagent@0.1.3
claude plugin install pramagent-guard@pramagent
```

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

Codex uses `hooks/codex_hooks.json`, including a Windows command override. Its
plugin hooks pass `PLUGIN_ROOT` and `PLUGIN_DATA`; the guard script also accepts
Claude-compatible `CLAUDE_PLUGIN_ROOT` for portability.

## Gemini CLI

Gemini CLI distributes hooks through extensions. The repository root is a
native Gemini extension: `gemini-extension.json` identifies it and
`hooks/hooks.json` registers a `BeforeTool` command hook. Install the pushed
repository source with:

```bash
python -m pip install "pramagent==0.8.9"
gemini extensions install https://github.com/sriram7737/pramagent --ref 0.1.3
```

Restart Gemini CLI, then verify the installed extension with:

```bash
gemini extensions list
```

The hook executes through `hook_bootstrap.py`, which verifies the approved
hook-child hash before launching the Gemini adapter. The standalone
`scripts/gemini_cli_hook.settings.json.example` remains available for an
organization-managed settings deployment.

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
6. In Claude Code and Codex, install the plugin and open `/hooks` to trust it.
7. In Gemini CLI, install the GitHub extension and restart the CLI.

## Security posture

The plugin fails closed by default when:

- the hook payload is malformed;
- `pramagent` is not importable;
- `policies.json` is missing or invalid;
- ToolGuard evaluation raises;
- self-protection cannot be loaded;
- a launcher fails to import, times out, or emits invalid JSON when the
  standalone bootstrap is used.

The default matcher is broad. Unknown tools therefore reach ToolGuard and are
denied until an administrator adds a policy. The guard also rejects writes to
its host settings, launchers, plugin registration and policy files, imported
Pramagent package, audit stores, and common credential/system locations.

This is still an application-layer control. Install the hook and its
configuration under an account the agent cannot write, or enforce equivalent
Windows ACL/Linux ownership controls. A process running as the same unrestricted
OS user can otherwise change permissions or use an execution path the host did
not send through the hook.

After installing a surface, run `pramagent hooks-doctor --repo-root <checkout>`
against the source checkout that supplied the hook/plugin files. It verifies the
host configuration, fail-closed launcher, approved runtime hashes, plugin
manifest, and signed control-plane state. The PyPI wheel supplies the policy
engine and doctor command, not the host hook bundle. Use `--strict` in deployment
checks to reject same-account writable hook files instead of reporting them as a
warning.

Set `PRAMAGENT_GUARD_FAILURE_DECISION=ask` only if you prefer human review over
hard denial for hook-runtime errors.
