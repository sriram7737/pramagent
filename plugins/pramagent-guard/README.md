# Pramagent Guard Plugin

Pramagent Guard is a PreToolUse/BeforeTool hook package for coding agents. It
checks proposed tool calls with Pramagent's deterministic `ToolGuardLayer`
before the host agent executes them.

Supported surfaces:

- Claude Code plugin hooks
- Codex plugin hooks
- Gemini CLI through the repository-root `pramagent` extension
- Grok Build plugin hooks, through Grok's Claude-compatible plugin/hook loading
- Any local agent that can send a Claude-style `PreToolUse` JSON event on stdin

This is not an MCP server, MCP client, MCP proxy, or MCP transport. It is a
host-agent hook that sees proposed tool calls and returns allow, ask, or deny.

## Install the Python dependency

The plugin shell is small; the policy engine is the `pramagent` Python package.
Install it in the Python environment that your hook command will run:

```bash
python -m pip install pramagent
```

For local development inside this repo, use editable mode:

```bash
python -m pip install -e .
```

The Python wheel supplies the policy engine. The host hook files in this
directory are distributed through the repository marketplace/plugin source;
installing the wheel alone does not register a coding-agent hook.

If the hook fails closed with an import error, check which interpreter the host
resolves for `python`. On Windows especially, you may need to edit
`hooks/hooks.json` so `command` points at a project venv such as
`.venv\\Scripts\\python.exe`.

## What ships by default

- `hooks/hooks.json` registers Claude/Codex/Grok-compatible tool-call hooks.
- `hooks/scripts/pramagent_guard.py` evaluates each matched tool event.
- `policies.json` contains conservative starter policies:
  - known read-only shell inspection is allowed;
  - destructive, publish, and deploy shell forms are denied;
  - other shell commands route to human confirmation or deny when the host has
    no interactive approval result;
  - write/edit tools route to human confirmation;
  - read/list/search tools are allowed unless ToolGuard detects injection or
    schema problems.

All tools are matched by default. Unknown tools are denied until a matching
entry is added to `policies.json` or through the admin console.

## Claude Code

After this repo is pushed, add the GitHub repo as a Claude plugin marketplace,
then install `pramagent-guard`.

For local testing from this checkout, copy or symlink this folder into a Claude
plugin path, then run `/plugins` and `/hooks` in Claude Code to enable and
trust it.

Claude Code hook configs should use exec form (`command` plus `args`) so paths
with spaces are not mangled by shell escaping on Windows.

## Codex

Codex discovers repo marketplaces from `.agents/plugins/marketplace.json`.
After pushing this repo, add the repo marketplace, install `pramagent-guard`,
then open `/hooks` to review and trust the hook.

Codex plugin hooks set `PLUGIN_ROOT` and also set `CLAUDE_PLUGIN_ROOT` for
Claude compatibility. This script reads both.

By default, the script maps ToolGuard `ESCALATE` to `deny` when it detects a
Codex plugin environment. Override with:

```bash
PRAMAGENT_HOOK_ESCALATE_DECISION=ask
```

only if your Codex surface supports an interactive ask decision.

## Gemini CLI

Gemini CLI uses a native extension rather than this Claude/Codex plugin
manifest. Install the repository-root extension after installing the Python
package:

```bash
python -m pip install "pramagent==0.8.9"
gemini extensions install https://github.com/sriram7737/pramagent --ref 0.1.1
```

Restart Gemini CLI and run `gemini extensions list` to confirm that the
`pramagent` extension is enabled. Gemini maps policy escalations to a denial
because its `BeforeTool` hook has no interactive approval result.

## Grok Build / xAI

Grok Build discovers plugins from project `.grok/plugins/`, user
`~/.grok/plugins/`, marketplace installs, `--plugin-dir`, and Claude-compatible
plugin sources. It also passes `GROK_PLUGIN_ROOT` to plugin hooks.

For local testing:

```bash
grok --plugin-dir plugins/pramagent-guard
```

Then open `/hooks` in the TUI and trust the hook for the project.

## Standalone smoke tests

Allow path:

```bash
echo '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"README.md"},"session_id":"smoke"}' \
  | PRAMAGENT_PLUGIN_ROOT=plugins/pramagent-guard python plugins/pramagent-guard/hooks/scripts/pramagent_guard.py
```

Read-only shell path:

```bash
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"},"session_id":"smoke"}' \
  | PRAMAGENT_PLUGIN_ROOT=plugins/pramagent-guard python plugins/pramagent-guard/hooks/scripts/pramagent_guard.py
```

Review path: replace `ls -la` above with `npm install`.

Block path:

```bash
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo test; DROP TABLE users; --"},"session_id":"smoke"}' \
  | PRAMAGENT_PLUGIN_ROOT=plugins/pramagent-guard python plugins/pramagent-guard/hooks/scripts/pramagent_guard.py
```

## Honest limits

This plugin is a guardrail and approval router. It is not a sandbox. It does
not isolate processes, network access, filesystem access, credentials, or
kernel-level behavior. Use it with OS sandboxing, least-privilege credentials,
and host-agent permission controls.

The in-hook self-protection blocks tool-mediated changes to the hook control
plane and common credential paths. It does not make same-user files immutable.
For a strong trust boundary, install the hook under a separate account or apply
OS permissions that the agent identity cannot change.
