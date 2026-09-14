# Hook Deployment Boundary

Pramagent's in-process path checks and integrity manifest detect common
self-disable attempts. They are not a security boundary when the agent owns
the hook files and host settings. A process can replace anything writable by
its OS identity.

## Hardened deployment

The deployment scripts under `deploy/enforcement/` create the minimum useful
OS boundary:

1. Install the reviewed hook runtime in an administrator- or root-owned path.
2. Verify the source runtime against `pramagent/hook_integrity.json` before
   installation.
3. Grant the agent identity read/execute access but no write, delete, ACL, or
   ownership access to the runtime and control-plane state.
4. Protect every host configuration directory, not only the active settings
   file. Otherwise an agent can create a higher-precedence local override.
5. Keep administrative policy changes outside the agent identity.

On Windows, run the installer from an elevated PowerShell session:

```powershell
& .\deploy\enforcement\windows\Install-PramagentHookBoundary.ps1 `
  -SourceRoot $PWD `
  -AgentIdentity "WORKSTATION\pramagent_agent" `
  -AgentHome "C:\Users\pramagent_agent" `
  -WhatIf

# Remove -WhatIf only after reviewing the affected paths.
```

On Linux, use a dedicated non-root agent account and group:

```bash
sudo deploy/enforcement/linux/install-pramagent-hook-boundary.sh \
  "$PWD" pramagent-agent
```

After installation, update Claude, Gemini, and Codex hook commands to invoke
the bootstrap from the protected runtime. Restart the host application so it
inherits the machine-level state paths, then run `pramagent hooks-doctor
--strict` from the agent identity. Every runtime writeability check must be
`ok`, not `warn`.

## Boundary and remaining work

This blocks a non-administrative agent process from rewriting the installed
runtime, state, or host hook configuration. It does not constrain an OS
administrator or root, and it does not make a host fail closed if that host
itself treats a killed hook process as permission to continue.

The final architecture requires host-specific tool brokers or restricted
process sandboxes so tool execution is unavailable except through the
protected enforcement service. That work cannot be supplied by a portable
Python hook alone and must be validated separately for each supported host.
