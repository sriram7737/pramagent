"""
pramagent.hook_admin
====================
Write / admin side of the central hook configuration (:mod:`pramagent.hook_state`
is the read side). Every mutation an operator makes from the console  - 
enable/disable a surface, enable/disable a tool, add/edit/delete a tool policy  - 
goes through here so that:

  1. the change is validated before it is persisted (a bad policy schema is
     rejected, not written and then crashed on by every hook), and
  2. the change is appended to a **SHA-256 hash-chained** audit
     (``SQLiteStore``, the same tamper-evident chain the rest of Pramagent
     uses), so *who changed what, when* is recoverable and any later edit to
     the log breaks ``verify_chain()``.

This module is imported by the dashboard, not by the hooks on their hot path.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Optional

from . import hook_state
from .hook_state import SURFACES
from .policies import PolicyLoadError, tool_policy_from_dict

# The full tool surface an operator can switch on/off, grouped by adapter, so
# the console can render a complete toggle list rather than only tools that
# already have an entry in the config. Mirrors each hook's own registration.
KNOWN_TOOLS: dict[str, tuple[str, ...]] = {
    "claude": ("Bash", "Write", "Edit", "Read", "Grep", "Glob"),
    "gemini": ("run_shell_command", "write_file", "replace",
               "read_file", "list_directory", "glob", "grep_search", "search_file_content"),
    "codex": ("Bash", "PowerShell", "apply_patch", "Edit", "Write", "MultiEdit",
              "Read", "LS", "Grep", "Glob"),
    "plugin": ("Bash", "PowerShell", "run_shell_command", "Write", "Edit", "MultiEdit",
               "apply_patch", "write_file", "replace", "Read", "LS", "Grep", "Glob",
               "read_file", "list_directory", "glob", "grep_search", "search_file_content"),
}


def all_known_tools() -> list[str]:
    """Sorted union of every tool name across all surfaces."""
    seen: set[str] = set()
    for tools in KNOWN_TOOLS.values():
        seen.update(tools)
    return sorted(seen)


def _audit_db_path() -> str:
    return os.environ.get(
        "PRAMAGENT_HOOK_ADMIN_AUDIT_DB",
        str(Path(hook_state.state_path()).with_name("pramagent_hook_admin_audit.db")),
    )


def _audit(action: str, *, actor: str, detail: dict[str, Any]) -> dict[str, Any]:
    """Append one config-change record to the SHA-256 hash chain. Returns the
    chain position {seq, this_hash, prev_hash}. A signing key (PRAMAGENT_SIGNING_KEY)
    upgrades the plain SHA-256 chain to HMAC-SHA256; without one it is still a
    SHA-256 chain, just not keyed."""
    from .store import SQLiteStore

    signing_key = os.environ.get("PRAMAGENT_SIGNING_KEY", "")
    store = SQLiteStore(path=_audit_db_path(), signing_key=signing_key)
    try:
        payload = {
            "source": "hook_admin",
            "action": action,
            "actor": actor,
            "detail": detail,
            "created_at": time.time(),
        }
        result = store.append(payload)
        return {
            "seq": getattr(result, "seq", None),
            "this_hash": getattr(result, "this_hash", None),
            "prev_hash": getattr(result, "prev_hash", None),
        }
    finally:
        store.close()


def get_config() -> dict[str, Any]:
    """Full current config plus audit-chain status, for the console to render."""
    state = hook_state.get_state()
    return {
        "surfaces": state["surfaces"],
        "tools": state["tools"],
        "policies": state["policies"] or [],
        "tenants": state["tenants"],
        "updated_at": state["updated_at"],
        "updated_by": state["updated_by"],
        "known_tools": all_known_tools(),
        "surface_tools": {k: list(v) for k, v in KNOWN_TOOLS.items()},
        "audit_head": audit_head(),
        "chain_valid": verify_chain(),
    }


def set_surface_enabled(surface: str, enabled: bool, *, actor: str) -> dict[str, Any]:
    if surface not in SURFACES:
        raise ValueError(f"unknown surface {surface!r}; expected one of {SURFACES}")
    state = hook_state.get_state()
    state["surfaces"][surface] = bool(enabled)
    saved = hook_state._save_state(state, actor=actor)
    chain = _audit("set_surface_enabled", actor=actor,
                   detail={"surface": surface, "enabled": bool(enabled)})
    return {"state": saved, "chain": chain}


def set_tool_enabled(tool_name: str, enabled: bool, *, actor: str) -> dict[str, Any]:
    if not tool_name:
        raise ValueError("tool_name is required")
    state = hook_state.get_state()
    state["tools"][tool_name] = bool(enabled)
    saved = hook_state._save_state(state, actor=actor)
    chain = _audit("set_tool_enabled", actor=actor,
                   detail={"tool": tool_name, "enabled": bool(enabled)})
    return {"state": saved, "chain": chain}


def upsert_policy(policy: dict[str, Any], *, actor: str) -> dict[str, Any]:
    """Add or replace one tool policy (matched by ``name``). The policy dict is
    validated with the same loader the runtime uses, so an invalid JSON schema
    is rejected here rather than written and then crashed on by every hook."""
    try:
        parsed = tool_policy_from_dict(policy)  # raises PolicyLoadError if invalid
    except PolicyLoadError as exc:
        raise ValueError(f"invalid policy: {exc}") from exc

    state = hook_state.get_state()
    policies = list(state["policies"] or [])
    policies = [p for p in policies if p.get("name") != parsed.name]
    policies.append(dict(policy))
    state["policies"] = policies
    saved = hook_state._save_state(state, actor=actor)
    chain = _audit("upsert_policy", actor=actor,
                   detail={"name": parsed.name, "side_effect": parsed.side_effect})
    return {"state": saved, "chain": chain}


def delete_policy(name: str, *, actor: str) -> dict[str, Any]:
    state = hook_state.get_state()
    policies = [p for p in (state["policies"] or []) if p.get("name") != name]
    state["policies"] = policies or None
    saved = hook_state._save_state(state, actor=actor)
    chain = _audit("delete_policy", actor=actor, detail={"name": name})
    return {"state": saved, "chain": chain}


# -- tenant permissions -----------------------------------------------------

def upsert_tenant(
    tenant_id: str,
    *,
    enabled: bool = True,
    allowed_tools: Optional[list[str]] = None,
    denied_tools: Optional[list[str]] = None,
    actor: str,
) -> dict[str, Any]:
    """Create or update one tenant's permissions.

    ``allowed_tools=None`` means "every tool" (an allow-all tenant, still
    subject to ``denied_tools``); a list restricts the tenant to exactly those
    tools. Names are validated against the known tool surface so a typo can't
    silently grant/deny a tool that does not exist."""
    if not tenant_id:
        raise ValueError("tenant_id is required")
    known = set(all_known_tools())
    for name in (allowed_tools or []) + (denied_tools or []):
        if name not in known:
            raise ValueError(
                f"unknown tool {name!r}; expected one of {sorted(known)}")

    state = hook_state.get_state()
    state["tenants"][tenant_id] = {
        "enabled": bool(enabled),
        "allowed_tools": list(allowed_tools) if allowed_tools is not None else None,
        "denied_tools": list(denied_tools or []),
    }
    saved = hook_state._save_state(state, actor=actor)
    chain = _audit("upsert_tenant", actor=actor, detail={
        "tenant": tenant_id,
        "enabled": bool(enabled),
        "allowed_tools": allowed_tools,
        "denied_tools": denied_tools or [],
    })
    return {"state": saved, "chain": chain}


def set_tenant_enabled(tenant_id: str, enabled: bool, *, actor: str) -> dict[str, Any]:
    state = hook_state.get_state()
    entry = state["tenants"].get(tenant_id, {"allowed_tools": None, "denied_tools": []})
    entry["enabled"] = bool(enabled)
    state["tenants"][tenant_id] = entry
    saved = hook_state._save_state(state, actor=actor)
    chain = _audit("set_tenant_enabled", actor=actor,
                   detail={"tenant": tenant_id, "enabled": bool(enabled)})
    return {"state": saved, "chain": chain}


def delete_tenant(tenant_id: str, *, actor: str) -> dict[str, Any]:
    state = hook_state.get_state()
    state["tenants"].pop(tenant_id, None)
    saved = hook_state._save_state(state, actor=actor)
    chain = _audit("delete_tenant", actor=actor, detail={"tenant": tenant_id})
    return {"state": saved, "chain": chain}


def audit_head() -> Optional[str]:
    from .store import SQLiteStore

    try:
        store = SQLiteStore(path=_audit_db_path(),
                            signing_key=os.environ.get("PRAMAGENT_SIGNING_KEY", ""))
    except Exception:
        return None
    try:
        return store.head
    finally:
        store.close()


def verify_chain() -> bool:
    """True if the config-change audit chain is intact (no tampering). An empty
    chain (no changes yet) verifies as True."""
    from .store import SQLiteStore

    try:
        store = SQLiteStore(path=_audit_db_path(),
                            signing_key=os.environ.get("PRAMAGENT_SIGNING_KEY", ""))
    except Exception:
        return False
    try:
        return store.verify_chain()
    finally:
        store.close()


def read_audit(limit: int = 100) -> list[dict[str, Any]]:
    """Most recent config-change records, newest first, each with its chain
    hash so the console can show the tamper-evident position of every change."""
    from .store import SQLiteStore

    try:
        store = SQLiteStore(path=_audit_db_path(),
                            signing_key=os.environ.get("PRAMAGENT_SIGNING_KEY", ""))
    except Exception:
        return []
    try:
        rows = store.records()
    except Exception:
        rows = []
    finally:
        store.close()

    out: list[dict[str, Any]] = []
    for row in reversed(rows):  # records() is oldest-first; newest-first here
        payload = row.get("payload", {}) if isinstance(row, dict) else {}
        if payload.get("source") != "hook_admin":
            continue
        out.append({
            "action": payload.get("action"),
            "actor": payload.get("actor"),
            "detail": payload.get("detail"),
            "created_at": payload.get("created_at"),
            "this_hash": row.get("this_hash"),
            "prev_hash": row.get("prev_hash"),
        })
        if len(out) >= limit:
            break
    return out
