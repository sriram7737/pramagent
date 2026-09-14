"""Validate, persist, and audit hook configuration changes."""
from __future__ import annotations

import time
import threading
import json
from typing import Any, Optional

from . import hook_state
from .hook_state import SURFACES
from .policies import PolicyLoadError, tool_policy_from_dict

# Keep this inventory aligned with each adapter's built-in registration.
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

_ADMIN_LOCK = threading.RLock()


def all_known_tools() -> list[str]:
    """Sorted union of every tool name across all surfaces."""
    seen: set[str] = set()
    for tools in KNOWN_TOOLS.values():
        seen.update(tools)
    return sorted(seen)


def _audit_db_path() -> str:
    return str(hook_state.audit_path())


def _audit(action: str, *, actor: str, detail: dict[str, Any]) -> dict[str, Any]:
    """Append a keyed config-change record and return its chain position."""
    from .store import SQLiteStore

    if not actor or not actor.strip():
        raise ValueError("authenticated actor is required")
    store = SQLiteStore(path=_audit_db_path(), **hook_state._audit_key_config())
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


def _commit(
    state: dict[str, Any], *, action: str, actor: str, detail: dict[str, Any]
) -> dict[str, Any]:
    with _ADMIN_LOCK:
        # Resolve and validate the key before touching the live config.
        hook_state._audit_key_config()
        proposed = dict(state)
        base_hash = proposed.pop("_base_state_hash", None)
        current, readable = hook_state._read_state()
        current_hash = hook_state.state_digest(current)
        if base_hash is not None and base_hash != current_hash:
            raise RuntimeError(
                "hook config changed during this update; reload before retrying"
            )
        saved = hook_state._save_state(proposed, actor=actor)
        audited_detail = dict(detail)
        audited_detail.update({
            "before_state_hash": current_hash if readable else "",
            "state_hash": hook_state.state_digest(saved),
            "changes": _state_changes(current, saved),
            "state_snapshot": json.loads(json.dumps(saved)),
        })
        chain = _audit(action, actor=actor, detail=audited_detail)
        return {"state": saved, "chain": chain}


def _state_changes(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    """Return compact, field-level changes for an operator-readable audit."""
    changes: list[dict[str, Any]] = []

    def walk(path: str, left: Any, right: Any) -> None:
        if isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(set(left) | set(right)):
                walk(f"{path}.{key}" if path else key, left.get(key), right.get(key))
            return
        if left != right:
            changes.append({"path": path, "before": left, "after": right})

    walk("", hook_state._normalize(before), hook_state._normalize(after))
    return changes


def _validated_snapshot(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("audit record does not contain a restorable state")
    state = hook_state._normalize(raw)
    for policy in state["policies"] or []:
        try:
            tool_policy_from_dict(policy)
        except PolicyLoadError as exc:
            raise ValueError(f"rollback policy is invalid: {exc}") from exc
    known = set(all_known_tools())
    for tenant, entry in state["tenants"].items():
        names = (entry.get("allowed_tools") or []) + (entry.get("denied_tools") or [])
        unknown = sorted(set(names) - known)
        if unknown:
            raise ValueError(
                f"rollback tenant {tenant!r} contains unknown tools: {unknown}"
            )
    return state


def rollback_config(target_hash: str, *, actor: str) -> dict[str, Any]:
    """Restore an audited snapshot by chain hash or state hash.

    Rollback appends a new event; it never deletes or rewrites audit history.
    """
    if not target_hash:
        raise ValueError("target_hash is required")
    if not verify_chain():
        raise RuntimeError("cannot roll back while the hook audit chain is invalid")

    from .store import SQLiteStore

    store = SQLiteStore(path=_audit_db_path(), **hook_state._audit_key_config())
    try:
        records = store.records()
    finally:
        store.close()
    target = None
    target_chain_hash = ""
    for row in records:
        payload = row.get("payload", {}) if isinstance(row, dict) else {}
        detail = payload.get("detail", {}) if isinstance(payload, dict) else {}
        if payload.get("source") != "hook_admin":
            continue
        if row.get("this_hash") == target_hash or detail.get("state_hash") == target_hash:
            target = detail.get("state_snapshot")
            target_chain_hash = row.get("this_hash", "")
            break
    state = _validated_snapshot(target)
    current = hook_state._state_for_update()
    state["_base_state_hash"] = current.get("_base_state_hash")
    return _commit(
        state,
        action="rollback_config",
        actor=actor,
        detail={
            "target_chain_hash": target_chain_hash,
            "target_state_hash": hook_state.state_digest(state),
        },
    )


def bind_legacy_state(*, actor: str) -> dict[str, Any]:
    """Bind a legacy config to the keyed chain after operator approval."""
    state, readable = hook_state._read_state()
    if not readable:
        raise RuntimeError("no readable hook config is available to bind")
    valid, _reason = hook_state.integrity_status(state)
    if valid:
        return {"state": state, "chain": None}
    return _commit(
        state,
        action="bind_legacy_state",
        actor=actor,
        detail={"migration": "operator-approved legacy config binding"},
    )


def get_config() -> dict[str, Any]:
    """Full current config plus audit-chain status, for the console to render."""
    state = hook_state.get_state()
    integrity_valid, integrity_reason = hook_state.integrity_status()
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
        "config_integrity_valid": integrity_valid,
        "config_integrity_reason": integrity_reason,
    }


def set_surface_enabled(surface: str, enabled: bool, *, actor: str) -> dict[str, Any]:
    if surface not in SURFACES:
        raise ValueError(f"unknown surface {surface!r}; expected one of {SURFACES}")
    state = hook_state._state_for_update()
    state["surfaces"][surface] = bool(enabled)
    return _commit(
        state, action="set_surface_enabled", actor=actor,
        detail={"surface": surface, "enabled": bool(enabled)},
    )


def set_tool_enabled(tool_name: str, enabled: bool, *, actor: str) -> dict[str, Any]:
    if not tool_name:
        raise ValueError("tool_name is required")
    state = hook_state._state_for_update()
    state["tools"][tool_name] = bool(enabled)
    return _commit(
        state, action="set_tool_enabled", actor=actor,
        detail={"tool": tool_name, "enabled": bool(enabled)},
    )


def upsert_policy(policy: dict[str, Any], *, actor: str) -> dict[str, Any]:
    """Add or replace one tool policy (matched by ``name``). The policy dict is
    validated with the same loader the runtime uses, so an invalid JSON schema
    is rejected here rather than written and then crashed on by every hook."""
    try:
        parsed = tool_policy_from_dict(policy)  # raises PolicyLoadError if invalid
    except PolicyLoadError as exc:
        raise ValueError(f"invalid policy: {exc}") from exc

    state = hook_state._state_for_update()
    policies = list(state["policies"] or [])
    policies = [p for p in policies if p.get("name") != parsed.name]
    policies.append(dict(policy))
    state["policies"] = policies
    return _commit(
        state, action="upsert_policy", actor=actor,
        detail={"name": parsed.name, "side_effect": parsed.side_effect},
    )


def delete_policy(name: str, *, actor: str) -> dict[str, Any]:
    state = hook_state._state_for_update()
    policies = [p for p in (state["policies"] or []) if p.get("name") != name]
    state["policies"] = policies or None
    return _commit(state, action="delete_policy", actor=actor, detail={"name": name})


# Tenant permissions

def upsert_tenant(
    tenant_id: str,
    *,
    enabled: bool = True,
    allowed_tools: Optional[list[str]] = None,
    denied_tools: Optional[list[str]] = None,
    actor: str,
) -> dict[str, Any]:
    """Create or update validated permissions for one tenant."""
    if not tenant_id:
        raise ValueError("tenant_id is required")
    known = set(all_known_tools())
    for name in (allowed_tools or []) + (denied_tools or []):
        if name not in known:
            raise ValueError(
                f"unknown tool {name!r}; expected one of {sorted(known)}")

    state = hook_state._state_for_update()
    state["tenants"][tenant_id] = {
        "enabled": bool(enabled),
        "allowed_tools": list(allowed_tools) if allowed_tools is not None else None,
        "denied_tools": list(denied_tools or []),
    }
    return _commit(state, action="upsert_tenant", actor=actor, detail={
        "tenant": tenant_id, "enabled": bool(enabled),
        "allowed_tools": allowed_tools, "denied_tools": denied_tools or [],
    })


def set_tenant_enabled(tenant_id: str, enabled: bool, *, actor: str) -> dict[str, Any]:
    state = hook_state._state_for_update()
    entry = state["tenants"].get(tenant_id, {"allowed_tools": None, "denied_tools": []})
    entry["enabled"] = bool(enabled)
    state["tenants"][tenant_id] = entry
    return _commit(
        state, action="set_tenant_enabled", actor=actor,
        detail={"tenant": tenant_id, "enabled": bool(enabled)},
    )


def delete_tenant(tenant_id: str, *, actor: str) -> dict[str, Any]:
    state = hook_state._state_for_update()
    state["tenants"].pop(tenant_id, None)
    return _commit(state, action="delete_tenant", actor=actor,
                   detail={"tenant": tenant_id})


def audit_head() -> Optional[str]:
    from .store import SQLiteStore

    try:
        store = SQLiteStore(path=_audit_db_path(), **hook_state._audit_key_config())
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
        store = SQLiteStore(path=_audit_db_path(), **hook_state._audit_key_config())
    except Exception:
        return False
    try:
        return store.verify_chain()
    finally:
        store.close()


def read_audit(limit: int = 100, *, include_state: bool = False) -> list[dict[str, Any]]:
    """Most recent config-change records, newest first, each with its chain
    hash so the console can show the tamper-evident position of every change."""
    from .store import SQLiteStore

    try:
        store = SQLiteStore(path=_audit_db_path(), **hook_state._audit_key_config())
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
        detail = dict(payload.get("detail") or {})
        if not include_state:
            detail.pop("state_snapshot", None)
        out.append({
            "action": payload.get("action"),
            "actor": payload.get("actor"),
            "detail": detail,
            "created_at": payload.get("created_at"),
            "this_hash": row.get("this_hash"),
            "prev_hash": row.get("prev_hash"),
            "restorable": isinstance(payload.get("detail", {}).get("state_snapshot"), dict),
        })
        if len(out) >= limit:
            break
    return out
