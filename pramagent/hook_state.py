"""Read and verify the shared hook configuration.

Hooks read this file for every invocation, so console changes take effect
without a daemon or cache refresh. Each saved state is bound to the keyed audit
chain. Missing, malformed, or unverified state falls back to enforcement-on
defaults.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from .hook_scan import iter_strings

# Hook adapters that can be toggled independently.
SURFACES: tuple[str, ...] = ("claude", "gemini", "codex", "plugin")

# Mutating tools cannot target the configuration or its audit database.
_MUTATING_FILE_TOOLS: frozenset[str] = frozenset({
    "Write", "Edit", "MultiEdit", "apply_patch", "write_file", "replace",
})
_SHELL_TOOLS: frozenset[str] = frozenset({
    "Bash", "PowerShell", "run_shell_command",
})


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def state_path() -> Path:
    """Return the config path, honoring the shared-location override."""
    override = os.environ.get("PRAMAGENT_HOOK_STATE_PATH")
    if override:
        return Path(override)
    return _repo_root() / "pramagent_hook_config.json"


def audit_path() -> Path:
    override = os.environ.get("PRAMAGENT_HOOK_ADMIN_AUDIT_DB")
    return Path(override) if override else state_path().with_name(
        "pramagent_hook_admin_audit.db"
    )


def _normalize(raw: Any) -> dict[str, Any]:
    """Normalize partial input without weakening enforcement defaults."""
    disk = raw if isinstance(raw, dict) else {}

    disk_surfaces = disk.get("surfaces") if isinstance(disk.get("surfaces"), dict) else {}
    surfaces = {
        name: (False if disk_surfaces.get(name, True) is False else True)
        for name in SURFACES
    }

    # Only an explicit false disables a tool.
    tools: dict[str, bool] = {}
    disk_tools = disk.get("tools") if isinstance(disk.get("tools"), dict) else {}
    for name, value in disk_tools.items():
        tools[str(name)] = False if value is False else True

    policies = disk.get("policies")
    if not isinstance(policies, list):
        policies = None

    # Preserve backward compatibility for unmanaged and partial tenant entries.
    tenants: dict[str, dict[str, Any]] = {}
    disk_tenants = disk.get("tenants") if isinstance(disk.get("tenants"), dict) else {}
    for tid, entry in disk_tenants.items():
        entry = entry if isinstance(entry, dict) else {}
        allowed = entry.get("allowed_tools")
        allowed = [str(x) for x in allowed] if isinstance(allowed, list) else None
        denied = entry.get("denied_tools")
        denied = [str(x) for x in denied] if isinstance(denied, list) else []
        tenants[str(tid)] = {
            "enabled": False if entry.get("enabled") is False else True,
            "allowed_tools": allowed,
            "denied_tools": denied,
        }

    return {
        "surfaces": surfaces,
        "tools": tools,
        "policies": policies,
        "tenants": tenants,
        "updated_at": disk.get("updated_at"),
        "updated_by": disk.get("updated_by"),
    }


def _read_state() -> tuple[dict[str, Any], bool]:
    try:
        raw = json.loads(state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _normalize(None), False
    return _normalize(raw), True


def state_digest(state: dict[str, Any]) -> str:
    canonical = json.dumps(
        _normalize(state), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _audit_key_config() -> dict[str, Any]:
    from .secrets import resolve_signing_key_ring
    from .security import assert_strong_secret

    config = resolve_signing_key_ring()
    keys = config.get("signing_keys") or {}
    if keys:
        for kid, value in keys.items():
            assert_strong_secret(f"PRAMAGENT_SIGNING_KEYS[{kid}]", value)
    else:
        assert_strong_secret("PRAMAGENT_SIGNING_KEY", config.get("signing_key", ""))
    return config


def integrity_status(state: Optional[dict[str, Any]] = None) -> tuple[bool, str]:
    """Verify that the live config is the latest state committed to the HMAC chain."""
    normalized, readable = _read_state() if state is None else (_normalize(state), True)
    if not readable:
        if audit_path().exists():
            return False, "config missing or unreadable while an audit history exists"
        return True, "unconfigured"
    if not audit_path().exists():
        return False, "config has no audit history"
    try:
        from .store import SQLiteStore

        store = SQLiteStore(path=str(audit_path()), **_audit_key_config())
        try:
            if not store.verify_chain():
                return False, "hook admin audit chain is invalid"
            records = store.records()
        finally:
            store.close()
    except Exception as exc:
        return False, f"hook config integrity unavailable: {type(exc).__name__}"
    if not records:
        return False, "config has an empty audit history"
    expected = records[-1]["payload"].get("detail", {}).get("state_hash", "")
    actual = state_digest(normalized)
    if not expected or not hmac.compare_digest(str(expected), actual):
        return False, "live config does not match the latest audited state"
    return True, "verified"


def get_state() -> dict[str, Any]:
    """Return verified state, or enforcement-on defaults on any integrity failure."""
    state, readable = _read_state()
    if not readable:
        return state
    valid, _reason = integrity_status(state)
    return state if valid else _normalize(None)


def _state_for_update() -> dict[str, Any]:
    """Return mutable state for an admin operation, refusing unbound legacy state."""
    state, readable = _read_state()
    if not readable and not state_path().exists():
        return state
    valid, reason = integrity_status(state)
    if not valid:
        raise RuntimeError(f"hook config integrity check failed: {reason}")
    return state


def is_enabled(surface: str) -> bool:
    """Return whether a surface enforces; unknown names stay enabled."""
    return get_state()["surfaces"].get(surface, True)


def tool_enabled(tool_name: str, state: Optional[dict[str, Any]] = None) -> bool:
    """Return whether a tool is enabled; absent entries default to enabled."""
    st = state if state is not None else get_state()
    return st["tools"].get(tool_name, True)


def get_policies() -> Optional[list[dict[str, Any]]]:
    """The policy override list, or None when the hook should use its built-in
    defaults."""
    return get_state()["policies"]


def get_tenants() -> dict[str, Any]:
    """Per-tenant permission map (possibly empty)."""
    return get_state()["tenants"]


def tenant_tool_allowed(
    tenant_id: str, tool_name: str, state: Optional[dict[str, Any]] = None
) -> bool:
    """Check a managed tenant's allow and deny lists.

    Unmanaged tenants remain unrestricted. ``allowed_tools=None`` means all
    tools except those explicitly denied.
    """
    st = state if state is not None else get_state()
    entry = st["tenants"].get(tenant_id)
    if entry is None:
        return True
    if entry.get("enabled") is False:
        return False
    if tool_name in (entry.get("denied_tools") or []):
        return False
    allowed = entry.get("allowed_tools")
    if isinstance(allowed, list):
        return tool_name in allowed
    return True


def protected_paths() -> tuple[Path, ...]:
    """Return resolved paths for the config and its admin audit database."""
    cfg = state_path()
    audit = audit_path()
    resolved: list[Path] = []
    for candidate in (cfg, audit):
        try:
            resolved.append(candidate.resolve())
        except (OSError, ValueError):
            resolved.append(candidate)
    return tuple(resolved)


def targets_protected_path(tool_name: str, arguments: Any) -> Optional[str]:
    """Return the first control-plane path targeted by a mutating call.

    Every string leaf is checked so nested arguments, patch bodies, and shell
    redirections cannot bypass the path check. Call this before reading the
    surface switch.
    """
    if tool_name not in _MUTATING_FILE_TOOLS and tool_name not in _SHELL_TOOLS:
        return None
    if not isinstance(arguments, dict):
        return None

    protected = protected_paths()
    protected_names = {p.name for p in protected}

    for _leaf_path, text in iter_strings(arguments):
        if not text:
            continue
        for name in protected_names:
            if name in text:
                return text if len(text) <= 200 else name
        try:
            resolved = Path(text).resolve()
        except (OSError, ValueError):
            continue
        if resolved in protected:
            return text
    return None


def _write_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".hook_config.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _save_state(state: dict[str, Any], *, actor: str) -> dict[str, Any]:
    """Persist normalized state atomically with actor and timestamp."""
    state = _normalize(state)
    state["updated_at"] = time.time()
    state["updated_by"] = actor
    _write_atomic(state_path(), state)
    return state
