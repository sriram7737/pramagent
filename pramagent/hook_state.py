"""
pramagent.hook_state
====================
Read side of the central Pramagent hook configuration  -  the single source of
truth an operator drives from the admin console. Every hook process (each hook
invocation is a fresh process) reads this at the top of its evaluation, so a
change from the console takes effect on the very next tool call with no daemon
or cache to reload.

The config carries three things:

  * ``surfaces``  -  per-adapter master switch (claude / gemini / codex / plugin).
  * ``tools``     -  per-tool master switch. A tool set to ``false`` is DENIED by
                   every enabled hook, so an operator can hard-disable, say,
                   ``Bash`` everywhere from one place.
  * ``policies``  -  optional ToolGuard policy override (the editable JSON schema
                   set). ``None`` / absent means each hook uses its built-in
                   defaults; a list overrides them.
  * ``tenants``   -  per-tenant permissions: which tools each tenant may use.
                   ``{tenant_id: {enabled, allowed_tools, denied_tools}}``. A
                   tenant with no entry is UNMANAGED (not restricted here), so
                   existing single-tenant setups are unaffected. ``allowed_tools``
                   ``None`` means "all tools"; a list means "only these".

WRITES go through :mod:`pramagent.hook_admin`, which also appends every change
to a SHA-256 hash-chained audit. This module is read-only and dependency-light
so the hot path (one ``is_enabled`` call per tool call) stays cheap.

Fail-safe, not fail-open
------------------------
This is a security control's configuration, so the safe default is enforcement
ON. A missing/unreadable/corrupt config, or an absent key, always resolves to:
surface ENABLED, tool ENABLED, no policy override. A garbled file can only
leave the guard on, never silently drop it. A tool is disabled (denied) ONLY
when the file exists, parses, and explicitly sets it ``false``.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from .hook_scan import iter_strings

# The surfaces an operator can toggle independently  -  one per hook adapter.
SURFACES: tuple[str, ...] = ("claude", "gemini", "codex", "plugin")

# Tools that can create or modify a file, across every adapter surface, and the
# shell tools. A call to one of these targeting the hook's own control plane is
# refused before the master switch is even consulted (see
# ``targets_protected_path``). Read-only tools are intentionally absent: reading
# the config is harmless, only writes can turn the guard off.
_MUTATING_FILE_TOOLS: frozenset[str] = frozenset({
    "Write", "Edit", "MultiEdit", "apply_patch", "write_file", "replace",
})
_SHELL_TOOLS: frozenset[str] = frozenset({
    "Bash", "PowerShell", "run_shell_command",
})


def _repo_root() -> Path:
    # pramagent/hook_state.py -> parents[1] is the repo root, matching the
    # sys.path root each script hook inserts.
    return Path(__file__).resolve().parents[1]


def state_path() -> Path:
    """Path to the JSON config file. Override with PRAMAGENT_HOOK_STATE_PATH so
    the hooks and the console can be pointed at a shared location."""
    override = os.environ.get("PRAMAGENT_HOOK_STATE_PATH")
    if override:
        return Path(override)
    return _repo_root() / "pramagent_hook_config.json"


def _normalize(raw: Any) -> dict[str, Any]:
    """Coerce whatever is on disk into a full, valid config. Anything missing
    or malformed defaults to the enforcement-ON state (fail-safe)."""
    disk = raw if isinstance(raw, dict) else {}

    disk_surfaces = disk.get("surfaces") if isinstance(disk.get("surfaces"), dict) else {}
    surfaces = {
        name: (False if disk_surfaces.get(name, True) is False else True)
        for name in SURFACES
    }

    # Per-tool switches: only an explicit False disables. Unknown tool names are
    # allowed (default enabled) so the console can pre-declare tools.
    tools: dict[str, bool] = {}
    disk_tools = disk.get("tools") if isinstance(disk.get("tools"), dict) else {}
    for name, value in disk_tools.items():
        tools[str(name)] = False if value is False else True

    policies = disk.get("policies")
    if not isinstance(policies, list):
        policies = None

    # Per-tenant permissions. Each entry is normalized so a partial/garbled
    # value can't accidentally over-grant: enabled defaults True, denied_tools
    # to [], allowed_tools to None ("all") unless an explicit list is given.
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


def get_state() -> dict[str, Any]:
    """Return the full normalized config. Never raises: an unreadable or corrupt
    file yields the enforcement-ON default."""
    try:
        raw = json.loads(state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raw = None
    return _normalize(raw)


def is_enabled(surface: str) -> bool:
    """True if this surface should enforce. Unknown surface names default to
    enabled  -  a hook asking about itself is never silently disabled by a typo."""
    return get_state()["surfaces"].get(surface, True)


def tool_enabled(tool_name: str, state: Optional[dict[str, Any]] = None) -> bool:
    """True unless the tool is explicitly switched off in the config. A tool
    with no entry is enabled (fail-safe). Pass a pre-read ``state`` to avoid a
    second file read when the caller already has one."""
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
    """Whether ``tenant_id`` is permitted to use ``tool_name``.

    A tenant with NO entry is unmanaged and therefore allowed (this switch does
    not restrict it)  -  so adding tenant permissions never silently breaks an
    existing single-tenant deployment. For a managed tenant: it must be enabled,
    the tool must not be in ``denied_tools``, and  -  when ``allowed_tools`` is a
    list  -  the tool must be in it. ``allowed_tools`` of None means every tool
    (minus the denied list)."""
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
    """Resolved paths of the hook's own control plane: the JSON config and its
    admin audit DB. A guarded tool call that writes either of these could
    disable or silently reprogram the guard, so the hooks refuse such calls
    (see ``targets_protected_path``). The audit DB location mirrors
    ``hook_admin._audit_db_path``: next to the config unless overridden."""
    cfg = state_path()
    audit_override = os.environ.get("PRAMAGENT_HOOK_ADMIN_AUDIT_DB")
    audit = (
        Path(audit_override) if audit_override
        else cfg.with_name("pramagent_hook_admin_audit.db")
    )
    resolved: list[Path] = []
    for candidate in (cfg, audit):
        try:
            resolved.append(candidate.resolve())
        except (OSError, ValueError):
            resolved.append(candidate)
    return tuple(resolved)


def targets_protected_path(tool_name: str, arguments: Any) -> Optional[str]:
    """Return the offending path string if this tool call would write or modify
    a hook control-plane file, else ``None``.

    This is the guard's self-protection: without it a constrained agent could
    use an allowed ``Write`` to set ``surfaces.claude`` to ``false`` in the
    config, and the very next tool call would run unguarded. It must be consulted
    BEFORE the master switch so a would-be-disabled surface cannot skip it.

    Only mutating and shell tools are considered. Every string leaf of the
    arguments is examined (via :func:`iter_strings`, so a target routed through a
    nested field or a patch body is still seen). A leaf matches when it contains
    a protected file's distinctive name  -  which catches structured ``file_path``
    values, shell redirections, ``tee``/patch bodies and one-liners alike  -  or
    when it resolves to a protected absolute path (covering a custom,
    non-distinctive config name set via ``PRAMAGENT_HOOK_STATE_PATH``)."""
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
    """Persist a full normalized state atomically, stamping who/when. Used by
    pramagent.hook_admin, which layers the hash-chained audit on top."""
    state = _normalize(state)
    state["updated_at"] = time.time()
    state["updated_by"] = actor
    _write_atomic(state_path(), state)
    return state
