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
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from .hook_scan import iter_strings, shell_command_risk

# Hook adapters that can be toggled independently.
SURFACES: tuple[str, ...] = ("claude", "gemini", "codex", "plugin")

# File and shell tools must not be able to rewrite the guard that evaluates them.
_MUTATING_FILE_TOOLS: frozenset[str] = frozenset({
    "write", "edit", "multiedit", "apply_patch", "write_file", "replace",
    "notebookedit", "create_file", "delete_file", "move_file",
})
_SHELL_TOOLS: frozenset[str] = frozenset({
    "bash", "powershell", "run_shell_command", "exec_command", "shell",
    "terminal",
})

_PATH_ARGUMENT_KEYS: frozenset[str] = frozenset({
    "file_path", "filepath", "path", "target", "destination", "directory",
    "notebook_path", "old_path", "new_path",
})

_SHELL_WRITE_SIGNAL = re.compile(
    r"(?:"
    r"(?<!<)>{1,2}|"
    r"\b(?:tee|rm|mv|cp|install|unlink|shred|truncate|touch|chmod|chown)\b|"
    r"\b(?:Set|Add|Clear)-Content\b|\bOut-File\b|"
    r"\b(?:New|Remove|Move|Copy|Rename)-Item\b|"
    r"\b(?:del|erase|rmdir|rd|copy|move|ren)\b|"
    r"\bsed\s+(?:-[A-Za-z]*i[A-Za-z]*|--in-place)\b|"
    r"\bperl\s+-[A-Za-z]*i[A-Za-z]*\b|"
    r"\b(?:git\s+(?:apply|checkout|restore|clean|reset)|patch)\b|"
    r"\.(?:write_text|write_bytes|unlink|rename|replace)\s*\(|"
    r"\bopen\s*\([^\r\n]{0,300},\s*['\"](?:w|a|x)[bt+]*['\"]"
    r")",
    re.IGNORECASE,
)

_HOST_CONFIGS: tuple[tuple[str, ...], ...] = (
    (".claude", "settings.json"),
    (".claude", "settings.local.json"),
    (".codex", "hooks.json"),
    (".codex", "config.toml"),
    (".gemini", "settings.json"),
    (".gemini", "config", "settings.json"),
)

_HOOK_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("scripts", "hook_bootstrap.py"),
    ("scripts", "claude_code_hook.py"),
    ("scripts", "gemini_cli_hook.py"),
    ("scripts", "codex_tool_hook.py"),
)

_PLUGIN_FILES: tuple[tuple[str, ...], ...] = (
    ("hooks", "hooks.json"),
    ("hooks", "scripts", "pramagent_guard.py"),
    ("policies.json",),
    (".claude-plugin", "plugin.json"),
    (".codex-plugin", "plugin.json"),
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def state_path() -> Path:
    """Return the config path, honoring the shared-location override."""
    override = os.environ.get("PRAMAGENT_HOOK_STATE_PATH")
    if override:
        return Path(override)
    return _repo_root() / "pramagent_hook_config.json"


def default_config_path() -> Path:
    """Return the shipped baseline config or an operator-selected baseline."""
    override = os.environ.get("PRAMAGENT_HOOK_DEFAULT_CONFIG")
    if override:
        return Path(override)
    return Path(__file__).with_name("default_hook_config.json")


def audit_path() -> Path:
    override = os.environ.get("PRAMAGENT_HOOK_ADMIN_AUDIT_DB")
    return Path(override) if override else state_path().with_name(
        "pramagent_hook_admin_audit.db"
    )


def _plugin_roots() -> tuple[Path, ...]:
    roots = [_repo_root() / "plugins" / "pramagent-guard"]
    for name in (
        "PRAMAGENT_PLUGIN_ROOT",
        "CLAUDE_PLUGIN_ROOT",
        "PLUGIN_ROOT",
        "GROK_PLUGIN_ROOT",
    ):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value).expanduser())
    return tuple(roots)


def _extra_protected_paths() -> tuple[Path, ...]:
    raw = os.environ.get("PRAMAGENT_HOOK_PROTECTED_PATHS", "")
    return tuple(Path(value).expanduser() for value in raw.split(os.pathsep) if value)


def _resolve(candidate: Path) -> Path:
    try:
        return candidate.expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return candidate.expanduser()


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

    normalized = {
        "surfaces": surfaces,
        "tools": tools,
        "policies": policies,
        "tenants": tenants,
        "updated_at": disk.get("updated_at"),
        "updated_by": disk.get("updated_by"),
    }
    # Omit the field for legacy state so its previously audited digest remains
    # valid. New states may opt into replacement explicitly.
    if "policy_mode" in disk:
        normalized["policy_mode"] = (
            "replace" if disk.get("policy_mode") == "replace" else "extend"
        )
    return normalized


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
        state["_base_state_hash"] = state_digest(state)
        return state
    valid, reason = integrity_status(state)
    if not valid:
        raise RuntimeError(f"hook config integrity check failed: {reason}")
    state["_base_state_hash"] = state_digest(state)
    return state


def is_enabled(surface: str) -> bool:
    """Return whether a surface enforces; unknown names stay enabled."""
    return get_state()["surfaces"].get(surface, True)


def tool_enabled(tool_name: str, state: Optional[dict[str, Any]] = None) -> bool:
    """Return whether a tool is enabled; absent entries default to enabled."""
    st = state if state is not None else get_state()
    return st["tools"].get(tool_name, True)


def get_policies() -> list[dict[str, Any]]:
    """Return shipped policies with audited user overrides merged by name.

    A user policy with the same ``name`` replaces the default in place. New
    names are appended. Deleting an override therefore restores the shipped
    default instead of silently removing protection for that tool.
    """
    defaults = get_default_policies()
    overrides = get_state()["policies"] or []
    if get_policy_mode() == "replace":
        return [dict(policy) for policy in overrides]
    positions = {
        str(policy.get("name")): index
        for index, policy in enumerate(defaults)
        if policy.get("name")
    }
    merged = [dict(policy) for policy in defaults]
    for policy in overrides:
        name = str(policy.get("name", ""))
        if not name:
            continue
        if name in positions:
            merged[positions[name]] = dict(policy)
        else:
            positions[name] = len(merged)
            merged.append(dict(policy))
    return merged


def get_default_policies() -> list[dict[str, Any]]:
    """Load the packaged baseline. Invalid files fail safe to adapter defaults."""
    try:
        raw = json.loads(default_config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    policies = raw.get("policies") if isinstance(raw, dict) else None
    if not isinstance(policies, list):
        return []
    return [dict(policy) for policy in policies if isinstance(policy, dict)]


def get_policy_overrides() -> list[dict[str, Any]]:
    """Return only policies stored in the audited user configuration."""
    return [dict(policy) for policy in (get_state()["policies"] or [])]


def get_policy_mode() -> str:
    """Return ``extend`` (default foundation) or explicit full ``replace``."""
    return str(get_state().get("policy_mode", "extend"))


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
    """Return files that can disable or weaken an installed hook."""
    repo = _repo_root()
    home = Path.home()
    candidates = [
        state_path(),
        default_config_path(),
        audit_path(),
        repo / "pramagent" / "hook_integrity.json",
        Path(os.environ.get(
            "PRAMAGENT_GEMINI_HOOK_AUDIT_DB",
            repo / "pramagent_gemini_hook_audit.db",
        )),
        *(repo.joinpath(*parts) for parts in _HOST_CONFIGS),
        *(home.joinpath(*parts) for parts in _HOST_CONFIGS),
        *(repo.joinpath(*parts) for parts in _HOOK_LAUNCHERS),
        *(
            home / ".claude" / "hooks" / Path(*parts).name
            for parts in _HOOK_LAUNCHERS
        ),
    ]
    for root in _plugin_roots():
        candidates.extend(root.joinpath(*parts) for parts in _PLUGIN_FILES)
    policy_override = os.environ.get("PRAMAGENT_GUARD_POLICY")
    if policy_override:
        candidates.append(Path(policy_override))
    candidates.extend(_extra_protected_paths())

    unique: dict[str, Path] = {}
    for candidate in candidates:
        resolved = _resolve(candidate)
        unique[os.path.normcase(str(resolved))] = resolved
    return tuple(unique.values())


def protected_roots() -> tuple[Path, ...]:
    """Return code roots whose contents participate in hook enforcement."""
    roots = [
        _resolve(Path(__file__).parent),
        _resolve(Path(sys.prefix)),
        *map(_resolve, _plugin_roots()),
    ]
    unique = {os.path.normcase(str(root)): root for root in roots}
    return tuple(unique.values())


def _tool_kind(tool_name: str) -> str:
    leaf = str(tool_name).replace("::", ".").replace("/", ".").split(".")[-1]
    return leaf.casefold()


def _shell_may_modify_paths(command: str) -> bool:
    """Return whether a shell command contains an observable write primitive."""
    risk, _reason = shell_command_risk(command)
    if risk == "allow":
        return False
    return bool(_SHELL_WRITE_SIGNAL.search(command))


def _candidate_strings(kind: str, arguments: dict[str, Any]):
    for leaf_path, text in iter_strings(arguments):
        key = leaf_path.rsplit(".", 1)[-1].split("[", 1)[0].casefold()
        if kind in _SHELL_TOOLS:
            if key not in {"command", "cmd"} or not _shell_may_modify_paths(text):
                continue
        elif kind != "apply_patch" and key not in _PATH_ARGUMENT_KEYS:
            continue
        yield text


def _path_aliases(path: Path) -> set[str]:
    aliases = {str(path), path.as_posix()}
    for base in (_repo_root(), Path.cwd(), Path.home()):
        try:
            relative = path.relative_to(_resolve(base))
        except ValueError:
            continue
        aliases.add(str(relative))
        aliases.add(relative.as_posix())
        if base == Path.home():
            aliases.add("~/" + relative.as_posix())
    return {
        alias.replace("\\", "/").casefold()
        for alias in aliases
        if alias not in {"", "."}
    }


def _is_in_root(candidate: Path, roots: tuple[Path, ...]) -> bool:
    key = os.path.normcase(str(candidate))
    for root in roots:
        root_key = os.path.normcase(str(root))
        if key == root_key or key.startswith(root_key.rstrip("\\/") + os.sep):
            return True
    return False


def sensitive_write_roots() -> tuple[Path, ...]:
    """Return user and system locations that coding hooks may not modify."""
    home = Path.home()
    candidates = [
        home / name
        for name in (".ssh", ".aws", ".azure", ".gnupg", ".kube", ".docker")
    ]
    candidates.extend((Path("/etc"), Path("/root")))
    system_root = os.environ.get("SystemRoot")
    if system_root:
        candidates.append(Path(system_root))
    return tuple(_resolve(path) for path in candidates)


def sensitive_write_paths() -> tuple[Path, ...]:
    home = Path.home()
    return tuple(
        _resolve(home / name)
        for name in (".git-credentials", ".npmrc", ".pypirc", ".netrc")
    )


def targets_sensitive_path(tool_name: str, arguments: Any) -> Optional[str]:
    """Return a credential or system path targeted by a mutating call."""
    kind = _tool_kind(tool_name)
    if kind not in _MUTATING_FILE_TOOLS and kind not in _SHELL_TOOLS:
        return None
    if not isinstance(arguments, dict):
        return None

    roots = sensitive_write_roots()
    files = sensitive_write_paths()
    aliases = set().union(*(_path_aliases(path) for path in (*roots, *files)))
    root_aliases = {alias.rstrip("/") + "/" for alias in aliases}
    for text in _candidate_strings(kind, arguments):
        if not text:
            continue
        normalized = os.path.expandvars(text).replace("\\", "/").casefold()
        if any(alias in normalized for alias in aliases | root_aliases):
            return text if len(text) <= 200 else "sensitive path"
        if kind not in _SHELL_TOOLS:
            candidate = _resolve(Path(os.path.expandvars(text)))
            if candidate in files or _is_in_root(candidate, roots):
                return text
    return None


def targets_protected_path(tool_name: str, arguments: Any) -> Optional[str]:
    """Return the first control-plane path targeted by a mutating call.

    Every string leaf is checked so nested arguments, patch bodies, and shell
    redirections cannot bypass the path check. Call this before reading the
    surface switch.
    """
    kind = _tool_kind(tool_name)
    if kind not in _MUTATING_FILE_TOOLS and kind not in _SHELL_TOOLS:
        return None
    if not isinstance(arguments, dict):
        return None

    protected = protected_paths()
    roots = protected_roots()
    aliases = set().union(*(_path_aliases(path) for path in protected))
    root_aliases = {
        alias.rstrip("/") + "/"
        for root in roots
        for alias in _path_aliases(root)
    }

    for text in _candidate_strings(kind, arguments):
        if not text:
            continue
        normalized = os.path.expandvars(text).replace("\\", "/").casefold()
        if any(alias in normalized for alias in aliases | root_aliases):
            return text if len(text) <= 200 else "protected hook path"
        try:
            resolved = _resolve(Path(os.path.expandvars(text)))
        except (OSError, RuntimeError, ValueError):
            continue
        if resolved in protected or _is_in_root(resolved, roots):
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
