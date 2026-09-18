"""Diagnostics for installed coding-agent hooks and their control plane."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

__all__ = ["HookDoctorCheck", "HookDoctorReport", "inspect_hooks"]


@dataclass(frozen=True)
class HookDoctorCheck:
    name: str
    status: str
    detail: str
    path: str = ""
    sha256: str = ""


@dataclass(frozen=True)
class HookDoctorReport:
    checks: tuple[HookDoctorCheck, ...]

    @property
    def healthy(self) -> bool:
        return not any(check.status == "fail" for check in self.checks)

    @property
    def hardened(self) -> bool:
        return all(check.status == "ok" for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "hardened": self.hardened,
            "checks": [asdict(check) for check in self.checks],
        }


_RUNTIME_FILES = (
    "pramagent/default_hook_config.json",
    "pramagent/hook_scan.py",
    "pramagent/hook_state.py",
    "scripts/hook_bootstrap.py",
    "scripts/claude_code_hook.py",
    "scripts/gemini_cli_hook.py",
    "scripts/codex_tool_hook.py",
    "plugins/pramagent-guard/hooks/hooks.json",
    "plugins/pramagent-guard/hooks/codex_hooks.json",
    "plugins/pramagent-guard/hooks/scripts/pramagent_guard.py",
    "plugins/pramagent-guard/policies.json",
)

_HOST_CONFIGS = {
    "claude": (
        (".claude", "settings.json"),
        (".claude", "settings.local.json"),
    ),
    "gemini": (
        (".gemini", "settings.json"),
        (".gemini", "config", "settings.json"),
    ),
    "codex": ((".codex", "hooks.json"),),
}

_HOST_SCRIPT = {
    "claude": "claude_code_hook.py",
    "gemini": "gemini_cli_hook.py",
    "codex": "codex_tool_hook.py",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            # Match hook_bootstrap: CRLF and LF have identical source semantics.
            digest.update(chunk.replace(b"\r\n", b"\n"))
    return digest.hexdigest()


def _writable(path: Path) -> bool:
    mode = path.stat().st_mode
    return bool(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)) and os.access(
        path, os.W_OK
    )


def _load_manifest(path: Path) -> dict[str, str]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    files = raw.get("files") if isinstance(raw, dict) else None
    if not isinstance(files, dict) or not all(
        isinstance(name, str) and isinstance(digest, str)
        for name, digest in files.items()
    ):
        raise ValueError("hook integrity manifest has an invalid files map")
    return files


def _candidate_configs(repo_root: Path, home: Path, parts: tuple[str, ...]):
    seen: set[str] = set()
    for base in (repo_root, home):
        path = base.joinpath(*parts)
        key = os.path.normcase(str(path.resolve(strict=False)))
        if key not in seen:
            seen.add(key)
            yield path


def _host_check(host: str, repo_root: Path, home: Path) -> HookDoctorCheck:
    present: list[Path] = []
    malformed: list[Path] = []
    for parts in _HOST_CONFIGS[host]:
        for path in _candidate_configs(repo_root, home, parts):
            if not path.exists():
                continue
            present.append(path)
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                text = json.dumps(raw, sort_keys=True)
            except (OSError, ValueError):
                malformed.append(path)
                continue
            if _HOST_SCRIPT[host] in text and "hook_bootstrap.py" in text:
                return HookDoctorCheck(
                    f"{host}.configuration",
                    "ok",
                    "host configuration references the fail-closed bootstrap",
                    str(path),
                )
    if malformed:
        return HookDoctorCheck(
            f"{host}.configuration",
            "fail",
            "host configuration is unreadable or malformed",
            str(malformed[0]),
        )
    return HookDoctorCheck(
        f"{host}.configuration",
        "warn",
        "hook is not configured through the fail-closed bootstrap",
        str(present[0]) if present else "",
    )


def inspect_hooks(
    *,
    repo_root: str | Path | None = None,
    home: str | Path | None = None,
    manifest_path: str | Path | None = None,
) -> HookDoctorReport:
    """Inspect runtime hashes, host wiring, state integrity, and write exposure."""
    repo = Path(repo_root or Path(__file__).resolve().parents[1]).resolve()
    user_home = Path(home or Path.home()).resolve()
    manifest = Path(manifest_path or (repo / "pramagent" / "hook_integrity.json"))
    checks: list[HookDoctorCheck] = []

    try:
        expected = _load_manifest(manifest)
    except (OSError, ValueError) as exc:
        checks.append(HookDoctorCheck(
            "runtime.manifest",
            "fail",
            f"integrity manifest unavailable: {type(exc).__name__}",
            str(manifest),
        ))
        expected = {}
    else:
        checks.append(HookDoctorCheck(
            "runtime.manifest", "ok", "integrity manifest loaded", str(manifest)
        ))

    for relative in _RUNTIME_FILES:
        path = repo / relative
        if not path.is_file() or path.is_symlink():
            checks.append(HookDoctorCheck(
                f"runtime.{relative}",
                "fail",
                "required hook file is missing or is a symbolic link",
                str(path),
            ))
            continue
        actual = _sha256(path)
        wanted = expected.get(relative)
        if not wanted or actual != wanted:
            checks.append(HookDoctorCheck(
                f"runtime.{relative}",
                "fail",
                "runtime hash does not match the approved manifest",
                str(path),
                actual,
            ))
            continue
        checks.append(HookDoctorCheck(
            f"runtime.{relative}",
            "warn" if _writable(path) else "ok",
            (
                "hash verified, but the current account can modify this file"
                if _writable(path)
                else "hash verified and file is read-only"
            ),
            str(path),
            actual,
        ))

    for host in _HOST_CONFIGS:
        checks.append(_host_check(host, repo, user_home))

    plugin_manifest = repo / "plugins" / "pramagent-guard" / "hooks" / "hooks.json"
    checks.append(HookDoctorCheck(
        "plugin.configuration",
        "ok" if plugin_manifest.is_file() else "fail",
        "plugin hook manifest is present" if plugin_manifest.is_file()
        else "plugin hook manifest is missing",
        str(plugin_manifest),
    ))

    try:
        from .hook_state import integrity_status

        valid, reason = integrity_status()
        state_status = "ok" if valid and reason == "verified" else (
            "warn" if valid else "fail"
        )
        checks.append(HookDoctorCheck(
            "control_plane.state", state_status, reason
        ))
    except Exception as exc:
        checks.append(HookDoctorCheck(
            "control_plane.state",
            "fail",
            f"state integrity check failed: {type(exc).__name__}",
        ))

    return HookDoctorReport(tuple(checks))
