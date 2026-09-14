from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
WINDOWS_INSTALLER = (
    ROOT
    / "deploy"
    / "enforcement"
    / "windows"
    / "Install-PramagentHookBoundary.ps1"
)
LINUX_INSTALLER = (
    ROOT
    / "deploy"
    / "enforcement"
    / "linux"
    / "install-pramagent-hook-boundary.sh"
)


@pytest.mark.skipif(sys.platform != "win32", reason="requires Windows PowerShell")
def test_windows_boundary_installer_parses_without_execution():
    command = (
        "$errors=$null; $tokens=$null; "
        "[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{WINDOWS_INSTALLER}', [ref]$tokens, [ref]$errors) | Out-Null; "
        "if ($errors.Count) { $errors | ForEach-Object { Write-Error $_ }; exit 1 }"
    )
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert completed.returncode == 0, completed.stderr


def test_windows_boundary_covers_runtime_state_and_host_directories():
    script = WINDOWS_INSTALLER.read_text(encoding="utf-8")

    assert "Assert-Elevated" in script
    assert "hook_integrity.json" in script
    assert "PRAMAGENT_HOOK_STATE_PATH" in script
    assert "PRAMAGENT_HOOK_ADMIN_AUDIT_DB" in script
    assert "HostControlDirectories" in script
    assert "Assert-ChildPath" in script
    assert "${AgentIdentity}:(OI)(CI)RX" in script
    assert "/setowner" in script


def test_linux_boundary_requires_root_and_removes_agent_write_access():
    script = LINUX_INSTALLER.read_text(encoding="utf-8")

    assert '"$(id -u)" -ne 0' in script
    assert "/opt/pramagent/*" in script
    assert "chown -R root:root" in script
    assert "chmod 0444" in script
    assert "chmod 0440" in script
    assert "PRAMAGENT_HOOK_STATE_PATH" in script
    assert "PRAMAGENT_HOOK_ADMIN_AUDIT_DB" in script
