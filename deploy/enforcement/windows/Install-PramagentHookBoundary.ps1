[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [string]$AgentIdentity,

    [Parameter(Mandatory = $true)]
    [string]$AgentHome,

    [string]$InstallRoot = "$env:ProgramFiles\Pramagent\hook-runtime",
    [string]$StateRoot = "$env:ProgramData\Pramagent",
    [string[]]$HostControlDirectories = @()
)

$ErrorActionPreference = "Stop"

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $administrator = [Security.Principal.WindowsBuiltInRole]::Administrator
    if (-not $principal.IsInRole($administrator)) {
        throw "Run this installer from an elevated PowerShell session."
    }
}

function Set-ProtectedDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    & icacls.exe $Path /inheritance:r | Out-Null
    & icacls.exe $Path /setowner "*S-1-5-32-544" /T /C | Out-Null
    & icacls.exe $Path /grant:r `
        "*S-1-5-18:(OI)(CI)F" `
        "*S-1-5-32-544:(OI)(CI)F" `
        "${AgentIdentity}:(OI)(CI)RX" /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to protect $Path with NTFS ACLs."
    }
}

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )

    $parentPath = [IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    $childPath = [IO.Path]::GetFullPath($Child)
    if (-not $childPath.StartsWith($parentPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Child is outside the intended installation root."
    }
}

Assert-Elevated
$source = (Resolve-Path -LiteralPath $SourceRoot).Path
$agentHomePath = (Resolve-Path -LiteralPath $AgentHome).Path
if ($HostControlDirectories.Count -eq 0) {
    $HostControlDirectories = @(
        (Join-Path $agentHomePath ".claude"),
        (Join-Path $agentHomePath ".gemini"),
        (Join-Path $agentHomePath ".codex")
    )
}
$manifestPath = Join-Path $source "pramagent\hook_integrity.json"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "The source tree does not contain pramagent\hook_integrity.json."
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
foreach ($property in $manifest.files.PSObject.Properties) {
    $candidate = Join-Path $source ($property.Name -replace "/", "\")
    $actual = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne [string]$property.Value) {
        throw "Integrity manifest mismatch for $($property.Name)."
    }
}

if ($PSCmdlet.ShouldProcess($InstallRoot, "install protected hook runtime")) {
    New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
    foreach ($name in @("pramagent", "scripts", "plugins")) {
        $destination = Join-Path $InstallRoot $name
        Assert-ChildPath -Parent $InstallRoot -Child $destination
        if (Test-Path -LiteralPath $destination) {
            Remove-Item -LiteralPath $destination -Recurse -Force
        }
        Copy-Item -LiteralPath (Join-Path $source $name) -Destination $destination -Recurse
    }
    Set-ProtectedDirectoryAcl -Path $InstallRoot

    New-Item -ItemType Directory -Force -Path $StateRoot | Out-Null
    & icacls.exe $StateRoot /inheritance:r | Out-Null
    & icacls.exe $StateRoot /setowner "*S-1-5-32-544" /T /C | Out-Null
    & icacls.exe $StateRoot /grant:r `
        "*S-1-5-18:(OI)(CI)F" `
        "*S-1-5-32-544:(OI)(CI)F" `
        "${AgentIdentity}:(OI)(CI)RX" /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to protect $StateRoot with NTFS ACLs."
    }

    foreach ($directory in $HostControlDirectories) {
        if (Test-Path -LiteralPath $directory -PathType Container) {
            Set-ProtectedDirectoryAcl -Path $directory
        }
    }

    [Environment]::SetEnvironmentVariable(
        "PRAMAGENT_HOOK_STATE_PATH",
        (Join-Path $StateRoot "hook-config.json"),
        "Machine"
    )
    [Environment]::SetEnvironmentVariable(
        "PRAMAGENT_HOOK_ADMIN_AUDIT_DB",
        (Join-Path $StateRoot "hook-admin-audit.db"),
        "Machine"
    )
}

Write-Host "Protected runtime: $InstallRoot"
Write-Host "Protected state:   $StateRoot"
Write-Host "Agent identity:    $AgentIdentity (read/execute only)"
Write-Warning "Update each host hook command to use the runtime under $InstallRoot."
Write-Warning "Administrators can still change this deployment; that remains in the threat model."
