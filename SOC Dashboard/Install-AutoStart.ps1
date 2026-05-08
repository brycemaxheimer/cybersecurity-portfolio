<#
.SYNOPSIS
    Install the SOC Dashboard as a per-user logon item.

.DESCRIPTION
    Thin wrapper around Enable-AutoStart in Modules\SecIntel.AutoStart.ps1.
    Creates a shortcut at %APPDATA%\Microsoft\Windows\Start Menu\Programs\
    Startup\SecIntel-Dashboard.lnk that launches SocDashboard.ps1 at next
    logon. No admin rights, no scheduled tasks, no service install.

.PARAMETER ScriptPath
    Absolute path to SocDashboard.ps1. Defaults to the SocDashboard.ps1
    sitting alongside this installer (typical layout when the repo is
    cloned to a single directory).

.PARAMETER Minimized
    Launch the WPF window minimized + ShowInTaskbar so the analyst sees
    a taskbar entry without the window stealing focus at logon.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Install-AutoStart.ps1
    # Idempotent. Run again to refresh the shortcut after moving the repo.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Install-AutoStart.ps1 -Minimized -WhatIf
    # Show what would happen without writing the .lnk.

.NOTES
    PowerShell 5.1+. No admin rights.
    See Uninstall-AutoStart.ps1 to remove.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ScriptPath,
    [switch]$Minimized
)

$ErrorActionPreference = 'Stop'

if (-not $ScriptPath) {
    $ScriptPath = Join-Path $PSScriptRoot 'SocDashboard.ps1'
}

. (Join-Path $PSScriptRoot 'Modules\SecIntel.AutoStart.ps1')

$result = Enable-AutoStart -ScriptPath $ScriptPath -Minimized:$Minimized

Write-Host ""
Write-Host "Auto-start configured." -ForegroundColor Green
Write-Host "  Shortcut: $($result.LnkPath)"
Write-Host "  Target:   $($result.Target)"
Write-Host "  Args:     $($result.Arguments)"
Write-Host "  Minimized: $($result.Minimized)"
Write-Host ""
Write-Host "It will fire at the next Windows logon. To disable, run Uninstall-AutoStart.ps1."
