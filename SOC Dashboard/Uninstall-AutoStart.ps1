<#
.SYNOPSIS
    Remove the SOC Dashboard auto-start shortcut.

.DESCRIPTION
    Thin wrapper around Disable-AutoStart in Modules\SecIntel.AutoStart.ps1.
    Idempotent: a no-op if the shortcut isn't present.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Uninstall-AutoStart.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Modules\SecIntel.AutoStart.ps1')

$result = Disable-AutoStart

if ($result.Removed) {
    Write-Host "Auto-start disabled. Removed: $($result.LnkPath)" -ForegroundColor Green
} else {
    Write-Host "Auto-start was already disabled (no shortcut at $($result.LnkPath))." -ForegroundColor DarkGray
}
