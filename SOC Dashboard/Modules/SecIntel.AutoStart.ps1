<#
.SYNOPSIS
    Auto-start support for the SOC Dashboard. Manages a per-user .lnk in
    the Windows Startup folder so the dashboard launches at logon
    without admin rights, scheduled tasks, or service installation.

.DESCRIPTION
    Functions:
        Enable-AutoStart    - create / refresh the Startup folder shortcut
        Disable-AutoStart   - remove the shortcut
        Test-AutoStart      - return @{ Installed; LnkPath; Target; Arguments }
        Test-StartupFolderPolicy - probe HKCU/HKLM for NoStartFolder GPO lockout
        Test-ExecutionPolicyAllowsBypass - check Machine/User scope policy

    All operations are idempotent. The shortcut path is fixed at:
        %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\SecIntel-Dashboard.lnk

    The shortcut launches the configured PS host (pwsh.exe when available,
    powershell.exe otherwise) with:
        -ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive
        -File <path-to-SocDashboard.ps1>

    The dashboard's WPF window then comes up minimized + ShowInTaskbar so
    the user can click the taskbar entry to bring it forward.

.NOTES
    PowerShell 5.1+. Dot-source SecIntel.Schema.ps1 + SecIntel.Settings.ps1
    first if you want autostart.enabled / autostart.scriptpath persisted
    in AppSettings.
#>

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.Settings.ps1')

# ============================================================
# Constants - shortcut file name + location.
# ============================================================
$script:AutoStartLnkName = 'SecIntel-Dashboard.lnk'

function Get-AutoStartLnkPath {
    [CmdletBinding()] param()
    $startup = [Environment]::GetFolderPath('Startup')
    return (Join-Path $startup $script:AutoStartLnkName)
}

# ============================================================
# Resolve the PowerShell host that should launch the dashboard.
# Prefers pwsh.exe (PS 7+) when on PATH so users on modern hosts
# don't drop back into Windows PowerShell at logon.
# ============================================================
function Resolve-AutoStartHost {
    [CmdletBinding()] param()
    $pwsh = Get-Command 'pwsh.exe' -ErrorAction SilentlyContinue
    if ($pwsh) { return $pwsh.Source }
    $wps = Get-Command 'powershell.exe' -ErrorAction SilentlyContinue
    if ($wps) { return $wps.Source }
    throw "Neither pwsh.exe nor powershell.exe is on PATH; cannot create auto-start shortcut."
}

# ============================================================
# Diagnostics. Each returns a PSCustomObject describing the
# environment so the caller can warn the user about lockouts
# the .lnk cannot work around.
# ============================================================
function Test-StartupFolderPolicy {
    [CmdletBinding()] param()
    # GPO 'NoStartFolder' (User Configuration > Admin Templates >
    # Start Menu and Taskbar) hides the Startup folder. The .lnk
    # gets created but Windows does not enumerate it at logon.
    $blocked = $false
    $sources = @()
    foreach ($root in @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    )) {
        try {
            $val = (Get-ItemProperty -Path $root -Name 'NoStartFolder' -ErrorAction SilentlyContinue).NoStartFolder
            if ($val -eq 1) { $blocked = $true; $sources += $root }
        } catch { }
    }
    return [pscustomobject]@{
        Blocked = $blocked
        Sources = $sources
    }
}

function Test-ExecutionPolicyAllowsBypass {
    [CmdletBinding()] param()
    # If MachinePolicy or UserPolicy scope is AllSigned/Restricted,
    # the .lnk's -ExecutionPolicy Bypass flag is overridden and the
    # dashboard fails to start at logon. Process-scope is irrelevant
    # here (each logon launch is a fresh process).
    $blocked = $false
    $details = @()
    foreach ($scope in @('MachinePolicy','UserPolicy')) {
        try {
            $ep = Get-ExecutionPolicy -Scope $scope -ErrorAction SilentlyContinue
            if ($ep -in @('AllSigned','Restricted')) {
                $blocked = $true
                $details += "$scope = $ep"
            }
        } catch { }
    }
    return [pscustomobject]@{
        Blocked = $blocked
        Details = $details
    }
}

function Test-AutoStartRoamingProfile {
    [CmdletBinding()] param()
    # %APPDATA% on a UNC path indicates a roaming/redirected profile.
    # The .lnk roams but the script target may not, breaking auto-start
    # on machines other than the original.
    return [pscustomobject]@{
        IsRoaming = ($env:APPDATA -match '^\\\\')
        AppData   = $env:APPDATA
    }
}

# ============================================================
# Test-AutoStart - report the current install state.
# ============================================================
function Test-AutoStart {
    [CmdletBinding()] param()
    $lnk = Get-AutoStartLnkPath
    $installed = Test-Path -LiteralPath $lnk
    $target = $null; $arguments = $null; $workingDir = $null

    if ($installed) {
        try {
            $shell = New-Object -ComObject WScript.Shell
            $sc = $shell.CreateShortcut($lnk)
            $target     = $sc.TargetPath
            $arguments  = $sc.Arguments
            $workingDir = $sc.WorkingDirectory
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($sc)
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
        } catch { }
    }

    return [pscustomobject]@{
        Installed        = $installed
        LnkPath          = $lnk
        Target           = $target
        Arguments        = $arguments
        WorkingDirectory = $workingDir
    }
}

# ============================================================
# Enable-AutoStart - create / refresh the shortcut.
# Idempotent: re-running just rewrites the shortcut to point at
# the current ScriptPath, so a moved repo self-heals next launch.
# ============================================================
function Enable-AutoStart {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [switch]$Minimized
    )

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        throw "Script not found: $ScriptPath"
    }
    $resolvedScript = (Resolve-Path -LiteralPath $ScriptPath).Path

    $hostExe = Resolve-AutoStartHost
    $lnkPath = Get-AutoStartLnkPath

    # Surface lockouts up front so the user knows the .lnk may not actually
    # auto-run. We still create it - the user might fix the policy later.
    $epCheck = Test-ExecutionPolicyAllowsBypass
    if ($epCheck.Blocked) {
        Write-Warning ("Execution policy blocks Bypass: {0}. Logon launch will fail until policy is loosened or scripts are signed." -f ($epCheck.Details -join ', '))
    }
    $sfCheck = Test-StartupFolderPolicy
    if ($sfCheck.Blocked) {
        Write-Warning ("GPO 'NoStartFolder' is set ({0}). Shortcut will be created but Windows won't enumerate it at logon." -f ($sfCheck.Sources -join ', '))
    }
    $rpCheck = Test-AutoStartRoamingProfile
    if ($rpCheck.IsRoaming) {
        Write-Warning ("AppData is roamed ({0}). Auto-start will only work on machines where the script path also exists." -f $rpCheck.AppData)
    }

    $arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -File `"$resolvedScript`""
    $workDir   = Split-Path -Path $resolvedScript -Parent
    # WshShortcut.WindowStyle constants: 1=Normal, 3=Maximized, 7=Minimized.
    $windowStyle = if ($Minimized) { 7 } else { 1 }

    if ($PSCmdlet.ShouldProcess($lnkPath, 'Create or refresh auto-start shortcut')) {
        $shell = New-Object -ComObject WScript.Shell
        try {
            $sc = $shell.CreateShortcut($lnkPath)
            $sc.TargetPath       = $hostExe
            $sc.Arguments        = $arguments
            $sc.WorkingDirectory = $workDir
            $sc.WindowStyle      = $windowStyle
            $sc.Description      = 'SOC Operations Dashboard - auto-launched at logon'
            $sc.IconLocation     = "$hostExe,0"
            $sc.Save()
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($sc)
        } finally {
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
        }

        # Persist state - tolerate a missing DB (Initialize-SecIntelSchema
        # will create it) so the install can run before the dashboard's
        # first launch.
        try {
            Initialize-SecIntelSchema
            Set-AppSetting -Name 'autostart.enabled'    -Value 'true'
            Set-AppSetting -Name 'autostart.scriptpath' -Value $resolvedScript
            Set-AppSetting -Name 'autostart.host'       -Value $hostExe
        } catch {
            Write-Warning "Auto-start shortcut written, but persisting AppSettings failed: $($_.Exception.Message)"
        }
    }

    return [pscustomobject]@{
        LnkPath    = $lnkPath
        Target     = $hostExe
        Arguments  = $arguments
        Minimized  = [bool]$Minimized
        Warnings   = @{
            ExecutionPolicy  = $epCheck
            StartupFolder    = $sfCheck
            RoamingProfile   = $rpCheck
        }
    }
}

# ============================================================
# Disable-AutoStart - remove the shortcut.
# ============================================================
function Disable-AutoStart {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $lnk = Get-AutoStartLnkPath
    if (Test-Path -LiteralPath $lnk) {
        if ($PSCmdlet.ShouldProcess($lnk, 'Remove auto-start shortcut')) {
            Remove-Item -LiteralPath $lnk -Force
        }
    }
    try {
        Initialize-SecIntelSchema
        Set-AppSetting -Name 'autostart.enabled' -Value 'false'
    } catch { }
    return [pscustomobject]@{ LnkPath = $lnk; Removed = (-not (Test-Path -LiteralPath $lnk)) }
}

# Files are dot-sourced; Export-ModuleMember would fail outside a module context.
