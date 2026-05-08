<#
.SYNOPSIS
    Orchestrates auto-refresh of SecIntel threat-intel feeds at dashboard
    launch. Two-wave runspace fan-out keeps the WPF UI interactive while
    feeds download in the background.

.DESCRIPTION
    Wave 1 (parallel): CISA KEV + FIRST.org EPSS - both write to disjoint
    tables, so concurrent runs don't block each other on SQLite.
    Wave 2 (sequential after Wave 1): NVD CVE -> MITRE ATT&CK STIX bundle.
    The CVE update writes back into CVEs.* before the EPSS daemon would
    benefit from it; running Wave 1 first means EPSS scores attach to
    the prior day's CVEs, which is acceptable - EPSS is enrichment, not
    a feed expansion.

    Per-feed TTL gates skip refreshes that ran recently. Defaults match
    upstream cadence:
        kev   : 24h   (CISA publishes daily)
        nvd   : 24h   (modStartDate window is 30d, but we don't need >1/d)
        epss  : 12h   (Cyentia drops fresh scores nightly UTC)
        mitre : 168h  (STIX bundle is large, changes infrequently)

    Override per-feed via AppSettings keys:
        feed.kev.ttlhours, feed.nvd.ttlhours, feed.epss.ttlhours, feed.mitre.ttlhours
    Disable orchestrator entirely:
        feed.autorefresh.enabled=false

    Status callbacks fire on the WPF dispatcher thread so callers can
    update bound ObservableCollections directly.

.NOTES
    Dot-source SecIntel.Schema.ps1 + SecIntel.Settings.ps1 first.
#>

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.Settings.ps1')

# ============================================================
# Default TTLs (hours). Override via AppSettings keys
# feed.<key>.ttlhours.
# ============================================================
$script:FeedDefaultTtl = @{
    kev   = 24
    nvd   = 24
    epss  = 12
    mitre = 168
}

# ============================================================
# Per-feed dispatch metadata. Each entry maps the user-facing
# key to the script + args used to refresh it, and the FeedMeta
# row name the underlying script writes (so we can read back
# the post-run timestamp / record count).
# ============================================================
$script:FeedDefinitions = [ordered]@{
    kev = @{
        DisplayName  = 'CISA KEV'
        Script       = 'Update-CveKevFeed.ps1'
        Arguments    = @{ SkipCves = $true }
        FeedMetaName = 'KEV'
        Wave         = 1
    }
    epss = @{
        DisplayName  = 'EPSS scores'
        Script       = 'Update-EpssFeed.ps1'
        # We already gate via TTL; -Force here just bypasses the script's
        # internal MaxAgeHours skip, which would otherwise short-circuit.
        Arguments    = @{ Force = $true }
        FeedMetaName = 'EPSS'
        Wave         = 1
    }
    nvd = @{
        DisplayName  = 'NVD CVE'
        Script       = 'Update-CveKevFeed.ps1'
        Arguments    = @{ SkipKevs = $true }
        FeedMetaName = 'CVEs'
        Wave         = 2
    }
    mitre = @{
        DisplayName  = 'MITRE ATT&CK'
        Script       = 'MitreAttackExplorer.ps1'
        Arguments    = @{ Update = $true; NoGui = $true }
        FeedMetaName = 'MITRE'
        Wave         = 2
    }
}

function Get-FeedTtlHours {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FeedKey)
    $setting = Get-AppSetting -Name "feed.$FeedKey.ttlhours" -Default $null
    if ($setting) {
        $parsed = 0
        if ([int]::TryParse([string]$setting, [ref]$parsed) -and $parsed -gt 0) {
            return $parsed
        }
    }
    return $script:FeedDefaultTtl[$FeedKey]
}

function Test-FeedTtlExpired {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FeedKey)
    $def = $script:FeedDefinitions[$FeedKey]
    if (-not $def) { return $true }
    $row = Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "SELECT LastUpdated FROM FeedMeta WHERE FeedName=@n" `
        -SqlParameters @{ n = $def.FeedMetaName } | Select-Object -First 1
    if (-not $row -or -not $row.LastUpdated) { return $true }
    try {
        $lastUtc = [DateTime]::Parse($row.LastUpdated).ToUniversalTime()
        $ageHrs  = ((Get-Date).ToUniversalTime() - $lastUtc).TotalHours
        return $ageHrs -ge (Get-FeedTtlHours -FeedKey $FeedKey)
    } catch {
        return $true
    }
}

function Get-FeedStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FeedKey)
    $def = $script:FeedDefinitions[$FeedKey]
    if (-not $def) { return $null }
    $row = Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "SELECT LastUpdated, RecordCount FROM FeedMeta WHERE FeedName=@n" `
        -SqlParameters @{ n = $def.FeedMetaName } | Select-Object -First 1
    [pscustomobject]@{
        FeedKey      = $FeedKey
        DisplayName  = $def.DisplayName
        LastUpdated  = if ($row) { $row.LastUpdated } else { $null }
        RecordCount  = if ($row) { $row.RecordCount } else { $null }
        TtlHours     = Get-FeedTtlHours -FeedKey $FeedKey
        Wave         = $def.Wave
        State        = $null
        Message      = $null
        DurationSec  = $null
    }
}

# ============================================================
# Inner runspace body. Dot-sources the target script (each
# script bootstraps schema + dependencies on its own) and
# splats the args. Returns @{ Success; ErrorMessage; DurationSec }.
# ============================================================
$script:FeedRunInner = {
    param($modulesDir, $scriptName, $argsHashTable)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $scriptFull = Join-Path $modulesDir $scriptName
        & $scriptFull @argsHashTable | Out-Null
        $sw.Stop()
        return @{
            Success      = $true
            ErrorMessage = $null
            DurationSec  = [int]$sw.Elapsed.TotalSeconds
        }
    } catch {
        $sw.Stop()
        return @{
            Success      = $false
            ErrorMessage = $_.Exception.Message
            DurationSec  = [int]$sw.Elapsed.TotalSeconds
        }
    }
}

# ============================================================
# Main entry point. Window must be the WPF Window so we can
# marshal status updates onto the UI thread.
# ============================================================
function Start-FeedRefresh {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Window,
        [Parameter(Mandatory)][string]$ModulesDir,
        [string[]]$Feeds = @('kev','epss','nvd','mitre'),
        [switch]$Force,
        # Invoked on the dispatcher thread for each FeedStatus update.
        # Args: a single PSCustomObject with FeedKey/DisplayName/State/Message/etc.
        [scriptblock]$OnStatusUpdate
    )

    # Master kill-switch.
    $enabled = Get-AppSetting -Name 'feed.autorefresh.enabled' -Default 'true'
    if (-not $Force -and ($enabled -eq 'false' -or $enabled -eq '0')) {
        if ($OnStatusUpdate) {
            & $OnStatusUpdate ([pscustomobject]@{
                FeedKey      = '_orchestrator'
                DisplayName  = 'Auto-refresh'
                State        = 'disabled'
                Message      = 'feed.autorefresh.enabled=false in AppSettings'
            })
        }
        return
    }

    # TTL filter.
    $toRefresh = @()
    $skipped   = @()
    foreach ($f in $Feeds) {
        if (-not $script:FeedDefinitions.Contains($f)) {
            Write-Warning "Unknown feed key '$f' - skipping."
            continue
        }
        if ($Force -or (Test-FeedTtlExpired -FeedKey $f)) { $toRefresh += $f }
        else { $skipped += $f }
    }

    foreach ($f in $skipped) {
        if ($OnStatusUpdate) {
            $st = Get-FeedStatus -FeedKey $f
            $st.State   = 'skipped'
            $st.Message = "within TTL ({0}h since last refresh)" -f $st.TtlHours
            & $OnStatusUpdate $st
        }
    }
    if (-not $toRefresh) {
        if ($OnStatusUpdate) {
            & $OnStatusUpdate ([pscustomobject]@{
                FeedKey     = '_orchestrator'
                DisplayName = 'Auto-refresh'
                State       = 'done'
                Message     = 'all feeds within TTL; no work to do'
            })
        }
        return
    }

    $wave1 = @($toRefresh | Where-Object { $script:FeedDefinitions[$_].Wave -eq 1 })
    $wave2 = @($toRefresh | Where-Object { $script:FeedDefinitions[$_].Wave -eq 2 })

    # Shared mutable state for the timer closure. Hashtable is a
    # reference type so writes inside the closure are visible outside.
    $state = @{
        Wave1            = $wave1
        Wave2            = $wave2
        Wave2Started     = $false
        ModulesDir       = $ModulesDir
        Definitions      = $script:FeedDefinitions
        Inner            = $script:FeedRunInner
        Dispatcher       = $Window.Dispatcher
        Callback         = $OnStatusUpdate
        Handles          = New-Object System.Collections.Generic.List[object]
        Pool             = $null
        Timer            = $null
    }

    $iss   = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $maxRs = [Math]::Max(2, ($wave1.Count + $wave2.Count))
    $state.Pool = [runspacefactory]::CreateRunspacePool(1, $maxRs, $iss, $Host)
    $state.Pool.Open()

    # Helper: kick off one feed in a runspace. Closes over $state.
    $startFeed = {
        param($key)
        $def = $state.Definitions[$key]

        if ($state.Callback) {
            $startMsg = [pscustomobject]@{
                FeedKey     = $key
                DisplayName = $def.DisplayName
                State       = 'running'
                Message     = 'downloading...'
                Wave        = $def.Wave
                StartedAt   = (Get-Date)
            }
            $state.Dispatcher.Invoke([action]{ & $state.Callback $startMsg }) | Out-Null
        }

        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $state.Pool
        [void]$ps.AddScript($state.Inner)
        [void]$ps.AddArgument($state.ModulesDir)
        [void]$ps.AddArgument($def.Script)
        [void]$ps.AddArgument($def.Arguments)
        $async = $ps.BeginInvoke()
        $state.Handles.Add(@{ Key=$key; Ps=$ps; Async=$async; StartedAt=(Get-Date) })
    }.GetNewClosure()

    foreach ($k in $wave1) { & $startFeed $k }

    # If Wave 1 was empty (everything within TTL there but Wave 2 needs work),
    # kick Wave 2 directly so the timer doesn't spin on an empty handle list.
    if ($wave1.Count -eq 0 -and $wave2.Count -gt 0) {
        $state.Wave2Started = $true
        foreach ($k in $wave2) { & $startFeed $k }
    }

    # Poll completions on the UI thread. 500ms is responsive enough that
    # the user sees per-feed transitions live; cheap on the timer queue.
    $state.Timer = New-Object System.Windows.Threading.DispatcherTimer
    $state.Timer.Interval = [TimeSpan]::FromMilliseconds(500)
    $state.Timer.Add_Tick({
        $stillRunning = 0
        for ($i = $state.Handles.Count - 1; $i -ge 0; $i--) {
            $h = $state.Handles[$i]
            if ($h.Async.IsCompleted) {
                $r = $null
                try {
                    $rows = $h.Ps.EndInvoke($h.Async)
                    $r = $rows | Select-Object -Last 1
                } catch {
                    $r = @{ Success=$false; ErrorMessage=$_.Exception.Message; DurationSec=0 }
                }
                $h.Ps.Dispose()
                $state.Handles.RemoveAt($i)

                if ($state.Callback) {
                    $final = Get-FeedStatus -FeedKey $h.Key
                    if ($r -and $r.Success) {
                        $final.State       = 'completed'
                        $final.Message     = 'done in {0}s' -f $r.DurationSec
                        $final.DurationSec = $r.DurationSec
                    } else {
                        $final.State       = 'error'
                        $final.Message     = if ($r) { $r.ErrorMessage } else { 'unknown error' }
                        $final.DurationSec = if ($r) { $r.DurationSec } else { 0 }
                    }
                    & $state.Callback $final
                }
            } else {
                $stillRunning++
            }
        }

        # Wave 2 kickoff once Wave 1 drains.
        if ($stillRunning -eq 0 -and -not $state.Wave2Started -and $state.Wave2.Count -gt 0) {
            $state.Wave2Started = $true
            foreach ($k in $state.Wave2) { & $startFeed $k }
            return
        }

        if ($stillRunning -eq 0 -and ($state.Wave2Started -or $state.Wave2.Count -eq 0)) {
            $state.Timer.Stop()
            try { $state.Pool.Close(); $state.Pool.Dispose() } catch { }
            if ($state.Callback) {
                & $state.Callback ([pscustomobject]@{
                    FeedKey     = '_orchestrator'
                    DisplayName = 'Auto-refresh'
                    State       = 'done'
                    Message     = 'all feeds processed'
                })
            }
        }
    }.GetNewClosure())
    $state.Timer.Start()
}

# Files are dot-sourced; Export-ModuleMember would fail outside a module context.
