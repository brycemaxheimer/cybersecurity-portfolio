<#
    Build-LargeDataset.ps1
    ----------------------
    Generates the "Expanded" CSV pack for /lab/ playground -- ~10 MB total,
    storyline-anchored, includes the small dataset's storyline beats VERBATIM
    so any query that worked against /kql/data/ returns a SUPERSET when run
    against /kql/data-large/.

    Run from the repo root:
        pwsh ./kql/data-large/Build-LargeDataset.ps1

    Targets (rough):
        SecurityEvent          ~8000 rows
        DeviceProcessEvents   ~12000
        DeviceLogonEvents      ~3000
        DeviceNetworkEvents    ~6000
        DeviceFileEvents       ~4000
        Syslog                 ~4000
        AuditLogs              ~1500
        SigninLogs             ~2500
        SecurityIncident         200
        CommonSecurityLog      ~5000
        (others)              ~1000-2000 each

    Storyline anchor: 2026-04-29T13:52:40Z (matches gold-results.json).
    The expanded set spans ~14 days back from the anchor.

    Layered storylines (write the table-specific generators to weave these in):
        1. The original brute-force-then-success on WS-FINANCE-01 (existing
           small-set rows kept verbatim).
        2. Slow-drip password spray from 198.51.100.55 hitting 4 accounts over
           18 hours.
        3. Hands-on-keyboard from CORP\dchen on WS-DEV-02 (mimikatz, rubeus,
           encoded PowerShell, beacon-shaped DNS).
        4. Phishing-link click chain on WS-HR-03: Outlook -> chrome.exe ->
           winword.exe -> EncodedCommand.
        5. Background noise: cron jobs, normal interactive logons, browser
           network calls, scheduled-task creates, log rotates.
#>

[CmdletBinding()]
param(
    [string]$SmallDataDir   = (Join-Path $PSScriptRoot '..' 'data'),
    [string]$OutputDir      = $PSScriptRoot,
    [datetime]$Anchor       = '2026-04-29T13:52:40Z',
    [int]$WindowDays        = 14,
    [int]$MaxRowsPerTable   = 12000,
    [switch]$SeedFromExisting = $true
)

$ErrorActionPreference = 'Stop'
$rng = [System.Random]::new(42)   # deterministic; bump seed if you want fresh noise

function Write-Csv {
    param(
        [string]$Path,
        [string]$Header,
        [string[]]$Rows
    )
    Set-Content -Path $Path -Value $Header -Encoding UTF8
    Add-Content -Path $Path -Value $Rows -Encoding UTF8
    Write-Host ("  wrote {0,-32}  {1,8} rows" -f (Split-Path $Path -Leaf), $Rows.Count)
}

function New-NoiseTimestamp {
    param([datetime]$Anchor, [int]$WindowDays)
    # Skewed -- 60% of noise lands in the last 24h around the anchor, 40% across
    # the broader window. That mimics real SOC volume curves where today is
    # always denser than two weeks ago.
    $r = $rng.NextDouble()
    if ($r -lt 0.6) {
        $secs = $rng.Next(-86400, 86400)
    } else {
        $secs = $rng.Next(-86400 * $WindowDays, -86400)
    }
    return $Anchor.AddSeconds($secs).ToUniversalTime()
}

function To-IsoZ { param([datetime]$Dt) $Dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }

# ------------------------------------------------------------
# Per-table generators. Each receives the small CSV (verbatim
# rows kept) and produces the expanded CSV.
# Fill in the body with table-specific noise. Skeletons below.
# ------------------------------------------------------------

function Build-SecurityEvent {
    param([string]$smallPath, [string]$outPath)
    # TODO: Layer in spray rows (4625), normal logons (4624), service installs
    # (4697), and process audit (4688). Aim for ~8000 rows.
    Copy-Item $smallPath $outPath -Force
    Write-Host "  TODO: SecurityEvent expansion -- copied small-set verbatim for now"
}

function Build-DeviceProcessEvents {
    param([string]$smallPath, [string]$outPath)
    # TODO: Background process noise (svchost, chrome, code.exe), with
    # storyline mimikatz/rubeus rows kept. Target ~12000 rows.
    Copy-Item $smallPath $outPath -Force
    Write-Host "  TODO: DeviceProcessEvents expansion -- copied small-set verbatim for now"
}

function Build-DeviceLogonEvents {
    param([string]$smallPath, [string]$outPath)
    # TODO: Normal interactive logons across ~10 hosts; keep storyline rows.
    Copy-Item $smallPath $outPath -Force
    Write-Host "  TODO: DeviceLogonEvents expansion -- copied small-set verbatim for now"
}

function Build-DeviceNetworkEvents {
    param([string]$smallPath, [string]$outPath)
    # TODO: Browser noise (HTTPS to public IPs/domains); keep storyline rows.
    Copy-Item $smallPath $outPath -Force
    Write-Host "  TODO: DeviceNetworkEvents expansion -- copied small-set verbatim for now"
}

function Build-DeviceFileEvents {
    param([string]$smallPath, [string]$outPath)
    Copy-Item $smallPath $outPath -Force
    Write-Host "  TODO: DeviceFileEvents expansion -- copied small-set verbatim for now"
}

function Build-Syslog {
    param([string]$smallPath, [string]$outPath)
    # TODO: Cron noise, normal sshd-session logins, package update lines.
    Copy-Item $smallPath $outPath -Force
    Write-Host "  TODO: Syslog expansion -- copied small-set verbatim for now"
}

function Build-AuditLogs                { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: AuditLogs"                 }
function Build-SigninLogs               { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: SigninLogs"                }
function Build-SecurityIncident         { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: SecurityIncident"          }
function Build-CommonSecurityLog        { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: CommonSecurityLog"         }
function Build-DHCP                     { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: DHCP"                      }
function Build-DeviceImageLoadEvents    { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: DeviceImageLoadEvents"     }
function Build-DeviceNetworkInfo        { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: DeviceNetworkInfo"         }
function Build-DeviceRegistryEvents     { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: DeviceRegistryEvents"      }
function Build-SecurityAlert            { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: SecurityAlert"             }
function Build-W3CIISLog                { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: W3CIISLog"                 }

# ------------------------------------------------------------
# Drive: discover every table in the small set and dispatch.
# ------------------------------------------------------------

Write-Host "Build-LargeDataset.ps1"
Write-Host "  small data:  $SmallDataDir"
Write-Host "  output:      $OutputDir"
Write-Host "  anchor:      $(To-IsoZ $Anchor)"
Write-Host "  window:      $WindowDays days"
Write-Host ""

$tables = Get-ChildItem $SmallDataDir -Filter '*.csv' | Sort-Object Name
foreach ($t in $tables) {
    $name = [System.IO.Path]::GetFileNameWithoutExtension($t.Name)
    $smallPath = $t.FullName
    $outPath = Join-Path $OutputDir $t.Name
    $fn = Get-Command "Build-$name" -ErrorAction SilentlyContinue
    if ($fn) {
        & $fn $smallPath $outPath
    } else {
        Copy-Item $smallPath $outPath -Force
        Write-Host "  no Build-$name function defined -- copied small-set verbatim"
    }
}

Write-Host ""
Write-Host "Done. Browse to /kql/ and switch the Dataset toggle to 'Expanded' to load."
