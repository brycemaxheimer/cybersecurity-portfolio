<#
.SYNOPSIS
    Generate a standalone HTML daily intel brief from the SecIntel DB.

.DESCRIPTION
    Outputs a single-file HTML report (dark mode, no external deps, air-gap
    safe) that summarizes:
        - Feed health (when each feed last refreshed, record counts)
        - Newest KEVs since last brief
        - Ransomware-linked KEVs in the window
        - Priority CVEs ranked by CVSS x EPSS-percentile
        - KPI tiles up top

    Uses AppSettings 'lastseen.kev' / 'lastseen.cve' to diff against the
    previous run. Markers update after the report is written so each brief
    only shows what's new.

    Aesthetic matches the SOC Dashboard (#0D1117 / #58A6FF / Consolas).

.PARAMETER OutputPath
    Where to write the HTML. Defaults to %USERPROFILE%\SecIntel\daily_brief_YYYY-MM-DD.html.

.PARAMETER Open
    Launch the file in the default browser after generation.

.PARAMETER ResetLastSeen
    Wipe lastseen markers so the brief includes everything (useful on first run).

.EXAMPLE
    .\SecIntel.DailyBrief.ps1 -Open

.EXAMPLE
    .\SecIntel.DailyBrief.ps1 -ResetLastSeen -Open
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $env:USERPROFILE "SecIntel\daily_brief_$(Get-Date -Format 'yyyy-MM-dd').html"),
    [switch]$Open,
    [switch]$ResetLastSeen
)

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.Settings.ps1')
Ensure-PSSQLite
Initialize-SecIntelSchema

$ErrorActionPreference = 'Stop'

if ($ResetLastSeen) {
    Remove-AppSetting 'lastseen.kev'
    Remove-AppSetting 'lastseen.cve'
    Write-Host "Reset last-seen markers." -ForegroundColor DarkYellow
}

$lastKev = Get-AppSetting 'lastseen.kev' '1970-01-01T00:00:00Z'
$lastCve = Get-AppSetting 'lastseen.cve' '1970-01-01T00:00:00Z'
$db      = $script:DbPath

# ---------- Pull data ----------
$feeds = Invoke-SqliteQuery -DataSource $db -Query "SELECT FeedName, LastUpdated, RecordCount FROM FeedMeta ORDER BY FeedName"

$newKevs = Invoke-SqliteQuery -DataSource $db `
    -Query "SELECT * FROM KEVs WHERE DateAdded > @t ORDER BY DateAdded DESC LIMIT 50" `
    -SqlParameters @{ t = $lastKev }

$ransom = Invoke-SqliteQuery -DataSource $db `
    -Query "SELECT * FROM KEVs WHERE KnownRansomware = 'Known' AND DateAdded > @t ORDER BY DateAdded DESC LIMIT 25" `
    -SqlParameters @{ t = $lastKev }

# Combined risk score: CVSS x EPSS percentile if EPSS present, else CVSS halved
$priorityCves = Invoke-SqliteQuery -DataSource $db -Query @"
SELECT CveId, CvssScore, EpssScore, EpssPercentile, Severity, Published,
       substr(Description, 1, 220) AS Snippet,
       CASE WHEN EpssPercentile IS NOT NULL THEN CvssScore * EpssPercentile
            ELSE CvssScore * 0.5 END AS RiskScore
FROM CVEs
WHERE Published > @t AND CvssScore >= 7.0
ORDER BY RiskScore DESC
LIMIT 30
"@ -SqlParameters @{ t = $lastCve }

# KPIs
$totalKevs    = (Invoke-SqliteQuery -DataSource $db -Query "SELECT COUNT(*) AS C FROM KEVs").C
$totalCves    = (Invoke-SqliteQuery -DataSource $db -Query "SELECT COUNT(*) AS C FROM CVEs").C
$mappedCves   = (Invoke-SqliteQuery -DataSource $db -Query "SELECT COUNT(DISTINCT CveId) AS C FROM CveTechniqueMap").C
$cachedHashes = (Invoke-SqliteQuery -DataSource $db -Query "SELECT COUNT(*) AS C FROM HashIntel").C
$savedQueries = (Invoke-SqliteQuery -DataSource $db -Query "SELECT COUNT(*) AS C FROM KqlQueries").C
$iocCount     = (Invoke-SqliteQuery -DataSource $db -Query "SELECT COUNT(*) AS C FROM Iocs").C

# ---------- HTML helpers ----------
function _Esc {
    param([string]$S)
    if ($null -eq $S) { return '' }
    return ($S -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
}

function _Row { param([string[]]$cells) "<tr>" + (($cells | ForEach-Object { "<td>$(_Esc $_)</td>" }) -join '') + "</tr>" }

# ---------- Compose tables ----------
$feedRows = ($feeds | ForEach-Object {
    $age = '?'
    try { $age = "{0:N0}h" -f ((Get-Date) - [DateTime]::Parse($_.LastUpdated)).TotalHours } catch {}
    _Row @($_.FeedName, $_.LastUpdated, $age, "$($_.RecordCount)")
}) -join "`n"

$kevRows = ($newKevs | ForEach-Object {
    _Row @($_.DateAdded, $_.CveId, $_.VendorProject, $_.Product, $_.VulnName, $_.KnownRansomware)
}) -join "`n"

$ranRows = ($ransom | ForEach-Object {
    _Row @($_.DateAdded, $_.CveId, $_.VendorProject, $_.Product, $_.VulnName)
}) -join "`n"

$cveRows = ($priorityCves | ForEach-Object {
    $epssPct = if ($null -ne $_.EpssPercentile) { "{0:N1}%" -f ([double]$_.EpssPercentile * 100) } else { '-' }
    $risk    = "{0:N2}" -f [double]$_.RiskScore
    $cvss    = "{0:N1}" -f [double]$_.CvssScore
    _Row @($_.CveId, $cvss, $epssPct, $risk, $_.Severity, $_.Snippet)
}) -join "`n"

$generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

# ---------- HTML ----------
$ransomBlock = ''
if ($ransom.Count -gt 0) {
    $ransomBlock = @"
<h2 class="danger">RANSOMWARE-LINKED KEVS ($($ransom.Count))</h2>
<table>
<thead><tr><th>Date Added</th><th>CVE</th><th>Vendor</th><th>Product</th><th>Vulnerability</th></tr></thead>
<tbody>$ranRows</tbody>
</table>
"@
}

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>SecIntel Daily Brief - $generated</title>
<style>
:root {
    --bg:#0D1117; --bgalt:#161B22; --panel:#1C2128; --border:#30363D;
    --fg:#E6EDF3; --dim:#8B949E; --accent:#58A6FF; --green:#39D353;
    --warn:#FFA657; --danger:#FF6B6B;
}
* { box-sizing:border-box; }
body {
    margin:0; padding:32px;
    font-family:'Consolas','Cascadia Code','Courier New',monospace;
    background:var(--bg); color:var(--fg);
    font-size:13px; line-height:1.5;
}
h1 { color:var(--accent); font-size:22px; margin:0 0 4px 0;
     letter-spacing:1px; font-weight:700; }
h2 { color:var(--accent); font-size:13px; margin:32px 0 12px 0;
     padding-bottom:6px; border-bottom:1px solid var(--border);
     letter-spacing:1px; font-weight:700; text-transform:uppercase; }
h2.danger { color:var(--danger); border-bottom-color:var(--danger); }
.sub { color:var(--dim); font-size:11px; margin-bottom:24px; }
.kpis { display:grid; grid-template-columns:repeat(auto-fit, minmax(170px, 1fr));
        gap:14px; margin:0 0 24px 0; }
.kpi { background:var(--panel); border:1px solid var(--border);
       border-radius:6px; padding:14px 16px; }
.kpi-cap { color:var(--dim); font-size:10px; font-weight:700;
           letter-spacing:0.5px; text-transform:uppercase; }
.kpi-val { color:var(--accent); font-size:28px; font-weight:700;
           margin:6px 0 2px 0; }
.kpi-sub { color:var(--dim); font-size:10px; }
.warn   { color:var(--warn);   }
.danger { color:var(--danger); }
.green  { color:var(--green);  }
table { width:100%; border-collapse:collapse; margin:0 0 16px 0;
        background:var(--panel); border:1px solid var(--border);
        border-radius:4px; overflow:hidden; }
th { background:var(--bgalt); color:var(--accent); text-align:left;
     padding:10px 12px; font-size:11px;
     border-bottom:1px solid var(--border); letter-spacing:0.5px;
     text-transform:uppercase; }
td { padding:8px 12px; border-bottom:1px solid var(--border);
     font-size:12px; vertical-align:top; word-break:break-word; }
tr:last-child td { border-bottom:none; }
tr:hover td { background:var(--bgalt); }
.empty { color:var(--dim); font-style:italic; padding:14px 0;
         text-align:center; }
.footer { margin-top:48px; padding-top:16px; border-top:1px solid var(--border);
          color:var(--dim); font-size:10px; }
</style>
</head>
<body>
<h1>SecIntel Daily Brief</h1>
<div class="sub">Generated $generated &middot; window since KEV: $lastKev &middot; CVE: $lastCve</div>

<div class="kpis">
    <div class="kpi">
        <div class="kpi-cap">Total KEVs</div>
        <div class="kpi-val">$totalKevs</div>
        <div class="kpi-sub">CISA known-exploited</div>
    </div>
    <div class="kpi">
        <div class="kpi-cap">CVEs cached</div>
        <div class="kpi-val">$totalCves</div>
        <div class="kpi-sub">NVD recent window</div>
    </div>
    <div class="kpi">
        <div class="kpi-cap">CVE&rarr;ATT&amp;CK maps</div>
        <div class="kpi-val">$mappedCves</div>
        <div class="kpi-sub">distinct CVEs mapped</div>
    </div>
    <div class="kpi">
        <div class="kpi-cap">Hash lookups cached</div>
        <div class="kpi-val">$cachedHashes</div>
        <div class="kpi-sub">across all sources</div>
    </div>
    <div class="kpi">
        <div class="kpi-cap">IoCs stored</div>
        <div class="kpi-val">$iocCount</div>
        <div class="kpi-sub">structured indicators</div>
    </div>
    <div class="kpi">
        <div class="kpi-cap">Saved KQL queries</div>
        <div class="kpi-val">$savedQueries</div>
        <div class="kpi-sub">hunt library</div>
    </div>
</div>

<h2>Feed Health</h2>
<table>
<thead><tr><th>Feed</th><th>Last Updated</th><th>Age</th><th>Records</th></tr></thead>
<tbody>
$(if ($feedRows) { $feedRows } else { '<tr><td colspan="4" class="empty">No feed metadata yet</td></tr>' })
</tbody>
</table>

<h2>Newest KEVs since last brief ($($newKevs.Count))</h2>
<table>
<thead><tr><th>Date Added</th><th>CVE</th><th>Vendor</th><th>Product</th><th>Vulnerability</th><th>Ransomware</th></tr></thead>
<tbody>
$(if ($kevRows) { $kevRows } else { '<tr><td colspan="6" class="empty">No new KEVs since last brief</td></tr>' })
</tbody>
</table>

$ransomBlock

<h2>Priority CVEs (CVSS &times; EPSS-percentile, top 30)</h2>
<table>
<thead><tr><th>CVE</th><th>CVSS</th><th>EPSS pct</th><th>Risk</th><th>Severity</th><th>Description</th></tr></thead>
<tbody>
$(if ($cveRows) { $cveRows } else { '<tr><td colspan="6" class="empty">No new high-severity CVEs since last brief</td></tr>' })
</tbody>
</table>

<div class="footer">
SecIntel local DB: $(_Esc $db)<br/>
Generated by SecIntel.DailyBrief.ps1 &middot; standalone HTML, no external dependencies, air-gap safe
</div>
</body>
</html>
"@

# ---------- Write file ----------
$dir = Split-Path $OutputPath -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$html | Out-File -FilePath $OutputPath -Encoding UTF8

# ---------- Update last-seen markers ----------
$now = (Get-Date).ToString('o')
Set-AppSetting 'lastseen.kev' $now
Set-AppSetting 'lastseen.cve' $now

Write-Host "Daily brief written: $OutputPath" -ForegroundColor Green
Write-Host ("  {0} new KEV(s)  |  {1} ransomware-linked  |  {2} priority CVE(s)" -f $newKevs.Count, $ransom.Count, $priorityCves.Count) -ForegroundColor DarkGray

if ($Open) { Invoke-Item $OutputPath }