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

# SIG # Begin signature block
# MIIcCwYJKoZIhvcNAQcCoIIb/DCCG/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDcgAcRvrgSGpg2
# /pn8f4HGudIScHWDsVfdc/iBb7UXqqCCFlAwggMSMIIB+qADAgECAhAtZQe+Ow97
# nknyVZUnzOU8MA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMMFkJyeWNlIFNPQyBD
# b2RlIFNpZ25pbmcwHhcNMjYwNDI5MTcxNzUwWhcNMzEwNDI5MTcyNzUxWjAhMR8w
# HQYDVQQDDBZCcnljZSBTT0MgQ29kZSBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEA3Oe6H+5W3DedBqU2kgW2FbDpJxacLR8tKrO+UgnFWcfe
# JTWv1bxs20yw8WNVkt3oHEjsyk9MZwIjvTfZbtyobU7UU1dSKHPhZT0pBWPenuCf
# EHef25jHGma52Iiyoh06U5Tb51e0TQx7eMF4DQbxfNMZbLFZL1ZIN2/bMHLikeJj
# +nzz606QDzfFjlAA0liD1WlTiK7wFclEd6yY2GwSCWBSIn6ZeyfQvHPRHMgwjmfK
# AYRVEA9WkpSRaTnWX15QWjn1iHxEJ8IeS4274cU369gWsxgFIvKCVdb3I+5eMBcy
# n//v3SF8uhJ6OtJipttmpNAvyf10N/QOnWu4CDzL9QIDAQABo0YwRDAOBgNVHQ8B
# Af8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFOAL/6bNQwxH
# 3Ir4b9IWNhfKv0dtMA0GCSqGSIb3DQEBCwUAA4IBAQAAePrK/7n1mnXEVikJrfFG
# Hm+MNL6LwrJPt1bLNiZDkG4AUHm0nLiGgSJSe/YpAAbXAamxfJtEWyZI1je8z+TW
# Adle3BHKJ4fttXffhvNoXZjbdq0LQDwehEtHROC1j4pshXmF9Y3NyTfuR31u7Bqp
# HU+x0WBvdIyHcDO8cm8clnZobNM9ASRHj3i3Kb2Bsgz+txIkgeEvor7oTBO9ubMI
# a9+nw1WOGk9K/IukfinUTyrO7hVG14YP9SkuCj75G6SfO4t4GSe8qMbcpB0jdqNt
# lrx2N4LKVH0Xi2BzK9NcLFnprfS4oXmO1GsTDKXQyocHSAthXEGNUpE5HfKVz5dm
# MIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBl
# MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
# d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
# b3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7J
# IT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxS
# D1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb
# 7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1ef
# VFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoY
# OAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSa
# M0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI
# 8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9L
# BADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfm
# Q6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDr
# McXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15Gkv
# mB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
# FgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGL
# p6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
# Y3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0G
# CSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6p
# Grsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1W
# z/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp
# 8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38dglo
# hJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8S
# uFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGtDCCBJygAwIBAgIQ
# DcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEV
# MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
# MSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAw
# MDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0
# YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaD
# LFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1
# +JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh
# /AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpL
# tlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8
# BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMv
# aB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL
# 6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/
# q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb
# 1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVF
# JfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MC
# AwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp
# 5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9P
# MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcB
# AQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggr
# BgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+
# Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNq
# hCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLery
# cvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26M
# HvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjat
# VB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPS
# egOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI
# 7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4Y
# tL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/
# wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch
# 28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQ
# D7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCCBu0wggTVoAMCAQICEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRp
# bWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNTA2MDQwMDAw
# MDBaFw0zNjA5MDMyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYgVGlt
# ZXN0YW1wIFJlc3BvbmRlciAyMDI1IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDQRqwtEsae0OquYFazK1e6b1H/hnAKAd/KN8wZQjBjMqiZ3xTWcfsL
# wOvRxUwXcGx8AUjni6bz52fGTfr6PHRNv6T7zsf1Y/E3IU8kgNkeECqVQ+3bzWYe
# sFtkepErvUSbf+EIYLkrLKd6qJnuzK8Vcn0DvbDMemQFoxQ2Dsw4vEjoT1FpS54d
# NApZfKY61HAldytxNM89PZXUP/5wWWURK+IfxiOg8W9lKMqzdIo7VA1R0V3Zp3Dj
# jANwqAf4lEkTlCDQ0/fKJLKLkzGBTpx6EYevvOi7XOc4zyh1uSqgr6UnbksIcFJq
# LbkIXIPbcNmA98Oskkkrvt6lPAw/p4oDSRZreiwB7x9ykrjS6GS3NR39iTTFS+EN
# TqW8m6THuOmHHjQNC3zbJ6nJ6SXiLSvw4Smz8U07hqF+8CTXaETkVWz0dVVZw7kn
# h1WZXOLHgDvundrAtuvz0D3T+dYaNcwafsVCGZKUhQPL1naFKBy1p6llN3QgshRt
# a6Eq4B40h5avMcpi54wm0i2ePZD5pPIssoszQyF4//3DoK2O65Uck5Wggn8O2klE
# TsJ7u8xEehGifgJYi+6I03UuT1j7FnrqVrOzaQoVJOeeStPeldYRNMmSF3voIgMF
# tNGh86w3ISHNm0IaadCKCkUe2LnwJKa8TIlwCUNVwppwn4D3/Pt5pwIDAQABo4IB
# lTCCAZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU5Dv88jHt/f3X85FxYxlQQ89h
# jOgwHwYDVR0jBBgwFoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQD
# AgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCBhTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAC
# hlFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRU
# aW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBU
# oFKgUIZOaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcw
# CAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAZSqt8Rwn
# BLmuYEHs0QhEnmNAciH45PYiT9s1i6UKtW+FERp8FgXRGQ/YAavXzWjZhY+hIfP2
# JkQ38U+wtJPBVBajYfrbIYG+Dui4I4PCvHpQuPqFgqp1PzC/ZRX4pvP/ciZmUnth
# fAEP1HShTrY+2DE5qjzvZs7JIIgt0GCFD9ktx0LxxtRQ7vllKluHWiKk6FxRPyUP
# xAAYH2Vy1lNM4kzekd8oEARzFAWgeW3az2xejEWLNN4eKGxDJ8WDl/FQUSntbjZ8
# 0FU3i54tpx5F/0Kr15zW/mJAxZMVBrTE2oi0fcI8VMbtoRAmaaslNXdCG1+lqvP4
# FbrQ6IwSBXkZagHLhFU9HCrG/syTRLLhAezu/3Lr00GrJzPQFnCEH1Y58678Igmf
# ORBPC1JKkYaEt2OdDh4GmO0/5cHelAK2/gTlQJINqDr6JfwyYHXSd+V08X1JUPvB
# 4ILfJdmL+66Gp3CSBXG6IwXMZUXBhtCyIaehr0XkBoDIGMUG1dUtwq1qmcwbdUfc
# SYCn+OwncVUXf53VJUNOaMWMts0VlRYxe5nK+At+DI96HAlXHAL5SlfYxJ7La54i
# 71McVWRP66bW+yERNpbJCjyCYG2j+bdpxo/1Cy4uPcU3AWVPGrbn5PhDBf3Frogu
# zzhk++ami+r3Qrx5bIbY3TVzgiFI7Gq3zWcxggURMIIFDQIBATA1MCExHzAdBgNV
# BAMMFkJyeWNlIFNPQyBDb2RlIFNpZ25pbmcCEC1lB747D3ueSfJVlSfM5TwwDQYJ
# YIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQgkJuBI2lX/9uIvNzNmKs+NTvwkfV9idDRswPGOr++
# bCIwDQYJKoZIhvcNAQEBBQAEggEAGrLGTDnhQlkEKgys1l2/FrB/k7+tLAmcV1b7
# SJcrvUUfNvW2HhIkCyLbkneqrjDVmTtRimCteLIiHjH4OnKFpS9E7dzA8wnJaox0
# EWKQWT0vbC91ViTvES2ozSebTt/1G46bT/8+lxOLcQJPgofmelJZ+Oc6R3a9WegA
# H1E6kq9FlM3GDMRnGj2whX/2IapSFEllTXXjAzegOZWTd74OuX8PW3TmS9oeQQZD
# tloJ2mySQIrphz0pqEDN72IjNYqGOph6/wLVN4itzMYBeucwIBZuZ2IgQs8HNN1C
# 7TkG/ioofJ01E5LYZZOIIROKZ2Omcl2cBoRRIKJVJD+/Fu0136GCAyYwggMiBgkq
# hkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeV
# dGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0yNjA0MjkxNzI5MjdaMC8GCSqGSIb3DQEJBDEiBCCONjXm
# ghN2Y4OiE3x9Yc/KmaG9VsdxbkS8VZ/28EYc2TANBgkqhkiG9w0BAQEFAASCAgBc
# 6EGjv5vVFauOTS2NZcAQFBfXsPt1MbbSFOWWV3QfAsND4gx87SToOkgTIhF/a5wA
# vMV74tdwWuJ0zLod+zsuo4qPy6CjCjDwT+UCCMm8aImBqPd/XHzN6/uij6xvC3pJ
# 1mDjavEItS2bIlAVb5WYzbjnT+2gkS1pPP3rnHbEsvuYmUf8jlsbsEznJLUfZGpO
# ZcN7evJJ5+NJuAO3lMywJTlk+qDzpG7R/vDICvGrjc5UAxmLuXxh8TlWkglUQ8yF
# 4vXD9pngW7uH+f9zbvKM4cqV/NZ7Joc4/VNl+8sweFTa7kICcE31v7YKH7klB67L
# Ue542FbR6yQImy6fxbDwDWJt2jNh7TdzXonAaph1GHEiLe5HRyEYn8Oq4aIbwAzy
# EEM3Pd9dWpRYzm28rAmoXur/WHvEwR+f+I/A826zHKGbLK3Q6r6Q1WcM+XeWFTVP
# YLAEDzm6LxtUWPiISlJUHlexbE9AQ+9vcXvHy5Ci4AhYkg4JbN1GvOTRJPWkAicN
# HR196qEbRIJzTCSY8MZvdjLIHaMXLB5FEvJO7V39JFdHhcTx7WBvWtVQUvKfiiAz
# 3bW8sOaIWi1C8F9UzIfpLZFnvIDvkAoSrGWwmJVjBWYmselTpzMQWYDP/51GY0ke
# rb55J+pWZVLVPgtoiCzRccLfWycvNrPvDlYlJEtjYg==
# SIG # End signature block
