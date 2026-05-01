<#
.SYNOPSIS
    Refresh /lab/cve/data.json from the public CISA KEV catalog and FIRST EPSS feed.

.DESCRIPTION
    Pulls:
      - CISA Known Exploited Vulnerabilities catalog (JSON, ~1.5 MB)
      - FIRST.org daily EPSS scores (gzipped CSV, ~2 MB compressed; ~10 MB raw)

    Joins them on CVE ID, slims to the fields the browser uses, and rewrites
    /lab/cve/data.json. Idempotent - safe to run any time.

    Run from the repo root:
        pwsh ./refresh-feeds.ps1

    Then commit + push to deploy the refresh:
        git add lab/cve/data.json
        git commit -m "refresh CVE/KEV/EPSS feeds"
        git push

    Requires PowerShell 7+ for native gzip support.

.NOTES
    No API keys required. Both feeds are public, CC0-licensed.
    NVD CVSS scores are NOT pulled here because their API is rate-limited and
    the KEV catalog already includes enough metadata for browsing. If you want
    CVSS, get an NVD API key (free) and extend this script to fetch the
    /rest/json/cves/2.0?cveId=... endpoint per CVE.
#>

[CmdletBinding()]
param(
    [string] $OutPath = (Join-Path $PSScriptRoot 'lab/cve/data.json')
)

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "PowerShell 7+ is required (you have $($PSVersionTable.PSVersion)). Install from https://aka.ms/powershell"
}

$kevUrl  = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
$epssUrl = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz'

$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "refresh-feeds-$(Get-Date -Format yyyyMMddHHmmss)") -Force

try {
    # ---- Fetch ----
    Write-Host "Fetching KEV catalog..."
    $kevPath = Join-Path $tmp 'kev.json'
    Invoke-WebRequest -Uri $kevUrl -OutFile $kevPath -UseBasicParsing
    $kev = Get-Content -Raw -Path $kevPath | ConvertFrom-Json
    Write-Host ("  KEV entries: {0} (catalog version {1})" -f $kev.vulnerabilities.Count, $kev.catalogVersion)

    Write-Host "Fetching EPSS scores..."
    $epssGz = Join-Path $tmp 'epss.csv.gz'
    Invoke-WebRequest -Uri $epssUrl -OutFile $epssGz -UseBasicParsing
    $epssCsv = Join-Path $tmp 'epss.csv'

    # Decompress gzip
    $inStream  = [System.IO.File]::OpenRead($epssGz)
    $outStream = [System.IO.File]::Create($epssCsv)
    $gz        = New-Object System.IO.Compression.GzipStream $inStream, ([System.IO.Compression.CompressionMode]::Decompress)
    try { $gz.CopyTo($outStream) }
    finally { $gz.Dispose(); $outStream.Dispose(); $inStream.Dispose() }

    # ---- Parse EPSS CSV (skip first comment row) ----
    Write-Host "Building EPSS lookup..."
    $epssMap = @{}
    $lines = Get-Content -Path $epssCsv
    $epssDate = ''
    if ($lines.Count -gt 0 -and $lines[0] -match 'score_date:([^,]+)') {
        $epssDate = ($Matches[1] -split 'T')[0]
    }
    # Header row at index 1: cve,epss,percentile
    for ($i = 2; $i -lt $lines.Count; $i++) {
        $cols = $lines[$i] -split ','
        if ($cols.Count -ge 3) {
            $epssMap[$cols[0]] = @{
                score      = [double] $cols[1]
                percentile = [double] $cols[2]
            }
        }
    }
    Write-Host ("  EPSS scored CVEs: {0} (score date {1})" -f $epssMap.Count, $epssDate)

    # ---- Join + slim ----
    Write-Host "Slimming KEV + EPSS into combined record..."
    $records = foreach ($v in $kev.vulnerabilities) {
        $epss = $epssMap[$v.cveID]
        [PSCustomObject]@{
            id             = $v.cveID
            vendor         = $v.vendorProject
            product        = $v.product
            name           = $v.vulnerabilityName
            dateAdded      = $v.dateAdded
            description    = $v.shortDescription
            requiredAction = $v.requiredAction
            dueDate        = $v.dueDate
            ransomware     = ($v.knownRansomwareCampaignUse -eq 'Known')
            notes          = $v.notes
            cwes           = @($v.cwes)
            epss           = if ($epss) { $epss.score }      else { $null }
            epssPercentile = if ($epss) { $epss.percentile } else { $null }
        }
    }

    # Sort: most recently added first
    $sorted = $records | Sort-Object dateAdded -Descending

    $payload = [PSCustomObject]@{
        catalogVersion  = $kev.catalogVersion
        dateReleased    = $kev.dateReleased
        epssDate        = $epssDate
        refreshed       = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ').ToString()
        count           = $sorted.Count
        vulnerabilities = $sorted
    }

    # ---- Write ----
    $outDir = Split-Path -Parent $OutPath
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

    $json = $payload | ConvertTo-Json -Depth 6 -Compress
    Set-Content -Path $OutPath -Value $json -Encoding UTF8 -NoNewline

    $sizeKb = [Math]::Round((Get-Item $OutPath).Length / 1024, 1)
    Write-Host "OK: wrote $OutPath ($sizeKb KB, $($sorted.Count) entries)" -ForegroundColor Green

} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Next: review the diff, commit, push:" -ForegroundColor Cyan
Write-Host "  git add lab/cve/data.json"
Write-Host "  git commit -m 'refresh CVE/KEV/EPSS feeds'"
Write-Host "  git push"
