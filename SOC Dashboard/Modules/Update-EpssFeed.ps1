<#
.SYNOPSIS
    Update EPSS scores on the CVEs table from the FIRST.org daily feed.

.DESCRIPTION
    Downloads the daily EPSS scores CSV (gzip) and updates the EpssScore,
    EpssPercentile, and EpssDate columns on rows already in the CVEs table.

    This is enrichment, not a feed expansion - it only updates CVEs you've
    already cached via Update-CveKevFeed.ps1. Run after that script to
    keep prioritization current.

    EPSS = Exploit Prediction Scoring System. Score is the probability
    a CVE will be exploited in the next 30 days. Percentile is rank
    within all CVEs. Combine with CVSS for "how bad x how likely":
        SELECT CveId, CvssScore, EpssPercentile,
               CvssScore * EpssPercentile AS RiskScore
        FROM CVEs
        ORDER BY RiskScore DESC

.PARAMETER FeedUrl
    Override the EPSS feed URL. Defaults to FIRST/Cyentia daily scores.
    If the host has changed, set this to the new URL.

.PARAMETER MaxAgeHours
    Skip update if FeedMeta says EPSS was fetched less than this many
    hours ago. Default 12.
#>

[CmdletBinding()]
param(
    [string]$FeedUrl     = 'https://epss.cyentia.com/epss_scores-current.csv.gz',
    [int]   $MaxAgeHours = 12,
    [switch]$Force
)

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
Ensure-PSSQLite
Initialize-SecIntelSchema

$ErrorActionPreference = 'Stop'

# ---------- Skip if recent ----------
if (-not $Force) {
    $meta = Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "SELECT LastUpdated FROM FeedMeta WHERE FeedName='EPSS'" | Select-Object -First 1
    if ($meta.LastUpdated) {
        try {
            $age = ((Get-Date) - [DateTime]::Parse($meta.LastUpdated)).TotalHours
            if ($age -lt $MaxAgeHours) {
                Write-Host "EPSS feed last updated $([int]$age)h ago. Skipping (use -Force to override)." -ForegroundColor Yellow
                return
            }
        } catch {}
    }
}

# ---------- Download + decompress ----------
Write-Host "Downloading EPSS feed: $FeedUrl" -ForegroundColor Cyan
$tmpGz  = Join-Path $env:TEMP "epss_$([guid]::NewGuid()).csv.gz"
$tmpCsv = Join-Path $env:TEMP "epss_$([guid]::NewGuid()).csv"

try {
    Invoke-WebRequest -Uri $FeedUrl -OutFile $tmpGz -UseBasicParsing
    Write-Host ("Downloaded {0:N1} KB" -f ((Get-Item $tmpGz).Length / 1KB)) -ForegroundColor DarkGray

    $in  = $null
    $gz  = $null
    $out = $null
    try {
        $in  = [System.IO.File]::OpenRead($tmpGz)
        $gz  = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
        $out = [System.IO.File]::Create($tmpCsv)
        $gz.CopyTo($out)
    } finally {
        if ($out) {
            try { $out.Close()   } catch {}
            try { $out.Dispose() } catch {}
        }
        if ($gz) {
            try { $gz.Close()   } catch {}
            try { $gz.Dispose() } catch {}
        }
        if ($in) {
            try { $in.Close()   } catch {}
            try { $in.Dispose() } catch {}
        }
    }

    # ---------- Parse ----------
    # File format: optional comment line(s) starting with '#', then header
    # 'cve,epss,percentile', then data rows.
    $lines     = Get-Content -LiteralPath $tmpCsv
    $modelDate = ''
    $startIdx  = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line.StartsWith('#')) {
            if ($line -match 'score_date\s*[:=]\s*([0-9T:Z\-]+)') {
                $modelDate = $matches[1]
            }
            continue
        }
        if ($line -match '^cve\s*,\s*epss\s*,\s*percentile') {
            $startIdx = $i + 1
            break
        }
    }
    if ($startIdx -lt 0) { throw "EPSS CSV has no recognizable header. First lines: $($lines | Select-Object -First 3)" }
    if (-not $modelDate) { $modelDate = (Get-Date).ToString('yyyy-MM-dd') }
    Write-Host "EPSS model date: $modelDate" -ForegroundColor DarkCyan

    # Hashtable for O(1) lookup
    $epssMap = @{}
    for ($i = $startIdx; $i -lt $lines.Count; $i++) {
        $parts = $lines[$i] -split ','
        if ($parts.Count -ge 3) {
            $epssMap[$parts[0].Trim()] = @{
                Score = [double]$parts[1]
                Pct   = [double]$parts[2]
            }
        }
    }
    Write-Host "EPSS feed contains $($epssMap.Count) CVEs" -ForegroundColor DarkGray

    # ---------- Apply to local cache ----------
    $localCves = (Invoke-SqliteQuery -DataSource $script:DbPath -Query "SELECT CveId FROM CVEs").CveId
    Write-Host "Local CVEs cache: $($localCves.Count)" -ForegroundColor DarkGray

    $matched = 0
    Invoke-SqliteQuery -DataSource $script:DbPath -Query "BEGIN TRANSACTION"
    try {
        foreach ($id in $localCves) {
            if ($epssMap.ContainsKey($id)) {
                $matched++
                $e = $epssMap[$id]
                Invoke-SqliteQuery -DataSource $script:DbPath `
                    -Query "UPDATE CVEs SET EpssScore=@s, EpssPercentile=@p, EpssDate=@d WHERE CveId=@c" `
                    -SqlParameters @{ s = $e.Score; p = $e.Pct; d = $modelDate; c = $id }
            }
        }
        Invoke-SqliteQuery -DataSource $script:DbPath -Query "COMMIT"
    } catch {
        Invoke-SqliteQuery -DataSource $script:DbPath -Query "ROLLBACK"
        throw
    }

    # ---------- Feed metadata ----------
    Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT OR REPLACE INTO FeedMeta (FeedName, LastUpdated, RecordCount) VALUES ('EPSS', @ts, @cnt)
"@ -SqlParameters @{ ts = (Get-Date).ToString('o'); cnt = $matched }

    Write-Host "EPSS update complete: $matched / $($localCves.Count) local CVEs enriched." -ForegroundColor Green

} finally {
    Remove-Item $tmpGz, $tmpCsv -Force -ErrorAction SilentlyContinue
}
