<#
.SYNOPSIS
    Pulls the last 30 days of CVEs from the NVD API and the full CISA KEV
    catalog, storing both in the same SQLite database used by
    MitreAttackExplorer.ps1 (%USERPROFILE%\SecIntel\secintel.db).

.DESCRIPTION
    After this script runs, the CVE and KEV tabs in MitreAttackExplorer.ps1
    will be populated, and global IoC search will match against CVE IDs and
    KEV product names.

    Runs entirely under user-level PowerShell. Only dependency is PSSQLite,
    which is auto-installed if missing.

.PARAMETER Days
    How many days of CVE history to pull from NVD. Default: 30. Max: 120
    (NVD API hard limit per request).

.PARAMETER NvdApiKey
    Optional NVD API key. Without one you're limited to ~5 requests per
    30 seconds. Request a free key at https://nvd.nist.gov/developers/request-an-api-key

.EXAMPLE
    .\Update-CveKevFeed.ps1
    Pulls last 30 days of CVEs and the full KEV catalog.

.EXAMPLE
    .\Update-CveKevFeed.ps1 -Days 14 -NvdApiKey 'abc123...'
    Pulls 14 days using an API key for faster throughput.

.NOTES
    PowerShell 5.1+. No admin rights required.
#>

[CmdletBinding()]
param(
    [int]$Days = 30,
    [string]$NvdApiKey,
    [switch]$SkipCves,
    [switch]$SkipKevs
)

$ErrorActionPreference = 'Stop'

if ($Days -gt 120) { throw "NVD API allows max 120 days per request." }

# NVD API key resolution, in priority order:
#   1. -NvdApiKey parameter (explicit override)
#   2. $env:NVD_API_KEY (set by automation/launcher)
#   3. apikey.nvd in the DPAPI-protected AppSettings vault (Set-AppSecret)
# The vault path means the dashboard's "Update CVE" button gets the
# 50 req/30s rate limit automatically, no env juggling required.
if (-not $NvdApiKey -and $env:NVD_API_KEY) { $NvdApiKey = $env:NVD_API_KEY }

# ---------- Shared schema / paths / dependency bootstrap ----------
. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
Ensure-PSSQLite
Initialize-SecIntelSchema

# Vault fallback (must come AFTER schema bootstrap because Get-AppSecret
# reads from AppSettings which is created by Initialize-SecIntelSchema).
if (-not $NvdApiKey) {
    try {
        . (Join-Path $PSScriptRoot 'SecIntel.Settings.ps1')
        $vaultKey = Get-AppSecret 'apikey.nvd'
        if ($vaultKey) {
            $NvdApiKey = $vaultKey
            Write-Host "Using NVD API key from DPAPI vault (apikey.nvd)." -ForegroundColor DarkGray
        }
    } catch {
        Write-Warning "Could not read apikey.nvd from vault: $($_.Exception.Message)"
    }
}
if (-not $NvdApiKey) {
    Write-Host "No NVD API key set - running at 5 req/30s. Set one with: Set-AppSecret 'apikey.nvd' '<KEY>'" -ForegroundColor Yellow
}

# ---------- Script-specific URLs ----------
$NvdBaseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
$KevUrl     = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'

# ---------- NVD CVE ingest ----------
function Update-Cves {
    param([int]$Days, [string]$ApiKey)

    $end   = (Get-Date).ToUniversalTime()
    $start = $end.AddDays(-$Days)
    # NVD requires ISO-8601 with milliseconds, no 'Z'
    $startStr = $start.ToString('yyyy-MM-ddTHH:mm:ss.fff')
    $endStr   = $end.ToString(  'yyyy-MM-ddTHH:mm:ss.fff')

    Write-Host "Pulling CVEs from NVD ($startStr to $endStr)..." -ForegroundColor Cyan

    $headers = @{}
    if ($ApiKey) { $headers['apiKey'] = $ApiKey }

    $resultsPerPage = 2000
    $startIndex     = 0
    $totalResults   = $null
    $allCves        = New-Object System.Collections.Generic.List[object]

    do {
        $uri = "$NvdBaseUrl`?pubStartDate=$startStr&pubEndDate=$endStr&resultsPerPage=$resultsPerPage&startIndex=$startIndex"
        Write-Host "  GET $uri" -ForegroundColor DarkGray
        try {
            $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -TimeoutSec 60
        } catch {
            Write-Warning "NVD request failed: $_"
            # NVD throttles aggressively without a key; back off and retry once
            Start-Sleep -Seconds 10
            $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -TimeoutSec 60
        }
        if ($null -eq $totalResults) { $totalResults = [int]$resp.totalResults }
        foreach ($item in $resp.vulnerabilities) { [void]$allCves.Add($item) }
        $startIndex += $resultsPerPage

        # Rate limit: without API key, 5 req / 30s; with key, 50 req / 30s
        if ($ApiKey) { Start-Sleep -Milliseconds 600 } else { Start-Sleep -Seconds 6 }
    } while ($startIndex -lt $totalResults)

    Write-Host "Fetched $($allCves.Count) of $totalResults CVEs. Loading to SQLite..." -ForegroundColor Cyan

    $conn = New-SQLiteConnection -DataSource $script:DbPath
    try {
        Invoke-SqliteQuery -SQLiteConnection $conn -Query "BEGIN TRANSACTION;"
        foreach ($v in $allCves) {
            $cve = $v.cve
            if (-not $cve) { continue }

            $cveId     = [string]$cve.id
            $published = [string]$cve.published
            $modified  = [string]$cve.lastModified

            # Description (prefer English)
            $desc = ''
            if ($cve.descriptions) {
                $en = $cve.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1
                if ($en) { $desc = [string]$en.value }
            }

            # CVSS - prefer v3.1 > v3.0 > v2
            $score = $null; $severity = ''; $vector = ''
            if ($cve.metrics.cvssMetricV31) {
                $m = $cve.metrics.cvssMetricV31 | Select-Object -First 1
                $score    = [double]$m.cvssData.baseScore
                $severity = [string]$m.cvssData.baseSeverity
                $vector   = [string]$m.cvssData.vectorString
            } elseif ($cve.metrics.cvssMetricV30) {
                $m = $cve.metrics.cvssMetricV30 | Select-Object -First 1
                $score    = [double]$m.cvssData.baseScore
                $severity = [string]$m.cvssData.baseSeverity
                $vector   = [string]$m.cvssData.vectorString
            } elseif ($cve.metrics.cvssMetricV2) {
                $m = $cve.metrics.cvssMetricV2 | Select-Object -First 1
                $score    = [double]$m.cvssData.baseScore
                $severity = [string]$m.baseSeverity
                $vector   = [string]$m.cvssData.vectorString
            }

            $refs = ''
            if ($cve.references) {
                $refs = (($cve.references | Select-Object -First 5 | ForEach-Object { $_.url }) -join ' | ')
            }

            Invoke-SqliteQuery -SQLiteConnection $conn -Query @"
INSERT OR REPLACE INTO CVEs (CveId, Published, LastModified, CvssScore, Severity, Vector, Description, RefLinks)
VALUES (@id, @pub, @mod, @score, @sev, @vec, @desc, @refs)
"@ -SqlParameters @{
                id    = $cveId
                pub   = $published
                mod   = $modified
                score = $score
                sev   = $severity
                vec   = $vector
                desc  = $desc
                refs  = $refs
            }
        }
        Invoke-SqliteQuery -SQLiteConnection $conn -Query "COMMIT;"

        Invoke-SqliteQuery -SQLiteConnection $conn -Query @"
INSERT OR REPLACE INTO FeedMeta (FeedName, LastUpdated, RecordCount)
VALUES ('NVD-CVE', @d, @c)
"@ -SqlParameters @{ d = (Get-Date).ToString('o'); c = $allCves.Count }

        Write-Host "CVE ingest complete: $($allCves.Count) records." -ForegroundColor Green
    }
    finally {
        $conn.Close()
    }
}

# ---------- CISA KEV ingest ----------
function Update-Kevs {
    Write-Host "Pulling CISA KEV catalog from GitHub mirror..." -ForegroundColor Cyan

    # Create a .NET WebClient object
    $webClient = New-Object System.Net.WebClient

    # A User-Agent header is still a good practice, even for GitHub
    $webClient.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36')

    try {
        # Use the WebClient to download the content as a string
        $jsonContent = $webClient.DownloadString($KevUrl)

        # Convert the downloaded JSON string into a PowerShell object
        $resp = $jsonContent | ConvertFrom-Json
    } catch {
        Write-Error "Failed to retrieve CISA KEV catalog from GitHub. Error: $($_.Exception.Message)"
        $webClient.Dispose()
        return
    } finally {
        if ($webClient) {
            $webClient.Dispose()
        }
    }

    # The structure of the JSON from this source is the same
    $vulns = $resp.vulnerabilities

    if (-not $vulns) {
        Write-Warning "No 'vulnerabilities' key found in the CISA KEV response, or it's empty."
        return
    }

    Write-Host "Fetched $($vulns.Count) KEV entries. Loading to SQLite..." -ForegroundColor Cyan

    $conn = New-SQLiteConnection -DataSource $script:DbPath
    try {
        Invoke-SqliteQuery -SQLiteConnection $conn -Query "DELETE FROM KEVs;"
        Invoke-SqliteQuery -SQLiteConnection $conn -Query "BEGIN TRANSACTION;"
        foreach ($k in $vulns) {
            Invoke-SqliteQuery -SQLiteConnection $conn -Query @"
INSERT OR REPLACE INTO KEVs (CveId, VendorProject, Product, VulnName, DateAdded, Description, RequiredAction, DueDate, KnownRansomware, Notes)
VALUES (@id, @vendor, @prod, @name, @added, @desc, @action, @due, @ransom, @notes)
"@ -SqlParameters @{
                id     = [string]$k.cveID
                vendor = [string]$k.vendorProject
                prod   = [string]$k.product
                name   = [string]$k.vulnerabilityName
                added  = [string]$k.dateAdded
                desc   = [string]$k.shortDescription
                action = [string]$k.requiredAction
                due    = [string]$k.dueDate
                ransom = [string]$k.knownRansomwareCampaignUse
                notes  = [string]$k.notes
            }
        }
        Invoke-SqliteQuery -SQLiteConnection $conn -Query "COMMIT;"
                Invoke-SqliteQuery -SQLiteConnection $conn -Query @"
INSERT OR REPLACE INTO FeedMeta (FeedName, LastUpdated, RecordCount)
VALUES ('CISA-KEV', @d, @c)
"@ -SqlParameters @{ d = (Get-Date).ToString('o'); c = $vulns.Count }
        Write-Host "KEV ingest complete: $($vulns.Count) records." -ForegroundColor Green
    }
    finally {
        $conn.Close()
    }
}

# ---------- Dispatcher ----------
if (-not $SkipCves) {
    try {
        Update-Cves -Days $Days -ApiKey $NvdApiKey
    } catch {
        Write-Warning "CVE ingest failed: $($_.Exception.Message)"
    }
} else {
    Write-Host "Skipping CVE ingest (-SkipCves)." -ForegroundColor DarkGray
}

if (-not $SkipKevs) {
    try {
        Update-Kevs
    } catch {
        Write-Warning "KEV ingest failed: $($_.Exception.Message)"
    }
} else {
    Write-Host "Skipping KEV ingest (-SkipKevs)." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "Done. Database: $script:DbPath" -ForegroundColor Cyan
