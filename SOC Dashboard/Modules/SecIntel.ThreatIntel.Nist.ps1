<#
.SYNOPSIS
    NIST NVD product/CPE search via the public CVE API. Cached in IntelCache
    with IocType='product' and IocValue='vendor:product'.

.DESCRIPTION
    https://nvd.nist.gov/developers/vulnerabilities

    Useful as a complement to the rolling 30-day CVE feed in
    Update-CveKevFeed.ps1. Given a product like 'apache:log4j' or
    'microsoft:exchange_server', this returns:
        - count of total CVEs known for that product
        - count of critical (CVSS >= 9.0) CVEs
        - top-5 most recent CVE IDs
    All rolled into a single IntelCache row so the IoC search tab can hit
    'log4j' and see a verdict at a glance.

    Verdict mapping:
        critical >= 1   -> 'malicious'    (treated as 'this product has
                                            a known critical exploit')
        any CVE         -> 'suspicious'
        none            -> 'clean'

    NVD API key is optional; without one the rate limit is 5 req / 30s.
    Set with:
        Set-AppSecret 'apikey.nvd' '<KEY>'

.NOTES
    Dot-source SecIntel.Schema.ps1, SecIntel.Settings.ps1,
    SecIntel.ThreatIntel.Core.ps1 first.
#>

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.Settings.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.Http.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.ThreatIntel.Core.ps1')

function Get-NistProductIntel {
    [CmdletBinding()]
    param(
        # 'vendor:product', e.g. 'apache:log4j'
        [Parameter(Mandatory)][string]$Product,
        [int]$ResultsPerPage = 200,
        [switch]$ForceRefresh
    )

    $key = $Product.Trim().ToLowerInvariant()
    if ($key -notmatch '^[a-z0-9_\-]+:[a-z0-9_\-]+$') {
        throw "Get-NistProductIntel: -Product must look like 'vendor:product' (lowercase, underscore/dash allowed). Got '$Product'."
    }

    if (-not $ForceRefresh) {
        $cached = Get-IntelCacheFresh -IocType 'product' -IocValue $key -Source 'nist'
        if ($cached) { return $cached }
    }

    $vendor, $product = $key.Split(':', 2)
    # virtualMatchString does prefix-match across the CPE dictionary;
    # 'cpeName' would require an exact dictionary entry which most
    # vendor:product pairs don't have at the version-wildcard level.
    # ':a:' restricts to the 'application' CPE class.
    $cpePrefix = "cpe:2.3:a:$($vendor):$($product)"
    $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=$([uri]::EscapeDataString($cpePrefix))&resultsPerPage=$ResultsPerPage"

    $headers = @{ Accept = 'application/json' }
    $apikey  = Get-AppSecret 'apikey.nvd'
    if ($apikey) { $headers['apiKey'] = $apikey }

    $now = (Get-Date).ToUniversalTime().ToString('o')

    try {
        # NVD throttles aggressively (especially without a key); 4 attempts
        # with 10s base backoff matches the documented 30s window.
        $resp = Invoke-RestMethodWithRetry -Uri $url -Headers $headers -Method GET `
                    -TimeoutSec 60 -MaxAttempts 4 -InitialDelaySeconds 10
    } catch {
        Write-Warning "NIST NVD lookup failed for $key : $($_.Exception.Message)"
        return $null
    }

    $vulns = @($resp.vulnerabilities)
    $total = $vulns.Count
    $crits = 0
    $highs = 0
    $top5  = @()

    foreach ($v in $vulns) {
        $cve = $v.cve
        if (-not $cve) { continue }
        $score = $null
        if ($cve.metrics.cvssMetricV31) {
            $score = [double]($cve.metrics.cvssMetricV31[0].cvssData.baseScore)
        } elseif ($cve.metrics.cvssMetricV30) {
            $score = [double]($cve.metrics.cvssMetricV30[0].cvssData.baseScore)
        } elseif ($cve.metrics.cvssMetricV2) {
            $score = [double]($cve.metrics.cvssMetricV2[0].cvssData.baseScore)
        }
        if ($null -ne $score) {
            if ($score -ge 9.0) { $crits++ }
            elseif ($score -ge 7.0) { $highs++ }
        }
    }

    # Sort by lastModified desc to surface the freshest CVEs in top5
    $sorted = $vulns | Sort-Object { [DateTime]::Parse($_.cve.lastModified) } -Descending
    $top5   = ($sorted | Select-Object -First 5 | ForEach-Object { $_.cve.id }) -join ','

    $verdict = if     ($crits -gt 0) { 'malicious'  }
               elseif ($total -gt 0) { 'suspicious' }
               else                   { 'clean'      }

    $row = @{
        IocType        = 'product'
        IocValue       = $key
        Source         = 'nist'
        Verdict        = $verdict
        Family         = ''
        Tags           = "vendor=$vendor,product=$product,critical=$crits,high=$highs"
        Reputation     = [int]$total
        DetectionRatio = "$crits crit / $highs high / $total total"
        ProviderUrl    = "https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&query=&search_type=all&cpe_vendor=cpe%3A%2F%3A$vendor&cpe_product=cpe%3A%2F%3A$vendor%3A$product"
        FirstSeen      = ''
        LastSeen       = if ($sorted.Count -gt 0) { [string]$sorted[0].cve.lastModified } else { '' }
        RawJson        = (@{ total=$total; critical=$crits; high=$highs; topRecent=$top5 } | ConvertTo-Json -Compress)
        FetchedAt      = $now
        TtlSeconds     = $script:IntelTtl[$verdict]
    }
    Save-IntelCache -Row $row
    return [PSCustomObject]$row
}

# Files are dot-sourced; Export-ModuleMember would fail outside a module context.
