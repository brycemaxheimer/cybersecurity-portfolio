<#
.SYNOPSIS
    URLScan.io URL reputation lookups, cached in IntelCache.

.DESCRIPTION
    https://urlscan.io/docs/api/

    Two-stage lookup:
      1) Search urlscan's public corpus for recent scans of the URL.
         Free, requires no API key for public results, fast.
      2) Optional: submit a new scan with -Submit. Requires an API key.
         Polls for ~30s for the result; returns 'unknown' if it doesn't
         complete in time (the cached row gets refreshed on the next call).

    Verdict mapping (stage 1):
      verdicts.overall.malicious -> 'malicious'
      verdicts.engines.malicious or community 'malicious' -> 'suspicious'
      no public scans -> 'unknown' (or trigger -Submit)

    Set the API key (optional, only needed for -Submit) with:
        Set-AppSecret 'apikey.urlscan' '<KEY>'

.NOTES
    Dot-source SecIntel.Schema.ps1, SecIntel.Settings.ps1,
    and SecIntel.ThreatIntel.Core.ps1 first.
#>

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.Settings.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.ThreatIntel.Core.ps1')

function Get-UrlScanIntel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [switch]$Submit,
        [int]$PollTimeoutSeconds = 60,
        [switch]$ForceRefresh
    )

    $type = Resolve-IocType $Url
    if ($type -ne 'url') { throw "Get-UrlScanIntel: '$Url' is not a recognised URL." }

    if (-not $ForceRefresh) {
        $cached = Get-IntelCacheFresh -IocType $type -IocValue $Url -Source 'urlscan'
        if ($cached) { return $cached }
    }

    $now      = (Get-Date).ToUniversalTime().ToString('o')
    $headers  = @{ Accept = 'application/json' }
    $apikey   = Get-AppSecret 'apikey.urlscan'
    if ($apikey) { $headers['API-Key'] = $apikey }

    # ---------- Stage 1: search the public corpus ----------
    $q = "page.url:`"$Url`""
    $searchUrl = "https://urlscan.io/api/v1/search/?q=$([uri]::EscapeDataString($q))&size=1"
    $hit       = $null
    try {
        $resp = Invoke-RestMethod -Uri $searchUrl -Headers $headers -Method GET -ErrorAction Stop -TimeoutSec 20
        if ($resp.results -and $resp.results.Count -gt 0) {
            $hit = $resp.results[0]
        }
    } catch {
        Write-Warning "URLScan search failed for $Url : $($_.Exception.Message)"
    }

    if (-not $hit -and $Submit.IsPresent) {
        if (-not $apikey) { throw "URLScan submit requires an API key. Use: Set-AppSecret 'apikey.urlscan' '<KEY>'" }

        # Submit a new scan
        $body = @{ url = $Url; visibility = 'public' } | ConvertTo-Json -Compress
        try {
            $sub = Invoke-RestMethod -Uri 'https://urlscan.io/api/v1/scan/' `
                -Headers @{ 'API-Key' = $apikey; 'Content-Type' = 'application/json' } `
                -Method POST -Body $body -TimeoutSec 30 -ErrorAction Stop
        } catch {
            Write-Warning "URLScan submit failed: $($_.Exception.Message)"
            return $null
        }

        # Poll for the result (urlscan typical completion ~10-20s)
        $deadline = (Get-Date).AddSeconds($PollTimeoutSeconds)
        $resultUrl = "https://urlscan.io/api/v1/result/$($sub.uuid)/"
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 5
            try {
                $hit = Invoke-RestMethod -Uri $resultUrl -Headers $headers -Method GET -TimeoutSec 20 -ErrorAction Stop
                break
            } catch {
                # 404 expected while scan is in progress; keep polling
                if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw }
            }
        }
    }

    if (-not $hit) {
        # No public scan and not asked to submit -> store an 'unknown' row so
        # the search tab shows that we looked. Short TTL so a recurring
        # incident triggers a re-look on the next call.
        $row = @{
            IocType=$type; IocValue=$Url; Source='urlscan'; Verdict='unknown'
            Family=''; Tags=''; Reputation=$null; DetectionRatio='no public scan'
            ProviderUrl="https://urlscan.io/search/#$([uri]::EscapeDataString($Url))"
            FirstSeen=''; LastSeen=''
            RawJson='{"note":"no public scan found"}'
            FetchedAt=$now; TtlSeconds=$script:IntelTtl['unknown']
        }
        Save-IntelCache -Row $row
        return [PSCustomObject]$row
    }

    # Hit either from search or submission
    $verdicts = $hit.verdicts
    $overallMal = [bool]$verdicts.overall.malicious
    $engMal     = [int]($verdicts.engines.maliciousTotal | Select-Object -First 1)
    $commMal    = [int]($verdicts.community.score        | Select-Object -First 1)

    $verdict = if ($overallMal)               { 'malicious' }
               elseif ($engMal -gt 0)         { 'suspicious' }
               elseif ($commMal -lt 0)        { 'suspicious' }
               else                           { 'clean'      }

    $tags = @()
    if ($hit.page.country)  { $tags += "cc=$($hit.page.country)" }
    if ($hit.page.server)   { $tags += "server=$($hit.page.server)" }
    if ($verdicts.overall.tags) { $tags += $verdicts.overall.tags }

    $providerUrl = if ($hit.result) { [string]$hit.result }
                   elseif ($hit.task.uuid) { "https://urlscan.io/result/$($hit.task.uuid)/" }
                   else { '' }

    $row = @{
        IocType        = $type
        IocValue       = $Url
        Source         = 'urlscan'
        Verdict        = $verdict
        Family         = if ($verdicts.overall.brands) { ($verdicts.overall.brands | ForEach-Object { $_.name }) -join ',' } else { '' }
        Tags           = ($tags -join ',')
        Reputation     = if ($null -ne $verdicts.overall.score) { [int]$verdicts.overall.score } else { $null }
        DetectionRatio = "engines=$engMal community=$commMal"
        ProviderUrl    = $providerUrl
        FirstSeen      = ''
        LastSeen       = [string]$hit.task.time
        RawJson        = ($hit | ConvertTo-Json -Depth 8 -Compress)
        FetchedAt      = $now
        TtlSeconds     = $script:IntelTtl[$verdict]
    }
    Save-IntelCache -Row $row
    return [PSCustomObject]$row
}

# Files are dot-sourced; Export-ModuleMember would fail outside a module context.
