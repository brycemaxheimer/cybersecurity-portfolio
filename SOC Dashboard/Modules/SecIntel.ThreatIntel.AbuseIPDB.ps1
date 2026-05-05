<#
.SYNOPSIS
    AbuseIPDB IP reputation lookups, cached in IntelCache.

.DESCRIPTION
    https://docs.abuseipdb.com/  - free tier 1000 checks/day with API key.
    abuseConfidenceScore 0-100 maps to:
        >= 75 -> malicious
        >= 25 -> suspicious
        >  0  -> clean (with reports but low confidence)
        =  0  -> clean

    Set the API key once with:
        Set-AppSecret 'apikey.abuseipdb' '<KEY>'

.NOTES
    Dot-source SecIntel.Schema.ps1, SecIntel.Settings.ps1,
    and SecIntel.ThreatIntel.Core.ps1 first.
#>

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.Settings.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.Http.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.ThreatIntel.Core.ps1')

function Get-AbuseIpIntel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Ip,
        [int]$MaxAgeDays = 90,
        [switch]$ForceRefresh
    )

    $type = Resolve-IocType $Ip
    if ($type -ne 'ip' -and $type -ne 'ipv6') {
        throw "Get-AbuseIpIntel: '$Ip' is not a recognised IPv4/IPv6 address."
    }

    if (-not $ForceRefresh) {
        $cached = Get-IntelCacheFresh -IocType $type -IocValue $Ip -Source 'abuseipdb'
        if ($cached) { return $cached }
    }

    $key = Get-AppSecret 'apikey.abuseipdb'
    if (-not $key) { throw "AbuseIPDB API key not set. Use: Set-AppSecret 'apikey.abuseipdb' '<KEY>'" }

    $headers = @{ Key = $key; Accept = 'application/json' }
    $url     = "https://api.abuseipdb.com/api/v2/check?ipAddress=$([uri]::EscapeDataString($Ip))&maxAgeInDays=$MaxAgeDays&verbose"
    $now     = (Get-Date).ToUniversalTime().ToString('o')

    try {
        $resp = Invoke-RestMethodWithRetry -Uri $url -Headers $headers -Method GET `
                    -TimeoutSec 30 -MaxAttempts 2 -InitialDelaySeconds 5
    } catch {
        Write-Warning "AbuseIPDB lookup failed for $Ip : $($_.Exception.Message)"
        return $null
    }

    $d     = $resp.data
    $score = [int]($d.abuseConfidenceScore  | Select-Object -First 1)
    $reps  = [int]($d.totalReports          | Select-Object -First 1)

    $verdict = if     ($score -ge 75) { 'malicious'  }
               elseif ($score -ge 25) { 'suspicious' }
               elseif ($reps  -gt 0)  { 'clean'      }
               else                   { 'clean'      }

    $tags = @()
    if ($d.usageType)        { $tags += "use=$($d.usageType)" }
    if ($d.countryCode)      { $tags += "cc=$($d.countryCode)" }
    if ($d.isp)              { $tags += "isp=$($d.isp)" }
    if ($d.isTor)            { $tags += 'tor' }
    if ($d.isWhitelisted)    { $tags += 'whitelisted' }

    $row = @{
        IocType        = $type
        IocValue       = [string]$d.ipAddress
        Source         = 'abuseipdb'
        Verdict        = $verdict
        Family         = ''
        Tags           = ($tags -join ',')
        Reputation     = $score
        DetectionRatio = "$reps reports / $score abuse"
        ProviderUrl    = "https://www.abuseipdb.com/check/$([uri]::EscapeDataString($Ip))"
        FirstSeen      = ''
        LastSeen       = [string]$d.lastReportedAt
        RawJson        = ($resp | ConvertTo-Json -Depth 6 -Compress)
        FetchedAt      = $now
        TtlSeconds     = $script:IntelTtl[$verdict]
    }
    Save-IntelCache -Row $row
    return [PSCustomObject]$row
}

# Files are dot-sourced; Export-ModuleMember would fail outside a module context.
