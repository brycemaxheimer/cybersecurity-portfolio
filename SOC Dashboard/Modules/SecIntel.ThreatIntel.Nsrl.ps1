<#
.SYNOPSIS
    NSRL / known-good hash lookups via CIRCL hashlookup, cached in IntelCache.

.DESCRIPTION
    https://hashlookup.circl.lu/  - free, no API key. Wraps NIST NSRL plus
    a few other "known software" lists (GitHub Releases, Mozilla, etc).

    Hit  -> verdict 'known-good' (file is on a recognised allowlist).
    Miss -> verdict 'unknown'.

    'known-good' has a 90-day TTL because NSRL classifications never flip;
    'unknown' has the standard 1-day TTL so a re-check happens promptly
    once a new release lands in NSRL.

.NOTES
    Dot-source SecIntel.Schema.ps1, SecIntel.ThreatIntel.Core.ps1 first.
#>

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.ThreatIntel.Core.ps1')

function Get-NsrlIntel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Hash,
        [switch]$ForceRefresh
    )

    $type = Resolve-IocType $Hash
    if ($type -notin @('md5','sha1','sha256')) {
        throw "Get-NsrlIntel: '$Hash' is not a recognised MD5/SHA1/SHA256 hash."
    }

    if (-not $ForceRefresh) {
        $cached = Get-IntelCacheFresh -IocType $type -IocValue $Hash -Source 'nsrl'
        if ($cached) { return $cached }
    }

    $now = (Get-Date).ToUniversalTime().ToString('o')
    $url = "https://hashlookup.circl.lu/lookup/$type/$($Hash.ToUpperInvariant())"

    $hit = $null
    try {
        $hit = Invoke-RestMethod -Uri $url -Method GET -TimeoutSec 20 -ErrorAction Stop
    } catch {
        $status = $null
        try { $status = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($status -ne 404) {
            Write-Warning "NSRL/CIRCL lookup failed for $Hash : $($_.Exception.Message)"
            return $null
        }
        # 404 = not in NSRL
    }

    if ($null -eq $hit -or $null -eq $hit.SHA1) {
        $row = @{
            IocType=$type; IocValue=$Hash; Source='nsrl'; Verdict='unknown'
            Family=''; Tags=''; Reputation=$null
            DetectionRatio='not in NSRL'
            ProviderUrl="https://hashlookup.circl.lu/lookup/$type/$($Hash.ToUpperInvariant())"
            FirstSeen=''; LastSeen=''
            RawJson='{"note":"miss"}'
            FetchedAt=$now; TtlSeconds=$script:IntelTtl['unknown']
        }
        Save-IntelCache -Row $row
        return [PSCustomObject]$row
    }

    $tags = @()
    if ($hit.source)        { $tags += "src=$($hit.source)" }
    if ($hit.FileName)      { $tags += "name=$($hit.FileName)" }
    if ($hit.ProductName)   { $tags += "product=$($hit.ProductName)" }
    if ($hit.OpSystemName)  { $tags += "os=$($hit.OpSystemName)" }

    $row = @{
        IocType        = $type
        IocValue       = $Hash
        Source         = 'nsrl'
        Verdict        = 'known-good'
        Family         = [string]$hit.ProductName
        Tags           = ($tags -join ',')
        Reputation     = $null
        DetectionRatio = 'NSRL match'
        ProviderUrl    = "https://hashlookup.circl.lu/lookup/$type/$($Hash.ToUpperInvariant())"
        FirstSeen      = ''
        LastSeen       = ''
        RawJson        = ($hit | ConvertTo-Json -Depth 6 -Compress)
        FetchedAt      = $now
        TtlSeconds     = $script:IntelTtl['known-good']
    }
    Save-IntelCache -Row $row
    return [PSCustomObject]$row
}

# Files are dot-sourced; Export-ModuleMember would fail outside a module context.
