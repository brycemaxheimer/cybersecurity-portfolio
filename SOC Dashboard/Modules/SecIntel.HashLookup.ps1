<#
.SYNOPSIS
    Hash enrichment module for SecIntel. Caches lookups in HashIntel table.

.DESCRIPTION
    Provides multi-source hash reputation lookups with local SQLite caching.
    Each source gets its own cached row keyed on (Sha256, Source). Cache TTL
    is verdict-driven so malicious verdicts stay cached longer than unknowns.

    Sources:
        virustotal     - requires API key (free tier 4 req/min, 500/day)
        malwarebazaar  - free, no key, abuse.ch
        otx            - AlienVault Open Threat Exchange, free with key

    API keys are loaded via Get-AppSecret from SecIntel.Settings.ps1:
        Set-AppSecret 'apikey.virustotal' '<KEY>'
        Set-AppSecret 'apikey.otx'        '<KEY>'   # optional

    Usage:
        $results = Get-HashIntel -Hash 'abc123...' -Sources virustotal,malwarebazaar
        $results | Format-Table Source, Verdict, Family, DetectionRatio, Cached

.NOTES
    Dot-source SecIntel.Schema.ps1 + SecIntel.Settings.ps1 first.
#>

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.Settings.ps1')

# ============================================================
# Verdict-driven TTL policy (seconds)
#   malicious  - 7d  (verdict unlikely to flip)
#   suspicious - 7d
#   clean      - 30d
#   unknown    - 1d  (give it a day, then re-check)
# Override per call with -MaxAgeSeconds.
# ============================================================
$script:HashIntelTtl = @{
    'malicious'  = 7  * 86400
    'suspicious' = 7  * 86400
    'clean'      = 30 * 86400
    'unknown'    = 1  * 86400
}

function Get-HashType {
    param([string]$Hash)
    if (-not $Hash) { return $null }
    switch ($Hash.Trim().Length) {
        32  { 'md5'    }
        40  { 'sha1'   }
        64  { 'sha256' }
        default { $null }
    }
}

# ============================================================
# Cache lookup - returns row only if fresh per TTL policy.
# ============================================================
function Get-HashIntelCached {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Hash,
        [Parameter(Mandatory)][string]$Source,
        [int]$MaxAgeSeconds = 0
    )
    $type = Get-HashType $Hash
    if (-not $type) { return $null }

    $col = switch ($type) { 'md5' { 'Md5' } 'sha1' { 'Sha1' } 'sha256' { 'Sha256' } }
    $row = Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "SELECT * FROM HashIntel WHERE $col = @h AND Source = @src" `
        -SqlParameters @{ h = $Hash.Trim(); src = $Source } | Select-Object -First 1
    if (-not $row) { return $null }

    try {
        $fetched = [DateTime]::Parse($row.FetchedAt)
    } catch { return $null }

    $ageSec = ((Get-Date).ToUniversalTime() - $fetched.ToUniversalTime()).TotalSeconds
    $ttl    = if ($MaxAgeSeconds -gt 0) { $MaxAgeSeconds }
              elseif ($script:HashIntelTtl.ContainsKey($row.Verdict)) { $script:HashIntelTtl[$row.Verdict] }
              else { 86400 }
    if ($ageSec -gt $ttl) { return $null }
    return $row
}

# ============================================================
# Upsert into HashIntel
# ============================================================
function Save-HashIntel {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Row)

    foreach ($k in @('Sha256','Source','Md5','Sha1','Verdict','FirstSeen','LastSeen','FamilyName','Tags','DetectionRatio','Reputation','FetchedAt','TtlSeconds','RawJson')) {
        if (-not $Row.ContainsKey($k)) { $Row[$k] = $null }
    }

    Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT OR REPLACE INTO HashIntel (Sha256, Source, Md5, Sha1, Verdict, FirstSeen, LastSeen,
                      FamilyName, Tags, DetectionRatio, Reputation, FetchedAt, TtlSeconds, RawJson)
VALUES (@Sha256,@Source,@Md5,@Sha1,@Verdict,@FirstSeen,@LastSeen,
        @FamilyName,@Tags,@DetectionRatio,@Reputation,@FetchedAt,@TtlSeconds,@RawJson)
"@ -SqlParameters $Row
}

# ============================================================
# Provider: VirusTotal v3
# ============================================================
function Invoke-VtHashLookup {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Hash)

    $key = Get-AppSecret 'apikey.virustotal'
    if (-not $key) { throw "VirusTotal API key not set. Use: Set-AppSecret 'apikey.virustotal' '<KEY>'" }

    $headers = @{ 'x-apikey' = $key }
    $url     = "https://www.virustotal.com/api/v3/files/$($Hash.Trim())"
    $now     = (Get-Date).ToUniversalTime().ToString('o')

    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method GET -ErrorAction Stop
    } catch {
        $status = $null
        try { $status = $_.Exception.Response.StatusCode.value__ } catch {}
        if ($status -eq 404) {
            return @{
                Sha256 = $Hash; Source = 'virustotal'; Verdict = 'unknown'
                Md5 = $null; Sha1 = $null; FirstSeen = ''; LastSeen = ''
                FamilyName = ''; Tags = ''; DetectionRatio = '0/0'; Reputation = $null
                FetchedAt = $now; TtlSeconds = $script:HashIntelTtl['unknown']
                RawJson = '{"error":"not found"}'
            }
        }
        throw
    }

    $a = $resp.data.attributes
    $stats = $a.last_analysis_stats
    $mal = [int]($stats.malicious  | Select-Object -First 1)
    $sus = [int]($stats.suspicious | Select-Object -First 1)
    $har = [int]($stats.harmless   | Select-Object -First 1)
    $und = [int]($stats.undetected | Select-Object -First 1)
    $tot = $mal + $sus + $har + $und

    $verdict = if     ($mal -ge 5)               { 'malicious'  }
               elseif ($mal -ge 1 -or $sus -ge 3){ 'suspicious' }
               elseif ($tot -gt 0)               { 'clean'      }
               else                              { 'unknown'    }

    $family = if ($a.popular_threat_classification.suggested_threat_label) { [string]$a.popular_threat_classification.suggested_threat_label } else { '' }
    $tags   = if ($a.tags) { ($a.tags -join ',') } else { '' }

    return @{
        Sha256         = if ($a.sha256) { $a.sha256 } else { $Hash }
        Md5            = $a.md5
        Sha1           = $a.sha1
        Source         = 'virustotal'
        Verdict        = $verdict
        FirstSeen      = if ($a.first_submission_date) { [DateTimeOffset]::FromUnixTimeSeconds($a.first_submission_date).UtcDateTime.ToString('o') } else { '' }
        LastSeen       = if ($a.last_submission_date)  { [DateTimeOffset]::FromUnixTimeSeconds($a.last_submission_date).UtcDateTime.ToString('o')  } else { '' }
        FamilyName     = $family
        Tags           = $tags
        DetectionRatio = "$mal/$tot"
        Reputation     = if ($null -ne $a.reputation) { [int]$a.reputation } else { $null }
        FetchedAt      = $now
        TtlSeconds     = $script:HashIntelTtl[$verdict]
        RawJson        = ($resp | ConvertTo-Json -Depth 6 -Compress)
    }
}

# ============================================================
# Provider: MalwareBazaar (abuse.ch) - free, no key
# Only stores known-malicious; absence is "unknown"
# ============================================================
function Invoke-MalwareBazaarLookup {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Hash)

    $now  = (Get-Date).ToUniversalTime().ToString('o')
    $body = @{ query = 'get_info'; hash = $Hash.Trim() }

    # abuse.ch added a User-Agent requirement in 2024 - requests without
    # one come back 403 / 429 with no useful body. Set one explicitly.
    $headers = @{ 'User-Agent' = 'SocDashboard-SecIntel/1.0 (+local lab)' }

    # Optional auth key (not required for get_info, but lifts rate limits)
    $authKey = Get-AppSecret 'apikey.malwarebazaar'
    if ($authKey) { $headers['Auth-Key'] = $authKey }

    try {
        $resp = Invoke-RestMethod -Uri 'https://mb-api.abuse.ch/api/v1/' `
            -Method POST -Body $body -Headers $headers -TimeoutSec 30 -ErrorAction Stop
    } catch {
        Write-Warning "MalwareBazaar lookup failed for $Hash : $($_.Exception.Message)"
        return $null
    }

    if ($resp.query_status -ne 'ok' -or -not $resp.data) {
        return @{
            Sha256 = $Hash; Source = 'malwarebazaar'; Verdict = 'unknown'
            Md5 = $null; Sha1 = $null; FirstSeen = ''; LastSeen = ''
            FamilyName = ''; Tags = ''; DetectionRatio = ''; Reputation = $null
            FetchedAt = $now; TtlSeconds = $script:HashIntelTtl['unknown']
            RawJson = ($resp | ConvertTo-Json -Compress)
        }
    }

    $d = $resp.data | Select-Object -First 1
    return @{
        Sha256         = $d.sha256_hash
        Md5            = $d.md5_hash
        Sha1           = $d.sha1_hash
        Source         = 'malwarebazaar'
        Verdict        = 'malicious'
        FirstSeen      = $d.first_seen
        LastSeen       = $d.last_seen
        FamilyName     = if ($d.signature) { $d.signature } else { '' }
        Tags           = if ($d.tags) { ($d.tags -join ',') } else { '' }
        DetectionRatio = ''
        Reputation     = $null
        FetchedAt      = $now
        TtlSeconds     = $script:HashIntelTtl['malicious']
        RawJson        = ($resp | ConvertTo-Json -Depth 6 -Compress)
    }
}

# ============================================================
# Provider: AlienVault OTX
# ============================================================
function Invoke-OtxHashLookup {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Hash)

    $key = Get-AppSecret 'apikey.otx'
    if (-not $key) { return $null }   # silently skip if not configured

    $now     = (Get-Date).ToUniversalTime().ToString('o')
    $headers = @{ 'X-OTX-API-KEY' = $key }
    $url     = "https://otx.alienvault.com/api/v1/indicators/file/$($Hash.Trim())/general"

    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method GET -ErrorAction Stop
    } catch {
        return $null
    }

    $pulseCount = [int]($resp.pulse_info.count)
    $verdict    = if ($pulseCount -ge 3) { 'malicious' } elseif ($pulseCount -ge 1) { 'suspicious' } else { 'unknown' }

    $firstPulse = $resp.pulse_info.pulses | Select-Object -First 1
    $allTags    = @()
    foreach ($p in $resp.pulse_info.pulses) { if ($p.tags) { $allTags += $p.tags } }

    return @{
        Sha256         = $resp.sha256
        Md5            = $resp.md5
        Sha1           = $resp.sha1
        Source         = 'otx'
        Verdict        = $verdict
        FirstSeen      = ''
        LastSeen       = ''
        FamilyName     = if ($firstPulse) { [string]$firstPulse.name } else { '' }
        Tags           = (($allTags | Select-Object -Unique) -join ',')
        DetectionRatio = "$pulseCount pulses"
        Reputation     = $null
        FetchedAt      = $now
        TtlSeconds     = $script:HashIntelTtl[$verdict]
        RawJson        = ($resp | ConvertTo-Json -Depth 6 -Compress)
    }
}

# ============================================================
# Public entry point
# ============================================================
function Get-HashIntel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Hash,
        [string[]]$Sources = @('virustotal','malwarebazaar','otx'),
        [switch]$ForceRefresh,
        [switch]$IncludeRaw
    )

    if (-not (Get-HashType $Hash)) {
        throw "Invalid hash length $($Hash.Length). Expected MD5(32), SHA1(40), or SHA256(64)."
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($src in $Sources) {
        # 1. Cache check
        if (-not $ForceRefresh) {
            $cached = Get-HashIntelCached -Hash $Hash -Source $src
            if ($cached) {
                $results.Add([PSCustomObject]@{
                    Source         = $src
                    Verdict        = $cached.Verdict
                    Family         = $cached.FamilyName
                    DetectionRatio = $cached.DetectionRatio
                    FirstSeen      = $cached.FirstSeen
                    LastSeen       = $cached.LastSeen
                    Tags           = $cached.Tags
                    FetchedAt      = $cached.FetchedAt
                    Cached         = $true
                    RawJson        = if ($IncludeRaw) { $cached.RawJson } else { $null }
                })
                continue
            }
        }

        # 2. Fetch
        try {
            $row = switch ($src) {
                'virustotal'    { Invoke-VtHashLookup        -Hash $Hash }
                'malwarebazaar' { Invoke-MalwareBazaarLookup -Hash $Hash }
                'otx'           { Invoke-OtxHashLookup       -Hash $Hash }
                default         { Write-Warning "Unknown source: $src"; $null }
            }
            if ($row) {
                Save-HashIntel -Row $row
                $results.Add([PSCustomObject]@{
                    Source         = $src
                    Verdict        = $row.Verdict
                    Family         = $row.FamilyName
                    DetectionRatio = $row.DetectionRatio
                    FirstSeen      = $row.FirstSeen
                    LastSeen       = $row.LastSeen
                    Tags           = $row.Tags
                    FetchedAt      = $row.FetchedAt
                    Cached         = $false
                    RawJson        = if ($IncludeRaw) { $row.RawJson } else { $null }
                })
            }
        } catch {
            Write-Warning "[$src] $Hash failed: $_"
        }
    }

    return $results
}

# ============================================================
# Convenience: roll all sources into a single verdict.
# Worst-of: malicious > suspicious > clean > unknown.
# ============================================================
function Resolve-HashVerdict {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Results)
    $rank = @{ 'malicious'=4; 'suspicious'=3; 'clean'=2; 'unknown'=1 }
    $best = 0; $verdict = 'unknown'
    foreach ($r in $Results) {
        $v = "$($r.Verdict)"
        if ($rank.ContainsKey($v) -and $rank[$v] -gt $best) {
            $best = $rank[$v]; $verdict = $v
        }
    }
    return $verdict
}
