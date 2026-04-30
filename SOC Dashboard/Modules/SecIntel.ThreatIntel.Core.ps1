<#
.SYNOPSIS
    Shared helpers for the SecIntel threat-intel providers. Cache CRUD against
    the IntelCache table, verdict-driven TTL, type detection.

.DESCRIPTION
    Every provider module (VT, OTX, URLScan, AbuseIPDB, NSRL, NIST) calls
    Save-IntelCache to upsert results and Get-IntelCacheFresh to honor TTLs.
    Auto-detection of IoC type from a free-text input also lives here.

.NOTES
    Dot-source SecIntel.Schema.ps1 first.
#>

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')

# ============================================================
# Verdict -> TTL (seconds). Same shape as HashIntel; separate
# variable so providers can tune (e.g. NSRL "known-good" longer).
# ============================================================
$script:IntelTtl = @{
    'malicious'  = 7  * 86400
    'suspicious' = 7  * 86400
    'clean'      = 30 * 86400
    'known-good' = 90 * 86400
    'unknown'    = 1  * 86400
}

# ============================================================
# Auto-detect IoC type from a free-text input. Returns:
#   ip | ipv6 | domain | url | sha256 | sha1 | md5 | $null
# Order matters: hash-by-length first (most specific), then URL,
# then IP, then domain.
# ============================================================
function Resolve-IocType {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Value)
    $v = $Value.Trim()
    if (-not $v) { return $null }

    # Hash by length and content
    if ($v -match '^[a-fA-F0-9]{64}$') { return 'sha256' }
    if ($v -match '^[a-fA-F0-9]{40}$') { return 'sha1'   }
    if ($v -match '^[a-fA-F0-9]{32}$') { return 'md5'    }

    # URL: must have scheme
    if ($v -match '^[a-zA-Z][a-zA-Z0-9+\-.]*://') { return 'url' }

    # IPv4
    if ($v -match '^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$') { return 'ip' }

    # IPv6 (loose)
    if ($v -match '^[0-9a-fA-F:]+$' -and $v -match ':' -and $v.Length -le 39) { return 'ipv6' }

    # Domain (one or more labels with TLD)
    if ($v -match '^([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$') { return 'domain' }

    return $null
}

# ============================================================
# Cache read - returns the row if it exists AND is within TTL.
# ============================================================
function Get-IntelCacheFresh {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IocType,
        [Parameter(Mandatory)][string]$IocValue,
        [Parameter(Mandatory)][string]$Source,
        [int]$MaxAgeSeconds = 0
    )
    $row = Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "SELECT * FROM IntelCache WHERE IocType=@t AND IocValue=@v AND Source=@s" `
        -SqlParameters @{ t=$IocType; v=$IocValue; s=$Source } | Select-Object -First 1
    if (-not $row) { return $null }

    try { $fetched = [DateTime]::Parse($row.FetchedAt) } catch { return $null }
    $ageSec = ((Get-Date).ToUniversalTime() - $fetched.ToUniversalTime()).TotalSeconds
    $ttl = if ($MaxAgeSeconds -gt 0)                    { $MaxAgeSeconds }
           elseif ($script:IntelTtl.ContainsKey($row.Verdict)) { $script:IntelTtl[$row.Verdict] }
           else                                          { 86400 }
    if ($ageSec -gt $ttl) { return $null }
    return $row
}

# ============================================================
# Upsert a result row into IntelCache.
# Caller passes a hashtable with the well-known keys.
# ============================================================
function Save-IntelCache {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Row)

    foreach ($k in @('IocType','IocValue','Source','Verdict','Family','Tags','Reputation','DetectionRatio','ProviderUrl','FirstSeen','LastSeen','RawJson','FetchedAt','TtlSeconds')) {
        if (-not $Row.ContainsKey($k)) { $Row[$k] = $null }
    }

    Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT OR REPLACE INTO IntelCache (IocType, IocValue, Source, Verdict, Family, Tags,
                        Reputation, DetectionRatio, ProviderUrl,
                        FirstSeen, LastSeen, RawJson, FetchedAt, TtlSeconds)
VALUES (@IocType,@IocValue,@Source,@Verdict,@Family,@Tags,
        @Reputation,@DetectionRatio,@ProviderUrl,
        @FirstSeen,@LastSeen,@RawJson,@FetchedAt,@TtlSeconds)
"@ -SqlParameters $Row
}

# ============================================================
# Resolve verdict to a colour name the dashboard understands.
# ============================================================
function Resolve-VerdictColor {
    param([string]$Verdict)
    switch -Regex ($Verdict) {
        '^malicious$'   { 'Danger' ; break }
        '^suspicious$'  { 'Warn'   ; break }
        '^known-good$'  { 'AccentAlt'; break }
        '^clean$'       { 'AccentAlt'; break }
        default         { 'FgDim'  ; break }
    }
}

# Files are dot-sourced; Export-ModuleMember would fail outside a module context.
