<#
.SYNOPSIS
    Top-level threat-intel dispatcher. Auto-detects IoC type, calls every
    compatible provider, returns normalised IntelCache rows.

.DESCRIPTION
    Single entry point for the dashboard's Threat Intel tab and any
    automation. Each provider runs in series here; the dashboard wraps
    this in a runspace pool to fan out in parallel without blocking
    the WPF UI thread.

    Compatible providers per type:
        ip          -> abuseipdb, virustotal (IP), otx (IP)
        ipv6        -> abuseipdb, virustotal (IP), otx (IP)
        domain      -> virustotal (domain), otx (domain)
        url         -> urlscan, virustotal (URL), otx (URL)
        sha256/1/md5 -> nsrl, virustotal (file), otx (file), malwarebazaar
        product     -> nist

    The hash providers go through Get-HashIntel from
    SecIntel.HashLookup.ps1 so the legacy HashIntel cache still gets used.

.NOTES
    Dot-source SecIntel.Schema.ps1, SecIntel.Settings.ps1,
    SecIntel.HashLookup.ps1, SecIntel.ThreatIntel.Core.ps1, and each of
    the SecIntel.ThreatIntel.<provider>.ps1 files first. This script does
    the dot-sources for you when run normally.
#>

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.Settings.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.Http.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.ThreatIntel.Core.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.HashLookup.ps1')         -ErrorAction SilentlyContinue
. (Join-Path $PSScriptRoot 'SecIntel.ThreatIntel.AbuseIPDB.ps1') -ErrorAction SilentlyContinue
. (Join-Path $PSScriptRoot 'SecIntel.ThreatIntel.UrlScan.ps1')   -ErrorAction SilentlyContinue
. (Join-Path $PSScriptRoot 'SecIntel.ThreatIntel.Nsrl.ps1')      -ErrorAction SilentlyContinue
. (Join-Path $PSScriptRoot 'SecIntel.ThreatIntel.Nist.ps1')      -ErrorAction SilentlyContinue

# ============================================================
# Map IoC type -> ordered list of provider invocations.
# Each entry is a hashtable with a Name and a script block that
# accepts the IoC value and returns a row (or $null on failure).
# ============================================================
function Get-IntelProviderPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$IocType)

    $hashLookup = {
        param($v, $src)
        if (Get-Command Get-HashIntel -ErrorAction SilentlyContinue) {
            (Get-HashIntel -Hash $v -Sources $src -ErrorAction SilentlyContinue) | Where-Object { $_.Source -eq $src } | Select-Object -First 1
        }
    }

    switch ($IocType) {
        'ip'     { return @(
                    @{ Name='abuseipdb';  Run={ param($v) Get-AbuseIpIntel -Ip $v -ErrorAction SilentlyContinue } }
                  ) }
        'ipv6'   { return @(
                    @{ Name='abuseipdb';  Run={ param($v) Get-AbuseIpIntel -Ip $v -ErrorAction SilentlyContinue } }
                  ) }
        'domain' { return @() }   # extension point: VT/OTX domain endpoints
        'url'    { return @(
                    @{ Name='urlscan';    Run={ param($v) Get-UrlScanIntel -Url $v -ErrorAction SilentlyContinue } }
                  ) }
        'sha256' { return @(
                    @{ Name='nsrl';          Run={ param($v) Get-NsrlIntel -Hash $v -ErrorAction SilentlyContinue } }
                    # GetNewClosure() goes on the SCRIPT BLOCK so $hashLookup is
                    # captured from this function's scope. Hashtables don't have
                    # that method - calling it on the outer @{} crashes WPF.
                    @{ Name='virustotal';    Run={ param($v) & $hashLookup $v 'virustotal'    }.GetNewClosure() }
                    @{ Name='malwarebazaar'; Run={ param($v) & $hashLookup $v 'malwarebazaar' }.GetNewClosure() }
                    @{ Name='otx';           Run={ param($v) & $hashLookup $v 'otx'           }.GetNewClosure() }
                  ) }
        'sha1'   { return @(
                    @{ Name='nsrl';       Run={ param($v) Get-NsrlIntel -Hash $v -ErrorAction SilentlyContinue } }
                  ) }
        'md5'    { return @(
                    @{ Name='nsrl';       Run={ param($v) Get-NsrlIntel -Hash $v -ErrorAction SilentlyContinue } }
                  ) }
        'product'{ return @(
                    @{ Name='nist';       Run={ param($v) Get-NistProductIntel -Product $v -ErrorAction SilentlyContinue } }
                  ) }
        default  { return @() }
    }
}

# ============================================================
# Synchronous dispatcher - calls every compatible provider in turn,
# returns the list of result rows.  The dashboard uses the parallel
# wrapper below; CLI users can call this directly.
# ============================================================
function Invoke-IntelLookup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Value,
        [string]$IocType,
        [switch]$ForceRefresh,
        [string[]]$ExcludeProviders
    )

    $type = if ($IocType) { $IocType } else { Resolve-IocType $Value }
    if (-not $type) {
        throw "Invoke-IntelLookup: could not determine IoC type for '$Value'. Pass -IocType explicitly (ip|ipv6|domain|url|sha256|sha1|md5|product)."
    }

    $plan    = Get-IntelProviderPlan -IocType $type
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($p in $plan) {
        if ($ExcludeProviders -contains $p.Name) { continue }
        try {
            $r = & $p.Run $Value
            if ($r) { [void]$results.Add($r) }
        } catch {
            Write-Warning "Provider '$($p.Name)' failed for $Value : $($_.Exception.Message)"
        }
    }
    return $results
}

# ============================================================
# Configured-provider checklist for the status bar.
# Returns a list of @{ Name; Configured; Reason } entries.
# ============================================================
function Get-IntelProviderStatus {
    [CmdletBinding()]
    param()

    $vt    = Get-AppSecret 'apikey.virustotal'
    $otx   = Get-AppSecret 'apikey.otx'
    $abu   = Get-AppSecret 'apikey.abuseipdb'
    $usc   = Get-AppSecret 'apikey.urlscan'
    $nvd   = Get-AppSecret 'apikey.nvd'
    $mbz   = Get-AppSecret 'apikey.malwarebazaar'

    @(
        [PSCustomObject]@{ Name='VirusTotal';    Configured=[bool]$vt;  Reason=if ($vt)  { '' } else { "Set-AppSecret 'apikey.virustotal' '<KEY>'" } }
        [PSCustomObject]@{ Name='OTX';           Configured=[bool]$otx; Reason=if ($otx) { '' } else { "Set-AppSecret 'apikey.otx' '<KEY>'" } }
        [PSCustomObject]@{ Name='AbuseIPDB';     Configured=[bool]$abu; Reason=if ($abu) { '' } else { "Set-AppSecret 'apikey.abuseipdb' '<KEY>'" } }
        [PSCustomObject]@{ Name='URLScan';       Configured=[bool]$usc; Reason=if ($usc) { '' } else { "(public scans work without a key)" } }
        [PSCustomObject]@{ Name='NSRL/CIRCL';    Configured=$true;      Reason='no key needed' }
        [PSCustomObject]@{ Name='NIST NVD';      Configured=$true;      Reason=if ($nvd) { 'with key (50 req/30s)' } else { 'no key (5 req/30s)' } }
        [PSCustomObject]@{ Name='MalwareBazaar'; Configured=[bool]$mbz; Reason=if ($mbz) { '' } else { "abuse.ch now requires a key. Get one from https://auth.abuse.ch/ then: Set-AppSecret 'apikey.malwarebazaar' '<KEY>'" } }
    )
}

# Files are dot-sourced; Export-ModuleMember would fail outside a module context.
