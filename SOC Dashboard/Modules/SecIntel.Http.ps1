<#
.SYNOPSIS
    Shared HTTP wrapper with retry / exponential-backoff / Retry-After support
    for the SecIntel.ThreatIntel.* provider family and the Update-CveKevFeed
    NVD downloader.

.DESCRIPTION
    Wraps Invoke-RestMethod with consistent transient-failure handling so
    every upstream provider treats 408 / 429 / 5xx the same way. Honors the
    Retry-After header when present (seconds OR HTTP-date). Otherwise uses
    exponential backoff (InitialDelaySeconds * 2^(attempt-1)) with +/- 25%
    jitter. Per-attempt detail goes to Write-Verbose; terminal failures
    rethrow the underlying exception unchanged so callers can still inspect
    the upstream response.

    Compatible with both Windows PowerShell 5.1 (System.Net.WebException)
    and PowerShell 7+ (Microsoft.PowerShell.Commands.HttpResponseException).

.EXAMPLE
    $resp = Invoke-RestMethodWithRetry -Uri $url -Headers @{ Key = $key } `
                                        -MaxAttempts 3 -InitialDelaySeconds 2 -Verbose
#>

if (-not $script:SecIntelHttpInitialized) {
    $script:SecIntelHttpInitialized = $true
    $script:SecIntelHttpRng = [System.Random]::new()
}

function Get-HttpStatusCode {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Exception)

    # PS7+: HttpResponseException exposes Response.StatusCode as HttpStatusCode.
    if ($Exception.Response -and $Exception.Response.StatusCode) {
        try { return [int]$Exception.Response.StatusCode } catch { }
    }
    # PS5.1: WebException -> HttpWebResponse.StatusCode.
    $resp = $Exception.Response
    if ($resp -and $resp.StatusCode) {
        try { return [int]$resp.StatusCode } catch { }
    }
    return 0
}

function Get-RetryAfterSeconds {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Exception)

    $resp = $Exception.Response
    if (-not $resp) { return $null }
    $headers = $null
    if ($resp.Headers) { $headers = $resp.Headers }
    if (-not $headers) { return $null }

    # Headers may be a HttpResponseHeaders, WebHeaderCollection, or hashtable.
    $value = $null
    try {
        if ($headers.GetValues) {
            $vals = $headers.GetValues('Retry-After')
            if ($vals -and $vals.Count -gt 0) { $value = $vals[0] }
        } elseif ($headers['Retry-After']) {
            $value = $headers['Retry-After']
        }
    } catch { }
    if (-not $value) { return $null }

    # Numeric seconds form
    [int]$seconds = 0
    if ([int]::TryParse($value, [ref]$seconds) -and $seconds -ge 0) { return $seconds }

    # HTTP-date form
    [datetime]$when = [datetime]::MinValue
    if ([datetime]::TryParse($value, [ref]$when)) {
        $delta = ($when.ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalSeconds
        if ($delta -gt 0) { return [int][math]::Ceiling($delta) }
        return 0
    }
    return $null
}

function Invoke-RestMethodWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $Uri,
        [hashtable]                        $Headers,
        [string]                           $Method = 'GET',
                                           $Body,
        [string]                           $ContentType,
        [int]                              $TimeoutSec          = 30,
        [int]                              $MaxAttempts         = 3,
        [int]                              $InitialDelaySeconds = 2,
        # Retried by default on common transient classes. Override per-call
        # for upstreams with quirky semantics.
        [int[]]                            $RetryStatusCodes    = @(408, 429, 500, 502, 503, 504)
    )

    $params = @{ Uri = $Uri; Method = $Method; TimeoutSec = $TimeoutSec; ErrorAction = 'Stop' }
    if ($Headers)      { $params['Headers']     = $Headers }
    if ($PSBoundParameters.ContainsKey('Body'))  { $params['Body']        = $Body }
    if ($ContentType)  { $params['ContentType'] = $ContentType }

    $attempt = 1
    $lastErr = $null
    while ($attempt -le $MaxAttempts) {
        try {
            return Invoke-RestMethod @params
        } catch {
            $lastErr = $_
            $status  = Get-HttpStatusCode $_.Exception
            $retryable = ($status -eq 0) -or ($RetryStatusCodes -contains $status)
            if ($attempt -ge $MaxAttempts -or -not $retryable) {
                Write-Warning ("HTTP {0} after {1} attempts: {2} -- {3}" -f $status, $attempt, $Uri, $_.Exception.Message)
                throw
            }

            $retryAfter = Get-RetryAfterSeconds $_.Exception
            if ($retryAfter -ne $null) {
                $delay = $retryAfter
            } else {
                $base   = $InitialDelaySeconds * [math]::Pow(2, $attempt - 1)
                $jitter = $script:SecIntelHttpRng.NextDouble() * 0.5 - 0.25  # +/- 25%
                $delay  = [math]::Max(1, [math]::Round($base * (1 + $jitter)))
            }
            Write-Verbose ("HTTP {0} on attempt {1}/{2} for {3}; sleeping {4}s before retry" -f `
                $status, $attempt, $MaxAttempts, $Uri, $delay)
            Start-Sleep -Seconds $delay
            $attempt++
        }
    }
    # Unreachable -- the loop either returns or throws, but be explicit.
    throw $lastErr
}

# Files are dot-sourced; Export-ModuleMember would fail outside a module context.
