<#
    Build-LargeDataset.ps1
    ----------------------
    Generates the "Expanded" CSV pack for /lab/ playground -- ~10 MB total,
    storyline-anchored, includes the small dataset's storyline beats VERBATIM
    so any query that worked against /kql/data/ returns a SUPERSET when run
    against /kql/data-large/.

    Run from the repo root:
        pwsh ./kql/data-large/Build-LargeDataset.ps1

    Targets (rough):
        SecurityEvent          ~8000 rows
        DeviceProcessEvents   ~12000
        DeviceLogonEvents      ~3000
        DeviceNetworkEvents    ~6000
        DeviceFileEvents       ~4000
        Syslog                 ~4000
        AuditLogs              ~1500
        SigninLogs             ~2500
        SecurityIncident         200
        CommonSecurityLog      ~5000
        (others)              ~1000-2000 each

    Storyline anchor: 2026-04-29T13:52:40Z (matches gold-results.json).
    The expanded set spans ~14 days back from the anchor.

    Layered storylines (write the table-specific generators to weave these in):
        1. The original brute-force-then-success on WS-FINANCE-01 (existing
           small-set rows kept verbatim).
        2. Slow-drip password spray from 198.51.100.55 hitting 4 accounts over
           18 hours.
        3. Hands-on-keyboard from CORP\dchen on WS-DEV-02 (mimikatz, rubeus,
           encoded PowerShell, beacon-shaped DNS).
        4. Phishing-link click chain on WS-HR-03: Outlook -> chrome.exe ->
           winword.exe -> EncodedCommand.
        5. Background noise: cron jobs, normal interactive logons, browser
           network calls, scheduled-task creates, log rotates.
#>

[CmdletBinding()]
param(
    [string]$SmallDataDir   = (Join-Path (Join-Path $PSScriptRoot '..') 'data'),
    [string]$OutputDir      = $PSScriptRoot,
    [datetime]$Anchor       = '2026-04-29T13:52:40Z',
    [int]$WindowDays        = 1,
    [int]$MaxRowsPerTable   = 12000,
    [int]$HoldoutSeconds    = 0,
    [switch]$SeedFromExisting = $true
)

$ErrorActionPreference = 'Stop'
$rng = [System.Random]::new(42)   # deterministic; bump seed if you want fresh noise

# Layer 1+2: shared field libraries, weighted-pick, wave timestamper.
. (Join-Path $PSScriptRoot 'LabFields.ps1')

function Write-Csv {
    param(
        [string]$Path,
        [string]$Header,
        [string[]]$Rows
    )
    # PS5.1 Set-Content -Encoding UTF8 emits a BOM; the JS CSV parser doesn't
    # strip BOMs, so the first column header would become "﻿TimeGenerated"
    # and break schema mapping. Force UTF-8 *without* BOM.
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $all = New-Object 'System.Collections.Generic.List[string]' ($Rows.Count + 1)
    $all.Add($Header)
    foreach ($r in $Rows) { $all.Add($r) }
    [System.IO.File]::WriteAllLines($Path, $all.ToArray(), $utf8NoBom)
    Write-Host ("  wrote {0,-32}  {1,8} rows" -f (Split-Path $Path -Leaf), $Rows.Count)
}

# ------------------------------------------------------------
# Per-table generators. Each receives the small CSV (verbatim
# rows kept) and produces the expanded CSV.
# Fill in the body with table-specific noise. Skeletons below.
# ------------------------------------------------------------

function Build-SecurityEvent {
    param([string]$smallPath, [string]$outPath)
    # Layered output:
    #   1. Verbatim copy of every small-set row (storyline preservation -- the
    #      gold-results contract pins to these rows).
    #   2. ~7800 noise rows distributed across [Anchor-14d, Anchor-1h] with a
    #      sine-bump density. Holdout of 1h keeps noise out of the recent
    #      window every "ago(1h)" practice question filters on.
    #   3. Noise users/hosts/IPs are drawn from disjoint pools (no storyline
    #      collisions) so 4625-against-bryce-from-198.51.100.55 stays unique.

    $smallLines = Get-Content $smallPath
    $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)

    $targetTotal = 8000
    $noiseCount  = $targetTotal - $kept.Count
    if ($noiseCount -lt 0) { $noiseCount = 0 }

    Write-Host ("  SecurityEvent: keeping {0} small-set rows, generating {1} noise rows..." -f $kept.Count, $noiseCount)

    $timestamps = New-WaveTimestamps -Count $noiseCount -Anchor $Anchor `
                                     -WindowDays $WindowDays -HoldoutSeconds $HoldoutSeconds `
                                     -Frequency ([double]$WindowDays) -Baseline 0.2 -Rng $rng

    # Prepare buffers
    $noiseRows = New-Object 'System.Collections.Generic.List[string]' $noiseCount

    foreach ($ts in $timestamps) {
        $eid     = Get-Weighted -Field $script:F_NoiseEventID -Rng $rng
        $computer = Get-Weighted -Field $script:F_NoiseHosts -Rng $rng
        $user    = Get-Weighted -Field $script:F_NoiseUsers   -Rng $rng
        $account = "CORP\$user"

        # Per-EID column population -- match the small-set's null patterns.
        $activity=''; $accountType='User'; $accountDomain='CORP'
        $accountName=$user; $targetUserName=$user; $targetDomainName='CORP'
        $ipAddress=''; $ipPort=''; $logonType=''; $logonProcessName=''
        $failureReason=''; $processName=''; $newProcessName=''
        $parentProcessName=''; $commandLine=''; $serviceName=''; $serviceFileName=''
        $eventSource='Microsoft-Windows-Security-Auditing'

        switch ($eid) {
            4624 {
                $logonType        = Get-Weighted -Field $script:F_NoiseLogonType -Rng $rng
                $logonProcessName = Get-Weighted -Field $script:F_LogonProcessName -Rng $rng
                $ipAddress        = Get-NoiseRfc1918Ip -Rng $rng
                $ipPort           = Get-EphemeralPort -Rng $rng
            }
            4625 {
                $logonType        = Get-Weighted -Field $script:F_NoiseLogonType -Rng $rng
                $logonProcessName = Get-Weighted -Field $script:F_LogonProcessName -Rng $rng
                $failureReason    = Get-Weighted -Field $script:F_FailureReason -Rng $rng
                $ipAddress        = Get-NoiseRfc1918Ip -Rng $rng
                $ipPort           = Get-EphemeralPort -Rng $rng
            }
            4634 {
                $logonType        = Get-Weighted -Field $script:F_NoiseLogonType -Rng $rng
                $logonProcessName = Get-Weighted -Field $script:F_LogonProcessName -Rng $rng
            }
            4672 {
                $accountType = 'Admin'
            }
            4688 {
                $proc        = Get-Weighted -Field $script:F_LegitProcess -Rng $rng
                $parent      = Get-Weighted -Field $script:F_LegitProcess -Rng $rng
                $processName = "C:\Windows\System32\$proc"
                $newProcessName = $processName
                $parentProcessName = "C:\Windows\System32\$parent"
                $commandLine = """$processName"""
            }
            4697 {
                $serviceName     = "svc-$([guid]::NewGuid().ToString().Substring(0,8))"
                $serviceFileName = "C:\Program Files\$serviceName\$serviceName.exe"
            }
            4720 {
                # New user account created (rare). Account = creator, Target = the new user.
                $targetUserName = "newuser$($rng.Next(100,999))"
            }
            4732 {
                # Member added to local group.
                $targetUserName = "newuser$($rng.Next(100,999))"
            }
            default { }
        }

        # CSV-escape: only quote fields containing commas or quotes.
        $row = @(
            (To-IsoZ $ts),
            $computer,
            $eid,
            $activity,
            $account,
            $accountType,
            $accountDomain,
            $accountName,
            $targetUserName,
            $targetDomainName,
            $ipAddress,
            $ipPort,
            $logonType,
            $logonProcessName,
            $failureReason,
            $processName,
            $newProcessName,
            $parentProcessName,
            $commandLine,
            $serviceName,
            $serviceFileName,
            $eventSource,
            'Security',
            'SecurityEvent'
        ) | ForEach-Object {
            $s = [string]$_
            if ($s -match '[,"\r\n]') { '"' + $s.Replace('"','""') + '"' } else { $s }
        }

        $noiseRows.Add(($row -join ','))
    }

    # Combine: small-set rows first (no sort -- preserve their exact order
    # and grouping), then noise. Keeps the storyline reading top-of-file.
    $allRows = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $noiseRows.Count)
    foreach ($r in $kept)      { $allRows.Add($r) }
    foreach ($r in $noiseRows) { $allRows.Add($r) }

    Write-Csv -Path $outPath -Header $header -Rows $allRows.ToArray()
}

function ConvertTo-CsvRow {
    param([object[]]$Cells)
    $out = New-Object 'System.Collections.Generic.List[string]' $Cells.Count
    foreach ($c in $Cells) {
        $s = [string]$c
        if ($s -match '[,"\r\n]') { $out.Add(('"' + $s.Replace('"','""') + '"')) }
        else { $out.Add($s) }
    }
    return ($out -join ',')
}

function Build-DeviceProcessEvents {
    param([string]$smallPath, [string]$outPath)
    # ~5000 noise rows: legit Windows process spawns from explorer/svchost/etc
    # under noise users on noise hosts. No storyline file collisions
    # (mimikatz/rubeus etc stay unique to small-set).
    $smallLines = Get-Content $smallPath
    $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $targetTotal = 5000
    $noiseCount = [math]::Max(0, $targetTotal - $kept.Count)
    Write-Host ("  DeviceProcessEvents: keeping {0}, generating {1} noise..." -f $kept.Count, $noiseCount)

    $timestamps = New-WaveTimestamps -Count $noiseCount -Anchor $Anchor `
                                     -WindowDays $WindowDays -HoldoutSeconds $HoldoutSeconds `
                                     -Frequency ([double]$WindowDays) -Baseline 0.2 -Rng $rng

    $noiseRows = New-Object 'System.Collections.Generic.List[string]' $noiseCount
    foreach ($ts in $timestamps) {
        $computer = Get-Weighted -Field $script:F_NoiseHosts -Rng $rng
        $user     = Get-Weighted -Field $script:F_NoiseUsers -Rng $rng
        $file     = Get-Weighted -Field $script:F_DPE_FileName   -Rng $rng
        $parent   = Get-Weighted -Field $script:F_DPE_ParentName -Rng $rng
        $signer   = Get-Weighted -Field $script:F_SignerType -Rng $rng
        $integ    = Get-Weighted -Field $script:F_IntegrityLevel -Rng $rng
        $folder   = if ($file -match '^(chrome|msedge|firefox|OUTLOOK|Teams|code|OneDrive)') { 'C:\Program Files' } else { 'C:\Windows\System32' }
        $tsIso = To-IsoZ $ts
        $row = ConvertTo-CsvRow @(
            $tsIso, $tsIso, $computer, "dev-$([string]$computer.ToLower())",
            $user, 'CORP',
            $file, $folder, $file,
            $rng.Next(1000,9999),
            (New-Sha256 $rng), (New-Sha1 $rng), (New-Md5 $rng),
            $rng.Next(50000, 5000000),
            $parent, 'C:\Windows', "C:\Windows\$parent",
            $rng.Next(100,9999),
            $user,
            (New-Sha256 $rng),
            $signer, 'Microsoft', $integ, 'TokenElevationTypeDefault',
            'DeviceProcessEvents'
        )
        $noiseRows.Add($row)
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $noiseRows.Count)
    foreach ($r in $kept)      { $all.Add($r) }
    foreach ($r in $noiseRows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows $all.ToArray()
}

function Build-DeviceLogonEvents {
    param([string]$smallPath, [string]$outPath)
    # ~3000 noise rows: mostly successful logons across hosts/users via RFC1918
    # IPs. Failed-logon noise uses noise users only (NEVER bryce, the
    # storyline brute-force target).
    $smallLines = Get-Content $smallPath
    $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $targetTotal = 3000
    $noiseCount = [math]::Max(0, $targetTotal - $kept.Count)
    Write-Host ("  DeviceLogonEvents: keeping {0}, generating {1} noise..." -f $kept.Count, $noiseCount)

    $timestamps = New-WaveTimestamps -Count $noiseCount -Anchor $Anchor `
                                     -WindowDays $WindowDays -HoldoutSeconds $HoldoutSeconds `
                                     -Frequency ([double]$WindowDays) -Baseline 0.2 -Rng $rng

    $noiseRows = New-Object 'System.Collections.Generic.List[string]' $noiseCount
    foreach ($ts in $timestamps) {
        $computer = Get-Weighted -Field $script:F_NoiseHosts -Rng $rng
        $user     = Get-Weighted -Field $script:F_NoiseUsers -Rng $rng
        $action   = Get-Weighted -Field $script:F_DLE_Action -Rng $rng
        $logonType= Get-Weighted -Field $script:F_DLE_LogonType -Rng $rng
        $initProc = Get-Weighted -Field $script:F_DLE_InitProc -Rng $rng
        $sid      = "S-1-5-21-1-2-3-{0}" -f $rng.Next(1100, 9999)
        $logonId  = $rng.Next(100000, 999999)
        $remoteIp = Get-NoiseRfc1918Ip -Rng $rng
        $remotePort = $rng.Next(49152, 65535)
        $failReason = ''
        if ($action -eq 'LogonFailed') {
            $failReason = Get-Weighted -Field $script:F_DLE_FailReason -Rng $rng
        }
        $tsIso = To-IsoZ $ts
        $row = ConvertTo-CsvRow @(
            $tsIso, $tsIso, $computer, $action,
            $user, 'CORP', $sid, $logonType, $failReason,
            0, $logonId, $remoteIp, 'Private', $remotePort, 'Kerberos',
            $initProc, 'SYSTEM',
            'DeviceLogonEvents'
        )
        $noiseRows.Add($row)
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $noiseRows.Count)
    foreach ($r in $kept)      { $all.Add($r) }
    foreach ($r in $noiseRows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows $all.ToArray()
}

function Build-DeviceNetworkEvents {
    param([string]$smallPath, [string]$outPath)
    # ~6000 noise rows: browser/Outlook/Teams HTTPS to public IPs from
    # known-good processes. Storyline (powershell.exe to 198.51.100.55 from
    # WS-DEV-02) stays unique because noise IPs come from a disjoint pool
    # and noise process pool excludes powershell.exe.
    $smallLines = Get-Content $smallPath
    $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $targetTotal = 6000
    $noiseCount = [math]::Max(0, $targetTotal - $kept.Count)
    Write-Host ("  DeviceNetworkEvents: keeping {0}, generating {1} noise..." -f $kept.Count, $noiseCount)

    $timestamps = New-WaveTimestamps -Count $noiseCount -Anchor $Anchor `
                                     -WindowDays $WindowDays -HoldoutSeconds $HoldoutSeconds `
                                     -Frequency ([double]$WindowDays) -Baseline 0.2 -Rng $rng

    $noiseRows = New-Object 'System.Collections.Generic.List[string]' $noiseCount
    foreach ($ts in $timestamps) {
        $computer = Get-Weighted -Field $script:F_NoiseHosts -Rng $rng
        $user     = Get-Weighted -Field $script:F_NoiseUsers -Rng $rng
        $action   = Get-Weighted -Field $script:F_DNE_Action -Rng $rng
        $proc     = Get-Weighted -Field $script:F_DNE_Process -Rng $rng
        $rport    = Get-Weighted -Field $script:F_DNE_RemotePort -Rng $rng
        $localIp  = "10.0.{0}.{1}" -f $rng.Next(1,30), $rng.Next(2,254)
        $localPort= $rng.Next(49152, 65535)
        $remoteIp = Get-NoisePublicIp -Rng $rng
        $tsIso = To-IsoZ $ts
        $folder = if ($proc -match '^(chrome|msedge|firefox|OUTLOOK|Teams|OneDrive|code)') { 'C:\Program Files' } else { 'C:\Windows\System32' }
        $row = ConvertTo-CsvRow @(
            $tsIso, $tsIso, $computer, $action,
            $localIp, 'Private', $localPort,
            $remoteIp, 'Public', $rport,
            '', 'Tcp',
            $proc, $folder, $proc,
            $user,
            (New-Sha256 $rng),
            'DeviceNetworkEvents'
        )
        $noiseRows.Add($row)
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $noiseRows.Count)
    foreach ($r in $kept)      { $all.Add($r) }
    foreach ($r in $noiseRows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows $all.ToArray()
}

function Build-DeviceFileEvents {
    param([string]$smallPath, [string]$outPath)
    Copy-Item $smallPath $outPath -Force
    Write-Host "  TODO: DeviceFileEvents expansion -- copied small-set verbatim for now"
}

function Build-Syslog {
    param([string]$smallPath, [string]$outPath)
    # ~3000 noise rows: cron jobs, normal sshd publickey logins, systemd unit
    # transitions, kernel UFW blocks, package upgrades. Storyline
    # (sshd-session "Failed password for test from 198.51.100.55" on
    # SVR-LINUX-01) stays unique because noise sshd messages use the
    # publickey-accept template, not failed-password.
    $smallLines = Get-Content $smallPath
    $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $targetTotal = 3000
    $noiseCount = [math]::Max(0, $targetTotal - $kept.Count)
    Write-Host ("  Syslog: keeping {0}, generating {1} noise..." -f $kept.Count, $noiseCount)

    $timestamps = New-WaveTimestamps -Count $noiseCount -Anchor $Anchor `
                                     -WindowDays $WindowDays -HoldoutSeconds $HoldoutSeconds `
                                     -Frequency ([double]$WindowDays) -Baseline 0.2 -Rng $rng

    $noiseRows = New-Object 'System.Collections.Generic.List[string]' $noiseCount
    foreach ($ts in $timestamps) {
        $computer = Get-Weighted -Field $script:F_SyslogHosts -Rng $rng
        $hostIp   = $script:F_SyslogHostIps[$computer]
        $facility = Get-Weighted -Field $script:F_SyslogFacility -Rng $rng
        $severity = Get-Weighted -Field $script:F_SyslogSeverity -Rng $rng
        $proc     = Get-Weighted -Field $script:F_SyslogProcess -Rng $rng
        $procId   = $rng.Next(100, 65535)
        $templates = $script:F_SyslogMsgs[$proc]
        if (-not $templates) { $templates = @('Service log entry') }
        $tmpl = $templates[$rng.Next(0, $templates.Count)]
        $msg = Format-SyslogMessage -Template $tmpl -Rng $rng
        $tsIso = To-IsoZ $ts
        $row = ConvertTo-CsvRow @(
            $tsIso, $tsIso, $computer, $computer, $hostIp,
            $facility, $severity, $proc, $procId, $msg,
            'syslog-collector-01', 'Syslog'
        )
        $noiseRows.Add($row)
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $noiseRows.Count)
    foreach ($r in $kept)      { $all.Add($r) }
    foreach ($r in $noiseRows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows $all.ToArray()
}

function Build-AuditLogs                { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: AuditLogs"                 }
function Build-SigninLogs               { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: SigninLogs"                }
function Build-SecurityIncident         { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: SecurityIncident"          }
function Build-CommonSecurityLog        { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: CommonSecurityLog"         }
function Build-DHCP                     { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: DHCP"                      }
function Build-DeviceImageLoadEvents    { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: DeviceImageLoadEvents"     }
function Build-DeviceNetworkInfo        { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: DeviceNetworkInfo"         }
function Build-DeviceRegistryEvents     { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: DeviceRegistryEvents"      }
function Build-SecurityAlert            { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: SecurityAlert"             }
function Build-W3CIISLog                { param($s,$o) Copy-Item $s $o -Force; Write-Host "  TODO: W3CIISLog"                 }

# ------------------------------------------------------------
# Drive: discover every table in the small set and dispatch.
# ------------------------------------------------------------

Write-Host "Build-LargeDataset.ps1"
Write-Host "  small data:  $SmallDataDir"
Write-Host "  output:      $OutputDir"
Write-Host "  anchor:      $(To-IsoZ $Anchor)"
Write-Host "  window:      $WindowDays days"
Write-Host ""

$tables = Get-ChildItem $SmallDataDir -Filter '*.csv' | Sort-Object Name
foreach ($t in $tables) {
    $name = [System.IO.Path]::GetFileNameWithoutExtension($t.Name)
    $smallPath = $t.FullName
    $outPath = Join-Path $OutputDir $t.Name
    $fn = Get-Command "Build-$name" -ErrorAction SilentlyContinue
    if ($fn) {
        & $fn $smallPath $outPath
    } else {
        Copy-Item $smallPath $outPath -Force
        Write-Host "  no Build-$name function defined -- copied small-set verbatim"
    }
}

Write-Host ""
Write-Host "Done. Browse to /kql/ and switch the Dataset toggle to 'Expanded' to load."
