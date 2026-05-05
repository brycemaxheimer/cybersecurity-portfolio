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
    [string]$SmallDataDir,
    [string]$OutputDir,
    [datetime]$Anchor       = '2026-04-29T13:52:40Z',
    [int]$WindowDays        = 1,
    [int]$MaxRowsPerTable   = 12000,
    [int]$HoldoutSeconds    = 0,
    [switch]$SeedFromExisting = $true
)

$ErrorActionPreference = 'Stop'

# $PSScriptRoot is unreliable inside param() defaults under WinPS 5.1 with
# certain -File invocations; resolve here in the body where it's always set.
if (-not $PSBoundParameters.ContainsKey('SmallDataDir') -or [string]::IsNullOrWhiteSpace($SmallDataDir)) {
    $SmallDataDir = Join-Path (Join-Path $PSScriptRoot '..') 'data'
}
if (-not $PSBoundParameters.ContainsKey('OutputDir') -or [string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = $PSScriptRoot
}

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
                # Deterministic hex from the seeded $rng so re-runs produce
                # byte-identical output. Previously used [guid]::NewGuid() which
                # ignored the seed and caused 8000-row CSV churn per build.
                $serviceName     = "svc-$(New-HexString 8 $rng)"
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
    # ~3000 noise rows of legit user file activity (Office docs, browser cache,
    # tmp files). No storyline-malicious file names; those stay unique to seed.
    $smallLines = Get-Content $smallPath
    $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $targetTotal = 3000
    $noiseCount = [math]::Max(0, $targetTotal - $kept.Count)
    Write-Host ("  DeviceFileEvents: keeping {0}, generating {1} noise..." -f $kept.Count, $noiseCount)

    $actions = @{ Values=@('FileCreated','FileModified','FileDeleted','FileRenamed'); Weights=@(45,35,15,5) }
    $kinds = @(
        @{ Ext='.docx';  Folder='C:\Users\{u}\Documents' },
        @{ Ext='.xlsx';  Folder='C:\Users\{u}\Documents' },
        @{ Ext='.pdf';   Folder='C:\Users\{u}\Downloads' },
        @{ Ext='.png';   Folder='C:\Users\{u}\Pictures'  },
        @{ Ext='.tmp';   Folder='C:\Users\{u}\AppData\Local\Temp' },
        @{ Ext='.log';   Folder='C:\Windows\Temp' },
        @{ Ext='.cache'; Folder='C:\Users\{u}\AppData\Local\Microsoft\Windows\INetCache' },
        @{ Ext='.json';  Folder='C:\Users\{u}\AppData\Roaming' },
        @{ Ext='.zip';   Folder='C:\Users\{u}\Downloads' }
    )
    $procs = @('explorer.exe','chrome.exe','OUTLOOK.EXE','code.exe','svchost.exe','OneDrive.exe')

    $timestamps = New-WaveTimestamps -Count $noiseCount -Anchor $Anchor `
                                     -WindowDays $WindowDays -HoldoutSeconds $HoldoutSeconds `
                                     -Frequency ([double]$WindowDays) -Baseline 0.2 -Rng $rng

    $noiseRows = New-Object 'System.Collections.Generic.List[string]' $noiseCount
    foreach ($ts in $timestamps) {
        $hostName = Get-AnyHost -Rng $rng
        $user = Get-NoiseUser -Rng $rng
        $action = Get-Weighted -Field $actions -Rng $rng
        $kind = $kinds[$rng.Next(0, $kinds.Count)]
        $folder = $kind.Folder.Replace('{u}', $user)
        $fname  = "file_$($rng.Next(1000,10000))$($kind.Ext)"
        $proc   = $procs[$rng.Next(0, $procs.Count)]
        $tsIso  = To-IsoZ $ts
        $row = ConvertTo-CsvRow @(
            $tsIso, $tsIso, $hostName, $action, $fname, $folder,
            (New-Sha256 $rng), (New-Sha1 $rng), (New-Md5 $rng),
            $rng.Next(1024, 5000001),
            $proc, $user, $proc, 'DeviceFileEvents'
        )
        $noiseRows.Add($row)
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $noiseRows.Count)
    foreach ($r in $kept)      { $all.Add($r) }
    foreach ($r in $noiseRows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows $all.ToArray()
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

# ------------------------------------------------------------
# Generators ported from kql/data-large/extend-tables.py so the
# expanded dataset can be rebuilt without a Python dependency.
# Each appends ~24h of noise to the small-set seed and writes the
# combined CSV. Sorted asc by timestamp for stable output.
# ------------------------------------------------------------

function Build-Wave {
    param([int]$Count)
    if ($Count -le 0) { return @() }
    return New-WaveTimestamps -Count $Count -Anchor $Anchor `
                              -WindowDays $WindowDays -HoldoutSeconds $HoldoutSeconds `
                              -Frequency ([double]$WindowDays) -Baseline 0.2 -Rng $rng
}

function Build-AuditLogs {
    param([string]$smallPath, [string]$outPath)
    $smallLines = Get-Content $smallPath; $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $target = 1500; $noise = [math]::Max(0, $target - $kept.Count)
    Write-Host ("  AuditLogs: keeping {0}, generating {1} noise..." -f $kept.Count, $noise)
    $ops = @(
        @('Add user',                              'UserManagement',         'success'),
        @('Update user',                           'UserManagement',         'success'),
        @('Delete user',                           'UserManagement',         'success'),
        @('Add member to group',                   'GroupManagement',        'success'),
        @('Remove member from group',              'GroupManagement',        'success'),
        @('Update group',                          'GroupManagement',        'success'),
        @('Reset user password',                   'UserManagement',         'success'),
        @('Add app role assignment to user',       'RoleManagement',         'success'),
        @('Add owner to application',              'ApplicationManagement',  'success'),
        @('Update application',                    'ApplicationManagement',  'success'),
        @('Sign-in activity',                      'SignInLogs',             'success'),
        @('Add user',                              'UserManagement',         'failure'),
        @('Reset user password',                   'UserManagement',         'failure'),
        @('Add member to role',                    'RoleManagement',         'success')
    )
    $rows = New-Object 'System.Collections.Generic.List[string]' $noise
    foreach ($ts in (Build-Wave $noise)) {
        $op = $ops[$rng.Next(0, $ops.Count)]
        $actor = Get-NoiseUser -Rng $rng
        $tgt   = Get-NoiseUser -Rng $rng
        $identity  = "$actor@corp.example"
        $initiated = '{"user":{"userPrincipalName":"' + $identity + '"}}'
        $targets   = '[{"displayName":"' + $tgt + '","userPrincipalName":"' + $tgt + '@corp.example","type":"User"}]'
        $tsIso = To-IsoZ $ts
        $rows.Add( (ConvertTo-CsvRow @(
            $tsIso, $op[0], $op[1], $op[2], '', '',
            $op[0], $tsIso, ($op[0].Split(' ')[0]), $identity, $initiated, $targets,
            'Core Directory', 'AuditLogs'
        )) )
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $rows.Count)
    foreach ($r in $kept) { $all.Add($r) }
    foreach ($r in $rows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows ($all | Sort-Object)
}

function Build-CommonSecurityLog {
    param([string]$smallPath, [string]$outPath)
    $smallLines = Get-Content $smallPath; $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $target = 4000; $noise = [math]::Max(0, $target - $kept.Count)
    Write-Host ("  CommonSecurityLog: keeping {0}, generating {1} noise..." -f $kept.Count, $noise)
    $fws = @(
        @('Palo Alto Networks','PAN-OS','1.0','fw-edge-01'),
        @('Cisco','ASA','9.16','fw-edge-02'),
        @('Fortinet','FortiGate','7.2','fw-perim-01')
    )
    $actionPick = @{ Values=@('allow','deny','drop'); Weights=@(85,10,5) }
    $appPick    = @{ Values=@('https','http','dns','ssh','smtp','ldap','rdp','smb');
                     Weights=@(60,8,15,3,2,2,5,5) }
    $appPort = @{ https=443; http=80; dns=53; ssh=22; smtp=25; ldap=389; rdp=3389; smb=445 }
    $rows = New-Object 'System.Collections.Generic.List[string]' $noise
    foreach ($ts in (Build-Wave $noise)) {
        $fw = $fws[$rng.Next(0, $fws.Count)]
        $action = Get-Weighted -Field $actionPick -Rng $rng
        $app    = Get-Weighted -Field $appPick    -Rng $rng
        $src = if ($rng.NextDouble() -gt 0.3) { Get-NoiseRfc1918Ip -Rng $rng } else { Get-NoisePublicIp -Rng $rng }
        $dst = if ($rng.NextDouble() -gt 0.4) { Get-NoisePublicIp -Rng $rng } else { Get-NoiseRfc1918Ip -Rng $rng }
        $sport = $rng.Next(49152, 65536)
        $dport = $appPort[$app]
        $sev = switch ($action) { 'allow' { 'Low' } 'deny' { 'Medium' } default { 'High' } }
        $rows.Add( (ConvertTo-CsvRow @(
            (To-IsoZ $ts), $fw[0], $fw[1], $fw[2], '100', 'Traffic', $sev, $action, $app,
            $src, $sport, $dst, $dport, 'TCP', $action, $fw[3], 'CommonSecurityLog'
        )) )
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $rows.Count)
    foreach ($r in $kept) { $all.Add($r) }
    foreach ($r in $rows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows ($all | Sort-Object)
}

function Build-DHCP {
    param([string]$smallPath, [string]$outPath)
    $smallLines = Get-Content $smallPath; $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $target = 500; $noise = [math]::Max(0, $target - $kept.Count)
    Write-Host ("  DHCP: keeping {0}, generating {1} noise..." -f $kept.Count, $noise)
    $actions = @(@('Assign',10), @('Renew',11), @('Release',12), @('NACK',16))
    $rows = New-Object 'System.Collections.Generic.List[string]' $noise
    foreach ($ts in (Build-Wave $noise)) {
        $a = $actions[$rng.Next(0, $actions.Count)]
        $hostName = Get-AnyHost -Rng $rng
        $ip   = Get-NoiseRfc1918Ip -Rng $rng
        $tid  = '{0:X5}' -f $rng.Next(10000, 100000)
        $tsIso = To-IsoZ $ts
        $date = $ts.ToString('MM/dd/yyyy')
        $time = $ts.ToString('HH:mm:ss')
        $rows.Add( (ConvertTo-CsvRow @(
            $tsIso, $a[1], $date, $time, $a[0], $ip, $hostName, (New-MacAddress -Rng $rng),
            '', $tid, '0', 'MSFT 5.0', 'DHCP'
        )) )
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $rows.Count)
    foreach ($r in $kept) { $all.Add($r) }
    foreach ($r in $rows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows ($all | Sort-Object)
}

function Build-DeviceImageLoadEvents {
    param([string]$smallPath, [string]$outPath)
    $smallLines = Get-Content $smallPath; $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $target = 3000; $noise = [math]::Max(0, $target - $kept.Count)
    Write-Host ("  DeviceImageLoadEvents: keeping {0}, generating {1} noise..." -f $kept.Count, $noise)
    $dlls = @('kernel32.dll','user32.dll','ntdll.dll','advapi32.dll','ole32.dll',
              'combase.dll','rpcrt4.dll','msvcrt.dll','shell32.dll','shlwapi.dll',
              'wininet.dll','winhttp.dll','crypt32.dll','wintrust.dll','version.dll',
              'iertutil.dll','mscoree.dll','clr.dll','System.dll','System.Core.dll')
    $procs = @('svchost.exe','services.exe','lsass.exe','wininit.exe','explorer.exe',
               'chrome.exe','msedge.exe','OUTLOOK.EXE','Teams.exe','OneDrive.exe',
               'SearchHost.exe','RuntimeBroker.exe','taskhostw.exe','code.exe',
               'WINWORD.EXE','EXCEL.EXE')
    $rows = New-Object 'System.Collections.Generic.List[string]' $noise
    foreach ($ts in (Build-Wave $noise)) {
        $hostName = Get-AnyHost -Rng $rng
        $dll  = $dlls[$rng.Next(0, $dlls.Count)]
        $proc = $procs[$rng.Next(0, $procs.Count)]
        $tsIso = To-IsoZ $ts
        $rows.Add( (ConvertTo-CsvRow @(
            $tsIso, $tsIso, $hostName, $dll, 'C:\Windows\System32',
            (New-Sha256 $rng), $proc, 'C:\Windows\System32', 'DeviceImageLoadEvents'
        )) )
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $rows.Count)
    foreach ($r in $kept) { $all.Add($r) }
    foreach ($r in $rows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows ($all | Sort-Object)
}

function Build-DeviceNetworkInfo {
    param([string]$smallPath, [string]$outPath)
    $smallLines = Get-Content $smallPath; $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $target = 100
    Write-Host ("  DeviceNetworkInfo: keeping {0}, target {1}..." -f $kept.Count, $target)
    $seedDevs = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in $kept) {
        $cells = $r -split ','
        if ($cells.Count -gt 2) { [void]$seedDevs.Add($cells[2]) }
    }
    $needDevs = [math]::Max(0, [int]([math]::Floor($target / 2)) - $seedDevs.Count)
    $newDevs = @()
    foreach ($h in $script:NoiseHosts) {
        if (-not $seedDevs.Contains($h)) { $newDevs += $h; if ($newDevs.Count -ge $needDevs) { break } }
    }
    $adapters = @(@('Ethernet','Ethernet'), @('Wi-Fi','IEEE80211'), @('vEthernet','Ethernet'))
    $rows = New-Object 'System.Collections.Generic.List[string]'
    foreach ($dev in $newDevs) {
        $snaps = $rng.Next(1, 4)
        for ($s = 0; $s -lt $snaps; $s++) {
            $hourBack = $rng.NextDouble() * ($WindowDays * 24 - 0.5) + 0.5
            $ts = $Anchor.AddSeconds(-1 * $hourBack * 3600)
            $tsIso = To-IsoZ $ts
            $ad = $adapters[$rng.Next(0, $adapters.Count)]
            $ip = Get-NoiseRfc1918Ip -Rng $rng
            $ips = '[{"IPAddress":"' + $ip + '"}]'
            $rows.Add( (ConvertTo-CsvRow @(
                $tsIso, $tsIso, $dev, "dev-$($dev.ToLower())", (New-MacAddress -Rng $rng),
                $ips, '["10.0.0.1"]', '["10.0.0.1"]', '["CORP"]',
                $ad[0], 'Up', $ad[1], 'DeviceNetworkInfo'
            )) )
        }
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $rows.Count)
    foreach ($r in $kept) { $all.Add($r) }
    foreach ($r in $rows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows ($all | Sort-Object)
}

function Build-DeviceRegistryEvents {
    param([string]$smallPath, [string]$outPath)
    $smallLines = Get-Content $smallPath; $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $target = 1500; $noise = [math]::Max(0, $target - $kept.Count)
    Write-Host ("  DeviceRegistryEvents: keeping {0}, generating {1} noise..." -f $kept.Count, $noise)
    $actionPick = @{ Values=@('RegistryValueSet','RegistryKeyCreated','RegistryValueDeleted','RegistryKeyDeleted');
                     Weights=@(70,15,10,5) }
    $keys = @(
        @('HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',                       'REG_SZ',     'C:\Program Files\{app}\{app}.exe'),
        @('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{svc}\Parameters',                 'REG_DWORD',  '1'),
        @('HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Common\Roaming',                       'REG_SZ',     '{user}@corp.example'),
        @('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender',                       'REG_DWORD',  '0'),
        @('HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',       'REG_BINARY', 'aabbccdd'),
        @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{app}',          'REG_SZ',     '1.0.0')
    )
    $apps = @('Teams','OneDrive','Office16','Chrome','Edge','Slack','Zoom')
    $svcs = @('DPS','EventLog','Schedule','Spooler','BITS','WinDefend')
    $procs = @('regedit.exe','msiexec.exe','svchost.exe','setup.exe','powershell.exe')
    $valNames = @('Default','Enabled','Path')
    $rows = New-Object 'System.Collections.Generic.List[string]' $noise
    foreach ($ts in (Build-Wave $noise)) {
        $hostName = Get-AnyHost -Rng $rng
        $user = Get-NoiseUser -Rng $rng
        $action = Get-Weighted -Field $actionPick -Rng $rng
        $tmpl = $keys[$rng.Next(0, $keys.Count)]
        $app  = $apps[$rng.Next(0, $apps.Count)]
        $svc  = $svcs[$rng.Next(0, $svcs.Count)]
        $key   = $tmpl[0].Replace('{app}', $app).Replace('{svc}', $svc)
        $value = $tmpl[2].Replace('{app}', $app).Replace('{user}', $user)
        $vname = if ($rng.Next(0,2) -eq 0) { $app } else { $valNames[$rng.Next(0, $valNames.Count)] }
        $proc  = $procs[$rng.Next(0, $procs.Count)]
        $tsIso = To-IsoZ $ts
        $rows.Add( (ConvertTo-CsvRow @(
            $tsIso, $tsIso, $hostName, $action, $key, $vname, $value, $tmpl[1],
            $proc, $user, "$proc /S", 'DeviceRegistryEvents'
        )) )
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $rows.Count)
    foreach ($r in $kept) { $all.Add($r) }
    foreach ($r in $rows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows ($all | Sort-Object)
}

function Build-SecurityAlert {
    param([string]$smallPath, [string]$outPath)
    $smallLines = Get-Content $smallPath; $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $target = 200; $noise = [math]::Max(0, $target - $kept.Count)
    Write-Host ("  SecurityAlert: keeping {0}, generating {1} noise..." -f $kept.Count, $noise)
    $tmpls = @(
        @('Suspicious PowerShell execution',           'Medium','Detected suspicious PowerShell EncodedCommand','Execution',         'T1059.001'),
        @('Anomalous sign-in from unfamiliar location','Medium','User signed in from a country not previously seen','InitialAccess', 'T1078'),
        @('Mass file deletion',                        'Low',   'A user deleted 200+ files within 5 minutes',  'Impact',             'T1485'),
        @('Lateral movement via SMB',                  'High',  'Unusual SMB activity from a single host to many destinations','LateralMovement','T1021.002'),
        @('Credential dumping detected',               'High',  'lsass.exe memory access from an untrusted process','CredentialAccess','T1003.001'),
        @('Suspicious scheduled task',                 'Medium','Schtasks created with binary in ProgramData', 'Persistence',        'T1053.005'),
        @('DNS tunneling indicator',                   'Medium','High volume of TXT-record queries to an uncommon domain','CommandAndControl','T1071.004'),
        @('Possible password spray',                   'High',  'A single source IP attempted login to many distinct accounts','CredentialAccess','T1110.003')
    )
    $statusPick = @{ Values=@('New','InProgress','Resolved'); Weights=@(60,25,15) }
    $seedN = $kept.Count
    $rows = New-Object 'System.Collections.Generic.List[string]' $noise
    $i = 0
    foreach ($ts in (Build-Wave $noise)) {
        $t = $tmpls[$rng.Next(0, $tmpls.Count)]
        $status = Get-Weighted -Field $statusPick -Rng $rng
        $endTs = $ts.AddMinutes($rng.Next(1, 31))
        $sysId = 'alert-{0:0000}' -f (200 + $seedN + $i)
        $entHost = Get-AnyHost -Rng $rng
        $ent = '[{"Type":"host","HostName":"' + $entHost + '"}]'
        $conf = ($rng.NextDouble() * (0.99 - 0.6) + 0.6).ToString('0.00')
        $rows.Add( (ConvertTo-CsvRow @(
            (To-IsoZ $ts), $t[0], $t[0], $t[1], $t[2], 'Azure Sentinel', 'Microsoft', 'Microsoft Defender',
            $sysId, ($t[0] -replace ' ',''), $status, 'High', $conf, '0',
            (To-IsoZ $ts), (To-IsoZ $endTs), $ent, $t[3], $t[4], (To-IsoZ $endTs.AddSeconds(5)),
            'SecurityAlert'
        )) )
        $i++
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $rows.Count)
    foreach ($r in $kept) { $all.Add($r) }
    foreach ($r in $rows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows ($all | Sort-Object)
}

function Build-W3CIISLog {
    param([string]$smallPath, [string]$outPath)
    $smallLines = Get-Content $smallPath; $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $target = 4000; $noise = [math]::Max(0, $target - $kept.Count)
    Write-Host ("  W3CIISLog: keeping {0}, generating {1} noise..." -f $kept.Count, $noise)
    $sites = @(
        @('W3SVC1','SVR-WEB-01',   '10.0.20.10'),
        @('W3SVC2','SVR-WEB-02',   '10.0.20.11'),
        @('W3SVC1','SVR-WEB-LX-01','10.0.30.10')
    )
    $methodPick = @{ Values=@('GET','POST','PUT','DELETE','OPTIONS'); Weights=@(78,18,2,1,1) }
    $paths = @(
        @('/',200), @('/index.html',200), @('/login',200), @('/api/v1/health',200),
        @('/api/v1/users',200), @('/api/v1/orders',200), @('/static/main.css',200),
        @('/static/app.js',200), @('/favicon.ico',200), @('/logout',200),
        @('/admin',401), @('/admin/users',403), @('/.env',404), @('/wp-admin',404),
        @('/api/v1/login',200), @('/api/v1/login',401)
    )
    $uas = @(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'curl/7.81.0',
        'python-requests/2.28.1',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)'
    )
    $rows = New-Object 'System.Collections.Generic.List[string]' $noise
    foreach ($ts in (Build-Wave $noise)) {
        $site = $sites[$rng.Next(0, $sites.Count)]
        $method = Get-Weighted -Field $methodPick -Rng $rng
        $p = $paths[$rng.Next(0, $paths.Count)]
        $cip = if ($rng.NextDouble() -gt 0.4) { Get-NoiseRfc1918Ip -Rng $rng } else { Get-NoisePublicIp -Rng $rng }
        $ua = $uas[$rng.Next(0, $uas.Count)]
        $tsIso = To-IsoZ $ts
        $date = $ts.ToString('yyyy-MM-dd'); $time = $ts.ToString('HH:mm:ss')
        $rows.Add( (ConvertTo-CsvRow @(
            $tsIso, $date, $time, $site[0], $site[1], $site[2], $method, $p[0], '-', '443',
            '-', $cip, $ua, $p[1], '0', '0',
            $rng.Next(200, 50001), $rng.Next(100, 5001),
            $rng.Next(10, 5001), $site[1], 'W3CIISLog'
        )) )
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $rows.Count)
    foreach ($r in $kept) { $all.Add($r) }
    foreach ($r in $rows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows ($all | Sort-Object)
}

function Build-SigninLogs {
    param([string]$smallPath, [string]$outPath)
    $smallLines = Get-Content $smallPath; $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $target = 1000; $noise = [math]::Max(0, $target - $kept.Count)
    Write-Host ("  SigninLogs: keeping {0}, generating {1} noise..." -f $kept.Count, $noise)
    $apps = @(
        @('Office 365','app-office_365'),
        @('Microsoft Teams','app-microsoft_teams'),
        @('Azure Portal','app-azure_portal'),
        @('SharePoint Online','app-sharepoint'),
        @('Exchange Online','app-exchange'),
        @('OneDrive','app-onedrive')
    )
    $locs = @(
        '{"city":"Indianapolis","state":"Indiana","countryOrRegion":"US"}',
        '{"city":"Seattle","state":"Washington","countryOrRegion":"US"}',
        '{"city":"Austin","state":"Texas","countryOrRegion":"US"}',
        '{"city":"Boston","state":"Massachusetts","countryOrRegion":"US"}',
        '{"city":"Chicago","state":"Illinois","countryOrRegion":"US"}'
    )
    $devs = @(
        '{"deviceId":"","operatingSystem":"Windows 11"}',
        '{"deviceId":"","operatingSystem":"Windows 10"}',
        '{"deviceId":"","operatingSystem":"macOS"}',
        '{"deviceId":"","operatingSystem":"iOS"}'
    )
    $rows = New-Object 'System.Collections.Generic.List[string]' $noise
    foreach ($ts in (Build-Wave $noise)) {
        $user = Get-NoiseUser -Rng $rng
        $a = $apps[$rng.Next(0, $apps.Count)]
        $loc = $locs[$rng.Next(0, $locs.Count)]
        $dev = $devs[$rng.Next(0, $devs.Count)]
        $ip = "73.45.12.$($rng.Next(2, 251))"
        $success = ($rng.NextDouble() -gt 0.05)
        $rt = if ($success) { '0' } else { (50053, 50074, 50057)[$rng.Next(0, 3)].ToString() }
        $rd = if ($success) { '' } else { 'Authentication failed' }
        $isRisky = if ($success) { '0' } else { '1' }
        $level   = if ($success) { 'low' } else { 'high' }
        $state   = if ($success) { 'none' } else { 'atRisk' }
        $detail  = if ($success) { '' }     else { 'unfamiliarFeatures' }
        $status  = if ($success) { 'success' } else { 'failure' }
        $userCap = if ($user.Length -gt 0) { $user.Substring(0,1).ToUpper() + $user.Substring(1) } else { $user }
        $rows.Add( (ConvertTo-CsvRow @(
            (To-IsoZ $ts), "$user@corp.example", $userCap, "uid-$user", $ip,
            $a[0], $a[1], 'Browser', $rt, $rd, $status,
            $isRisky, $level, $state, $detail,
            $loc, $dev, 'singleFactorAuthentication', '1', 'Mozilla/5.0', 'SigninLogs'
        )) )
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $rows.Count)
    foreach ($r in $kept) { $all.Add($r) }
    foreach ($r in $rows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows ($all | Sort-Object)
}

function Build-SecurityIncident {
    param([string]$smallPath, [string]$outPath)
    $smallLines = Get-Content $smallPath; $header = $smallLines[0]
    $kept = @($smallLines | Select-Object -Skip 1)
    $target = 50; $noise = [math]::Max(0, $target - $kept.Count)
    Write-Host ("  SecurityIncident: keeping {0}, generating {1} noise..." -f $kept.Count, $noise)
    $titles = @(
        @('Anomalous sign-in pattern observed',            'Low'),
        @('Multiple failed sign-ins detected',             'Medium'),
        @('Suspicious file download flagged by AV',        'Low'),
        @('Defender alert: potentially unwanted application','Low'),
        @('Conditional access policy violation',           'Medium'),
        @('Unusual mailbox forwarding rule created',       'High'),
        @('Possible credential theft attempt',             'High'),
        @('Out-of-office anomaly investigation',           'Low')
    )
    $statusPick = @{ Values=@('New','Active','Closed'); Weights=@(40,30,30) }
    $clsPool = @('','TruePositive','BenignPositive','FalsePositive')
    $seedN = $kept.Count
    $rows = New-Object 'System.Collections.Generic.List[string]' $noise
    $i = 0
    foreach ($ts in (Build-Wave $noise)) {
        $t = $titles[$rng.Next(0, $titles.Count)]
        $status = Get-Weighted -Field $statusPick -Rng $rng
        $cls = if ($status -eq 'Closed') { $clsPool[$rng.Next(0, $clsPool.Count)] } else { '' }
        $clsReason = if ($cls -eq 'BenignPositive') { 'InaccurateData' } else { '' }
        $hoursBack = $rng.NextDouble() * 1.5 + 0.5
        $first = $ts.AddSeconds(-1 * $hoursBack * 3600)
        $alertCount = $rng.Next(1, 4)
        $alerts = New-Object 'System.Collections.Generic.List[string]'
        for ($k = 0; $k -lt $alertCount; $k++) {
            [void]$alerts.Add('"alert-{0:0000}"' -f (300 + $seedN * 5 + $i * 10 + $k))
        }
        $alertsJson = '[' + ($alerts -join ',') + ']'
        $incNum = 2000 + $seedN + $i
        $tsIso = To-IsoZ $ts
        $rows.Add( (ConvertTo-CsvRow @(
            $tsIso, $incNum, $t[0], "Incident $($incNum): $($t[0])",
            $t[1], $status, $cls, $clsReason,
            (To-IsoZ $first), $tsIso, $tsIso, $tsIso, $tsIso,
            $alertsJson, 'automation', 'SecurityIncident'
        )) )
        $i++
    }
    $all = New-Object 'System.Collections.Generic.List[string]' ($kept.Count + $rows.Count)
    foreach ($r in $kept) { $all.Add($r) }
    foreach ($r in $rows) { $all.Add($r) }
    Write-Csv -Path $outPath -Header $header -Rows ($all | Sort-Object)
}

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
