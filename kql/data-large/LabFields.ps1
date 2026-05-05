<#
    LabFields.ps1
    Shared field libraries + weighted-pick helpers for the Build-LargeDataset
    per-table generators. Dot-source from Build-LargeDataset.ps1.

    Conventions:
      - $script:Rng is the deterministic Random instance owned by the caller.
        Helpers use [System.Random] from the calling scope so seeded runs stay
        reproducible.
      - "Storyline" cast (bryce, dchen, jadams, mholmes, backup_svc, the 5
        primary hosts) is OFF-LIMITS to noise generators -- those rows are
        owned by /kql/data and the gold-results contract.
      - "Noise" cast is everything else: 12 background users, 8 background
        hosts, RFC1918 IP pools, browsing-IP pools.
#>

# ---------- Cast ----------
$script:NoiseUsers = @(
    'jharris','kpatel','mwhite','rmorales','sthompson','agarcia',
    'lwoods','tnguyen','ehernandez','dkim','bsato','olopez'
)
$script:NoiseHosts = @(
    'WS-IT-01','WS-IT-02','WS-MKT-01','WS-MKT-02','WS-OPS-01',
    'WS-OPS-02','LAP-EXEC-01','LAP-SALES-03'
)
$script:AllHosts = @(
    'WS-FINANCE-01','WS-DEV-02','WS-HR-03','SVR-DC-01','SVR-WEB-01'
) + $script:NoiseHosts

$script:LegitProcesses = @(
    'svchost.exe','services.exe','lsass.exe','wininit.exe','smss.exe',
    'csrss.exe','winlogon.exe','explorer.exe','taskmgr.exe','msiexec.exe',
    'chrome.exe','msedge.exe','firefox.exe','code.exe','OUTLOOK.EXE',
    'WINWORD.EXE','EXCEL.EXE','Teams.exe','OneDrive.exe','SearchHost.exe'
)

# ---------- Weighted pick helper ----------
# $Field = @{ Values=@(...); Weights=@(...) }
function Get-Weighted {
    param([hashtable]$Field, [System.Random]$Rng)
    $vals = $Field.Values
    $wts  = $Field.Weights
    $sum = 0; foreach ($w in $wts) { $sum += $w }
    $r = $Rng.NextDouble() * $sum
    $acc = 0.0
    for ($i = 0; $i -lt $vals.Count; $i++) {
        $acc += $wts[$i]
        if ($r -lt $acc) { return $vals[$i] }
    }
    return $vals[-1]
}

# ---------- Field libraries (SecurityEvent-relevant) ----------
$script:F_NoiseEventID = @{
    Values  = @(4624, 4688, 4625, 4634, 4672, 4697, 4720, 4732, 4624)
    Weights = @(40,   30,   12,   10,   3,    2,    1,    1,    1)
}
# 4624 doubled to bias toward successful logons (background noise reality)

$script:F_NoiseLogonType = @{
    # 2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 10=RemoteInteractive, 11=CachedInteractive
    Values  = @(3, 5, 2, 11, 7, 10, 4)
    Weights = @(40, 25, 15, 10, 5, 3, 2)
}

$script:F_FailureReason = @{
    Values = @(
        'Unknown user name or bad password.',
        'The user has not been granted the requested logon type at this machine.',
        'Account currently disabled.',
        'The specified account''s password has expired.',
        'Account locked out.'
    )
    Weights = @(70, 12, 8, 6, 4)
}

$script:F_LogonProcessName = @{
    Values  = @('Kerberos','NtLmSsp','Negotiate','User32','Advapi','Seclogo')
    Weights = @(40, 25, 20, 8, 4, 3)
}

$script:F_NoiseUsers = @{
    Values  = $script:NoiseUsers
    Weights = @(8,8,8,8,8,8,6,6,6,4,4,3)
}

$script:F_NoiseHosts = @{
    Values  = $script:AllHosts
    Weights = @(6,6,6,6,6,5,5,5,5,5,5,4,4)
}

$script:F_LegitProcess = @{
    Values  = $script:LegitProcesses
    Weights = @(20,15,15,12,10,10,8,8,7,7,15,12,8,12,10,10,8,12,8,6)
}

# ---------- Helpers used by generators ----------
function Get-NoiseRfc1918Ip {
    param([System.Random]$Rng)
    # ~70% 10/8 internal LAN, 25% 172.16/12 server farm, 5% 192.168/16
    $r = $Rng.NextDouble()
    if ($r -lt 0.70) {
        return ('10.{0}.{1}.{2}' -f $Rng.Next(0,256), $Rng.Next(0,256), $Rng.Next(1,255))
    } elseif ($r -lt 0.95) {
        return ('172.{0}.{1}.{2}' -f $Rng.Next(16,32), $Rng.Next(0,256), $Rng.Next(1,255))
    } else {
        return ('192.168.{0}.{1}' -f $Rng.Next(0,256), $Rng.Next(1,255))
    }
}

function Get-EphemeralPort {
    param([System.Random]$Rng)
    return $Rng.Next(49152, 65535)
}

# ---------- Wave timestamp generator ----------
# Returns [DateTime[]] of length ~Count, sorted ascending, distributed across
# [Anchor - WindowDays, Anchor - HoldoutSeconds]. Density follows
# amplitude * |sin(2*pi*Frequency*t)| + Baseline -- bumpy diurnal feel
# without sleeping. HoldoutSeconds keeps noise out of the recent window the
# small-set storyline owns so ago(1h) practice questions stay deterministic.
function New-WaveTimestamps {
    param(
        [int]$Count,
        [datetime]$Anchor,
        [int]$WindowDays = 14,
        [int]$HoldoutSeconds = 3600,
        [double]$Frequency = 14.0,   # one bump per day across a 14d window
        [double]$Baseline  = 0.2,    # 20% flat floor so troughs aren't zero
        [System.Random]$Rng
    )
    $startSec = -86400 * $WindowDays
    $endSec   = -1 * $HoldoutSeconds
    $span     = $endSec - $startSec  # negative offsets, span > 0

    # Inverse-CDF via rejection sampling against the |sin| envelope.
    # Max density = 1.0 + Baseline; accept ratio is density(t)/maxDensity.
    $maxD = 1.0 + $Baseline
    $out = New-Object 'System.Collections.Generic.List[datetime]' $Count
    $tries = 0
    $maxTries = $Count * 10
    while ($out.Count -lt $Count -and $tries -lt $maxTries) {
        $tries++
        $offset = $startSec + ($Rng.NextDouble() * $span)
        # Normalize to a 0..WindowDays t for the wave
        $t = ($offset - $startSec) / 86400.0
        $density = [math]::Abs([math]::Sin([math]::PI * $Frequency * $t / $WindowDays)) + $Baseline
        if ($Rng.NextDouble() -lt ($density / $maxD)) {
            $out.Add($Anchor.AddSeconds($offset))
        }
    }
    return ,@($out | Sort-Object)
}

function To-IsoZ { param([datetime]$Dt) $Dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }

# ---------- Hash helpers (deterministic via Rng) ----------
function New-HexString {
    param([int]$Length, [System.Random]$Rng)
    $sb = New-Object System.Text.StringBuilder $Length
    for ($i = 0; $i -lt $Length; $i++) {
        [void]$sb.Append('0123456789abcdef'[$Rng.Next(0,16)])
    }
    return $sb.ToString()
}
function New-Sha256 { param([System.Random]$Rng) New-HexString 64 $Rng }
function New-Sha1   { param([System.Random]$Rng) New-HexString 40 $Rng }
function New-Md5    { param([System.Random]$Rng) New-HexString 32 $Rng }

# ---------- Public/browsing IPs (used in noise -- no overlap with storyline 198.51.100.55) ----------
$script:NoisePublicIps = @(
    '142.250.80.46','142.250.80.78','13.107.42.14','20.232.97.97',
    '52.96.165.18','40.99.4.34','151.101.1.69','199.232.65.69',
    '23.40.44.17','104.18.32.115','172.217.14.110','157.240.22.35'
)

function Get-NoisePublicIp { param([System.Random]$Rng) return $script:NoisePublicIps[$Rng.Next(0,$script:NoisePublicIps.Count)] }

# ---------- DeviceProcessEvents fields ----------
$script:F_DPE_FileName = @{
    Values  = @('chrome.exe','msedge.exe','OUTLOOK.EXE','Teams.exe','code.exe','svchost.exe','OneDrive.exe','SearchHost.exe','explorer.exe','notepad.exe','cmd.exe','powershell.exe','taskhostw.exe','RuntimeBroker.exe','conhost.exe')
    Weights = @(20, 15, 14, 12, 10, 8, 7, 6, 5, 3, 3, 3, 2, 2, 2)
}
$script:F_DPE_ParentName = @{
    Values  = @('explorer.exe','svchost.exe','services.exe','RuntimeBroker.exe','OUTLOOK.EXE','chrome.exe','code.exe')
    Weights = @(35, 25, 15, 10, 5, 5, 5)
}
$script:F_SignerType = @{ Values=@('Microsoft','Valid','Unsigned'); Weights=@(70,25,5) }
$script:F_IntegrityLevel = @{ Values=@('Low','Medium','High','System'); Weights=@(5,75,15,5) }

# ---------- DeviceNetworkEvents fields ----------
$script:F_DNE_Action = @{ Values=@('ConnectionSuccess','ConnectionAttempt','ConnectionFailed'); Weights=@(85,10,5) }
$script:F_DNE_Process = @{
    Values  = @('chrome.exe','msedge.exe','firefox.exe','OUTLOOK.EXE','Teams.exe','OneDrive.exe','svchost.exe','code.exe','SearchHost.exe')
    Weights = @(30, 20, 5, 15, 10, 8, 6, 4, 2)
}
$script:F_DNE_RemotePort = @{ Values=@(443, 80, 53, 8443); Weights=@(80, 12, 5, 3) }

# ---------- DeviceLogonEvents fields ----------
$script:F_DLE_Action = @{ Values=@('LogonSuccess','LogonFailed'); Weights=@(85, 15) }
$script:F_DLE_LogonType = @{ Values=@('Network','Interactive','RemoteInteractive','Service','Batch','CachedInteractive'); Weights=@(40,25,12,15,5,3) }
$script:F_DLE_FailReason = @{ Values=@('InvalidUserNameOrPassword','AccountLocked','AccountDisabled','PasswordExpired'); Weights=@(75,10,8,7) }
$script:F_DLE_InitProc = @{ Values=@('lsass.exe','winlogon.exe','svchost.exe'); Weights=@(60,30,10) }

# ---------- Syslog fields ----------
$script:F_SyslogHosts = @{ Values=@('SVR-LINUX-01','SVR-LINUX-02','SVR-WEB-LX-01','SVR-DB-LX-01'); Weights=@(35,30,20,15) }
$script:F_SyslogHostIps = @{
    'SVR-LINUX-01'='10.0.20.20';'SVR-LINUX-02'='10.0.20.21';
    'SVR-WEB-LX-01'='10.0.30.10';'SVR-DB-LX-01'='10.0.30.20'
}
$script:F_SyslogFacility = @{ Values=@('auth','cron','daemon','kern','user','mail'); Weights=@(35,25,15,10,10,5) }
$script:F_SyslogSeverity = @{ Values=@('info','notice','warning','err','debug'); Weights=@(60,15,15,8,2) }
$script:F_SyslogProcess = @{
    Values  = @('sshd-session','CRON','systemd','kernel','sudo','apt','snapd','dbus-daemon','systemd-resolved')
    Weights = @(20, 25, 15, 8, 5, 12, 4, 4, 3)
}

# Pre-built syslog message templates by process. Each template uses {U}/{N}/{IP} placeholders.
$script:F_SyslogMsgs = @{
    'sshd-session' = @(
        'Accepted publickey for {U} from {IP} port {P} ssh2: RSA SHA256:{H8}',
        'pam_unix(sshd:session): session opened for user {U} by (uid=0)',
        'pam_unix(sshd:session): session closed for user {U}',
        'Connection closed by {IP} port {P} [preauth]'
    )
    'CRON' = @(
        '({U}) CMD (/usr/lib/sysstat/sa1 1 1)',
        '({U}) CMD (test -x /usr/sbin/anacron || (cd / && run-parts --report /etc/cron.daily))',
        '({U}) CMD (/etc/munin/plugins/check-disk-{N} > /dev/null 2>&1)'
    )
    'systemd' = @(
        'Started Session {N} of user {U}.',
        'Stopped Session {N} of user {U}.',
        'Reloading.',
        'Started Daily apt download activities.'
    )
    'kernel' = @(
        '[UFW BLOCK] IN=eth0 OUT= MAC=... SRC={IP} DST=10.0.20.20 LEN=60 PROTO=TCP SPT={P} DPT=22',
        'TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies.',
        'audit: type=1400 audit({N}.{N}:{N}): apparmor="DENIED" operation="open" profile="/usr/sbin/cupsd"'
    )
    'sudo'   = @(
        '{U} : TTY=pts/0 ; PWD=/home/{U} ; USER=root ; COMMAND=/usr/bin/apt update',
        '{U} : TTY=pts/0 ; PWD=/home/{U} ; USER=root ; COMMAND=/bin/systemctl status nginx'
    )
    'apt'    = @( 'Started Daily apt download activities.', 'Finished apt-daily.service.', 'Upgrading: openssl, libssl3' )
    'snapd'  = @( 'Started snap.snapd.service.', 'Connection from {IP} closed' )
    'dbus-daemon' = @( '[system] Successfully activated service ''org.freedesktop.systemd1''' )
    'systemd-resolved' = @( 'Positive Trust Anchors:', 'DNSSEC validation failed for question example.com IN A: signature-expired' )
    'daemon' = @( 'Service started successfully', 'Configuration reloaded' )
    'mail'   = @( 'postfix/smtpd[{N}]: connect from unknown[{IP}]', 'postfix/smtpd[{N}]: disconnect from unknown[{IP}]' )
}

$script:F_SyslogUsers = @('root','www-data','postgres','ubuntu','deploy','jenkins','backup')
function Get-SyslogUser { param([System.Random]$Rng) return $script:F_SyslogUsers[$Rng.Next(0,$script:F_SyslogUsers.Count)] }

function Format-SyslogMessage {
    param([string]$Template, [System.Random]$Rng)
    $msg = $Template
    if ($msg -match '\{U\}')  { $msg = $msg -replace '\{U\}',  (Get-SyslogUser $Rng) }
    if ($msg -match '\{IP\}') { $msg = $msg -replace '\{IP\}', (Get-NoiseRfc1918Ip -Rng $Rng) }
    if ($msg -match '\{P\}')  { $msg = $msg -replace '\{P\}',  ([string]$Rng.Next(1024,65535)) }
    if ($msg -match '\{N\}')  { $msg = $msg -replace '\{N\}',  ([string]$Rng.Next(1,9999)) }
    if ($msg -match '\{H8\}') { $msg = $msg -replace '\{H8\}', (New-HexString 8 $Rng) }
    return $msg
}

# ---------- Networking helpers used by the ported Build-* generators ----------
function New-MacAddress {
    param([System.Random]$Rng)
    $parts = for ($i = 0; $i -lt 6; $i++) { '{0:X2}' -f $Rng.Next(0, 256) }
    return ($parts -join '-')
}

# Random user pick (non-weighted) -- used by AuditLogs / DRE / DFE noise.
function Get-NoiseUser { param([System.Random]$Rng) return $script:NoiseUsers[$Rng.Next(0, $script:NoiseUsers.Count)] }
function Get-AnyHost   { param([System.Random]$Rng) return $script:AllHosts[$Rng.Next(0, $script:AllHosts.Count)] }

# Read a small CSV into ($header, [string[]]$rows) preserving raw lines.
function Read-SeedCsv {
    param([string]$Path)
    $lines = Get-Content -LiteralPath $Path
    if (-not $lines) { return @('', @()) }
    $h = $lines[0]
    $r = @()
    if ($lines.Count -gt 1) { $r = $lines[1..($lines.Count - 1)] }
    return @($h, $r)
}
