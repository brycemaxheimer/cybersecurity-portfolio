"""
extend-tables.py - Generate noise for tables that Build-LargeDataset.ps1
left as TODO (Copy-Item verbatim).

Reads each small-set seed from kql/data/<tbl>.csv, appends ~24h of noise
within the same anchor window the rest of the lab uses, writes the result
to kql/data-large/<tbl>.csv. Run after Build-LargeDataset.ps1 so the noise
overlay is consistent.

Run from repo root:
    python3 kql/data-large/extend-tables.py
"""
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO  = Path(__file__).resolve().parents[2]
SMALL = REPO / 'kql' / 'data'
LARGE = REPO / 'kql' / 'data-large'
ANCHOR = datetime(2026, 4, 29, 13, 52, 40, tzinfo=timezone.utc)
WINDOW_HOURS = 24
RNG = random.Random(42)

NOISE_USERS = ['jharris','kpatel','mwhite','rmorales','sthompson','agarcia',
               'lwoods','tnguyen','ehernandez','dkim','bsato','olopez',
               'fortega','gnorris','iyamamoto','vchen','phopkins','kdoyle',
               'ssmith','rrivera','mevans','bcarter','ahaynes','pjohnston']
NOISE_HOSTS = ['WS-IT-01','WS-IT-02','WS-MKT-01','WS-MKT-02','WS-OPS-01',
               'WS-OPS-02','LAP-EXEC-01','LAP-SALES-03','LAP-SALES-04',
               'WS-FIN-02','WS-FIN-03','WS-ENG-01','WS-ENG-02','WS-LEGAL-01',
               'LAP-DEV-05','LAP-DEV-06','WS-SUPPORT-01','WS-RECEPTION-01']
STORY_HOSTS = ['WS-FINANCE-01','WS-DEV-02','WS-HR-03','SVR-DC-01','SVR-WEB-01']
ALL_HOSTS = STORY_HOSTS + NOISE_HOSTS
LINUX_HOSTS = ['SVR-LINUX-01','SVR-LINUX-02','SVR-WEB-LX-01','SVR-DB-LX-01']

LEGIT_PROCS = ['svchost.exe','services.exe','lsass.exe','wininit.exe',
               'explorer.exe','chrome.exe','msedge.exe','OUTLOOK.EXE',
               'Teams.exe','OneDrive.exe','SearchHost.exe','RuntimeBroker.exe',
               'taskhostw.exe','code.exe','WINWORD.EXE','EXCEL.EXE']

LEGIT_DLLS = ['kernel32.dll','user32.dll','ntdll.dll','advapi32.dll',
              'ole32.dll','combase.dll','rpcrt4.dll','msvcrt.dll',
              'shell32.dll','shlwapi.dll','wininet.dll','winhttp.dll',
              'crypt32.dll','wintrust.dll','version.dll','iertutil.dll',
              'mscoree.dll','clr.dll','System.dll','System.Core.dll']

def iso(dt): return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
def hex_(seed, n):
    r = random.Random(seed)
    return ''.join(r.choice('0123456789abcdef') for _ in range(n))
def rfc1918():
    r = RNG.random()
    if r < 0.7: return f"10.{RNG.randint(0,255)}.{RNG.randint(0,255)}.{RNG.randint(1,254)}"
    if r < 0.95: return f"172.{RNG.randint(16,31)}.{RNG.randint(0,255)}.{RNG.randint(1,254)}"
    return f"192.168.{RNG.randint(0,255)}.{RNG.randint(1,254)}"
def public_ip():
    return RNG.choice([
        '142.250.80.46','13.107.42.14','20.232.97.97','40.99.4.34',
        '52.96.165.18','151.101.1.69','199.232.65.69','23.40.44.17',
        '104.18.32.115','172.217.14.110','157.240.22.35','185.220.101.5',
        '203.0.113.10','203.0.113.20','203.0.113.30','203.0.113.40',
        '198.51.100.55'
    ])
def mac():
    return '-'.join(f"{RNG.randint(0,255):02X}" for _ in range(6))

def wave_timestamps(count):
    """Uniform-ish timestamps across [anchor - WINDOW_HOURS, anchor], sorted asc."""
    times = []
    for _ in range(count):
        sec = RNG.uniform(0, WINDOW_HOURS * 3600)
        times.append(ANCHOR - timedelta(seconds=sec))
    times.sort()
    return times

def read_seed(name):
    """Read kql/data/<name>.csv and return (header, rows)."""
    p = SMALL / f"{name}.csv"
    with open(p, encoding='utf-8') as f:
        rdr = csv.reader(f)
        header = next(rdr)
        rows = list(rdr)
    return header, rows

def write_large(name, header, rows):
    p = LARGE / f"{name}.csv"
    with open(p, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f, lineterminator='\n')
        w.writerow(header)
        w.writerows(rows)
    print(f"  {p.name}: {len(rows)} rows")

# ---------- Generators ----------

def gen_audit_logs(target):
    header, seed = read_seed('AuditLogs')
    ops = [
        ('Add user','UserManagement','success'),
        ('Update user','UserManagement','success'),
        ('Delete user','UserManagement','success'),
        ('Add member to group','GroupManagement','success'),
        ('Remove member from group','GroupManagement','success'),
        ('Update group','GroupManagement','success'),
        ('Reset user password','UserManagement','success'),
        ('Add app role assignment to user','RoleManagement','success'),
        ('Add owner to application','ApplicationManagement','success'),
        ('Update application','ApplicationManagement','success'),
        ('Sign-in activity','SignInLogs','success'),
        ('Add user','UserManagement','failure'),
        ('Reset user password','UserManagement','failure'),
        ('Add member to role','RoleManagement','success'),
    ]
    new_rows = []
    for ts in wave_timestamps(target - len(seed)):
        op, cat, result = RNG.choice(ops)
        actor = RNG.choice(NOISE_USERS)
        target_user = RNG.choice(NOISE_USERS)
        identity = f"{actor}@corp.example"
        initiated = json.dumps({"user": {"userPrincipalName": identity}})
        targets = json.dumps([{"displayName": target_user, "userPrincipalName": f"{target_user}@corp.example", "type": "User"}])
        new_rows.append([
            iso(ts), op, cat, result, '', '',
            op, iso(ts), op.split()[0], identity, initiated, targets,
            'Core Directory', 'AuditLogs'
        ])
    rows = seed + new_rows
    rows.sort(key=lambda r: r[0])
    write_large('AuditLogs', header, rows)

def gen_common_security_log(target):
    header, seed = read_seed('CommonSecurityLog')
    fws = [('Palo Alto Networks','PAN-OS','1.0','fw-edge-01'),
           ('Cisco','ASA','9.16','fw-edge-02'),
           ('Fortinet','FortiGate','7.2','fw-perim-01')]
    actions = [('allow', 0.85), ('deny', 0.10), ('drop', 0.05)]
    apps = ['https','http','dns','ssh','smtp','ldap','rdp','smb']
    new_rows = []
    for ts in wave_timestamps(target - len(seed)):
        vendor, product, ver, host = RNG.choice(fws)
        action = RNG.choices([a for a,_ in actions], weights=[w for _,w in actions])[0]
        app = RNG.choices(apps, weights=[60,8,15,3,2,2,5,5])[0]
        src = rfc1918() if RNG.random() > 0.3 else public_ip()
        dst = public_ip() if RNG.random() > 0.4 else rfc1918()
        sport = RNG.randint(49152, 65535)
        dport = {'https': 443, 'http': 80, 'dns': 53, 'ssh': 22, 'smtp': 25,
                 'ldap': 389, 'rdp': 3389, 'smb': 445}[app]
        sev = 'Low' if action == 'allow' else 'Medium' if action == 'deny' else 'High'
        new_rows.append([
            iso(ts), vendor, product, ver, '100', 'Traffic', sev, action, app,
            src, str(sport), dst, str(dport), 'TCP', action, host, 'CommonSecurityLog'
        ])
    rows = seed + new_rows
    rows.sort(key=lambda r: r[0])
    write_large('CommonSecurityLog', header, rows)

def gen_device_file_events(target):
    header, seed = read_seed('DeviceFileEvents')
    actions = [('FileCreated', 0.45), ('FileModified', 0.35), ('FileDeleted', 0.15), ('FileRenamed', 0.05)]
    file_kinds = [
        ('.docx', 'C:\\Users\\{u}\\Documents'),
        ('.xlsx', 'C:\\Users\\{u}\\Documents'),
        ('.pdf',  'C:\\Users\\{u}\\Downloads'),
        ('.png',  'C:\\Users\\{u}\\Pictures'),
        ('.tmp',  'C:\\Users\\{u}\\AppData\\Local\\Temp'),
        ('.log',  'C:\\Windows\\Temp'),
        ('.cache','C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Windows\\INetCache'),
        ('.json', 'C:\\Users\\{u}\\AppData\\Roaming'),
        ('.zip',  'C:\\Users\\{u}\\Downloads'),
    ]
    new_rows = []
    for ts in wave_timestamps(target - len(seed)):
        host = RNG.choice(ALL_HOSTS)
        user = RNG.choice(NOISE_USERS)
        action = RNG.choices([a for a,_ in actions], weights=[w for _,w in actions])[0]
        ext, folder_tmpl = RNG.choice(file_kinds)
        folder = folder_tmpl.format(u=user)
        fname = f"file_{RNG.randint(1000,9999)}{ext}"
        proc = RNG.choice(['explorer.exe','chrome.exe','OUTLOOK.EXE','code.exe','svchost.exe','OneDrive.exe'])
        ts_iso = iso(ts)
        new_rows.append([
            ts_iso, ts_iso, host, action, fname, folder,
            hex_(host+fname, 64), hex_(host+fname+'1', 40), hex_(host+fname+'m', 32),
            str(RNG.randint(1024, 5000000)),
            proc, user, proc, 'DeviceFileEvents'
        ])
    rows = seed + new_rows
    rows.sort(key=lambda r: r[0])
    write_large('DeviceFileEvents', header, rows)

def gen_device_image_load_events(target):
    header, seed = read_seed('DeviceImageLoadEvents')
    new_rows = []
    for ts in wave_timestamps(target - len(seed)):
        host = RNG.choice(ALL_HOSTS)
        dll = RNG.choice(LEGIT_DLLS)
        proc = RNG.choice(LEGIT_PROCS)
        ts_iso = iso(ts)
        new_rows.append([
            ts_iso, ts_iso, host, dll, 'C:\\Windows\\System32',
            hex_(dll, 64), proc, 'C:\\Windows\\System32', 'DeviceImageLoadEvents'
        ])
    rows = seed + new_rows
    rows.sort(key=lambda r: r[0])
    write_large('DeviceImageLoadEvents', header, rows)

def gen_device_network_info(target):
    header, seed = read_seed('DeviceNetworkInfo')
    seed_devs = {r[2] for r in seed}
    devices_needed = max(0, target // 2 - len(seed_devs))
    new_devs = [h for h in NOISE_HOSTS if h not in seed_devs][:devices_needed]
    adapter_choices = [('Ethernet', 'Ethernet'), ('Wi-Fi', 'IEEE80211'), ('vEthernet', 'Ethernet')]
    new_rows = []
    for dev in new_devs:
        n_snapshots = RNG.randint(1, 3)
        for s in range(n_snapshots):
            ts = ANCHOR - timedelta(hours=RNG.uniform(0.5, WINDOW_HOURS))
            ts_iso = iso(ts)
            adapter, atype = RNG.choice(adapter_choices)
            ip = rfc1918()
            ips = json.dumps([{"IPAddress": ip}])
            new_rows.append([
                ts_iso, ts_iso, dev, f"dev-{dev.lower()}", mac(),
                ips, '["10.0.0.1"]', '["10.0.0.1"]', '["CORP"]',
                adapter, 'Up', atype, 'DeviceNetworkInfo'
            ])
    rows = seed + new_rows
    rows.sort(key=lambda r: r[0])
    write_large('DeviceNetworkInfo', header, rows)

def gen_device_registry_events(target):
    header, seed = read_seed('DeviceRegistryEvents')
    actions = [('RegistryValueSet', 0.7), ('RegistryKeyCreated', 0.15),
               ('RegistryValueDeleted', 0.1), ('RegistryKeyDeleted', 0.05)]
    keys = [
        ('HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'REG_SZ', 'C:\\Program Files\\{app}\\{app}.exe'),
        ('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\{svc}\\Parameters', 'REG_DWORD', '1'),
        ('HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Common\\Roaming', 'REG_SZ', '{user}@corp.example'),
        ('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender', 'REG_DWORD', '0'),
        ('HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs', 'REG_BINARY', 'aabbccdd'),
        ('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{app}', 'REG_SZ', '1.0.0'),
    ]
    apps = ['Teams','OneDrive','Office16','Chrome','Edge','Slack','Zoom']
    svcs = ['DPS','EventLog','Schedule','Spooler','BITS','WinDefend']
    new_rows = []
    for ts in wave_timestamps(target - len(seed)):
        host = RNG.choice(ALL_HOSTS)
        user = RNG.choice(NOISE_USERS)
        action = RNG.choices([a for a,_ in actions], weights=[w for _,w in actions])[0]
        key_tmpl, vtype, val_tmpl = RNG.choice(keys)
        app = RNG.choice(apps); svc = RNG.choice(svcs)
        key = key_tmpl.format(app=app, svc=svc)
        valname = RNG.choice([app, 'Default', 'Enabled', 'Path'])
        value = val_tmpl.format(app=app, user=user)
        proc = RNG.choice(['regedit.exe','msiexec.exe','svchost.exe','setup.exe','powershell.exe'])
        ts_iso = iso(ts)
        new_rows.append([
            ts_iso, ts_iso, host, action, key, valname, value, vtype,
            proc, user, f"{proc} /S", 'DeviceRegistryEvents'
        ])
    rows = seed + new_rows
    rows.sort(key=lambda r: r[0])
    write_large('DeviceRegistryEvents', header, rows)

def gen_dhcp(target):
    header, seed = read_seed('DHCP')
    actions = [('Assign', 'Assign', 10),
               ('Renew', 'Renew', 11),
               ('Release', 'Release', 12),
               ('NACK', 'NACK', 16)]
    new_rows = []
    for ts in wave_timestamps(target - len(seed)):
        action_name, desc, eid = RNG.choice(actions)
        host = RNG.choice(ALL_HOSTS)
        ip = rfc1918()
        ts_iso = iso(ts)
        date_str = ts.strftime('%m/%d/%Y')
        time_str = ts.strftime('%H:%M:%S')
        new_rows.append([
            ts_iso, str(eid), date_str, time_str, desc, ip, host, mac(),
            '', f"{RNG.randint(10000,99999):05X}", '0', 'MSFT 5.0', 'DHCP'
        ])
    rows = seed + new_rows
    rows.sort(key=lambda r: r[0])
    write_large('DHCP', header, rows)

def gen_security_alert(target):
    header, seed = read_seed('SecurityAlert')
    templates = [
        ('Suspicious PowerShell execution', 'Medium', 'Detected suspicious PowerShell EncodedCommand', 'Execution', 'T1059.001'),
        ('Anomalous sign-in from unfamiliar location', 'Medium', 'User signed in from a country not previously seen', 'InitialAccess', 'T1078'),
        ('Mass file deletion', 'Low', 'A user deleted 200+ files within 5 minutes', 'Impact', 'T1485'),
        ('Lateral movement via SMB', 'High', 'Unusual SMB activity from a single host to many destinations', 'LateralMovement', 'T1021.002'),
        ('Credential dumping detected', 'High', 'lsass.exe memory access from an untrusted process', 'CredentialAccess', 'T1003.001'),
        ('Suspicious scheduled task', 'Medium', 'Schtasks created with binary in ProgramData', 'Persistence', 'T1053.005'),
        ('DNS tunneling indicator', 'Medium', 'High volume of TXT-record queries to an uncommon domain', 'CommandAndControl', 'T1071.004'),
        ('Possible password spray', 'High', 'A single source IP attempted login to many distinct accounts', 'CredentialAccess', 'T1110.003'),
    ]
    statuses = ['New', 'InProgress', 'Resolved']
    new_rows = []
    seed_n = len(seed)
    for i, ts in enumerate(wave_timestamps(target - seed_n)):
        name, sev, desc, tactic, technique = RNG.choice(templates)
        status = RNG.choices(statuses, weights=[60, 25, 15])[0]
        end_ts = ts + timedelta(minutes=RNG.randint(1, 30))
        sys_id = f"alert-{200 + seed_n + i:04d}"
        entities = json.dumps([{"Type": "host", "HostName": RNG.choice(ALL_HOSTS)}])
        new_rows.append([
            iso(ts), name, name, sev, desc, 'Azure Sentinel', 'Microsoft', 'Microsoft Defender',
            sys_id, name.replace(' ', ''), status, 'High', f"{RNG.uniform(0.6, 0.99):.2f}", '0',
            iso(ts), iso(end_ts), entities, tactic, technique, iso(end_ts + timedelta(seconds=5)),
            'SecurityAlert'
        ])
    rows = seed + new_rows
    rows.sort(key=lambda r: r[0])
    write_large('SecurityAlert', header, rows)

def gen_w3ciislog(target):
    header, seed = read_seed('W3CIISLog')
    sites = [('W3SVC1', 'SVR-WEB-01', '10.0.20.10'),
             ('W3SVC2', 'SVR-WEB-02', '10.0.20.11'),
             ('W3SVC1', 'SVR-WEB-LX-01', '10.0.30.10')]
    methods = [('GET', 0.78), ('POST', 0.18), ('PUT', 0.02), ('DELETE', 0.01), ('OPTIONS', 0.01)]
    paths = [
        ('/', 200), ('/index.html', 200), ('/login', 200), ('/api/v1/health', 200),
        ('/api/v1/users', 200), ('/api/v1/orders', 200), ('/static/main.css', 200),
        ('/static/app.js', 200), ('/favicon.ico', 200), ('/logout', 200),
        ('/admin', 401), ('/admin/users', 403), ('/.env', 404), ('/wp-admin', 404),
        ('/api/v1/login', 200), ('/api/v1/login', 401),
    ]
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'curl/7.81.0',
        'python-requests/2.28.1',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)',
    ]
    new_rows = []
    for ts in wave_timestamps(target - len(seed)):
        site, host, sip = RNG.choice(sites)
        method = RNG.choices([m for m,_ in methods], weights=[w for _,w in methods])[0]
        path, status = RNG.choice(paths)
        cip = rfc1918() if RNG.random() > 0.4 else public_ip()
        ua = RNG.choice(user_agents)
        ts_iso = iso(ts)
        date_str = ts.strftime('%Y-%m-%d')
        time_str = ts.strftime('%H:%M:%S')
        new_rows.append([
            ts_iso, date_str, time_str, site, host, sip, method, path, '-', '443',
            '-', cip, ua, str(status), '0', '0',
            str(RNG.randint(200, 50000)), str(RNG.randint(100, 5000)),
            str(RNG.randint(10, 5000)), host, 'W3CIISLog'
        ])
    rows = seed + new_rows
    rows.sort(key=lambda r: r[0])
    write_large('W3CIISLog', header, rows)

def gen_signin_logs(target):
    header, seed = read_seed('SigninLogs')
    apps = [('Office 365','app-office_365'),('Microsoft Teams','app-microsoft_teams'),
            ('Azure Portal','app-azure_portal'),('SharePoint Online','app-sharepoint'),
            ('Exchange Online','app-exchange'),('OneDrive','app-onedrive')]
    locations_us = [
        ('{"city": "Indianapolis", "state": "Indiana", "countryOrRegion": "US"}', 'US'),
        ('{"city": "Seattle", "state": "Washington", "countryOrRegion": "US"}', 'US'),
        ('{"city": "Austin", "state": "Texas", "countryOrRegion": "US"}', 'US'),
        ('{"city": "Boston", "state": "Massachusetts", "countryOrRegion": "US"}', 'US'),
        ('{"city": "Chicago", "state": "Illinois", "countryOrRegion": "US"}', 'US'),
    ]
    devices = [
        '{"deviceId": "", "operatingSystem": "Windows 11"}',
        '{"deviceId": "", "operatingSystem": "Windows 10"}',
        '{"deviceId": "", "operatingSystem": "macOS"}',
        '{"deviceId": "", "operatingSystem": "iOS"}',
    ]
    new_rows = []
    for ts in wave_timestamps(target - len(seed)):
        user = RNG.choice(NOISE_USERS)
        app, app_id = RNG.choice(apps)
        loc, _ = RNG.choice(locations_us)
        dev = RNG.choice(devices)
        ip = '73.45.12.' + str(RNG.randint(2, 250))
        success = RNG.random() > 0.05
        rt = '0' if success else str(RNG.choice([50053, 50074, 50057]))
        rd = '' if success else 'Authentication failed'
        is_risky = '0' if success else '1'
        new_rows.append([
            iso(ts), f"{user}@corp.example", user.capitalize(), f"uid-{user}", ip,
            app, app_id, 'Browser', rt, rd, 'success' if success else 'failure',
            is_risky, 'low' if success else 'high',
            'none' if success else 'atRisk', '' if success else 'unfamiliarFeatures',
            loc, dev, 'singleFactorAuthentication', '1', 'Mozilla/5.0', 'SigninLogs'
        ])
    rows = seed + new_rows
    rows.sort(key=lambda r: r[0])
    write_large('SigninLogs', header, rows)

def gen_security_incident(target):
    header, seed = read_seed('SecurityIncident')
    titles = [
        ('Anomalous sign-in pattern observed', 'Low'),
        ('Multiple failed sign-ins detected', 'Medium'),
        ('Suspicious file download flagged by AV', 'Low'),
        ('Defender alert: potentially unwanted application', 'Low'),
        ('Conditional access policy violation', 'Medium'),
        ('Unusual mailbox forwarding rule created', 'High'),
        ('Possible credential theft attempt', 'High'),
        ('Out-of-office anomaly investigation', 'Low'),
    ]
    statuses = ['New', 'Active', 'Closed']
    classifications = ['', 'TruePositive', 'BenignPositive', 'FalsePositive']
    new_rows = []
    seed_n = len(seed)
    for i, ts in enumerate(wave_timestamps(target - seed_n)):
        title, sev = RNG.choice(titles)
        status = RNG.choices(statuses, weights=[40, 30, 30])[0]
        cls = RNG.choice(classifications) if status == 'Closed' else ''
        cls_reason = 'InaccurateData' if cls == 'BenignPositive' else ''
        first = ts - timedelta(hours=RNG.uniform(0.5, 2))
        alert_count = RNG.randint(1, 3)
        alerts = json.dumps([f"alert-{300 + seed_n*5 + i*10 + k:04d}" for k in range(alert_count)])
        inc_num = 2000 + seed_n + i
        new_rows.append([
            iso(ts), str(inc_num), title, f"Incident {inc_num}: {title}",
            sev, status, cls, cls_reason,
            iso(first), iso(ts), iso(ts), iso(ts), iso(ts),
            alerts, 'automation', 'SecurityIncident'
        ])
    rows = seed + new_rows
    rows.sort(key=lambda r: r[0])
    write_large('SecurityIncident', header, rows)

# ---------- Drive ----------
print('Extending tables in kql/data-large/...')
gen_audit_logs(1500)
gen_common_security_log(4000)
gen_device_file_events(3000)
gen_device_image_load_events(3000)
gen_device_network_info(100)
gen_device_registry_events(1500)
gen_dhcp(500)
gen_security_alert(200)
gen_w3ciislog(4000)
gen_signin_logs(1000)
gen_security_incident(50)
print('Done.')
