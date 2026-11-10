"""A synthetic benign baseline: ordinary activity on a small fictional estate.

Every event is benign by construction, so any row a detection returns from it
is a false positive. It is deterministic for a seed and anchored to the run
time, so time-windowed hunting queries (ago(7d)) still see it. Names,
domains and addresses are reserved for documentation (.example, 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) or private.

It is small and synthetic. A clean result here says a query is not noisy on
ordinary activity; it says nothing about how the query behaves on a real
estate, which is why the label names the baseline and its size.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

SEED = 20261110
SPAN = timedelta(days=6)
WINDOWS = [(f"wks-{i:02d}", "Windows11", "10.0.26100") for i in range(1, 7)] + [
    ("srv-app-01", "WindowsServer2022", "10.0.20348"),
    ("srv-files-01", "WindowsServer2022", "10.0.20348"),
]
LINUX = [("lnx-web-01", "Linux", "Ubuntu 24.04"), ("lnx-db-01", "Linux", "Ubuntu 24.04")]
USERS = ["alex.rivera", "sam.chen", "jordan.lee", "riley.park", "morgan.diaz", "casey.nguyen"]
DOMAIN = "corp"

_CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
_EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
_OFFICE = r"C:\Program Files\Microsoft Office\root\Office16"
_CODE = r"C:\Users\{u}\AppData\Local\Programs\Microsoft VS Code\Code.exe"
_EXPLORER = r"C:\Windows\explorer.exe"
_SVCHOST = r"C:\Windows\System32\svchost.exe"
_SERVICES = r"C:\Windows\System32\services.exe"

# (parent path, child path, command line, weight). {u} is the user, {p} the child path.
WIN_PROCESSES = [
    (_EXPLORER, _CHROME, '"{p}"', 8),
    (_CHROME, _CHROME, '"{p}" --type=renderer --lang=en-US --renderer-client-id=7', 12),
    (_EXPLORER, _EDGE, '"{p}" --profile-directory=Default', 5),
    (_EXPLORER, _OFFICE + r"\OUTLOOK.EXE", '"{p}"', 4),
    (_EXPLORER, _OFFICE + r"\WINWORD.EXE", r'"{p}" /n "C:\Users\{u}\Documents\Quarterly notes.docx"', 3),
    (_EXPLORER, _OFFICE + r"\EXCEL.EXE", r'"{p}" "C:\Users\{u}\Documents\Budget 2026.xlsx"', 3),
    (_EXPLORER, r"C:\Users\{u}\AppData\Local\Microsoft\Teams\current\Teams.exe", '"{p}" --process-start-reason=AutoStart', 3),
    (_EXPLORER, r"C:\Users\{u}\AppData\Local\Microsoft\OneDrive\OneDrive.exe", '"{p}" /background', 2),
    (_EXPLORER, _CODE, '"{p}"', 3),
    (_CODE, r"C:\Program Files\Git\cmd\git.exe", "git status --porcelain", 4),
    (_CODE, r"C:\Program Files\Git\cmd\git.exe", "git fetch origin", 2),
    (_CODE, r"C:\Program Files\Python313\python.exe", "python -m pytest -q", 2),
    (_EXPLORER, r"C:\Windows\System32\cmd.exe", r'"C:\Windows\System32\cmd.exe" /c ipconfig /all', 1),
    (_EXPLORER, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     'powershell.exe -NoProfile -Command "Get-Service | Where-Object Status -eq Running"', 1),
    (_EXPLORER, r"C:\Windows\System32\notepad.exe", r'"{p}" C:\Users\{u}\Desktop\todo.txt', 2),
    (_SERVICES, _SVCHOST, r"C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule", 6),
    (_SERVICES, _SVCHOST, r"C:\Windows\System32\svchost.exe -k LocalService -p -s EventLog", 3),
    (_SVCHOST, r"C:\Windows\System32\taskhostw.exe", "taskhostw.exe", 3),
    (_SVCHOST, r"C:\Windows\System32\RuntimeBroker.exe", r"C:\Windows\System32\RuntimeBroker.exe -Embedding", 3),
    (_SVCHOST, r"C:\Windows\System32\backgroundTaskHost.exe",
     '"{p}" -ServerName:BackgroundTaskHost.WebAccountProvider', 2),
    (_SVCHOST, r"C:\Windows\System32\wuauclt.exe", "wuauclt.exe /UpdateDeploymentProvider UpdateDeploymentProvider.dll /ClassId 1", 1),
    (_SVCHOST, r"C:\Windows\System32\msiexec.exe", r"C:\Windows\System32\msiexec.exe /V", 1),
    (_SERVICES, r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25010.11-0\MsMpEng.exe", '"{p}"', 1),
]
LINUX_PROCESSES = [
    ("/usr/lib/systemd/systemd", "/usr/sbin/nginx", "/usr/sbin/nginx -g daemon on; master_process on;", 2),
    ("/usr/sbin/cron", "/usr/bin/python3", "/usr/bin/python3 /opt/backup/run_backup.py --nightly", 2),
    ("/usr/sbin/sshd", "/usr/bin/bash", "-bash", 3),
    ("/usr/bin/bash", "/usr/bin/git", "git pull --ff-only", 2),
    ("/usr/bin/bash", "/usr/bin/systemctl", "systemctl status nginx", 2),
    ("/usr/bin/bash", "/usr/bin/apt-get", "apt-get update", 1),
    ("/usr/lib/systemd/systemd", "/usr/lib/postgresql/16/bin/postgres", "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main", 2),
]
# (initiating process path, remote host, port)
CONNECTIONS = [
    (_CHROME, "www.example.com", 443), (_CHROME, "docs.example.org", 443), (_CHROME, "cdn.example.net", 443),
    (_EDGE, "news.example.com", 443), (_OFFICE + r"\OUTLOOK.EXE", "mail.example.com", 443),
    (r"C:\Users\{u}\AppData\Local\Microsoft\Teams\current\Teams.exe", "teams.example.com", 443),
    (r"C:\Users\{u}\AppData\Local\Microsoft\OneDrive\OneDrive.exe", "storage.example.net", 443),
    (_SVCHOST, "update.example.com", 443), (_SVCHOST, "time.example.org", 123),
    (r"C:\Program Files\Git\cmd\git.exe", "git.example.org", 443),
    (r"C:\Program Files\Python313\python.exe", "packages.example.org", 443),
]
LINUX_CONNECTIONS = [("/usr/bin/apt-get", "archive.example.org", 80), ("/usr/bin/git", "git.example.org", 443),
                     ("/usr/bin/python3", "backup.example.net", 443)]
# (initiating process path, folder template, file names, action)
FILES = [
    (_OFFICE + r"\WINWORD.EXE", r"C:\Users\{u}\Documents", ["Quarterly notes.docx", "Minutes 2026-11.docx"], "FileModified"),
    (_OFFICE + r"\EXCEL.EXE", r"C:\Users\{u}\Documents", ["Budget 2026.xlsx"], "FileModified"),
    (_CHROME, r"C:\Users\{u}\Downloads", ["invoice-1042.pdf", "photos.zip", "agenda.pdf", "VendorAppSetup.msi"], "FileCreated"),
    (r"C:\Users\{u}\AppData\Local\Microsoft\OneDrive\OneDrive.exe", r"C:\Users\{u}\OneDrive - Corp\Shared", ["roadmap.pptx"], "FileCreated"),
    (_CODE, r"C:\Users\{u}\source\repos\inventory", ["app.py", "README.md", "requirements.txt"], "FileModified"),
    (_SVCHOST, r"C:\Windows\Temp", ["MpCmdRun.log", "setup.tmp"], "FileCreated"),
    (r"C:\Windows\System32\msiexec.exe", r"C:\Program Files\Vendor App", ["VendorApp.exe", "VendorApp.dll"], "FileCreated"),
]
REGISTRY = [
    (_EXPLORER, r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx", "0", "Quarterly notes.docx"),
    (r"C:\Users\{u}\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
     r"HKEY_CURRENT_USER\Software\Microsoft\OneDrive\Accounts\Business1", "LastSignInTime", "1762700000"),
    (r"C:\Windows\System32\msiexec.exe",
     r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{4F3A1C2D-0B6E-4E2F-9C1A-2B7D8E9F0A11}",
     "DisplayName", "Vendor App"),
    (_SVCHOST, r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam\State\UserSettings", "Version", "1"),
]
IMAGES = [(_CHROME, r"C:\Windows\System32\ntdll.dll"), (_CHROME, r"C:\Windows\System32\kernel32.dll"),
          (_OFFICE + r"\OUTLOOK.EXE", r"C:\Windows\System32\user32.dll"), (_SVCHOST, r"C:\Windows\System32\combase.dll")]
SOFTWARE = [("google", "chrome", "131.0.6778.86"), ("microsoft", "office", "16.0.18129.20116"), ("7-zip", "7-zip", "24.08"),
            ("microsoft", "visual_studio_code", "1.96.0"), ("python", "python", "3.13.1"), ("git", "git", "2.47.1")]


def _name(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


class _Gen:
    def __init__(self, now: datetime, seed: int):
        self.rnd = random.Random(seed)
        self.now = now
        self.report = 1000

    def ts(self) -> datetime:
        return self.now - timedelta(seconds=self.rnd.uniform(60, SPAN.total_seconds()))

    def rid(self) -> int:
        self.report += 1
        return self.report

    def ip(self) -> str:
        return f"{self.rnd.choice(['192.0.2', '198.51.100', '203.0.113'])}.{self.rnd.randint(1, 254)}"

    def device(self, linux=False):
        name, platform, version = self.rnd.choice(LINUX if linux else WINDOWS)
        return {"DeviceId": f"dev-{name}", "DeviceName": f"{name}.{DOMAIN}.example"}, platform, version

    def initiator(self, path: str, user: str) -> dict:
        return {"InitiatingProcessFolderPath": path, "InitiatingProcessFileName": _name(path),
                "InitiatingProcessAccountName": user, "InitiatingProcessAccountDomain": DOMAIN,
                "InitiatingProcessId": self.rnd.randint(1000, 30000)}


def build(now: datetime | None = None, seed: int = SEED, scale: int = 1) -> dict[str, list[dict]]:
    """table -> rows. `scale` multiplies the event volume."""
    g = _Gen(now or datetime.now(timezone.utc), seed)
    rnd = g.rnd
    out: dict[str, list[dict]] = {t: [] for t in (
        "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceRegistryEvents",
        "DeviceImageLoadEvents", "DeviceLogonEvents", "DeviceInfo", "DeviceNetworkInfo",
        "DeviceTvmSoftwareInventory", "EmailEvents", "CloudAppEvents")}

    def pick(table, weights_at=-1):
        return rnd.choices(table, weights=[t[weights_at] for t in table])[0]

    for _ in range(500 * scale):
        linux = rnd.random() < 0.15
        dev, _p, _v = g.device(linux)
        user = rnd.choice(USERS)
        parent, child, cmd, _w = pick(LINUX_PROCESSES if linux else WIN_PROCESSES)
        parent, child = parent.format(u=user), child.format(u=user)
        out["DeviceProcessEvents"].append({
            "Timestamp": g.ts(), **dev, "ActionType": "ProcessCreated", "FileName": _name(child), "FolderPath": child,
            "ProcessCommandLine": cmd.format(u=user, p=child), "ProcessId": rnd.randint(1000, 30000),
            "AccountName": "root" if linux and "sshd" not in parent else user, "AccountDomain": DOMAIN,
            "ProcessIntegrityLevel": "Medium", "InitiatingProcessFolderPath": parent, "InitiatingProcessFileName": _name(parent),
            "InitiatingProcessCommandLine": f'"{parent}"', "ReportId": g.rid()})

    for _ in range(300 * scale):
        linux = rnd.random() < 0.15
        dev, _p, _v = g.device(linux)
        user = rnd.choice(USERS)
        path, host, port = rnd.choice(LINUX_CONNECTIONS if linux else CONNECTIONS)
        out["DeviceNetworkEvents"].append({
            "Timestamp": g.ts(), **dev, "ActionType": "ConnectionSuccess", "RemoteIP": g.ip(), "RemotePort": port,
            "RemoteUrl": host, "LocalIP": f"10.20.0.{rnd.randint(10, 200)}", "LocalPort": rnd.randint(49152, 65535),
            "Protocol": "Udp" if port == 123 else "Tcp", "RemoteIPType": "Public", "LocalIPType": "Private",
            **g.initiator(path.format(u=user), user), "ReportId": g.rid()})

    for _ in range(150 * scale):
        dev, _p, _v = g.device()
        user = rnd.choice(USERS)
        path, folder, names, action = rnd.choice(FILES)
        name = rnd.choice(names)
        out["DeviceFileEvents"].append({
            "Timestamp": g.ts(), **dev, "ActionType": action, "FileName": name,
            "FolderPath": folder.format(u=user) + "\\" + name, "FileSize": rnd.randint(2_000, 9_000_000),
            **g.initiator(path.format(u=user), user), "ReportId": g.rid()})

    for _ in range(60 * scale):
        dev, _p, _v = g.device()
        user = rnd.choice(USERS)
        path, key, value_name, data = rnd.choice(REGISTRY)
        out["DeviceRegistryEvents"].append({
            "Timestamp": g.ts(), **dev, "ActionType": "RegistryValueSet", "RegistryKey": key,
            "RegistryValueType": "String", "RegistryValueName": value_name, "RegistryValueData": data,
            **g.initiator(path.format(u=user), user), "ReportId": g.rid()})

    for _ in range(60 * scale):
        dev, _p, _v = g.device()
        user = rnd.choice(USERS)
        path, dll = rnd.choice(IMAGES)
        out["DeviceImageLoadEvents"].append({
            "Timestamp": g.ts(), **dev, "ActionType": "ImageLoaded", "FileName": _name(dll), "FolderPath": dll,
            **g.initiator(path, user), "ReportId": g.rid()})

    for _ in range(80 * scale):
        dev, _p, _v = g.device()
        network = rnd.random() < 0.3
        out["DeviceLogonEvents"].append({
            "Timestamp": g.ts(), **dev, "ActionType": "LogonSuccess", "LogonType": "Network" if network else "Interactive",
            "AccountName": rnd.choice(USERS), "AccountDomain": DOMAIN, "Protocol": "Kerberos" if network else "Negotiate",
            "RemoteIP": f"10.20.0.{rnd.randint(10, 200)}" if network else "", "IsLocalAdmin": False, "ReportId": g.rid()})

    for name, platform, version in WINDOWS + LINUX:
        dev = {"DeviceId": f"dev-{name}", "DeviceName": f"{name}.{DOMAIN}.example"}
        for day in range(SPAN.days):
            out["DeviceInfo"].append({
                "Timestamp": g.now - timedelta(days=day, hours=1), **dev, "OSPlatform": platform, "OSVersion": version,
                "OSArchitecture": "64-bit", "PublicIP": "203.0.113.10", "MachineGroup": "Corp", "OnboardingStatus": "Onboarded",
                "DeviceType": "Server" if name.startswith(("srv", "lnx")) else "Workstation", "ReportId": g.rid()})
        out["DeviceNetworkInfo"].append({
            "Timestamp": g.now - timedelta(hours=2), **dev, "NetworkAdapterName": "Ethernet", "NetworkAdapterStatus": "Up",
            "IPAddresses": f'[{{"IPAddress":"10.20.0.{rnd.randint(10, 200)}","SubnetPrefix":24}}]', "ReportId": g.rid()})
        if platform != "Linux":
            for vendor, software, sw_version in SOFTWARE:
                out["DeviceTvmSoftwareInventory"].append({
                    **dev, "OSPlatform": platform, "OSVersion": version, "OSArchitecture": "x64",
                    "SoftwareVendor": vendor, "SoftwareName": software, "SoftwareVersion": sw_version})

    for _ in range(40 * scale):
        user = rnd.choice(USERS)
        sender = rnd.choice(["newsletter@news.example.com", "it-helpdesk@corp.example", "billing@vendor.example.net"])
        out["EmailEvents"].append({
            "Timestamp": g.ts(), "NetworkMessageId": str(uuid.UUID(int=rnd.getrandbits(128))),
            "SenderFromAddress": sender, "SenderMailFromAddress": sender, "SenderFromDomain": sender.split("@")[1],
            "SenderMailFromDomain": sender.split("@")[1], "SenderIPv4": g.ip(), "RecipientEmailAddress": f"{user}@corp.example",
            "Subject": rnd.choice(["Weekly digest", "Your invoice for November", "Scheduled maintenance this weekend"]),
            "EmailDirection": "Inbound", "DeliveryAction": "Delivered", "DeliveryLocation": "Inbox/folder",
            "AttachmentCount": rnd.randint(0, 1), "UrlCount": rnd.randint(0, 4), "ReportId": str(g.rid())})

    for _ in range(30 * scale):
        user = rnd.choice(USERS)
        out["CloudAppEvents"].append({
            "Timestamp": g.ts(), "ActionType": rnd.choice(["FileAccessed", "FileModified", "MailItemsAccessed"]),
            "Application": rnd.choice(["Microsoft SharePoint Online", "Microsoft Exchange Online"]),
            "AccountDisplayName": user.replace(".", " ").title(), "AccountObjectId": f"obj-{user}",
            "IPAddress": f"203.0.113.{rnd.randint(10, 40)}", "CountryCode": "US", "IsAdminOperation": False,
            "ReportId": str(g.rid())})
    return out
