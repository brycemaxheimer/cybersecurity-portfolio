<#
.SYNOPSIS
    Shared schema, paths, and PSSQLite bootstrap for the SecIntel SQLite DB
    used by every SOC Dashboard component.

.DESCRIPTION
    Single source of truth for the SQLite schema, the on-disk database
    location, and the PSSQLite dependency check. Dot-source this from any
    SOC Dashboard ingest, query, or GUI script:

        . (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
        Ensure-PSSQLite
        Initialize-SecIntelSchema

    After dot-sourcing, the following are available in the caller's scope:

        $script:DbDir              %USERPROFILE%\SecIntel
        $script:DbPath             %USERPROFILE%\SecIntel\secintel.db
        $script:SecIntelSchemaDdl  Full DDL string (idempotent)
        Ensure-PSSQLite            Installs/imports PSSQLite (CurrentUser)
        Initialize-SecIntelSchema  Creates all tables + indexes + migrations

    Adding a new table to the SOC dataset is now a one-file change here.

.NOTES
    PowerShell 5.1+. No admin rights required.
    Files using this module:
      - MitreAttackExplorer.ps1
      - Update-CveKevFeed.ps1
      - Update-EpssFeed.ps1
      - Update-CveAttackMap.ps1
      - SecIntel.HashLookup.ps1
      - SecIntel.KqlHelpers.ps1
      - SecIntel.Settings.ps1
      - SecIntel.DailyBrief.ps1
      - SecIntel.UiHelpers.ps1
      - SocDashboard.ps1
      - SecIntel.ThreatIntel.* (provider modules)
#>

# ---------- Paths ----------
$script:DbDir  = Join-Path $env:USERPROFILE 'SecIntel'
$script:DbPath = Join-Path $script:DbDir    'secintel.db'

if (-not (Test-Path $script:DbDir)) {
    New-Item -ItemType Directory -Path $script:DbDir -Force | Out-Null
}

# ---------- Dependency bootstrap ----------
function Ensure-PSSQLite {
    [CmdletBinding()]
    param()
    # TLS 1.2 enforcement first so PSGallery contact doesn't silently fail on
    # Windows PowerShell 5.1's default 'Ssl3, Tls' mix.
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {}

    if (Get-Module -Name PSSQLite) { return }
    if (Get-Module -ListAvailable -Name PSSQLite) {
        Import-Module PSSQLite
        if (Get-Command Invoke-SqliteQuery -ErrorAction SilentlyContinue) { return }
        Write-Warning "PSSQLite imported but Invoke-SqliteQuery not exposed. Reinstalling..."
    }
    Write-Host "PSSQLite not found or broken. Installing to CurrentUser scope..." -ForegroundColor Cyan
    try {
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
        }
        if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
            Register-PSRepository -Default -ErrorAction SilentlyContinue
        }
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        Install-Module -Name PSSQLite -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck
    } catch {
        throw "Failed to install PSSQLite: $_`nManually install with: Install-Module PSSQLite -Scope CurrentUser -Force -SkipPublisherCheck"
    }
    Import-Module PSSQLite
    if (-not (Get-Command Invoke-SqliteQuery -ErrorAction SilentlyContinue)) {
        throw "PSSQLite installed but Invoke-SqliteQuery still missing. Try removing the module folder under \$env:USERPROFILE\Documents\WindowsPowerShell\Modules\PSSQLite and reinstalling."
    }
}

# ---------- Schema (single source of truth) ----------
$script:SecIntelSchemaDdl = @'
-- ============================================================
-- SecIntel SQLite schema
-- Idempotent (CREATE IF NOT EXISTS). Local-only DB.
-- ============================================================

-- ===== MITRE ATT&CK =====
CREATE TABLE IF NOT EXISTS Tactics (
    StixId TEXT PRIMARY KEY,
    ExternalId TEXT,
    Name TEXT,
    ShortName TEXT,
    Description TEXT,
    Url TEXT
);
CREATE TABLE IF NOT EXISTS Techniques (
    StixId TEXT PRIMARY KEY,
    ExternalId TEXT,
    Name TEXT,
    IsSubtechnique INTEGER,
    ParentExternalId TEXT,
    Tactics TEXT,
    Platforms TEXT,
    DataSources TEXT,
    Detection TEXT,
    Description TEXT,
    Url TEXT
);
CREATE TABLE IF NOT EXISTS AttackGroups (
    StixId TEXT PRIMARY KEY,
    ExternalId TEXT,
    Name TEXT,
    Aliases TEXT,
    Description TEXT,
    Url TEXT
);
CREATE TABLE IF NOT EXISTS Software (
    StixId TEXT PRIMARY KEY,
    ExternalId TEXT,
    Name TEXT,
    Type TEXT,
    Aliases TEXT,
    Platforms TEXT,
    Description TEXT,
    Url TEXT
);
CREATE TABLE IF NOT EXISTS Mitigations (
    StixId TEXT PRIMARY KEY,
    ExternalId TEXT,
    Name TEXT,
    Description TEXT,
    Url TEXT
);
CREATE TABLE IF NOT EXISTS Relationships (
    SourceId TEXT,
    TargetId TEXT,
    RelType TEXT,
    Description TEXT
);
CREATE INDEX IF NOT EXISTS IX_Tech_Parent ON Techniques(ParentExternalId);
CREATE INDEX IF NOT EXISTS IX_Rel_Source  ON Relationships(SourceId);
CREATE INDEX IF NOT EXISTS IX_Rel_Target  ON Relationships(TargetId);

-- ===== Vulnerability feeds =====
CREATE TABLE IF NOT EXISTS CVEs (
    CveId TEXT PRIMARY KEY,
    Published TEXT,
    LastModified TEXT,
    CvssScore REAL,
    Severity TEXT,
    Vector TEXT,
    Description TEXT,
    RefLinks TEXT
    -- EpssScore, EpssPercentile, EpssDate added via migration below
);
CREATE INDEX IF NOT EXISTS IX_CVE_Published ON CVEs(Published);
CREATE INDEX IF NOT EXISTS IX_CVE_Score     ON CVEs(CvssScore);

CREATE TABLE IF NOT EXISTS KEVs (
    CveId TEXT PRIMARY KEY,
    VendorProject TEXT,
    Product TEXT,
    VulnName TEXT,
    DateAdded TEXT,
    Description TEXT,
    RequiredAction TEXT,
    DueDate TEXT,
    KnownRansomware TEXT,
    Notes TEXT
);
CREATE INDEX IF NOT EXISTS IX_KEV_DateAdded ON KEVs(DateAdded);
CREATE INDEX IF NOT EXISTS IX_KEV_Vendor    ON KEVs(VendorProject);

-- ===== CVE -> ATT&CK technique mapping =====
CREATE TABLE IF NOT EXISTS CveTechniqueMap (
    CveId TEXT,
    TechniqueId TEXT,
    Source TEXT,
    Confidence TEXT,
    Mapping TEXT,
    PRIMARY KEY (CveId, TechniqueId, Source)
);
CREATE INDEX IF NOT EXISTS IX_CveTech_Cve  ON CveTechniqueMap(CveId);
CREATE INDEX IF NOT EXISTS IX_CveTech_Tech ON CveTechniqueMap(TechniqueId);

-- ===== Hash enrichment cache (legacy, hash-only) =====
CREATE TABLE IF NOT EXISTS HashIntel (
    Sha256 TEXT,
    Source TEXT,
    Md5 TEXT,
    Sha1 TEXT,
    Verdict TEXT,
    FirstSeen TEXT,
    LastSeen TEXT,
    FamilyName TEXT,
    Tags TEXT,
    DetectionRatio TEXT,
    Reputation INTEGER,
    FetchedAt TEXT,
    TtlSeconds INTEGER,
    RawJson TEXT,
    PRIMARY KEY (Sha256, Source)
);
CREATE INDEX IF NOT EXISTS IX_HashIntel_Md5    ON HashIntel(Md5);
CREATE INDEX IF NOT EXISTS IX_HashIntel_Sha1   ON HashIntel(Sha1);
CREATE INDEX IF NOT EXISTS IX_HashIntel_Family ON HashIntel(FamilyName);

-- ===== IoC table (proper structured store) =====
CREATE TABLE IF NOT EXISTS Iocs (
    IocId INTEGER PRIMARY KEY AUTOINCREMENT,
    Type TEXT,
    Value TEXT,
    Source TEXT,
    FirstSeen TEXT,
    LastSeen TEXT,
    Confidence INTEGER,
    Tlp TEXT,
    Tags TEXT,
    Notes TEXT
);
CREATE INDEX IF NOT EXISTS IX_Iocs_Type   ON Iocs(Type);
CREATE INDEX IF NOT EXISTS IX_Iocs_Value  ON Iocs(Value);
CREATE INDEX IF NOT EXISTS IX_Iocs_Source ON Iocs(Source);

-- ===== Saved KQL queries =====
CREATE TABLE IF NOT EXISTS KqlQueries (
    QueryId INTEGER PRIMARY KEY AUTOINCREMENT,
    Name TEXT,
    Description TEXT,
    Tags TEXT,
    Tactics TEXT,
    TechniqueIds TEXT,
    TableName TEXT,
    Query TEXT,
    Author TEXT,
    Created TEXT,
    LastModified TEXT,
    LastRun TEXT,
    RunCount INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS IX_KqlQ_Name ON KqlQueries(Name);
CREATE INDEX IF NOT EXISTS IX_KqlQ_Tags ON KqlQueries(Tags);

-- ===== Built-in + user KQL template library =====
-- Distinct from KqlQueries (which is the runtime log of executed
-- queries with timestamps and run counts). KqlTemplates is the
-- reusable starting-point library: 5 built-in templates seeded from
-- lab/templates/data.json (IsBuiltIn=1) plus any analyst-authored
-- templates (IsBuiltIn=0). Tags are stored as a JSON array string,
-- matching the pattern used by KqlQueries.Tags and Iocs.Tags.
CREATE TABLE IF NOT EXISTS KqlTemplates (
    TemplateId    INTEGER PRIMARY KEY AUTOINCREMENT,
    Name          TEXT NOT NULL UNIQUE,
    Description   TEXT,
    Tags          TEXT,
    Kql           TEXT NOT NULL,
    Author        TEXT,
    IsBuiltIn     INTEGER DEFAULT 0,
    Created       TEXT,
    LastModified  TEXT
);
CREATE INDEX IF NOT EXISTS IX_KqlTmpl_Name ON KqlTemplates(Name);
CREATE INDEX IF NOT EXISTS IX_KqlTmpl_Tags ON KqlTemplates(Tags);

-- ===== Watchlists =====
CREATE TABLE IF NOT EXISTS Watchlists (
    WatchlistId INTEGER PRIMARY KEY AUTOINCREMENT,
    Name TEXT UNIQUE,
    ItemType TEXT,
    Description TEXT,
    Created TEXT,
    LastModified TEXT
);
CREATE TABLE IF NOT EXISTS WatchlistItems (
    WatchlistId INTEGER,
    Value TEXT,
    Note TEXT,
    AddedAt TEXT,
    PRIMARY KEY (WatchlistId, Value),
    FOREIGN KEY (WatchlistId) REFERENCES Watchlists(WatchlistId)
);

-- ===== Local app settings + per-user state =====
CREATE TABLE IF NOT EXISTS AppSettings (
    Name TEXT PRIMARY KEY,
    Value TEXT,
    IsSecret INTEGER DEFAULT 0,
    Updated TEXT
);

-- ===== Feed metadata =====
CREATE TABLE IF NOT EXISTS FeedMeta (
    FeedName TEXT PRIMARY KEY,
    LastUpdated TEXT,
    RecordCount INTEGER
);

-- ===== Generic threat-intel cache (sidecar to HashIntel) =====
-- Hash lookups continue to go through HashIntel (legacy, hash-only).
-- IntelCache holds enrichment for ANY IoC type (IP, domain, URL, hash)
-- across ANY provider (VirusTotal IP/domain/URL, OTX, URLScan,
-- AbuseIPDB, NSRL/CIRCL, NIST NVD product searches, ...).
-- One row per (IocType, IocValue, Source). TTL is verdict-driven.
CREATE TABLE IF NOT EXISTS IntelCache (
    IocType        TEXT,
    IocValue       TEXT,
    Source         TEXT,
    Verdict        TEXT,
    Family         TEXT,
    Tags           TEXT,
    Reputation     INTEGER,
    DetectionRatio TEXT,
    ProviderUrl    TEXT,
    FirstSeen      TEXT,
    LastSeen       TEXT,
    RawJson        TEXT,
    FetchedAt      TEXT,
    TtlSeconds     INTEGER,
    PRIMARY KEY (IocType, IocValue, Source)
);
CREATE INDEX IF NOT EXISTS IX_IntelCache_Value   ON IntelCache(IocValue);
CREATE INDEX IF NOT EXISTS IX_IntelCache_Source  ON IntelCache(Source);
CREATE INDEX IF NOT EXISTS IX_IntelCache_Verdict ON IntelCache(Verdict);
'@

# ---------- Column-level migrations ----------
function Add-CveEpssColumnsIfMissing {
    param([string]$DbPath = $script:DbPath)
    $cols = (Invoke-SqliteQuery -DataSource $DbPath -Query "PRAGMA table_info(CVEs)").name
    if ($cols -notcontains 'EpssScore')      { Invoke-SqliteQuery -DataSource $DbPath -Query "ALTER TABLE CVEs ADD COLUMN EpssScore REAL" }
    if ($cols -notcontains 'EpssPercentile') { Invoke-SqliteQuery -DataSource $DbPath -Query "ALTER TABLE CVEs ADD COLUMN EpssPercentile REAL" }
    if ($cols -notcontains 'EpssDate')       { Invoke-SqliteQuery -DataSource $DbPath -Query "ALTER TABLE CVEs ADD COLUMN EpssDate TEXT" }
}

# Builds a JSON array string from a [string[]]. Required because
# `@('one') | ConvertTo-Json -Compress` returns '"one"' (the inner
# string) not '["one"]' (a one-element array) on PS 5.1, which would
# corrupt the Tags column for any single-tag template. Manual build is
# reliable across all PS versions.
function ConvertTo-SecIntelTagsJson {
    [CmdletBinding()]
    param([string[]]$Tags)
    if (-not $Tags) { return '[]' }
    $arr = @($Tags) | Where-Object { $_ -ne $null -and $_ -ne '' }
    if ($arr.Count -eq 0) { return '[]' }
    # Use plain String.Replace (not -replace) to avoid PowerShell's
    # regex replacement semantics, where '\\\\' would expand to four
    # literal backslashes instead of two. Bind to the
    # Replace(string,string) overload by passing string args on both
    # sides; Replace(char,char) would reject the 2-char '\r' / '\n'.
    $parts = foreach ($t in $arr) {
        $s = [string]$t
        $s = $s.Replace('\', '\\').Replace('"', '\"')
        $s = $s.Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t')
        '"' + $s + '"'
    }
    return '[' + ($parts -join ',') + ']'
}

function Import-KqlTemplatesFromJsonIfEmpty {
    [CmdletBinding()]
    param([string]$DbPath = $script:DbPath)

    $count = (Invoke-SqliteQuery -DataSource $DbPath `
                -Query "SELECT COUNT(*) AS N FROM KqlTemplates").N
    if ($count -gt 0) { return }

    # Resolve lab/templates/data.json relative to this script:
    # SOC Dashboard/Modules/SecIntel.Schema.ps1 -> ../../lab/templates/data.json
    $jsonPath = Join-Path $PSScriptRoot '..\..\lab\templates\data.json'
    $resolved = Resolve-Path $jsonPath -ErrorAction SilentlyContinue
    if (-not $resolved) {
        Write-Verbose "lab/templates/data.json not found; skipping built-in KQL template seed."
        return
    }

    try {
        $data = Get-Content -Raw $resolved.Path | ConvertFrom-Json
    } catch {
        Write-Warning ("Failed to parse {0}: {1}" -f $resolved.Path, $_.Exception.Message)
        return
    }

    $now     = (Get-Date).ToString('o')
    $created = if ($data.updated) { $data.updated } else { $now }
    $tplList = @($data.templates)
    $inserted = 0

    foreach ($t in $tplList) {
        if (-not $t.name -or -not $t.kql) { continue }
        $tagsJson = ConvertTo-SecIntelTagsJson -Tags $t.tags
        Invoke-SqliteQuery -DataSource $DbPath -Query @"
INSERT OR IGNORE INTO KqlTemplates
    (Name, Description, Tags, Kql, Author, IsBuiltIn, Created, LastModified)
VALUES
    (@n, @d, @tg, @k, @a, 1, @c, @m)
"@ -SqlParameters @{
            n  = $t.name
            d  = $t.description
            tg = $tagsJson
            k  = $t.kql
            a  = 'lab/templates/data.json'
            c  = $created
            m  = $now
        }
        $inserted++
    }
    if ($inserted -gt 0) {
        Write-Host ("Seeded {0} built-in KQL templates from {1}" -f $inserted, $resolved.Path) -ForegroundColor Cyan
    }
}

function Initialize-SecIntelSchema {
    [CmdletBinding()]
    param([string]$DbPath = $script:DbPath)
    # WAL is a database-level setting that persists in the DB file
    # header, so setting it once here applies to every future
    # connection. Required for the parallel feed orchestrator
    # (Phase 3) which writes KEV and EPSS simultaneously.
    #
    # PRAGMA busy_timeout is intentionally NOT set here: it is a
    # per-connection setting that does not persist, and PSSQLite
    # opens a fresh connection per Invoke-SqliteQuery call. Phase 3
    # will introduce a connection wrapper that sets busy_timeout
    # on each acquired connection.
    Invoke-SqliteQuery -DataSource $DbPath -Query "PRAGMA journal_mode=WAL" | Out-Null
    Invoke-SqliteQuery -DataSource $DbPath -Query $script:SecIntelSchemaDdl
    Add-CveEpssColumnsIfMissing -DbPath $DbPath
    Import-KqlTemplatesFromJsonIfEmpty -DbPath $DbPath
}
