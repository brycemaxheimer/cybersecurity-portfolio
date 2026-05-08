<#
.SYNOPSIS
    Self-contained builder + readiness probe for the KQL practice lab DB.

.DESCRIPTION
    The 16-table Sentinel-projected schema (ported verbatim from
    kql/engine/schema.js) ships inline as $script:KqlLabSchema. Earlier
    the toolkit shipped a Build-KqlLabDb.ps1 that read schema definitions
    out of CommonTableSchema.txt - that file isn't tracked in the repo,
    so the legacy script bricks on first run. This module replaces it.

    Initialize-KqlLab creates %USERPROFILE%\SecIntel\kql_lab.db (or any
    explicit path), declares the 16 tables, indexes the common pivots
    (TimeGenerated, DeviceName, Computer, Account, EventID, ActionType),
    writes a __schema__ metadata table that Invoke-KqlPS reads to
    coerce columns, and bulk-loads CSVs from the requested data dir.

    Test-KqlLabReady returns @{ Ready; DbPath; Tables; TotalRows; Note }
    so the dashboard can decide whether to bootstrap.

    The lab DB is independent of secintel.db. Practice queries never
    touch the SOC's live data; secintel.db only stores per-question
    state in KqlPracticeState.

.NOTES
    PowerShell 5.1+. Dot-source SecIntel.Schema.ps1 first for $script:DbDir.
#>

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')

# ============================================================
# Default lab DB path. Sits alongside secintel.db so all
# SecIntel state lives under one folder for back-up / move.
# ============================================================
$script:KqlLabDbPath = Join-Path $script:DbDir 'kql_lab.db'

# ============================================================
# Sentinel-projected lab schema (16 tables). Ported from
# kql/engine/schema.js. Order is preserved so column ordinals
# match the JS runtime + browser practice harness.
# ============================================================
$script:KqlLabSchema = [ordered]@{
    AuditLogs = @(
        @{n='TimeGenerated';        t='datetime'}
        @{n='OperationName';        t='string'}
        @{n='Category';             t='string'}
        @{n='Result';               t='string'}
        @{n='ResultReason';         t='string'}
        @{n='ResultDescription';    t='string'}
        @{n='ActivityDisplayName';  t='string'}
        @{n='ActivityDateTime';     t='datetime'}
        @{n='AADOperationType';     t='string'}
        @{n='Identity';             t='string'}
        @{n='InitiatedBy';          t='string'}
        @{n='TargetResources';      t='dynamic'}
        @{n='LoggedByService';      t='string'}
        @{n='Type';                 t='string'}
    )
    CommonSecurityLog = @(
        @{n='TimeGenerated';        t='datetime'}
        @{n='DeviceVendor';         t='string'}
        @{n='DeviceProduct';        t='string'}
        @{n='DeviceVersion';        t='string'}
        @{n='DeviceEventClassID';   t='string'}
        @{n='Activity';             t='string'}
        @{n='LogSeverity';          t='int'}
        @{n='DeviceAction';         t='string'}
        @{n='ApplicationProtocol';  t='string'}
        @{n='SourceIP';             t='string'}
        @{n='SourcePort';           t='int'}
        @{n='DestinationIP';        t='string'}
        @{n='DestinationPort';      t='int'}
        @{n='Protocol';             t='string'}
        @{n='SimplifiedDeviceAction'; t='string'}
        @{n='Computer';             t='string'}
        @{n='Type';                 t='string'}
    )
    DHCP = @(
        @{n='TimeGenerated'; t='datetime'}
        @{n='ID';            t='string'}
        @{n='Date';          t='string'}
        @{n='Time';          t='string'}
        @{n='Description';   t='string'}
        @{n='IP';            t='string'}
        @{n='HostName';      t='string'}
        @{n='MAC';           t='string'}
        @{n='User';          t='string'}
        @{n='TransactionID'; t='string'}
        @{n='QResult';       t='string'}
        @{n='VendorClass';   t='string'}
        @{n='Type';          t='string'}
    )
    DeviceFileEvents = @(
        @{n='TimeGenerated';                t='datetime'}
        @{n='Timestamp';                    t='datetime'}
        @{n='DeviceName';                   t='string'}
        @{n='ActionType';                   t='string'}
        @{n='FileName';                     t='string'}
        @{n='FolderPath';                   t='string'}
        @{n='SHA256';                       t='string'}
        @{n='SHA1';                         t='string'}
        @{n='MD5';                          t='string'}
        @{n='FileSize';                     t='long'}
        @{n='InitiatingProcessFileName';    t='string'}
        @{n='InitiatingProcessAccountName'; t='string'}
        @{n='InitiatingProcessCommandLine'; t='string'}
        @{n='Type';                         t='string'}
    )
    DeviceImageLoadEvents = @(
        @{n='TimeGenerated';                  t='datetime'}
        @{n='Timestamp';                      t='datetime'}
        @{n='DeviceName';                     t='string'}
        @{n='FileName';                       t='string'}
        @{n='FolderPath';                     t='string'}
        @{n='SHA256';                         t='string'}
        @{n='InitiatingProcessFileName';      t='string'}
        @{n='InitiatingProcessFolderPath';    t='string'}
        @{n='Type';                           t='string'}
    )
    DeviceLogonEvents = @(
        @{n='TimeGenerated';                t='datetime'}
        @{n='Timestamp';                    t='datetime'}
        @{n='DeviceName';                   t='string'}
        @{n='ActionType';                   t='string'}
        @{n='AccountName';                  t='string'}
        @{n='AccountDomain';                t='string'}
        @{n='AccountSid';                   t='string'}
        @{n='LogonType';                    t='string'}
        @{n='FailureReason';                t='string'}
        @{n='IsLocalAdmin';                 t='bool'}
        @{n='LogonId';                      t='string'}
        @{n='RemoteIP';                     t='string'}
        @{n='RemoteIPType';                 t='string'}
        @{n='RemotePort';                   t='int'}
        @{n='Protocol';                     t='string'}
        @{n='InitiatingProcessFileName';    t='string'}
        @{n='InitiatingProcessAccountName'; t='string'}
        @{n='Type';                         t='string'}
    )
    DeviceNetworkEvents = @(
        @{n='TimeGenerated';                t='datetime'}
        @{n='Timestamp';                    t='datetime'}
        @{n='DeviceName';                   t='string'}
        @{n='ActionType';                   t='string'}
        @{n='LocalIP';                      t='string'}
        @{n='LocalIPType';                  t='string'}
        @{n='LocalPort';                    t='int'}
        @{n='RemoteIP';                     t='string'}
        @{n='RemoteIPType';                 t='string'}
        @{n='RemotePort';                   t='int'}
        @{n='RemoteUrl';                    t='string'}
        @{n='Protocol';                     t='string'}
        @{n='InitiatingProcessFileName';    t='string'}
        @{n='InitiatingProcessFolderPath';  t='string'}
        @{n='InitiatingProcessCommandLine'; t='string'}
        @{n='InitiatingProcessAccountName'; t='string'}
        @{n='InitiatingProcessSHA256';      t='string'}
        @{n='Type';                         t='string'}
    )
    DeviceNetworkInfo = @(
        @{n='TimeGenerated';        t='datetime'}
        @{n='Timestamp';            t='datetime'}
        @{n='DeviceName';           t='string'}
        @{n='DeviceId';             t='string'}
        @{n='MacAddress';           t='string'}
        @{n='IPAddresses';          t='string'}
        @{n='DnsAddresses';         t='string'}
        @{n='DefaultGateways';      t='string'}
        @{n='ConnectedNetworks';    t='string'}
        @{n='NetworkAdapterName';   t='string'}
        @{n='NetworkAdapterStatus'; t='string'}
        @{n='NetworkAdapterType';   t='string'}
        @{n='Type';                 t='string'}
    )
    DeviceProcessEvents = @(
        @{n='TimeGenerated';                       t='datetime'}
        @{n='Timestamp';                           t='datetime'}
        @{n='DeviceName';                          t='string'}
        @{n='DeviceId';                            t='string'}
        @{n='AccountName';                         t='string'}
        @{n='AccountDomain';                       t='string'}
        @{n='FileName';                            t='string'}
        @{n='FolderPath';                          t='string'}
        @{n='ProcessCommandLine';                  t='string'}
        @{n='ProcessId';                           t='long'}
        @{n='SHA256';                              t='string'}
        @{n='SHA1';                                t='string'}
        @{n='MD5';                                 t='string'}
        @{n='FileSize';                            t='long'}
        @{n='InitiatingProcessFileName';           t='string'}
        @{n='InitiatingProcessFolderPath';         t='string'}
        @{n='InitiatingProcessCommandLine';        t='string'}
        @{n='InitiatingProcessId';                 t='long'}
        @{n='InitiatingProcessAccountName';        t='string'}
        @{n='InitiatingProcessSHA256';             t='string'}
        @{n='InitiatingProcessSignatureStatus';    t='string'}
        @{n='InitiatingProcessSignerType';         t='string'}
        @{n='ProcessIntegrityLevel';               t='string'}
        @{n='ProcessTokenElevation';               t='string'}
        @{n='Type';                                t='string'}
    )
    DeviceRegistryEvents = @(
        @{n='TimeGenerated';                t='datetime'}
        @{n='Timestamp';                    t='datetime'}
        @{n='DeviceName';                   t='string'}
        @{n='ActionType';                   t='string'}
        @{n='RegistryKey';                  t='string'}
        @{n='RegistryValueName';            t='string'}
        @{n='RegistryValueData';            t='string'}
        @{n='RegistryValueType';            t='string'}
        @{n='InitiatingProcessFileName';    t='string'}
        @{n='InitiatingProcessAccountName'; t='string'}
        @{n='InitiatingProcessCommandLine'; t='string'}
        @{n='Type';                         t='string'}
    )
    SecurityAlert = @(
        @{n='TimeGenerated';      t='datetime'}
        @{n='DisplayName';        t='string'}
        @{n='AlertName';          t='string'}
        @{n='AlertSeverity';      t='string'}
        @{n='Description';        t='string'}
        @{n='ProviderName';       t='string'}
        @{n='VendorName';         t='string'}
        @{n='ProductName';        t='string'}
        @{n='SystemAlertId';      t='string'}
        @{n='AlertType';          t='string'}
        @{n='Status';             t='string'}
        @{n='ConfidenceLevel';    t='string'}
        @{n='ConfidenceScore';    t='real'}
        @{n='IsIncident';         t='bool'}
        @{n='StartTime';          t='datetime'}
        @{n='EndTime';            t='datetime'}
        @{n='Entities';           t='dynamic'}
        @{n='Tactics';            t='string'}
        @{n='Techniques';         t='string'}
        @{n='ProcessingEndTime';  t='datetime'}
        @{n='Type';               t='string'}
    )
    SecurityEvent = @(
        @{n='TimeGenerated';     t='datetime'}
        @{n='Computer';          t='string'}
        @{n='EventID';           t='int'}
        @{n='Activity';          t='string'}
        @{n='Account';           t='string'}
        @{n='AccountType';       t='string'}
        @{n='AccountDomain';     t='string'}
        @{n='AccountName';       t='string'}
        @{n='TargetUserName';    t='string'}
        @{n='TargetDomainName';  t='string'}
        @{n='IpAddress';         t='string'}
        @{n='IpPort';            t='int'}
        @{n='LogonType';         t='string'}
        @{n='LogonProcessName';  t='string'}
        @{n='FailureReason';     t='string'}
        @{n='ProcessName';       t='string'}
        @{n='NewProcessName';    t='string'}
        @{n='ParentProcessName'; t='string'}
        @{n='CommandLine';       t='string'}
        @{n='ServiceName';       t='string'}
        @{n='ServiceFileName';   t='string'}
        @{n='EventSourceName';   t='string'}
        @{n='Channel';           t='string'}
        @{n='Type';              t='string'}
    )
    SecurityIncident = @(
        @{n='TimeGenerated';         t='datetime'}
        @{n='IncidentNumber';        t='string'}
        @{n='Title';                 t='string'}
        @{n='Description';           t='string'}
        @{n='Severity';              t='string'}
        @{n='Status';                t='string'}
        @{n='Classification';        t='string'}
        @{n='ClassificationReason';  t='string'}
        @{n='FirstActivityTime';     t='datetime'}
        @{n='LastActivityTime';      t='datetime'}
        @{n='FirstModifiedTime';     t='datetime'}
        @{n='LastModifiedTime';      t='datetime'}
        @{n='CreatedTime';           t='datetime'}
        @{n='AlertIds';              t='dynamic'}
        @{n='ModifiedBy';            t='string'}
        @{n='Type';                  t='string'}
    )
    SigninLogs = @(
        @{n='TimeGenerated';              t='datetime'}
        @{n='UserPrincipalName';          t='string'}
        @{n='UserDisplayName';            t='string'}
        @{n='UserId';                     t='string'}
        @{n='IPAddress';                  t='string'}
        @{n='AppDisplayName';             t='string'}
        @{n='AppId';                      t='string'}
        @{n='ClientAppUsed';              t='string'}
        @{n='ResultType';                 t='int'}
        @{n='ResultDescription';          t='string'}
        @{n='ConditionalAccessStatus';    t='string'}
        @{n='IsRisky';                    t='bool'}
        @{n='RiskLevelDuringSignIn';      t='string'}
        @{n='RiskState';                  t='string'}
        @{n='RiskEventTypes';             t='string'}
        @{n='LocationDetails';            t='dynamic'}
        @{n='DeviceDetail';               t='dynamic'}
        @{n='AuthenticationRequirement';  t='string'}
        @{n='IsInteractive';              t='bool'}
        @{n='UserAgent';                  t='string'}
        @{n='Type';                       t='string'}
    )
    Syslog = @(
        @{n='TimeGenerated';      t='datetime'}
        @{n='EventTime';          t='datetime'}
        @{n='Computer';           t='string'}
        @{n='HostName';           t='string'}
        @{n='HostIP';             t='string'}
        @{n='Facility';           t='string'}
        @{n='SeverityLevel';      t='string'}
        @{n='ProcessName';        t='string'}
        @{n='ProcessID';          t='long'}
        @{n='SyslogMessage';      t='string'}
        @{n='CollectorHostName';  t='string'}
        @{n='Type';               t='string'}
    )
    W3CIISLog = @(
        @{n='TimeGenerated';   t='datetime'}
        @{n='Date';            t='string'}
        @{n='Time';            t='string'}
        @{n='sSiteName';       t='string'}
        @{n='sComputerName';   t='string'}
        @{n='sIP';             t='string'}
        @{n='csMethod';        t='string'}
        @{n='csUriStem';       t='string'}
        @{n='csUriQuery';      t='string'}
        @{n='sPort';           t='int'}
        @{n='csUserName';      t='string'}
        @{n='cIP';             t='string'}
        @{n='csUserAgent';     t='string'}
        @{n='scStatus';        t='int'}
        @{n='scSubStatus';     t='int'}
        @{n='scWin32Status';   t='int'}
        @{n='scBytes';         t='long'}
        @{n='csBytes';         t='long'}
        @{n='TimeTaken';       t='long'}
        @{n='Computer';        t='string'}
        @{n='Type';            t='string'}
    )
}

# Common pivots that get an index per table when present.
$script:KqlLabIndexedColumns = @(
    'TimeGenerated','Computer','DeviceName',
    'Account','AccountName','UserPrincipalName',
    'EventID','ActionType'
)

function ConvertTo-KqlLabSqlType {
    param([string]$KqlType)
    switch ($KqlType) {
        'int'      { 'INTEGER' }
        'long'     { 'INTEGER' }
        'bool'     { 'INTEGER' }
        'real'     { 'REAL' }
        default    { 'TEXT' }
    }
}

# ============================================================
# Build the empty schema (no data). Idempotent: drops + rebuilds
# everything if -Force; otherwise no-ops on existing tables.
# ============================================================
function New-KqlLabDatabase {
    [CmdletBinding()]
    param(
        [string]$DbPath = $script:KqlLabDbPath,
        [switch]$Force
    )

    if ($Force -and (Test-Path -LiteralPath $DbPath)) {
        Remove-Item -LiteralPath $DbPath -Force
    }

    $conn = New-SQLiteConnection -DataSource $DbPath
    try {
        Invoke-SqliteQuery -SQLiteConnection $conn -Query @"
CREATE TABLE IF NOT EXISTS __schema__ (
    table_name TEXT NOT NULL,
    col_name   TEXT NOT NULL,
    kql_type   TEXT NOT NULL,
    sql_type   TEXT NOT NULL,
    ordinal    INTEGER NOT NULL,
    PRIMARY KEY (table_name, col_name)
);
"@
        Invoke-SqliteQuery -SQLiteConnection $conn -Query 'BEGIN TRANSACTION;'
        try {
            foreach ($tableName in $script:KqlLabSchema.Keys) {
                $cols = $script:KqlLabSchema[$tableName]
                $colDefs = ($cols | ForEach-Object {
                    '"' + $_.n + '" ' + (ConvertTo-KqlLabSqlType $_.t)
                }) -join ", "
                $ddl = 'CREATE TABLE IF NOT EXISTS "{0}" ({1});' -f $tableName, $colDefs
                Invoke-SqliteQuery -SQLiteConnection $conn -Query $ddl

                $names = $cols | ForEach-Object { $_.n }
                foreach ($pivot in $script:KqlLabIndexedColumns) {
                    if ($names -contains $pivot) {
                        $ix = 'CREATE INDEX IF NOT EXISTS "ix_{0}_{1}" ON "{0}" ("{1}");' -f $tableName, $pivot
                        Invoke-SqliteQuery -SQLiteConnection $conn -Query $ix
                    }
                }

                # __schema__ rows. Re-insert OR IGNORE so re-runs don't double up.
                $ord = 0
                foreach ($c in $cols) {
                    Invoke-SqliteQuery -SQLiteConnection $conn `
                        -Query 'INSERT OR IGNORE INTO __schema__ VALUES (@t,@c,@k,@s,@o);' `
                        -SqlParameters @{
                            t = $tableName; c = $c.n; k = $c.t
                            s = (ConvertTo-KqlLabSqlType $c.t); o = $ord
                        } | Out-Null
                    $ord++
                }
            }
            Invoke-SqliteQuery -SQLiteConnection $conn -Query 'COMMIT;'
        } catch {
            Invoke-SqliteQuery -SQLiteConnection $conn -Query 'ROLLBACK;' -ErrorAction SilentlyContinue
            throw
        }
    } finally {
        $conn.Close()
        $conn.Dispose()
    }
}

# ============================================================
# CSV value coercion. Mirrors Convert-CellValue from
# Import-KqlLabCsv.ps1 - kept inline so this module is
# self-contained (the original script needs CommonTableSchema.txt
# which isn't tracked in the repo).
# ============================================================
$script:KqlLabBoolTrue  = @('true','1','yes','y','t')
$script:KqlLabBoolFalse = @('false','0','no','n','f')

function _ConvertKqlLabCell {
    param(
        [AllowNull()][string]$Value,
        [string]$KqlType,
        [string]$SqlType
    )
    if ($null -eq $Value) { return $null }
    $v = $Value.Trim()
    if ($v -eq '') { return $null }
    try {
        switch ($KqlType) {
            'bool' {
                $lo = $v.ToLowerInvariant()
                if ($script:KqlLabBoolTrue  -contains $lo) { return 1 }
                if ($script:KqlLabBoolFalse -contains $lo) { return 0 }
                return $null
            }
            'dynamic' { return $v }   # raw JSON kept verbatim
            default {
                switch ($SqlType) {
                    'INTEGER' { return [int64]([double]::Parse($v, [System.Globalization.CultureInfo]::InvariantCulture)) }
                    'REAL'    { return [double]::Parse($v, [System.Globalization.CultureInfo]::InvariantCulture) }
                    default   { return $v }
                }
            }
        }
    } catch { return $null }
}

# ============================================================
# Bulk-load one CSV into the named table. -Truncate clears
# the table first; default is append.
# ============================================================
function Import-KqlLabCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Table,
        [Parameter(Mandatory)][string]$CsvPath,
        [string]$DbPath = $script:KqlLabDbPath,
        [switch]$Truncate
    )

    if (-not (Test-Path -LiteralPath $CsvPath)) {
        throw "CSV not found: $CsvPath"
    }
    if (-not $script:KqlLabSchema.Contains($Table)) {
        throw "Unknown lab table: $Table"
    }

    $cols = $script:KqlLabSchema[$Table]
    $schemaMap = @{}
    foreach ($c in $cols) {
        $schemaMap[$c.n] = [pscustomobject]@{
            KqlType = $c.t
            SqlType = (ConvertTo-KqlLabSqlType $c.t)
        }
    }

    $rows = Import-Csv -LiteralPath $CsvPath
    if (-not $rows) { return 0 }

    $headers    = $rows[0].psobject.Properties.Name
    $recognized = @($headers | Where-Object { $schemaMap.ContainsKey($_) })
    if ($recognized.Count -eq 0) {
        throw "No CSV columns match table '$Table'."
    }

    $colList     = ($recognized | ForEach-Object { '"' + $_ + '"' }) -join ', '
    $paramNames  = ($recognized | ForEach-Object { '@' + ($_ -replace '\W','_') })
    $insertSql   = 'INSERT INTO "{0}" ({1}) VALUES ({2});' -f $Table, $colList, ($paramNames -join ', ')

    $conn = New-SQLiteConnection -DataSource $DbPath
    try {
        if ($Truncate) {
            Invoke-SqliteQuery -SQLiteConnection $conn -Query ('DELETE FROM "{0}";' -f $Table)
        }
        Invoke-SqliteQuery -SQLiteConnection $conn -Query 'BEGIN TRANSACTION;'
        $count = 0
        foreach ($row in $rows) {
            $params = @{}
            foreach ($colName in $recognized) {
                $paramKey = $colName -replace '\W','_'
                $type = $schemaMap[$colName]
                $params[$paramKey] = _ConvertKqlLabCell `
                    -Value $row.$colName `
                    -KqlType $type.KqlType `
                    -SqlType $type.SqlType
            }
            Invoke-SqliteQuery -SQLiteConnection $conn -Query $insertSql -SqlParameters $params | Out-Null
            $count++
        }
        Invoke-SqliteQuery -SQLiteConnection $conn -Query 'COMMIT;'
        return $count
    } catch {
        Invoke-SqliteQuery -SQLiteConnection $conn -Query 'ROLLBACK;' -ErrorAction SilentlyContinue
        throw
    } finally {
        $conn.Close()
        $conn.Dispose()
    }
}

# ============================================================
# One-shot bootstrap: ensure the lab DB exists, all 16 tables
# exist, every table has at least one row. Imports CSVs from
# the requested directory (defaults to <repo>/kql/data-large
# relative to this module). Streams progress to OnProgress.
# Returns @{ Built; ImportedRows; Tables; SkippedTables }.
# ============================================================
function Initialize-KqlLab {
    [CmdletBinding()]
    param(
        [string]$DbPath = $script:KqlLabDbPath,
        [string]$DataDir,
        [switch]$Force,
        [scriptblock]$OnProgress
    )

    if (-not $DataDir) {
        # Default: <repo>/kql/data. The practice gold-results were
        # generated against this dataset by kql/test-harness/
        # regenerate-gold.cjs, so the practice grader only passes
        # against this exact CSV set.
        #
        # The data-large/ folder exists too (~3-4x the rows, plus
        # storyline seeds for the harder questions) but the gold
        # contract isn't aligned with it. Pass -DataDir explicitly
        # to use it for free-form KQL exploration.
        $candidate = Join-Path $PSScriptRoot '..\..\kql\data'
        $resolved  = Resolve-Path -LiteralPath $candidate -ErrorAction SilentlyContinue
        if (-not $resolved) {
            $candidate = Join-Path $PSScriptRoot '..\..\kql\data-large'
            $resolved  = Resolve-Path -LiteralPath $candidate -ErrorAction SilentlyContinue
        }
        if (-not $resolved) {
            throw "Could not locate kql/data or kql/data-large relative to $PSScriptRoot"
        }
        $DataDir = $resolved.Path
    }

    if ($OnProgress) { & $OnProgress "building schema in $DbPath" }
    New-KqlLabDatabase -DbPath $DbPath -Force:$Force

    $imported   = @{}
    $skipped    = @()
    $rowCount   = 0
    foreach ($table in $script:KqlLabSchema.Keys) {
        $csvPath = Join-Path $DataDir ($table + '.csv')
        if (-not (Test-Path -LiteralPath $csvPath)) {
            $skipped += $table
            if ($OnProgress) { & $OnProgress "skip $table (no CSV at $csvPath)" }
            continue
        }
        if ($OnProgress) { & $OnProgress "loading $table from $($csvPath | Split-Path -Leaf)..." }
        # Truncate so reruns reload cleanly without compounding.
        $n = Import-KqlLabCsv -Table $table -CsvPath $csvPath -DbPath $DbPath -Truncate
        $imported[$table] = $n
        $rowCount += $n
    }

    return [pscustomobject]@{
        DbPath        = $DbPath
        DataDir       = $DataDir
        Built         = $true
        ImportedRows  = $rowCount
        Tables        = $imported
        SkippedTables = $skipped
    }
}

# ============================================================
# Lightweight readiness probe. Counts rows per table without
# blocking; returns Ready=$false on any DB problem.
# ============================================================
function Test-KqlLabReady {
    [CmdletBinding()]
    param([string]$DbPath = $script:KqlLabDbPath)

    if (-not (Test-Path -LiteralPath $DbPath)) {
        return [pscustomobject]@{
            Ready=$false; DbPath=$DbPath; Tables=@{}; TotalRows=0
            Note='database file does not exist'
        }
    }

    $tables   = @{}
    $total    = 0
    $missing  = @()
    try {
        foreach ($t in $script:KqlLabSchema.Keys) {
            try {
                $r = Invoke-SqliteQuery -DataSource $DbPath `
                        -Query ('SELECT COUNT(*) AS N FROM "{0}"' -f $t) | Select-Object -First 1
                $tables[$t] = [int]$r.N
                $total      += [int]$r.N
            } catch {
                $tables[$t] = -1
                $missing   += $t
            }
        }
    } catch {
        return [pscustomobject]@{
            Ready=$false; DbPath=$DbPath; Tables=@{}; TotalRows=0
            Note=("DB open failed: " + $_.Exception.Message)
        }
    }

    $ready = ($missing.Count -eq 0 -and $total -gt 0)
    [pscustomobject]@{
        Ready          = $ready
        DbPath         = $DbPath
        Tables         = $tables
        TotalRows      = $total
        MissingTables  = $missing
        Note = if (-not $ready) {
            if ($missing.Count) { "missing tables: $($missing -join ', ')" }
            else                { 'all tables empty - run Initialize-KqlLab' }
        } else { 'ready' }
    }
}

# Files are dot-sourced; Export-ModuleMember would fail outside a module context.
