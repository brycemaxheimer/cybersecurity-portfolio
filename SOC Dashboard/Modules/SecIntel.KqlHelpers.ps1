<#
.SYNOPSIS
    KQL helper utilities for SecIntel: hunt-query generation, lint, Sentinel
    portal URL builder, saved-query CRUD.

.DESCRIPTION
    Functions:
        New-HuntQueryFromTechnique  - generates a starter KQL query for a
                                      MITRE technique using its DataSources.
        New-HuntQueryFromCve        - generates a hunt query for a CVE by
                                      pivoting through CveTechniqueMap.
        Test-KqlQuery               - lightweight lint: filter ordering,
                                      missing time predicate, expensive ops
                                      before cheap ones, unbounded take.
        New-SentinelQueryUrl        - builds an Azure portal deep link that
                                      opens a query in the Sentinel Logs
                                      blade for a given workspace.
        Save-KqlQuery / Get-KqlQuery / Remove-KqlQuery / Register-KqlQueryRun
                                    - persistence in KqlQueries table.

.NOTES
    Dot-source SecIntel.Schema.ps1 first.
#>

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')

# ============================================================
# Map ATT&CK DataSource strings to Sentinel/Defender XDR tables.
# This is the bridge between MITRE's data-source taxonomy and the
# tables you actually query. Extend as your environment grows.
# ============================================================
$script:KqlTableForDataSource = @{
    'Process'                     = 'DeviceProcessEvents'
    'Process Creation'            = 'DeviceProcessEvents'
    'Process Access'              = 'DeviceProcessEvents'
    'Process Metadata'            = 'DeviceProcessEvents'
    'OS API Execution'            = 'DeviceProcessEvents'
    'Command'                     = 'DeviceProcessEvents'
    'Command Execution'           = 'DeviceProcessEvents'
    'Script Execution'            = 'DeviceProcessEvents'
    'File'                        = 'DeviceFileEvents'
    'File Creation'               = 'DeviceFileEvents'
    'File Modification'           = 'DeviceFileEvents'
    'File Access'                 = 'DeviceFileEvents'
    'File Metadata'               = 'DeviceFileEvents'
    'File Deletion'               = 'DeviceFileEvents'
    'Module'                      = 'DeviceImageLoadEvents'
    'Module Load'                 = 'DeviceImageLoadEvents'
    'Image Load'                  = 'DeviceImageLoadEvents'
    'Driver Load'                 = 'DeviceImageLoadEvents'
    'Network Traffic'             = 'DeviceNetworkEvents'
    'Network Connection'          = 'DeviceNetworkEvents'
    'Network Connection Creation' = 'DeviceNetworkEvents'
    'Network Traffic Flow'        = 'DeviceNetworkEvents'
    'Logon Session'               = 'DeviceLogonEvents'
    'Logon Session Creation'      = 'DeviceLogonEvents'
    'Authentication'              = 'DeviceLogonEvents'
    'User Account Authentication' = 'SigninLogs'
    'User Account'                = 'IdentityInfo'
    'Cloud Service'               = 'CloudAppEvents'
    'Cloud Service Modification'  = 'CloudAppEvents'
    'Application Log'             = 'SecurityEvent'
    'Windows Registry'            = 'DeviceRegistryEvents'
    'Windows Registry Key Creation'     = 'DeviceRegistryEvents'
    'Windows Registry Key Modification' = 'DeviceRegistryEvents'
    'Registry'                    = 'DeviceRegistryEvents'
    'Scheduled Job'               = 'DeviceEvents'
    'Service'                     = 'DeviceEvents'
    'Service Creation'            = 'DeviceEvents'
    'Sysmon'                      = 'Event'
}

function Get-TablesForTechnique {
    [CmdletBinding()]
    param([string]$DataSourcesText)
    if (-not $DataSourcesText) { return @('DeviceProcessEvents') }
    $parts = $DataSourcesText -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $tables = New-Object System.Collections.Generic.HashSet[string]
    foreach ($p in $parts) {
        $hit = $null
        if ($script:KqlTableForDataSource.ContainsKey($p)) {
            $hit = $script:KqlTableForDataSource[$p]
        } else {
            foreach ($k in $script:KqlTableForDataSource.Keys) {
                if ($p -like "*$k*" -or $k -like "*$p*") { $hit = $script:KqlTableForDataSource[$k]; break }
            }
        }
        if ($hit) { [void]$tables.Add($hit) }
    }
    if ($tables.Count -eq 0) { return @('DeviceProcessEvents') }
    return $tables
}

# ============================================================
# Hunt-query generators
# ============================================================
function New-HuntQueryFromTechnique {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TechniqueId,
        [int]$LookbackDays = 7,
        [string]$DbPath    = $script:DbPath
    )
    $tech = Invoke-SqliteQuery -DataSource $DbPath `
        -Query "SELECT ExternalId, Name, DataSources, Detection FROM Techniques WHERE ExternalId=@id" `
        -SqlParameters @{ id = $TechniqueId } | Select-Object -First 1
    if (-not $tech) { throw "Technique $TechniqueId not found in DB. Run MitreAttackExplorer.ps1 first." }

    $tables   = Get-TablesForTechnique $tech.DataSources
    $detLines = @()
    if ($tech.Detection) {
        $detLines = ($tech.Detection -split "`n") | Where-Object { $_.Trim() } | Select-Object -First 5
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("// Hunt scaffold for $($tech.ExternalId): $($tech.Name)")
    [void]$sb.AppendLine("// Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') by SOC Dashboard")
    [void]$sb.AppendLine("// MITRE data sources: $($tech.DataSources)")
    if ($detLines) {
        [void]$sb.AppendLine("// Detection guidance:")
        foreach ($l in $detLines) { [void]$sb.AppendLine("//   $($l.Trim())") }
    }
    [void]$sb.AppendLine("// <<EXTEND>> Add tactic-specific predicates below.")
    [void]$sb.AppendLine("")

    $first = $true
    foreach ($t in $tables) {
        if (-not $first) { [void]$sb.AppendLine("// ---") }
        $first = $false
        [void]$sb.AppendLine($t)
        [void]$sb.AppendLine("| where TimeGenerated > ago($($LookbackDays)d)")
        switch ($t) {
            'DeviceProcessEvents'   { [void]$sb.AppendLine("// | where FileName in~ ('powershell.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe')") }
            'DeviceFileEvents'      { [void]$sb.AppendLine("// | where ActionType in ('FileCreated','FileRenamed','FileModified')") }
            'DeviceNetworkEvents'   { [void]$sb.AppendLine("// | where RemotePort in (443, 8443, 80) and not(ipv4_is_private(RemoteIP))") }
            'DeviceImageLoadEvents' { [void]$sb.AppendLine("// | where FolderPath !startswith @'C:\Windows\System32\'") }
            'DeviceLogonEvents'     { [void]$sb.AppendLine("// | where ActionType == 'LogonSuccess' and LogonType in (3, 10)") }
            'DeviceRegistryEvents'  { [void]$sb.AppendLine("// | where ActionType == 'RegistryValueSet'") }
            'SigninLogs'            { [void]$sb.AppendLine("// | where ResultType == 0 and RiskLevelDuringSignIn in ('high','medium')") }
            'CloudAppEvents'        { [void]$sb.AppendLine("// | where ActionType has 'Add' or ActionType has 'Update'") }
        }
        [void]$sb.AppendLine("| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName")
        [void]$sb.AppendLine("| take 100")
        [void]$sb.AppendLine("")
    }
    return $sb.ToString().TrimEnd()
}

function New-HuntQueryFromCve {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CveId,
        [int]$LookbackDays    = 7,
        [int]$MaxTechniques   = 3,
        [string]$DbPath       = $script:DbPath
    )
    $maps = Invoke-SqliteQuery -DataSource $DbPath -Query @"
SELECT TechniqueId, Source, Confidence, Mapping
FROM CveTechniqueMap
WHERE CveId=@c
ORDER BY
    CASE Confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END,
    CASE Mapping    WHEN 'primary' THEN 0 WHEN 'secondary' THEN 1 ELSE 2 END
"@ -SqlParameters @{ c = $CveId }

    if (-not $maps) {
        return @"
// No ATT&CK mapping found for $CveId in CveTechniqueMap.
// <<EXTEND>> Run Update-CveAttackMap.ps1 with a mapping CSV first,
// or write the hunt manually below.
//
// Example skeleton - look for the CVE referenced in command lines / args:
DeviceProcessEvents
| where TimeGenerated > ago($($LookbackDays)d)
| where ProcessCommandLine has '$CveId'
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| take 100
"@
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("// Hunt scaffold for $CveId")
    [void]$sb.AppendLine("// Mapped to $($maps.Count) ATT&CK technique(s):")
    foreach ($m in $maps) {
        [void]$sb.AppendLine("//   $($m.TechniqueId)  source=$($m.Source) conf=$($m.Confidence) mapping=$($m.Mapping)")
    }
    [void]$sb.AppendLine("")

    foreach ($m in ($maps | Select-Object -First $MaxTechniques)) {
        try {
            [void]$sb.AppendLine((New-HuntQueryFromTechnique -TechniqueId $m.TechniqueId -LookbackDays $LookbackDays))
            [void]$sb.AppendLine("")
        } catch {
            [void]$sb.AppendLine("// $($m.TechniqueId) not in Techniques table - skipped")
            [void]$sb.AppendLine("")
        }
    }
    return $sb.ToString().TrimEnd()
}

# ============================================================
# Lightweight KQL lint
# Returns @() of {Severity, Code, Message}
# ============================================================
function Test-KqlQuery {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Query)
    $issues = New-Object System.Collections.Generic.List[object]

    function _Add { param($sev,$code,$msg) $issues.Add([PSCustomObject]@{ Severity=$sev; Code=$code; Message=$msg }) }

    # Strip comments and string literals to reduce false positives in the rules below
    $stripped = $Query `
        -replace '//[^\r\n]*', '' `
        -replace '"[^"]*"', '""' `
        -replace "'[^']*'", "''"

    # KQL001 - missing time filter
    if ($stripped -notmatch '(?im)\b(TimeGenerated|Timestamp|StartTime|EventStartTime)\b\s*[><=]' -and
        $stripped -notmatch '(?i)\bago\s*\(') {
        _Add 'high' 'KQL001' 'No time predicate detected. Always bound queries with `where TimeGenerated > ago(Nd)`.'
    }

    # KQL002 - where after summarize (post-aggregate filter)
    $sumIdx = $stripped.IndexOf('summarize', [StringComparison]::OrdinalIgnoreCase)
    if ($sumIdx -ge 0) {
        $whereAfter = $stripped.IndexOf('| where', $sumIdx, [StringComparison]::OrdinalIgnoreCase)
        if ($whereAfter -ge 0) {
            _Add 'medium' 'KQL002' '`where` after `summarize` filters aggregated results - move pre-aggregation filters above `summarize`.'
        }
    }

    # KQL003 - prefer has over contains for tokenized fields
    $containsCount = ([regex]::Matches($stripped, '(?i)\bcontains\b')).Count
    $hasCount      = ([regex]::Matches($stripped, '(?i)\bhas\b')).Count
    if ($containsCount -gt 0 -and $containsCount -gt $hasCount) {
        _Add 'low' 'KQL003' "Found $containsCount uses of ``contains``. Prefer ``has`` for whole-token matching - it uses term indexes."
    }

    # KQL004 - regex on first predicate
    if ($stripped -match '(?im)^\s*\|\s*where[^\r\n]*matches\s+regex') {
        _Add 'medium' 'KQL004' '`matches regex` is the most expensive predicate. Place a cheaper filter (==, has, startswith) before it.'
    }

    # KQL005 - no take/top
    if ($stripped -notmatch '(?i)\b(take|top|limit)\s+\d+') {
        _Add 'low' 'KQL005' 'No `take`/`top`/`limit` clause - busy tables can return huge result sets.'
    } elseif ($stripped -match '(?i)\btake\s+(\d+)') {
        $n = [int]$matches[1]
        if ($n -gt 10000) { _Add 'low' 'KQL006' "``take $n`` is very large - confirm this is intended." }
    }

    # KQL007 - project-away with no positive project
    if ($stripped -match '(?i)project-away' -and $stripped -notmatch '(?i)\|\s*project\b') {
        _Add 'info' 'KQL007' '`project-away` only - no positive `project`. Confirm you want all remaining columns.'
    }

    # KQL008 - tolower/toupper inside where defeats indexes
    if ($stripped -match '(?i)\bwhere\b[^|]*\b(tolower|toupper)\s*\(') {
        _Add 'medium' 'KQL008' '`tolower`/`toupper` inside `where` defeats indexes. Use `=~` or `in~` for case-insensitive comparison.'
    }

    # KQL009 - join without explicit kind
    if ($stripped -match '(?i)\bjoin\b' -and $stripped -notmatch '(?i)\bkind\s*=') {
        _Add 'medium' 'KQL009' '`join` without explicit `kind=` defaults to `innerunique` and silently dedupes - specify `kind=inner|leftouter|...`.'
    }

    return $issues
}

# ============================================================
# Build a Sentinel/Log Analytics deep link.
# Workspace coordinates pulled from AppSettings if not supplied.
#   env.subscription, env.resourcegroup, env.workspace
# ============================================================
function New-SentinelQueryUrl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [string]$SubscriptionId = (Get-AppSetting 'env.subscription'),
        [string]$ResourceGroup  = (Get-AppSetting 'env.resourcegroup'),
        [string]$WorkspaceName  = (Get-AppSetting 'env.workspace')
    )
    if (-not $SubscriptionId -or -not $ResourceGroup -or -not $WorkspaceName) {
        throw "Workspace not configured. Set with:`n  Set-AppSetting 'env.subscription'  '<sub-guid>'`n  Set-AppSetting 'env.resourcegroup' '<rg>'`n  Set-AppSetting 'env.workspace'     '<workspace-name>'"
    }
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $resId    = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
    $encQuery = [System.Web.HttpUtility]::UrlEncode($Query)
    $encResId = [System.Web.HttpUtility]::UrlEncode($resId)

    return "https://portal.azure.com/#blade/Microsoft_OperationsManagementSuite_Workspace/Logs.ReactView/resourceId/$encResId/source/LogsBlade.AnalyticsShareLinkToQuery/query/$encQuery"
}

# ============================================================
# Saved query CRUD
# ============================================================
function Save-KqlQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Query,
        [string]$Description    = '',
        [string[]]$Tags         = @(),
        [string[]]$Tactics      = @(),
        [string[]]$TechniqueIds = @(),
        [string]$TableName      = '',
        [string]$Author         = $env:USERNAME,
        [int]$QueryId           = 0
    )
    $now      = (Get-Date).ToString('o')
    $tagsStr  = $Tags         -join ','
    $tactStr  = $Tactics      -join ','
    $techStr  = $TechniqueIds -join ','

    if ($QueryId -gt 0) {
        Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
UPDATE KqlQueries SET
    Name=@n, Description=@d, Tags=@tg, Tactics=@ta, TechniqueIds=@ti,
    TableName=@tb, Query=@q, LastModified=@m
WHERE QueryId=@id
"@ -SqlParameters @{
            n=$Name; d=$Description; tg=$tagsStr; ta=$tactStr; ti=$techStr;
            tb=$TableName; q=$Query; m=$now; id=$QueryId
        }
        return $QueryId
    } else {
        Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT INTO KqlQueries (Name, Description, Tags, Tactics, TechniqueIds, TableName, Query, Author, Created, LastModified)
VALUES (@n,@d,@tg,@ta,@ti,@tb,@q,@a,@c,@m)
"@ -SqlParameters @{
            n=$Name; d=$Description; tg=$tagsStr; ta=$tactStr; ti=$techStr;
            tb=$TableName; q=$Query; a=$Author; c=$now; m=$now
        }
        return [int](Invoke-SqliteQuery -DataSource $script:DbPath -Query "SELECT last_insert_rowid() AS Id").Id
    }
}

function Get-KqlQuery {
    [CmdletBinding()]
    param(
        [int]$QueryId,
        [string]$NameLike,
        [string]$Tag,
        [string]$TechniqueId
    )
    $clauses = @()
    $params  = @{}
    if ($QueryId)     { $clauses += "QueryId=@id";              $params.id   = $QueryId }
    if ($NameLike)    { $clauses += "Name LIKE @n";             $params.n    = "%$NameLike%" }
    if ($Tag)         { $clauses += "Tags LIKE @t";             $params.t    = "%$Tag%" }
    if ($TechniqueId) { $clauses += "TechniqueIds LIKE @tech";  $params.tech = "%$TechniqueId%" }

    $where = if ($clauses) { "WHERE " + ($clauses -join ' AND ') } else { '' }
    $q     = "SELECT * FROM KqlQueries $where ORDER BY LastModified DESC"

    if ($params.Count -gt 0) {
        return Invoke-SqliteQuery -DataSource $script:DbPath -Query $q -SqlParameters $params
    }
    return Invoke-SqliteQuery -DataSource $script:DbPath -Query $q
}

function Remove-KqlQuery {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$QueryId)
    Invoke-SqliteQuery -DataSource $script:DbPath -Query "DELETE FROM KqlQueries WHERE QueryId=@id" -SqlParameters @{ id = $QueryId }
}

function Register-KqlQueryRun {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$QueryId)
    Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "UPDATE KqlQueries SET LastRun=@ts, RunCount=COALESCE(RunCount,0)+1 WHERE QueryId=@id" `
        -SqlParameters @{ ts=(Get-Date).ToString('o'); id=$QueryId }
}