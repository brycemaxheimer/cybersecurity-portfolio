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

# SIG # Begin signature block
# MIIcCwYJKoZIhvcNAQcCoIIb/DCCG/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAuw/GdYtwXJylb
# Bl/eHeTnlR5VXnmIlgjQueZgqpY2cKCCFlAwggMSMIIB+qADAgECAhAtZQe+Ow97
# nknyVZUnzOU8MA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMMFkJyeWNlIFNPQyBD
# b2RlIFNpZ25pbmcwHhcNMjYwNDI5MTcxNzUwWhcNMzEwNDI5MTcyNzUxWjAhMR8w
# HQYDVQQDDBZCcnljZSBTT0MgQ29kZSBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEA3Oe6H+5W3DedBqU2kgW2FbDpJxacLR8tKrO+UgnFWcfe
# JTWv1bxs20yw8WNVkt3oHEjsyk9MZwIjvTfZbtyobU7UU1dSKHPhZT0pBWPenuCf
# EHef25jHGma52Iiyoh06U5Tb51e0TQx7eMF4DQbxfNMZbLFZL1ZIN2/bMHLikeJj
# +nzz606QDzfFjlAA0liD1WlTiK7wFclEd6yY2GwSCWBSIn6ZeyfQvHPRHMgwjmfK
# AYRVEA9WkpSRaTnWX15QWjn1iHxEJ8IeS4274cU369gWsxgFIvKCVdb3I+5eMBcy
# n//v3SF8uhJ6OtJipttmpNAvyf10N/QOnWu4CDzL9QIDAQABo0YwRDAOBgNVHQ8B
# Af8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFOAL/6bNQwxH
# 3Ir4b9IWNhfKv0dtMA0GCSqGSIb3DQEBCwUAA4IBAQAAePrK/7n1mnXEVikJrfFG
# Hm+MNL6LwrJPt1bLNiZDkG4AUHm0nLiGgSJSe/YpAAbXAamxfJtEWyZI1je8z+TW
# Adle3BHKJ4fttXffhvNoXZjbdq0LQDwehEtHROC1j4pshXmF9Y3NyTfuR31u7Bqp
# HU+x0WBvdIyHcDO8cm8clnZobNM9ASRHj3i3Kb2Bsgz+txIkgeEvor7oTBO9ubMI
# a9+nw1WOGk9K/IukfinUTyrO7hVG14YP9SkuCj75G6SfO4t4GSe8qMbcpB0jdqNt
# lrx2N4LKVH0Xi2BzK9NcLFnprfS4oXmO1GsTDKXQyocHSAthXEGNUpE5HfKVz5dm
# MIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBl
# MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
# d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
# b3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7J
# IT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxS
# D1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb
# 7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1ef
# VFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoY
# OAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSa
# M0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI
# 8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9L
# BADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfm
# Q6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDr
# McXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15Gkv
# mB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
# FgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGL
# p6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
# Y3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0G
# CSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6p
# Grsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1W
# z/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp
# 8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38dglo
# hJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8S
# uFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGtDCCBJygAwIBAgIQ
# DcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEV
# MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
# MSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAw
# MDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0
# YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaD
# LFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1
# +JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh
# /AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpL
# tlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8
# BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMv
# aB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL
# 6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/
# q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb
# 1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVF
# JfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MC
# AwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp
# 5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9P
# MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcB
# AQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggr
# BgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+
# Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNq
# hCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLery
# cvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26M
# HvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjat
# VB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPS
# egOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI
# 7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4Y
# tL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/
# wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch
# 28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQ
# D7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCCBu0wggTVoAMCAQICEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRp
# bWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNTA2MDQwMDAw
# MDBaFw0zNjA5MDMyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYgVGlt
# ZXN0YW1wIFJlc3BvbmRlciAyMDI1IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDQRqwtEsae0OquYFazK1e6b1H/hnAKAd/KN8wZQjBjMqiZ3xTWcfsL
# wOvRxUwXcGx8AUjni6bz52fGTfr6PHRNv6T7zsf1Y/E3IU8kgNkeECqVQ+3bzWYe
# sFtkepErvUSbf+EIYLkrLKd6qJnuzK8Vcn0DvbDMemQFoxQ2Dsw4vEjoT1FpS54d
# NApZfKY61HAldytxNM89PZXUP/5wWWURK+IfxiOg8W9lKMqzdIo7VA1R0V3Zp3Dj
# jANwqAf4lEkTlCDQ0/fKJLKLkzGBTpx6EYevvOi7XOc4zyh1uSqgr6UnbksIcFJq
# LbkIXIPbcNmA98Oskkkrvt6lPAw/p4oDSRZreiwB7x9ykrjS6GS3NR39iTTFS+EN
# TqW8m6THuOmHHjQNC3zbJ6nJ6SXiLSvw4Smz8U07hqF+8CTXaETkVWz0dVVZw7kn
# h1WZXOLHgDvundrAtuvz0D3T+dYaNcwafsVCGZKUhQPL1naFKBy1p6llN3QgshRt
# a6Eq4B40h5avMcpi54wm0i2ePZD5pPIssoszQyF4//3DoK2O65Uck5Wggn8O2klE
# TsJ7u8xEehGifgJYi+6I03UuT1j7FnrqVrOzaQoVJOeeStPeldYRNMmSF3voIgMF
# tNGh86w3ISHNm0IaadCKCkUe2LnwJKa8TIlwCUNVwppwn4D3/Pt5pwIDAQABo4IB
# lTCCAZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU5Dv88jHt/f3X85FxYxlQQ89h
# jOgwHwYDVR0jBBgwFoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQD
# AgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCBhTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAC
# hlFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRU
# aW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBU
# oFKgUIZOaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcw
# CAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAZSqt8Rwn
# BLmuYEHs0QhEnmNAciH45PYiT9s1i6UKtW+FERp8FgXRGQ/YAavXzWjZhY+hIfP2
# JkQ38U+wtJPBVBajYfrbIYG+Dui4I4PCvHpQuPqFgqp1PzC/ZRX4pvP/ciZmUnth
# fAEP1HShTrY+2DE5qjzvZs7JIIgt0GCFD9ktx0LxxtRQ7vllKluHWiKk6FxRPyUP
# xAAYH2Vy1lNM4kzekd8oEARzFAWgeW3az2xejEWLNN4eKGxDJ8WDl/FQUSntbjZ8
# 0FU3i54tpx5F/0Kr15zW/mJAxZMVBrTE2oi0fcI8VMbtoRAmaaslNXdCG1+lqvP4
# FbrQ6IwSBXkZagHLhFU9HCrG/syTRLLhAezu/3Lr00GrJzPQFnCEH1Y58678Igmf
# ORBPC1JKkYaEt2OdDh4GmO0/5cHelAK2/gTlQJINqDr6JfwyYHXSd+V08X1JUPvB
# 4ILfJdmL+66Gp3CSBXG6IwXMZUXBhtCyIaehr0XkBoDIGMUG1dUtwq1qmcwbdUfc
# SYCn+OwncVUXf53VJUNOaMWMts0VlRYxe5nK+At+DI96HAlXHAL5SlfYxJ7La54i
# 71McVWRP66bW+yERNpbJCjyCYG2j+bdpxo/1Cy4uPcU3AWVPGrbn5PhDBf3Frogu
# zzhk++ami+r3Qrx5bIbY3TVzgiFI7Gq3zWcxggURMIIFDQIBATA1MCExHzAdBgNV
# BAMMFkJyeWNlIFNPQyBDb2RlIFNpZ25pbmcCEC1lB747D3ueSfJVlSfM5TwwDQYJ
# YIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQgQkS/1iv9v4N+UUy0F/xmKvSZsZCw6R2A+KnqEmZt
# dB4wDQYJKoZIhvcNAQEBBQAEggEAE7YhexG+4YLiUaDl30Eez1Oy+WhFlpaw3HhG
# 0vZOWtozn4PDAZXtIJQXWW8REh+2y4wgvZvdSHJ9XNUhRJEBuH2d0HIumC5OOa75
# 4iS6iuDip8fBdVSszopp/a+OYmR6w2Or5R9DOG1y6Gljg355a06ITTUib/y1A6e2
# FTQPsrmKbTnX61rH3d4/T0zKvOG0tKItdb7AwL8KGEfwcnPgajba/DwrZsZSbmVk
# V3pN7wMK97TiRI0W+t+7DsBYjTwOwNrGSHiaJGbr6+3Tie3vmSK8+ZD4amamI5No
# SAEPHO9z5ocWOcfeNniHvrOBatJaGCzgAjc6LpOQlGjA/vzhjaGCAyYwggMiBgkq
# hkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeV
# dGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0yNjA0MjkxNzI5MjdaMC8GCSqGSIb3DQEJBDEiBCCrP5My
# 436GkuOiEPQFk9/GdcMClrhzy/yXMiiEW3upYjANBgkqhkiG9w0BAQEFAASCAgCf
# x/z3rl4GFCCwMjI22ssfgQ6RGGO//xaVLtDS8S8LcuryJsDbOV8/3bR1d8e5thbq
# mOeWS2d00VftaD+K+l5b6mEEkMevaH7azXrNIdC+gS2j9sjl158YC1FRN1Jw/ynd
# zCxB5AS1wQotw2ryN5YycSoHOv+aYIV6A8dpD1SQWmOQoxMudYTKv3Nc+9XmfdtH
# KkUN76nlZdjpIxH8JHnWgO0zzH5u3EK3+4j3rle9kznS2FQd0jLZ8YGaaVmrzyC5
# zXzJ2+D3C2c//Xyp2jgk2Hb390G34/3ogD4RfNdi1Lb8Atfodwn9ufnVuBetOcJP
# QEe5fr32db7mw1Tcca7ZNvrtFVcbUpUn03fi3aZukZXjkwyXUh9eU7TbaqyJQSNX
# 1frkAbFusD+9LobeBZ/Cd/9dbXPoDs8WhtqNOZUQmHCDp+C6knc0DaHP2vDyNOq7
# 1qAV5MqaXPow69Q45OY26A1eJ8xP9bSWLNPVufBVSoWEVAH4ehg1vHhEOZLRCO81
# y1exPl5L1ySsMTTa4xvGJYYZ+kfuCXdEXvDv6iTZvnuvahCha3JIys7y9TqegLOM
# mbqhoXy5Qo47XNysZu+d+UXOMCZfhmHtqED6AQZUllWYAXy7oGKem5Z1dUd7SViO
# sBYgayuFg7034sA4zQ4LPbqTT3NejaqhNAmJiUtMiQ==
# SIG # End signature block
