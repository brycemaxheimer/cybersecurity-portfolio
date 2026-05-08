<#
.SYNOPSIS
    KQL Query Builder - GUI tool for constructing KQL queries against ADX /
    Sentinel / Log Analytics, with persistent storage of saved queries in
    an MS Access database (or JSON fallback if Access is unavailable).

.DESCRIPTION
    Interactive Windows Forms GUI that walks you through building a KQL
    query: pick a table, set time range, add computer/user filters, choose
    table-specific options (EventID, Sysmon parsing, etc.), select output
    columns, toggle auto-parsing of common formats, and pick detailed vs.
    summarized output. Generated queries can be tagged with searchable
    keywords and saved to a local DB for later retrieval.

    Built to run on a stock user-level PowerShell session. The only optional
    dependency is the Microsoft Access Database Engine (ACE OLEDB provider),
    which ships with any Office install that includes Access. If ACE isn't
    present, the script falls back to JSON file storage automatically - no
    install required, no admin rights needed either way.

.PARAMETER ResetDb
    Delete and recreate the saved-query database. Use with caution.

.NOTES
    PLACEHOLDERS to customize for your environment are marked with the
    string "<<ENV>>" - search for it after first run. Includes things like
    your default workspace name, default time range, custom table list,
    and any org-specific filters you want pre-populated.

    Storage location: %USERPROFILE%\SecIntel\KqlBuilder.accdb (or .json)

    Run with: powershell.exe -ExecutionPolicy Bypass -File .\KqlBuilder.ps1
#>

[CmdletBinding()]
param(
    [switch]$ResetDb
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ================================================================
# PATHS & STORAGE INIT
# ================================================================
$script:DataDir   = Join-Path $env:USERPROFILE 'SecIntel'
$script:AccdbPath = Join-Path $script:DataDir 'KqlBuilder.accdb'
$script:JsonPath  = Join-Path $script:DataDir 'KqlBuilder.json'
if (-not (Test-Path $script:DataDir)) {
    New-Item -ItemType Directory -Path $script:DataDir -Force | Out-Null
}

if ($ResetDb) {
    Remove-Item $script:AccdbPath, $script:JsonPath -Force -ErrorAction SilentlyContinue
}

$script:StorageMode = 'json'   # default fallback
$script:OleDbConnStr = $null

function Initialize-Storage {
    # Try ADOX first to create the .accdb without needing Access.Application
    if (-not (Test-Path $script:AccdbPath)) {
        try {
            $catalog = New-Object -ComObject ADOX.Catalog
            $catalog.Create("Provider=Microsoft.ACE.OLEDB.12.0;Data Source=$script:AccdbPath;")
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($catalog) | Out-Null
        } catch {
            # ACE not present - fall through to JSON
            $script:StorageMode = 'json'
            if (-not (Test-Path $script:JsonPath)) { '[]' | Set-Content $script:JsonPath -Encoding UTF8 }
            return
        }
    }

    # Try opening via OleDb and ensure SavedQueries table exists
    try {
        $script:OleDbConnStr = "Provider=Microsoft.ACE.OLEDB.12.0;Data Source=$script:AccdbPath;Persist Security Info=False;"
        $conn = New-Object System.Data.OleDb.OleDbConnection $script:OleDbConnStr
        $conn.Open()

        # Check if table exists
        $schema = $conn.GetSchema('Tables')
        $tableExists = $false
        foreach ($row in $schema.Rows) {
            if ($row['TABLE_NAME'] -eq 'SavedQueries') { $tableExists = $true; break }
        }
        if (-not $tableExists) {
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = @"
CREATE TABLE SavedQueries (
    Id COUNTER PRIMARY KEY,
    QueryName TEXT(255),
    Description LONGTEXT,
    Tags TEXT(500),
    TableName TEXT(100),
    KqlText LONGTEXT,
    CreatedDate DATETIME,
    LastModified DATETIME
)
"@
            [void]$cmd.ExecuteNonQuery()
        }
        $conn.Close()
        $script:StorageMode = 'access'
    } catch {
        $script:StorageMode = 'json'
        if (-not (Test-Path $script:JsonPath)) { '[]' | Set-Content $script:JsonPath -Encoding UTF8 }
    }
}
Initialize-Storage

# ================================================================
# STORAGE FUNCTIONS (abstracted - work for both Access and JSON)
# ================================================================
function Save-Query {
    param(
        [string]$Name,
        [string]$Description,
        [string]$Tags,
        [string]$TableName,
        [string]$KqlText
    )
    $now = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    if ($script:StorageMode -eq 'access') {
        $conn = New-Object System.Data.OleDb.OleDbConnection $script:OleDbConnStr
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = @"
INSERT INTO SavedQueries (QueryName, Description, Tags, TableName, KqlText, CreatedDate, LastModified)
VALUES (?, ?, ?, ?, ?, ?, ?)
"@
        [void]$cmd.Parameters.AddWithValue('@p1', $Name)
        [void]$cmd.Parameters.AddWithValue('@p2', $Description)
        [void]$cmd.Parameters.AddWithValue('@p3', $Tags)
        [void]$cmd.Parameters.AddWithValue('@p4', $TableName)
        [void]$cmd.Parameters.AddWithValue('@p5', $KqlText)
        [void]$cmd.Parameters.AddWithValue('@p6', $now)
        [void]$cmd.Parameters.AddWithValue('@p7', $now)
        [void]$cmd.ExecuteNonQuery()
        $conn.Close()
    } else {
        $existing = @(Get-Content $script:JsonPath -Raw | ConvertFrom-Json)
        $newId = if ($existing.Count -gt 0) { ($existing | Measure-Object Id -Maximum).Maximum + 1 } else { 1 }
        $entry = [PSCustomObject]@{
            Id           = $newId
            QueryName    = $Name
            Description  = $Description
            Tags         = $Tags
            TableName    = $TableName
            KqlText      = $KqlText
            CreatedDate  = $now
            LastModified = $now
        }
        $list = @($existing) + $entry
        $list | ConvertTo-Json -Depth 5 | Set-Content $script:JsonPath -Encoding UTF8
    }
}

function Search-SavedQueries {
    param([string]$SearchTerm)
    if ($script:StorageMode -eq 'access') {
        $conn = New-Object System.Data.OleDb.OleDbConnection $script:OleDbConnStr
        $conn.Open()
        $cmd = $conn.CreateCommand()
        if ($SearchTerm) {
            $cmd.CommandText = @"
SELECT Id, QueryName, TableName, Tags, Description, CreatedDate
FROM SavedQueries
WHERE QueryName LIKE ? OR Tags LIKE ? OR Description LIKE ? OR KqlText LIKE ?
ORDER BY LastModified DESC
"@
            $like = "%$SearchTerm%"
            [void]$cmd.Parameters.AddWithValue('@p1', $like)
            [void]$cmd.Parameters.AddWithValue('@p2', $like)
            [void]$cmd.Parameters.AddWithValue('@p3', $like)
            [void]$cmd.Parameters.AddWithValue('@p4', $like)
        } else {
            $cmd.CommandText = "SELECT Id, QueryName, TableName, Tags, Description, CreatedDate FROM SavedQueries ORDER BY LastModified DESC"
        }
        $adapter = New-Object System.Data.OleDb.OleDbDataAdapter $cmd
        $dt = New-Object System.Data.DataTable
        [void]$adapter.Fill($dt)
        $conn.Close()
        return $dt
    } else {
        $list = @(Get-Content $script:JsonPath -Raw | ConvertFrom-Json)
        if ($SearchTerm) {
            $list = $list | Where-Object {
                $_.QueryName -like "*$SearchTerm*" -or
                $_.Tags -like "*$SearchTerm*" -or
                $_.Description -like "*$SearchTerm*" -or
                $_.KqlText -like "*$SearchTerm*"
            }
        }
        $dt = New-Object System.Data.DataTable
        [void]$dt.Columns.Add('Id', [int])
        [void]$dt.Columns.Add('QueryName', [string])
        [void]$dt.Columns.Add('TableName', [string])
        [void]$dt.Columns.Add('Tags', [string])
        [void]$dt.Columns.Add('Description', [string])
        [void]$dt.Columns.Add('CreatedDate', [string])
        foreach ($e in $list) {
            $r = $dt.NewRow()
            $r.Id          = [int]$e.Id
            $r.QueryName   = [string]$e.QueryName
            $r.TableName   = [string]$e.TableName
            $r.Tags        = [string]$e.Tags
            $r.Description = [string]$e.Description
            $r.CreatedDate = [string]$e.CreatedDate
            [void]$dt.Rows.Add($r)
        }
        return $dt
    }
}

function Get-SavedQuery {
    param([int]$Id)
    if ($script:StorageMode -eq 'access') {
        $conn = New-Object System.Data.OleDb.OleDbConnection $script:OleDbConnStr
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "SELECT * FROM SavedQueries WHERE Id = ?"
        [void]$cmd.Parameters.AddWithValue('@p1', $Id)
        $adapter = New-Object System.Data.OleDb.OleDbDataAdapter $cmd
        $dt = New-Object System.Data.DataTable
        [void]$adapter.Fill($dt)
        $conn.Close()
        if ($dt.Rows.Count -gt 0) { return $dt.Rows[0] }
    } else {
        $list = @(Get-Content $script:JsonPath -Raw | ConvertFrom-Json)
        return $list | Where-Object { [int]$_.Id -eq $Id } | Select-Object -First 1
    }
}

function Remove-SavedQuery {
    param([int]$Id)
    if ($script:StorageMode -eq 'access') {
        $conn = New-Object System.Data.OleDb.OleDbConnection $script:OleDbConnStr
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "DELETE FROM SavedQueries WHERE Id = ?"
        [void]$cmd.Parameters.AddWithValue('@p1', $Id)
        [void]$cmd.ExecuteNonQuery()
        $conn.Close()
    } else {
        $list = @(Get-Content $script:JsonPath -Raw | ConvertFrom-Json) | Where-Object { [int]$_.Id -ne $Id }
        @($list) | ConvertTo-Json -Depth 5 | Set-Content $script:JsonPath -Encoding UTF8
    }
}

# ================================================================
# TABLE DEFINITIONS - the schema that drives the GUI
# <<ENV>> Add or remove tables to match your environment
# ================================================================
$script:TableDefinitions = @{
    'SecurityEvent' = @{
        ComputerField = 'Computer'
        UserField     = 'Account'
        TimeField     = 'TimeGenerated'
        DefaultColumns = @('TimeGenerated','Computer','Account','EventID','Activity','LogonType','IpAddress')
        AvailableColumns = @('TimeGenerated','Computer','Account','EventID','Activity','LogonType','IpAddress','WorkstationName','LogonProcessName','AuthenticationPackageName','TargetUserName','SubjectUserName','ProcessName','CommandLine','ParentProcessName')
        Specifics = @{
            EventID    = @('','4624','4625','4634','4648','4672','4688','4697','4698','4720','4732','4738','7045','1102')
            LogonType  = @('','2','3','4','5','7','8','9','10','11')
        }
        AutoParse = $false
        SummarizeBy = @('Account','EventID','Computer')
    }
    'Event' = @{
        ComputerField = 'Computer'
        UserField     = $null
        TimeField     = 'TimeGenerated'
        DefaultColumns = @('TimeGenerated','Computer','Source','EventID','EventLevelName','RenderedDescription')
        AvailableColumns = @('TimeGenerated','Computer','Source','EventID','EventLog','EventLevel','EventLevelName','RenderedDescription','ParameterXml','EventData')
        Specifics = @{
            Source = @('','Microsoft-Windows-Sysmon','Microsoft-Windows-PowerShell','Microsoft-Windows-WMI-Activity','Microsoft-Windows-TaskScheduler')
            EventID = @('','1','3','7','8','10','11','12','13','22','4104','4688')
        }
        AutoParse = $true   # XML EventData parsing available
        SummarizeBy = @('Source','EventID','Computer')
    }
    'DeviceProcessEvents' = @{
        ComputerField = 'DeviceName'
        UserField     = 'AccountName'
        TimeField     = 'TimeGenerated'
        DefaultColumns = @('TimeGenerated','DeviceName','AccountName','FileName','FolderPath','ProcessCommandLine','InitiatingProcessFileName','SHA256')
        AvailableColumns = @('TimeGenerated','DeviceName','AccountName','AccountDomain','FileName','FolderPath','ProcessCommandLine','ProcessId','SHA256','MD5','InitiatingProcessFileName','InitiatingProcessFolderPath','InitiatingProcessCommandLine','InitiatingProcessParentFileName','InitiatingProcessAccountName')
        Specifics = @{}
        AutoParse = $false
        SummarizeBy = @('FileName','DeviceName','AccountName')
    }
    'DeviceNetworkEvents' = @{
        ComputerField = 'DeviceName'
        UserField     = 'InitiatingProcessAccountName'
        TimeField     = 'TimeGenerated'
        DefaultColumns = @('TimeGenerated','DeviceName','RemoteIP','RemotePort','RemoteUrl','InitiatingProcessFileName','InitiatingProcessAccountName','ActionType')
        AvailableColumns = @('TimeGenerated','DeviceName','ActionType','RemoteIP','RemotePort','RemoteUrl','LocalIP','LocalPort','Protocol','InitiatingProcessFileName','InitiatingProcessFolderPath','InitiatingProcessCommandLine','InitiatingProcessAccountName','InitiatingProcessSHA256')
        Specifics = @{
            ActionType = @('','ConnectionSuccess','ConnectionFailed','ConnectionAttempt','InboundConnectionAccepted')
            Protocol   = @('','Tcp','Udp','Icmp')
        }
        AutoParse = $false
        SummarizeBy = @('RemoteIP','InitiatingProcessFileName','DeviceName')
    }
    'DeviceFileEvents' = @{
        ComputerField = 'DeviceName'
        UserField     = 'InitiatingProcessAccountName'
        TimeField     = 'TimeGenerated'
        DefaultColumns = @('TimeGenerated','DeviceName','ActionType','FileName','FolderPath','SHA256','InitiatingProcessFileName','InitiatingProcessAccountName')
        AvailableColumns = @('TimeGenerated','DeviceName','ActionType','FileName','FolderPath','SHA256','MD5','FileSize','InitiatingProcessFileName','InitiatingProcessFolderPath','InitiatingProcessCommandLine','InitiatingProcessAccountName')
        Specifics = @{
            ActionType = @('','FileCreated','FileModified','FileDeleted','FileRenamed')
        }
        AutoParse = $false
        SummarizeBy = @('FileName','InitiatingProcessFileName','DeviceName')
    }
    'DeviceLogonEvents' = @{
        ComputerField = 'DeviceName'
        UserField     = 'AccountName'
        TimeField     = 'TimeGenerated'
        DefaultColumns = @('TimeGenerated','DeviceName','AccountName','LogonType','RemoteIP','InitiatingProcessFileName','ActionType')
        AvailableColumns = @('TimeGenerated','DeviceName','ActionType','LogonType','AccountName','AccountDomain','RemoteIP','RemoteDeviceName','InitiatingProcessFileName','InitiatingProcessAccountName')
        Specifics = @{
            LogonType  = @('','Interactive','Network','Batch','Service','Unlock','RemoteInteractive')
            ActionType = @('','LogonSuccess','LogonFailed','LogonAttempted')
        }
        AutoParse = $false
        SummarizeBy = @('AccountName','LogonType','DeviceName')
    }
    'Syslog' = @{
        ComputerField = 'Computer'
        UserField     = $null
        TimeField     = 'TimeGenerated'
        DefaultColumns = @('TimeGenerated','Computer','Facility','SeverityLevel','ProcessName','SyslogMessage')
        AvailableColumns = @('TimeGenerated','Computer','Facility','SeverityLevel','ProcessName','ProcessID','HostName','SyslogMessage')
        Specifics = @{
            SeverityLevel = @('','emerg','alert','crit','err','warning','notice','info','debug')
            Facility      = @('','auth','authpriv','daemon','kern','syslog','user','local0','local1')
        }
        AutoParse = $true   # Key:Value parsing available
        SummarizeBy = @('Facility','ProcessName','Computer')
    }
    'CommonSecurityLog' = @{
        ComputerField = 'Computer'
        UserField     = 'SourceUserName'
        TimeField     = 'TimeGenerated'
        DefaultColumns = @('TimeGenerated','DeviceVendor','DeviceProduct','Activity','SourceIP','DestinationIP','SourceUserName','Message')
        AvailableColumns = @('TimeGenerated','DeviceVendor','DeviceProduct','DeviceAction','Activity','SourceIP','SourcePort','DestinationIP','DestinationPort','Protocol','SourceUserName','DestinationUserName','RequestURL','Message')
        Specifics = @{}
        AutoParse = $false
        SummarizeBy = @('DeviceProduct','SourceIP','DestinationIP')
    }
    'Custom' = @{
        ComputerField = 'Computer'
        UserField     = 'Account'
        TimeField     = 'TimeGenerated'
        DefaultColumns = @()
        AvailableColumns = @()
        Specifics = @{}
        AutoParse = $false
        SummarizeBy = @()
    }
}

# ================================================================
# QUERY BUILDER - assembles the KQL string from GUI state
# ================================================================
function Build-KqlQuery {
    param($State)

    $tableName  = $State.TableName
    $tableDef   = $script:TableDefinitions[$tableName]
    if (-not $tableDef -and $tableName -ne 'Custom') { return "// Unknown table: $tableName" }
    if ($tableName -eq 'Custom' -and $State.CustomTableName) {
        $tableName = $State.CustomTableName
        $tableDef = $script:TableDefinitions['Custom']
    }

    $sb = New-Object System.Text.StringBuilder

    # Header comment block - what makes the query searchable later
    [void]$sb.AppendLine("// ================================================================")
    [void]$sb.AppendLine("// Name: $($State.Name)")
    if ($State.Description) { [void]$sb.AppendLine("// Description: $($State.Description)") }
    if ($State.Tags)        { [void]$sb.AppendLine("// Tags: $($State.Tags)") }
    [void]$sb.AppendLine("// Table: $tableName")
    [void]$sb.AppendLine("// Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
    [void]$sb.AppendLine("// <<ENV>> Workspace: REPLACE_WITH_WORKSPACE_NAME")
    [void]$sb.AppendLine("// ================================================================")
    [void]$sb.AppendLine("")

    # Body
    [void]$sb.AppendLine($tableName)

    # Time filter
    if ($State.TimeRange -and $State.TimeRange -ne 'all') {
        [void]$sb.AppendLine("| where $($tableDef.TimeField) > ago($($State.TimeRange))")
    }

    # Computer filter
    if ($State.Computer -and $tableDef.ComputerField) {
        if ($State.Computer -match '[,\*]') {
            $list = ($State.Computer -split ',' | ForEach-Object { "`"$($_.Trim())`"" }) -join ', '
            [void]$sb.AppendLine("| where $($tableDef.ComputerField) in~ ($list)")
        } else {
            [void]$sb.AppendLine("| where $($tableDef.ComputerField) =~ `"$($State.Computer)`"")
        }
    }

    # User filter
    if ($State.User -and $tableDef.UserField) {
        [void]$sb.AppendLine("| where $($tableDef.UserField) has `"$($State.User)`"")
    }

    # Specific filters from the dynamic specifics panel
    if ($State.Specifics) {
        foreach ($k in $State.Specifics.Keys) {
            $v = $State.Specifics[$k]
            if ($v) {
                if ($k -eq 'EventID' -or $k -eq 'LogonType') {
                    [void]$sb.AppendLine("| where $k == $v")
                } else {
                    [void]$sb.AppendLine("| where $k =~ `"$v`"")
                }
            }
        }
    }

    # Auto-parse injection
    if ($State.AutoParse) {
        if ($tableName -eq 'Syslog') {
            [void]$sb.AppendLine("// Auto-parse: extract Key:Value pairs from SyslogMessage")
            [void]$sb.AppendLine("| extend Pairs = extract_all(@'([A-Za-z0-9_.\- ]+?)\s*:\s*([^,]+?)(?:,\s*|$)', SyslogMessage)")
            [void]$sb.AppendLine("| mv-apply p = Pairs to typeof(dynamic) on (")
            [void]$sb.AppendLine("    summarize Bag = make_bag(bag_pack(tostring(p[0]), tostring(p[1])))")
            [void]$sb.AppendLine("  )")
            [void]$sb.AppendLine("| evaluate bag_unpack(Bag, 'msg_')")
        }
        elseif ($tableName -eq 'Event') {
            [void]$sb.AppendLine("// Auto-parse: extract Sysmon EventData XML into named columns")
            [void]$sb.AppendLine("| extend xml = parse_xml(EventData)")
            [void]$sb.AppendLine("| mv-apply d = xml.DataItem.EventData.Data on (")
            [void]$sb.AppendLine("    summarize Bag = make_bag(bag_pack(tostring(d['@Name']), tostring(d['#text'])))")
            [void]$sb.AppendLine("  )")
            [void]$sb.AppendLine("| evaluate bag_unpack(Bag, 'evt_')")
        }
    }

    # Output mode
    if ($State.OutputMode -eq 'Summarized' -and $tableDef.SummarizeBy.Count -gt 0) {
        $by = $tableDef.SummarizeBy -join ', '
        [void]$sb.AppendLine("| summarize EventCount = count(), FirstSeen = min($($tableDef.TimeField)), LastSeen = max($($tableDef.TimeField)) by $by")
        [void]$sb.AppendLine("| order by EventCount desc")
    }
    elseif ($State.Columns -and $State.Columns.Count -gt 0) {
        $cols = $State.Columns -join ', '
        [void]$sb.AppendLine("| project $cols")
        [void]$sb.AppendLine("| order by $($tableDef.TimeField) desc")
    }

    # Limit (avoid runaway queries during testing)
    if ($State.Limit -gt 0) {
        [void]$sb.AppendLine("| take $($State.Limit)")
    }

    return $sb.ToString()
}

# ================================================================
# GUI CONSTRUCTION
# ================================================================
$form               = New-Object System.Windows.Forms.Form
$form.Text          = "KQL Query Builder  -  Storage: $($script:StorageMode.ToUpper())"
$form.Size          = New-Object System.Drawing.Size(1280, 900)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize   = New-Object System.Drawing.Size(1100, 800)

# --- Top: input panel (left) and output panel (right) ---
$split             = New-Object System.Windows.Forms.SplitContainer
$split.Dock        = 'Fill'
$split.Orientation = 'Vertical'
$split.SplitterDistance = 520
$form.Controls.Add($split)

$inputPanel        = New-Object System.Windows.Forms.Panel
$inputPanel.Dock   = 'Fill'
$inputPanel.AutoScroll = $true
$split.Panel1.Controls.Add($inputPanel)

$outputPanel       = New-Object System.Windows.Forms.Panel
$outputPanel.Dock  = 'Fill'
$split.Panel2.Controls.Add($outputPanel)

# --- helper to create labeled controls quickly ---
$y = 10
function Add-Field {
    param([string]$Label, [System.Windows.Forms.Control]$Control, [int]$Height = 22)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Label
    $lbl.Location = New-Object System.Drawing.Point(10, $script:y)
    $lbl.AutoSize = $true
    $inputPanel.Controls.Add($lbl)
    $Control.Location = New-Object System.Drawing.Point(160, ($script:y - 3))
    $Control.Width = 340
    $inputPanel.Controls.Add($Control)
    $script:y += [Math]::Max($Height, 28)
}

# Query name + description + tags
$txtName = New-Object System.Windows.Forms.TextBox
Add-Field "Query Name:" $txtName

$txtDescription = New-Object System.Windows.Forms.TextBox
$txtDescription.Multiline = $true
$txtDescription.Height = 50
$txtDescription.ScrollBars = 'Vertical'
Add-Field "Description:" $txtDescription 50

$txtTags = New-Object System.Windows.Forms.TextBox
Add-Field "Tags (comma-sep):" $txtTags
$tipTags = New-Object System.Windows.Forms.ToolTip
$tipTags.SetToolTip($txtTags, "e.g.: lateral-movement, sysmon, lsass, T1003")

# Table dropdown
$cmbTable = New-Object System.Windows.Forms.ComboBox
$cmbTable.DropDownStyle = 'DropDownList'
foreach ($t in $script:TableDefinitions.Keys | Sort-Object) { [void]$cmbTable.Items.Add($t) }
$cmbTable.SelectedItem = 'DeviceProcessEvents'
Add-Field "Table:" $cmbTable

# Custom table name (only relevant when Custom selected)
$txtCustomTable = New-Object System.Windows.Forms.TextBox
$txtCustomTable.Enabled = $false
Add-Field "Custom Table Name:" $txtCustomTable

# Time range
$cmbTime = New-Object System.Windows.Forms.ComboBox
$cmbTime.DropDownStyle = 'DropDownList'
@('15m','1h','4h','24h','3d','7d','14d','30d','90d','all') | ForEach-Object { [void]$cmbTime.Items.Add($_) }
$cmbTime.SelectedItem = '24h'
Add-Field "Time Range:" $cmbTime

# Computer filter
$txtComputer = New-Object System.Windows.Forms.TextBox
Add-Field "Computer (csv ok):" $txtComputer

# User filter
$txtUser = New-Object System.Windows.Forms.TextBox
Add-Field "User / Account:" $txtUser

# --- Dynamic specifics panel (rebuilt when table changes) ---
$lblSpec = New-Object System.Windows.Forms.Label
$lblSpec.Text = "Table Specifics:"
$lblSpec.Location = New-Object System.Drawing.Point(10, $script:y)
$lblSpec.AutoSize = $true
$inputPanel.Controls.Add($lblSpec)
$script:y += 22

$specPanel = New-Object System.Windows.Forms.Panel
$specPanel.Location = New-Object System.Drawing.Point(10, $script:y)
$specPanel.Size = New-Object System.Drawing.Size(490, 80)
$specPanel.BorderStyle = 'FixedSingle'
$inputPanel.Controls.Add($specPanel)
$script:y += 90

$script:SpecificsControls = @{}

# Columns (checked listbox)
$lblCols = New-Object System.Windows.Forms.Label
$lblCols.Text = "Output Columns:"
$lblCols.Location = New-Object System.Drawing.Point(10, $script:y)
$lblCols.AutoSize = $true
$inputPanel.Controls.Add($lblCols)
$script:y += 22

$lstCols = New-Object System.Windows.Forms.CheckedListBox
$lstCols.Location = New-Object System.Drawing.Point(10, $script:y)
$lstCols.Size = New-Object System.Drawing.Size(490, 140)
$lstCols.CheckOnClick = $true
$inputPanel.Controls.Add($lstCols)
$script:y += 150

# Auto-parse + output mode + limit
$chkAutoParse = New-Object System.Windows.Forms.CheckBox
$chkAutoParse.Text = "Auto-parse (Syslog Key:Value / Sysmon EventData XML)"
$chkAutoParse.Location = New-Object System.Drawing.Point(10, $script:y)
$chkAutoParse.AutoSize = $true
$inputPanel.Controls.Add($chkAutoParse)
$script:y += 28

$grpOutput = New-Object System.Windows.Forms.GroupBox
$grpOutput.Text = "Output Mode"
$grpOutput.Location = New-Object System.Drawing.Point(10, $script:y)
$grpOutput.Size = New-Object System.Drawing.Size(240, 50)
$rdoDetailed = New-Object System.Windows.Forms.RadioButton
$rdoDetailed.Text = "Detailed"
$rdoDetailed.Location = New-Object System.Drawing.Point(10, 20)
$rdoDetailed.Checked = $true
$rdoDetailed.AutoSize = $true
$grpOutput.Controls.Add($rdoDetailed)
$rdoSummarized = New-Object System.Windows.Forms.RadioButton
$rdoSummarized.Text = "Summarized"
$rdoSummarized.Location = New-Object System.Drawing.Point(110, 20)
$rdoSummarized.AutoSize = $true
$grpOutput.Controls.Add($rdoSummarized)
$inputPanel.Controls.Add($grpOutput)

$lblLimit = New-Object System.Windows.Forms.Label
$lblLimit.Text = "Limit:"
$lblLimit.Location = New-Object System.Drawing.Point(265, ($script:y + 18))
$lblLimit.AutoSize = $true
$inputPanel.Controls.Add($lblLimit)

$numLimit = New-Object System.Windows.Forms.NumericUpDown
$numLimit.Location = New-Object System.Drawing.Point(305, ($script:y + 16))
$numLimit.Minimum = 0
$numLimit.Maximum = 1000000
$numLimit.Value = 1000
$numLimit.Width = 80
$inputPanel.Controls.Add($numLimit)
$script:y += 60

# Action buttons
$btnGenerate = New-Object System.Windows.Forms.Button
$btnGenerate.Text = "Generate"
$btnGenerate.Location = New-Object System.Drawing.Point(10, $script:y)
$btnGenerate.Width = 90
$btnGenerate.BackColor = [System.Drawing.Color]::FromArgb(220, 235, 255)
$inputPanel.Controls.Add($btnGenerate)

$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Text = "Save to DB"
$btnSave.Location = New-Object System.Drawing.Point(105, $script:y)
$btnSave.Width = 90
$inputPanel.Controls.Add($btnSave)

$btnLoad = New-Object System.Windows.Forms.Button
$btnLoad.Text = "Search Saved"
$btnLoad.Location = New-Object System.Drawing.Point(200, $script:y)
$btnLoad.Width = 100
$inputPanel.Controls.Add($btnLoad)

$btnCopy = New-Object System.Windows.Forms.Button
$btnCopy.Text = "Copy"
$btnCopy.Location = New-Object System.Drawing.Point(305, $script:y)
$btnCopy.Width = 60
$inputPanel.Controls.Add($btnCopy)

$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = "Clear"
$btnClear.Location = New-Object System.Drawing.Point(370, $script:y)
$btnClear.Width = 60
$inputPanel.Controls.Add($btnClear)
$script:y += 40

# --- Output panel: KQL textbox ---
$lblOut = New-Object System.Windows.Forms.Label
$lblOut.Text = "Generated KQL:"
$lblOut.Dock = 'Top'
$lblOut.Height = 20
$outputPanel.Controls.Add($lblOut)

$txtKql = New-Object System.Windows.Forms.TextBox
$txtKql.Multiline = $true
$txtKql.ScrollBars = 'Both'
$txtKql.Font = New-Object System.Drawing.Font('Consolas', 10)
$txtKql.WordWrap = $false
$txtKql.Dock = 'Fill'
$outputPanel.Controls.Add($txtKql)
$txtKql.BringToFront()

# Status strip
$status = New-Object System.Windows.Forms.StatusStrip
$statusLbl = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLbl.Text = "Storage: $($script:StorageMode.ToUpper()) | $(if ($script:StorageMode -eq 'access') { $script:AccdbPath } else { $script:JsonPath })"
[void]$status.Items.Add($statusLbl)
$form.Controls.Add($status)

# ================================================================
# DYNAMIC POPULATION based on selected table
# ================================================================
function Refresh-TableContext {
    $tableName = $cmbTable.SelectedItem
    $def = $script:TableDefinitions[$tableName]

    # Custom table textbox enable
    $txtCustomTable.Enabled = ($tableName -eq 'Custom')

    # Rebuild specifics panel
    $specPanel.Controls.Clear()
    $script:SpecificsControls = @{}
    $sx = 5; $sy = 5
    foreach ($k in $def.Specifics.Keys) {
        $sLbl = New-Object System.Windows.Forms.Label
        $sLbl.Text = "$k`:"
        $sLbl.Location = New-Object System.Drawing.Point($sx, ($sy + 3))
        $sLbl.AutoSize = $true
        $specPanel.Controls.Add($sLbl)

        $sCmb = New-Object System.Windows.Forms.ComboBox
        $sCmb.Location = New-Object System.Drawing.Point(($sx + 80), $sy)
        $sCmb.Width = 130
        $sCmb.DropDownStyle = 'DropDown'
        foreach ($val in $def.Specifics[$k]) { [void]$sCmb.Items.Add($val) }
        $specPanel.Controls.Add($sCmb)
        $script:SpecificsControls[$k] = $sCmb

        $sy += 26
        if ($sy -gt 60) { $sy = 5; $sx += 230 }
    }

    # Rebuild columns checked list
    $lstCols.Items.Clear()
    foreach ($col in $def.AvailableColumns) {
        $idx = $lstCols.Items.Add($col)
        if ($col -in $def.DefaultColumns) { $lstCols.SetItemChecked($idx, $true) }
    }

    # Auto-parse availability
    $chkAutoParse.Enabled = $def.AutoParse
    if (-not $def.AutoParse) { $chkAutoParse.Checked = $false }
}
$cmbTable.Add_SelectedIndexChanged({ Refresh-TableContext })
Refresh-TableContext

# ================================================================
# BUTTON HANDLERS
# ================================================================
function Get-CurrentState {
    $specs = @{}
    foreach ($k in $script:SpecificsControls.Keys) {
        $specs[$k] = $script:SpecificsControls[$k].Text
    }
    $cols = @()
    for ($i = 0; $i -lt $lstCols.Items.Count; $i++) {
        if ($lstCols.GetItemChecked($i)) { $cols += $lstCols.Items[$i] }
    }
    return [PSCustomObject]@{
        Name            = $txtName.Text
        Description     = $txtDescription.Text
        Tags            = $txtTags.Text
        TableName       = $cmbTable.SelectedItem
        CustomTableName = $txtCustomTable.Text
        TimeRange       = $cmbTime.SelectedItem
        Computer        = $txtComputer.Text
        User            = $txtUser.Text
        Specifics       = $specs
        Columns         = $cols
        AutoParse       = $chkAutoParse.Checked
        OutputMode      = if ($rdoSummarized.Checked) { 'Summarized' } else { 'Detailed' }
        Limit           = [int]$numLimit.Value
    }
}

$btnGenerate.Add_Click({
    $state = Get-CurrentState
    $kql = Build-KqlQuery -State $state
    $txtKql.Text = $kql
    $statusLbl.Text = "Generated $(($kql -split "`n").Count) lines"
})

$btnSave.Add_Click({
    if (-not $txtKql.Text) {
        [System.Windows.Forms.MessageBox]::Show("Generate a query before saving.", "Nothing to save", 'OK', 'Warning') | Out-Null
        return
    }
    if (-not $txtName.Text) {
        [System.Windows.Forms.MessageBox]::Show("Query Name is required to save.", "Missing name", 'OK', 'Warning') | Out-Null
        return
    }
    try {
        Save-Query -Name $txtName.Text -Description $txtDescription.Text -Tags $txtTags.Text -TableName ($cmbTable.SelectedItem) -KqlText $txtKql.Text
        $statusLbl.Text = "Saved '$($txtName.Text)' to $($script:StorageMode)"
        [System.Windows.Forms.MessageBox]::Show("Saved.", "Saved", 'OK', 'Information') | Out-Null
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Save failed: $_", "Error", 'OK', 'Error') | Out-Null
    }
})

$btnLoad.Add_Click({
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "Search Saved Queries"
    $dlg.Size = New-Object System.Drawing.Size(900, 600)
    $dlg.StartPosition = 'CenterParent'

    $top = New-Object System.Windows.Forms.Panel
    $top.Dock = 'Top'; $top.Height = 40
    $dlg.Controls.Add($top)

    $sLbl = New-Object System.Windows.Forms.Label
    $sLbl.Text = "Search:"
    $sLbl.Location = New-Object System.Drawing.Point(10, 12)
    $sLbl.AutoSize = $true
    $top.Controls.Add($sLbl)

    $sTxt = New-Object System.Windows.Forms.TextBox
    $sTxt.Location = New-Object System.Drawing.Point(60, 9)
    $sTxt.Width = 400
    $top.Controls.Add($sTxt)

    $sBtn = New-Object System.Windows.Forms.Button
    $sBtn.Text = "Search"
    $sBtn.Location = New-Object System.Drawing.Point(470, 8)
    $top.Controls.Add($sBtn)

    $dBtn = New-Object System.Windows.Forms.Button
    $dBtn.Text = "Delete Selected"
    $dBtn.Location = New-Object System.Drawing.Point(560, 8)
    $dBtn.Width = 110
    $top.Controls.Add($dBtn)

    $dgv = New-Object System.Windows.Forms.DataGridView
    $dgv.Dock = 'Fill'
    $dgv.ReadOnly = $true
    $dgv.AllowUserToAddRows = $false
    $dgv.SelectionMode = 'FullRowSelect'
    $dgv.AutoSizeColumnsMode = 'AllCells'
    $dgv.RowHeadersVisible = $false
    $dgv.DataSource = Search-SavedQueries -SearchTerm ''
    $dlg.Controls.Add($dgv)
    $dgv.BringToFront()

    $sBtn.Add_Click({ $dgv.DataSource = Search-SavedQueries -SearchTerm $sTxt.Text })
    $sTxt.Add_KeyDown({ if ($_.KeyCode -eq 'Enter') { $dgv.DataSource = Search-SavedQueries -SearchTerm $sTxt.Text; $_.SuppressKeyPress = $true } })

    $dBtn.Add_Click({
        if ($dgv.SelectedRows.Count -gt 0) {
            $id = [int]$dgv.SelectedRows[0].Cells['Id'].Value
            $confirm = [System.Windows.Forms.MessageBox]::Show("Delete saved query Id $id?", "Confirm", 'YesNo', 'Warning')
            if ($confirm -eq 'Yes') {
                Remove-SavedQuery -Id $id
                $dgv.DataSource = Search-SavedQueries -SearchTerm $sTxt.Text
            }
        }
    })

    $dgv.Add_CellDoubleClick({
        param($s, $e)
        if ($e.RowIndex -lt 0) { return }
        $id = [int]$dgv.Rows[$e.RowIndex].Cells['Id'].Value
        $row = Get-SavedQuery -Id $id
        if ($row) {
            $txtName.Text        = [string]$row.QueryName
            $txtDescription.Text = [string]$row.Description
            $txtTags.Text        = [string]$row.Tags
            $txtKql.Text         = [string]$row.KqlText
            $statusLbl.Text      = "Loaded query Id $id"
        }
        $dlg.Close()
    })

    [void]$dlg.ShowDialog()
})

$btnCopy.Add_Click({
    if ($txtKql.Text) {
        [System.Windows.Forms.Clipboard]::SetText($txtKql.Text)
        $statusLbl.Text = "Copied to clipboard"
    }
})

$btnClear.Add_Click({
    $txtName.Clear(); $txtDescription.Clear(); $txtTags.Clear()
    $txtComputer.Clear(); $txtUser.Clear(); $txtCustomTable.Clear()
    $txtKql.Clear()
    foreach ($k in $script:SpecificsControls.Keys) { $script:SpecificsControls[$k].Text = '' }
    for ($i = 0; $i -lt $lstCols.Items.Count; $i++) { $lstCols.SetItemChecked($i, $false) }
    Refresh-TableContext
    $statusLbl.Text = "Cleared"
})

# ================================================================
# SHOW
# ================================================================
[void]$form.ShowDialog()