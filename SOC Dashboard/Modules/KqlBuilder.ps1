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
    present, the script falls back to JSON file storage automatically — no
    install required, no admin rights needed either way.

.PARAMETER ResetDb
    Delete and recreate the saved-query database. Use with caution.

.NOTES
    PLACEHOLDERS to customize for your environment are marked with the
    string "<<ENV>>" — search for it after first run. Includes things like
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
$form.Text          = "KQL Query Builder  —  Storage: $($script:StorageMode.ToUpper())"
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

# SIG # Begin signature block
# MIIcCwYJKoZIhvcNAQcCoIIb/DCCG/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAP/ycMpscyc/u8
# EHOMriHmA6r07TS3J0f+QvGJKijf1qCCFlAwggMSMIIB+qADAgECAhAtZQe+Ow97
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
# FTAvBgkqhkiG9w0BCQQxIgQgL153KIlo3uQg9qKf0WYAgHaVGY4nslcJqKeWsjpS
# uhcwDQYJKoZIhvcNAQEBBQAEggEAun9tGiXGcNro6xrNIXXUKI2Whf2tBZZF+v6V
# yLUbtpj9jB5xm/Uxq/GJRxYMqqqfnSB3FrGnvE8v+/h6p+aaM+ZI2ecywYjnHSWp
# Be6BVHMCPM5+LbV9JF6ZoNs+Udk1UFoZlPnRdPR73PwrH+sNakHtN7B6Jx4GR88K
# jePuRrANny6bvD8VD7YhdjeZ3AurENiGun2ywJyhT5iZJGXvAo0EBcboITq5xQFR
# no1187qJqYsX+eksacHw+Z4TEzgTf6NPxvd7snViffwdcYEpSEml201PnYjcVis5
# 1/ir4VzGv1yKnU0DUqW2yHBMsWtJzLSm9jo+w2U3WimQLC5wBqGCAyYwggMiBgkq
# hkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeV
# dGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0yNjA0MjkxNzI5MjdaMC8GCSqGSIb3DQEJBDEiBCC5pSc8
# mQ1UYpZkbCxV42lN768Ft2CMzoGSbOca7isGMjANBgkqhkiG9w0BAQEFAASCAgA7
# UGPv+po4JnVmxE1q+tS78j2Gt+Z2eK5RmoM1goEpxRJVpGDa0y9VRvoW0hmFNmvc
# twX+ladPflYL7l6s9y24kAXvkQxhUF+skI+vUIHAxD9Y/SoPj0dSukk60iAZDYJR
# K4Y1Qdw0ZavmXSG7LUYZWifZW99FKWqIMiHOh8U922UHbHo83mJHUzykROk7nMLQ
# PxcnT064Oge1ynQK50TdHDmzdQIhPYaKVqAprrLLWTCZBYxBKsHN0pYx3wVoVIlx
# v1RnuqssT6WAU/HX7aPwmt4hoC2sxufv96dSkUF86EJF/XiEqxrfTgkWwHG/MHQn
# gsa5ejfJXU0z+BIDUv1eUqS91K0cLapCQm209HE3JAvhwrxgS9LyP0W62rwgqH2n
# 5OCQPfzvMvY7qADhGJKYkdGS8lctDjMvjx/a2xrO2ILIlJ0wBPgupxcg7/n6xcMD
# /SAtPdogaSpXb7HK1fjtbL6NZOPNsyq5jN9ixxs36g7yvvGYlScjfcOxToRtmuu7
# RFUN5ynlXfBj9zNulycV+b6n5Mx/A8x1cWqaLgguV5UUmbPGTJgFjmUd5Wlzx3Mo
# VsPb7qPI3vgRSO9+/8ud02M+3b8PhmukPv2ZJ4X2ZbBCGNrRef8yMoUZCXKxDb8R
# y7r/q1nLxacGCx91NCtpx1hNIQzq4RttGzmRfb0JTg==
# SIG # End signature block
