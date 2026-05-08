<#
.SYNOPSIS
    UI helpers for the SOC Dashboard WPF: context menus on grids, status bar
    updater, and "what's new since last open" snapshot.

.DESCRIPTION
    Dot-source from SocDashboard.ps1 AFTER the XAML has been loaded and
    named-element binding has run. Functions:

        Add-GridContextMenu     - attach a right-click copy/pivot menu to
                                  a DataGrid bound to one of the known
                                  schema tables. The menu is built per-Kind
                                  so CVE rows get NVD links, technique rows
                                  get MITRE links, hash rows get VT links,
                                  etc. Generic copy actions (cell, row JSON,
                                  column as KQL `in` list) are always added.

        Update-StatusBar        - refresh a TextBlock with DB size + row
                                  counts for the major tables.

        Get-DiffSinceLastOpen   - returns counts of new rows since the
                                  AppSettings 'lastseen.*' markers; useful
                                  for a banner on the dashboard's home tab.

        Set-LastSeenNow         - bump markers (typically called when the
                                  user clicks "Mark all reviewed").

    Hooks back into the dashboard via optional scriptblock parameters so
    this module stays decoupled from the XAML.

.NOTES
    Dot-source SecIntel.Schema.ps1, .Settings.ps1, .KqlHelpers.ps1,
    .HashLookup.ps1 first.
#>

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.Settings.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.KqlHelpers.ps1') -ErrorAction SilentlyContinue
. (Join-Path $PSScriptRoot 'SecIntel.HashLookup.ps1') -ErrorAction SilentlyContinue

# ============================================================
# Context-menu factory
# ============================================================
function Add-GridContextMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Grid,
        [Parameter(Mandatory)]
        [ValidateSet('cve','kev','technique','tactic','group','software','mitigation','hash','ioc','generic')]
        [string]$Kind,
        # Optional callbacks - dashboard wires these to its own pivot logic
        [scriptblock]$OnPivotKql,        # called as: & $OnPivotKql $kqlText $rowObject
        [scriptblock]$OnLookupHash,      # called as: & $OnLookupHash $sha256
        [scriptblock]$OnViewDetails      # called as: & $OnViewDetails $rowObject
    )

    $menu = New-Object System.Windows.Controls.ContextMenu

    # Closure-friendly grid reference for inner scriptblocks
    $g = $Grid

    function _AddItem {
        param($menu, $header, $action)
        $mi = New-Object System.Windows.Controls.MenuItem
        $mi.Header = $header
        $mi.Add_Click($action)
        [void]$menu.Items.Add($mi)
    }

    function _AddSep { param($menu) [void]$menu.Items.Add((New-Object System.Windows.Controls.Separator)) }

    # ----- Always available: copy actions -----
    _AddItem $menu 'Copy cell value' ({
        $cell = $g.CurrentCell
        if ($null -ne $cell -and $null -ne $cell.Item -and $null -ne $cell.Column) {
            $colName = "$($cell.Column.Header)"
            $val = $cell.Item.$colName
            if ($null -ne $val) { [System.Windows.Clipboard]::SetText([string]$val) }
        }
    }.GetNewClosure())

    _AddItem $menu 'Copy row as JSON' ({
        $sel = $g.SelectedItem
        if ($sel) {
            $obj = [ordered]@{}
            foreach ($p in $sel.PSObject.Properties) { $obj[$p.Name] = $p.Value }
            [System.Windows.Clipboard]::SetText(($obj | ConvertTo-Json -Compress -Depth 4))
        }
    }.GetNewClosure())

    _AddItem $menu 'Copy column as KQL `in` list' ({
        $cell = $g.CurrentCell
        if ($null -eq $cell -or $null -eq $cell.Column) { return }
        $colName = "$($cell.Column.Header)"
        $vals = New-Object System.Collections.Generic.List[string]
        foreach ($item in $g.Items) {
            $v = $item.$colName
            if ($null -ne $v) {
                $esc = ([string]$v -replace '\\','\\' -replace '"','\"')
                [void]$vals.Add('"' + $esc + '"')
            }
        }
        if ($vals.Count -gt 0) {
            [System.Windows.Clipboard]::SetText("$colName in ($([string]::Join(',', $vals)))")
        }
    }.GetNewClosure())

    _AddSep $menu

    # ----- Kind-specific actions -----
    switch ($Kind) {

        'cve' {
            _AddItem $menu 'Open NVD page' ({
                $sel = $g.SelectedItem
                if ($sel -and $sel.CveId) { Start-Process "https://nvd.nist.gov/vuln/detail/$($sel.CveId)" }
            }.GetNewClosure())
            if ($OnPivotKql) {
                _AddItem $menu 'Generate hunt query (CVE -> ATT&CK)' ({
                    $sel = $g.SelectedItem
                    if ($sel -and $sel.CveId) {
                        try {
                            $q = New-HuntQueryFromCve -CveId $sel.CveId
                            & $OnPivotKql $q $sel
                        } catch { [System.Windows.MessageBox]::Show($_.Exception.Message, 'Hunt query failed') | Out-Null }
                    }
                }.GetNewClosure())
            }
        }

        'kev' {
            _AddItem $menu 'Open CISA KEV catalog (search)' ({
                $sel = $g.SelectedItem
                if ($sel -and $sel.CveId) {
                    Start-Process "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=$($sel.CveId)"
                }
            }.GetNewClosure())
            _AddItem $menu 'Open NVD page' ({
                $sel = $g.SelectedItem
                if ($sel -and $sel.CveId) { Start-Process "https://nvd.nist.gov/vuln/detail/$($sel.CveId)" }
            }.GetNewClosure())
            if ($OnPivotKql) {
                _AddItem $menu 'Generate hunt query (CVE -> ATT&CK)' ({
                    $sel = $g.SelectedItem
                    if ($sel -and $sel.CveId) {
                        try {
                            $q = New-HuntQueryFromCve -CveId $sel.CveId
                            & $OnPivotKql $q $sel
                        } catch { [System.Windows.MessageBox]::Show($_.Exception.Message, 'Hunt query failed') | Out-Null }
                    }
                }.GetNewClosure())
            }
        }

        'technique' {
            _AddItem $menu 'Open MITRE ATT&CK page' ({
                $sel = $g.SelectedItem
                if ($sel -and $sel.ExternalId) {
                    $id = $sel.ExternalId -replace '\.', '/'
                    Start-Process "https://attack.mitre.org/techniques/$id/"
                }
            }.GetNewClosure())
            if ($OnPivotKql) {
                _AddItem $menu 'Generate hunt query (Technique)' ({
                    $sel = $g.SelectedItem
                    if ($sel -and $sel.ExternalId) {
                        try {
                            $q = New-HuntQueryFromTechnique -TechniqueId $sel.ExternalId
                            & $OnPivotKql $q $sel
                        } catch { [System.Windows.MessageBox]::Show($_.Exception.Message, 'Hunt query failed') | Out-Null }
                    }
                }.GetNewClosure())
            }
        }

        'tactic' {
            _AddItem $menu 'Open MITRE Tactic page' ({
                $sel = $g.SelectedItem
                if ($sel -and $sel.ExternalId) {
                    Start-Process "https://attack.mitre.org/tactics/$($sel.ExternalId)/"
                }
            }.GetNewClosure())
        }

        'group' {
            _AddItem $menu 'Open MITRE Group page' ({
                $sel = $g.SelectedItem
                if ($sel -and $sel.ExternalId) {
                    Start-Process "https://attack.mitre.org/groups/$($sel.ExternalId)/"
                }
            }.GetNewClosure())
        }

        'software' {
            _AddItem $menu 'Open MITRE Software page' ({
                $sel = $g.SelectedItem
                if ($sel -and $sel.ExternalId) {
                    Start-Process "https://attack.mitre.org/software/$($sel.ExternalId)/"
                }
            }.GetNewClosure())
        }

        'mitigation' {
            _AddItem $menu 'Open MITRE Mitigation page' ({
                $sel = $g.SelectedItem
                if ($sel -and $sel.ExternalId) {
                    Start-Process "https://attack.mitre.org/mitigations/$($sel.ExternalId)/"
                }
            }.GetNewClosure())
        }

        'hash' {
            if ($OnLookupHash) {
                _AddItem $menu 'Refresh from all sources' ({
                    $sel = $g.SelectedItem
                    if ($sel -and $sel.Sha256) { & $OnLookupHash $sel.Sha256 }
                }.GetNewClosure())
            }
            _AddItem $menu 'Open in VirusTotal (browser)' ({
                $sel = $g.SelectedItem
                if ($sel -and $sel.Sha256) { Start-Process "https://www.virustotal.com/gui/file/$($sel.Sha256)" }
            }.GetNewClosure())
            _AddItem $menu 'Open in MalwareBazaar (browser)' ({
                $sel = $g.SelectedItem
                if ($sel -and $sel.Sha256) { Start-Process "https://bazaar.abuse.ch/sample/$($sel.Sha256)/" }
            }.GetNewClosure())
            if ($OnPivotKql) {
                _AddItem $menu 'Search KQL Builder by hash' ({
                    $sel = $g.SelectedItem
                    if ($sel -and $sel.Sha256) {
                        $q = @"
DeviceFileEvents
| where TimeGenerated > ago(7d)
| where SHA256 == '$($sel.Sha256)'
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| take 100
"@
                        & $OnPivotKql $q $sel
                    }
                }.GetNewClosure())
            }
        }

        'ioc' {
            if ($OnPivotKql) {
                _AddItem $menu 'Search KQL Builder by IoC value' ({
                    $sel = $g.SelectedItem
                    if (-not $sel) { return }
                    $val = $sel.Value
                    $q = switch ($sel.Type) {
                        'ip'        { "DeviceNetworkEvents | where TimeGenerated > ago(7d) | where RemoteIP == '$val' | take 100" }
                        'domain'    { "DeviceNetworkEvents | where TimeGenerated > ago(7d) | where RemoteUrl has '$val' | take 100" }
                        'url'       { "DeviceNetworkEvents | where TimeGenerated > ago(7d) | where RemoteUrl == '$val' | take 100" }
                        'sha256'    { "DeviceFileEvents    | where TimeGenerated > ago(7d) | where SHA256 == '$val' | take 100" }
                        'sha1'      { "DeviceFileEvents    | where TimeGenerated > ago(7d) | where SHA1 == '$val'   | take 100" }
                        'md5'       { "DeviceFileEvents    | where TimeGenerated > ago(7d) | where MD5 == '$val'    | take 100" }
                        'filename'  { "DeviceFileEvents    | where TimeGenerated > ago(7d) | where FileName =~ '$val' | take 100" }
                        default     { "// IoC type '$($sel.Type)' has no default mapping`n// <<EXTEND>> Add to SecIntel.UiHelpers.ps1 ioc switch" }
                    }
                    & $OnPivotKql $q $sel
                }.GetNewClosure())
            }
        }
    }

    # ----- View details (any kind) -----
    if ($OnViewDetails) {
        _AddSep $menu
        _AddItem $menu 'View details...' ({
            $sel = $g.SelectedItem
            if ($sel) { & $OnViewDetails $sel }
        }.GetNewClosure())
    }

    $Grid.ContextMenu = $menu
}

# ============================================================
# Status bar
# ============================================================
function Update-StatusBar {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $StatusTextBlock,
        [string]$LastRefresh
    )
    $sizeMb = '?'
    if (Test-Path $script:DbPath) {
        $sizeMb = "{0:N1} MB" -f ((Get-Item $script:DbPath).Length / 1MB)
    }
    $counts = @{}
    foreach ($t in 'KEVs','CVEs','Techniques','HashIntel','Iocs','KqlQueries','CveTechniqueMap') {
        try {
            $counts[$t] = (Invoke-SqliteQuery -DataSource $script:DbPath -Query "SELECT COUNT(*) AS C FROM $t").C
        } catch { $counts[$t] = '?' }
    }
    $parts = @(
        "DB: $sizeMb"
        "KEVs: $($counts['KEVs'])"
        "CVEs: $($counts['CVEs'])"
        "Tech: $($counts['Techniques'])"
        "Maps: $($counts['CveTechniqueMap'])"
        "Hash: $($counts['HashIntel'])"
        "IoCs: $($counts['Iocs'])"
        "Queries: $($counts['KqlQueries'])"
    )
    if ($LastRefresh) { $parts += "Last refresh: $LastRefresh" }
    $StatusTextBlock.Text = ($parts -join '  |  ')
}

# ============================================================
# Diff-since-last-open
# ============================================================
function Get-DiffSinceLastOpen {
    [CmdletBinding()]
    param()
    $lastKev = Get-AppSetting 'lastseen.kev' '1970-01-01T00:00:00Z'
    $lastCve = Get-AppSetting 'lastseen.cve' '1970-01-01T00:00:00Z'

    $newKevs = (Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "SELECT COUNT(*) AS C FROM KEVs WHERE DateAdded > @t" `
        -SqlParameters @{ t=$lastKev }).C

    $newCves = (Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "SELECT COUNT(*) AS C FROM CVEs WHERE Published > @t AND CvssScore >= 9.0" `
        -SqlParameters @{ t=$lastCve }).C

    $newRan = (Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "SELECT COUNT(*) AS C FROM KEVs WHERE KnownRansomware='Known' AND DateAdded > @t" `
        -SqlParameters @{ t=$lastKev }).C

    return [PSCustomObject]@{
        NewKevs           = [int]$newKevs
        NewCriticalCves   = [int]$newCves
        NewRansomwareKevs = [int]$newRan
        LastKevSeen       = $lastKev
        LastCveSeen       = $lastCve
        Summary           = "$newKevs new KEV(s) [$newRan ransomware-linked], $newCves new CVSS>=9 CVE(s)"
    }
}

function Set-LastSeenNow {
    [CmdletBinding()]
    param()
    $now = (Get-Date).ToString('o')
    Set-AppSetting 'lastseen.kev' $now
    Set-AppSetting 'lastseen.cve' $now
}