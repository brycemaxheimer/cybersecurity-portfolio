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

# SIG # Begin signature block
# MIIcCwYJKoZIhvcNAQcCoIIb/DCCG/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBkMiLOetyILne2
# i0Ncryxe/VQMKb597MHhZAZ5G+f1rKCCFlAwggMSMIIB+qADAgECAhAtZQe+Ow97
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
# FTAvBgkqhkiG9w0BCQQxIgQgL8YqYCgDWioahP5JTn2mlT4lMW6Xg6EBBm1vzbpb
# Hf8wDQYJKoZIhvcNAQEBBQAEggEAuhoC4usIR+j4U689LEJ2k5q+0oNddJxYvtRg
# tIC0pzyDY/FpLuOUGJZfIanGZ8SUh1GE59ZV9ktfEliJ00VhaNbvw29NLJAWjeTm
# rX1N7ReVhIa0phXaRJPCdI90vaxQZ7oP+uLamPEp2od82jkWvVEgCyvIchzLykAq
# xVTBgGPQeJQ2QVQzAxt45g9JIXnINRpGNBZP1dcTseBAqH9A15o7t/MzxCxWFsQC
# FZzz4/IaKWFeSVMdsF8SYjhMKjBZy7EnnQC0STSmzf9YCGS48crneLA9vlgXX4LO
# LMz6ghsk+wRjuBm7u8pq4BqbnzEnmdowGrk6JMU5fpPR83/oFqGCAyYwggMiBgkq
# hkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeV
# dGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0yNjA0MjkxNzI5MjhaMC8GCSqGSIb3DQEJBDEiBCDHu1w7
# 2rTStpyaO4EvvFHgCywq5fcF1PVT4yrA5dF9OjANBgkqhkiG9w0BAQEFAASCAgAO
# iifX8GDRPriO6fSaIsrcNIol1oO4/4iDperUGKBMOqHffWW217Rtldz+WZAWEpQX
# 8zmrMvJzFzqSnEXQjtwF5fI42MgRdXya5FAErL60XKAcDg1a6BV2TH6CfOJ+sTHW
# VqpzyecOzLcSX1SdfcW8CRQ8tQIbpUG4aFMn/glPWr5jd6y4z6RpS9hJyB9qmnJx
# ECm2f97NXDIXpEfXITtpBNqINBhMD9orlURrSm1G80rNdH4UPvccMBVFqvOXbmqx
# 9koHIeqyqMdfDmXmzydeLSHeDT7fVRzjn/lQ+tlvzeTPUGIgpjJQsnGVd8clZZjs
# FCntG41HbE0DY6l9GbehB/UO+TVfMba/XXJjiTpcmdVF/NqfN/SmJjBYPn0aipRf
# K8/iYK+ECyZntBeSlFkxOYqSE0qDlyR7OwOW4HPBfLqzdr9QJamuRz2tenlLzQWR
# wTQNahRFk0L5q2wB2zCmuBJewrEPR/weAtMj6tR1IDXiMgVehDVJ/T+yJJY7fDLV
# WiDxEGPRtJIsU6wxEwrTK3cMsLNS365o61YQglZlSdRyFo7gGad6/XBxebIVUvh6
# xKbhhEZDSTUM2ke3/pTyfye7UvwpT+YOfdVJUO7Bhv+AD+scXPLXYb9LXFCX08Yq
# 6c1xF7QN0WikpKIz/mcIoF9Y+VtxL8/GEjLCnfN10w==
# SIG # End signature block
