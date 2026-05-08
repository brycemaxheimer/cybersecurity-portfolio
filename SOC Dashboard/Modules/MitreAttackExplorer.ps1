<#
.SYNOPSIS
    MITRE ATT&CK Explorer - downloads enterprise-attack.json, stores it in a
    local SQLite database, and launches a Windows Forms GUI for filtering and
    searching tactics, techniques, sub-techniques, groups, software, and
    mitigations. Also displays CVE/KEV data if Update-CveKevFeed.ps1 has
    been run against the same DB.

.DESCRIPTION
    First run: downloads the MITRE Enterprise ATT&CK STIX bundle, parses it,
    and populates a SQLite database at %USERPROFILE%\SecIntel\secintel.db.
    Subsequent runs just launch the GUI against the cached DB.

    Runs entirely under user-level PowerShell. The only dependency is the
    PSSQLite module, which is auto-installed to CurrentUser scope on first
    run if not already present.

.PARAMETER Update
    Force a refresh of the MITRE dataset from GitHub, even if the local DB
    already exists.

.PARAMETER NoGui
    Skip the GUI. Useful for automated DB builds/updates.

.EXAMPLE
    .\MitreAttackExplorer.ps1
    First run builds the DB and launches the GUI. Later runs just launch it.

.EXAMPLE
    .\MitreAttackExplorer.ps1 -Update
    Re-downloads and re-parses the MITRE bundle, then launches the GUI.

.NOTES
    PowerShell 5.1+ (PowerShell 7+ strongly recommended for faster JSON parse)
    No admin rights required.
#>

[CmdletBinding()]
param(
    [switch]$Update,
    [switch]$NoGui
)

$ErrorActionPreference = 'Stop'

# ---------- Shared schema / paths / dependency bootstrap ----------
. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.Http.ps1')
Ensure-PSSQLite

# ---------- Script-specific URL ----------
$script:MitreUrl = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'

# ---------- MITRE ingest ----------
function Update-MitreData {
    Write-Host "Downloading MITRE ATT&CK Enterprise dataset..." -ForegroundColor Cyan
    $tempFile = Join-Path $env:TEMP 'enterprise-attack.json'
    # -OutFile streams the ~30 MB JSON. Stamp the shared UA so MITRE/
    # GitHub raw.githubusercontent.com doesn't get a default PS UA
    # (some corporate WAFs throttle/block based on UA heuristics).
    Invoke-WebRequest -Uri $script:MitreUrl -OutFile $tempFile -UseBasicParsing `
        -UserAgent (Get-SecIntelUserAgent)

    Write-Host "Parsing STIX bundle (this can take ~30-60s on PS 5.1)..." -ForegroundColor Cyan
    $raw = Get-Content $tempFile -Raw
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $bundle = $raw | ConvertFrom-Json -Depth 50
    } else {
        $bundle = $raw | ConvertFrom-Json
    }

    Write-Host "Loading into SQLite..." -ForegroundColor Cyan
    $conn = New-SQLiteConnection -DataSource $script:DbPath
    try {
        # Clear MITRE tables only; leave CVE/KEV alone
        Invoke-SqliteQuery -SQLiteConnection $conn -Query "DELETE FROM Tactics;       DELETE FROM Techniques;
                                                           DELETE FROM AttackGroups;  DELETE FROM Software;
                                                           DELETE FROM Mitigations;   DELETE FROM Relationships;"
        Invoke-SqliteQuery -SQLiteConnection $conn -Query "BEGIN TRANSACTION;"

        $counters = @{ Tactics=0; Techniques=0; Groups=0; Software=0; Mitigations=0; Relationships=0 }

        foreach ($obj in $bundle.objects) {
            if ($obj.revoked -or $obj.x_mitre_deprecated) { continue }

            $extId = ''; $url = ''
            if ($obj.external_references) {
                $ref = $obj.external_references | Where-Object { $_.source_name -eq 'mitre-attack' } | Select-Object -First 1
                if ($ref) { $extId = [string]$ref.external_id; $url = [string]$ref.url }
            }

            switch ($obj.type) {
                'x-mitre-tactic' {
                    Invoke-SqliteQuery -SQLiteConnection $conn -Query @"
INSERT OR REPLACE INTO Tactics (StixId, ExternalId, Name, ShortName, Description, Url)
VALUES (@id, @ext, @name, @short, @desc, @url)
"@ -SqlParameters @{
                        id    = [string]$obj.id
                        ext   = $extId
                        name  = [string]$obj.name
                        short = [string]$obj.x_mitre_shortname
                        desc  = [string]$obj.description
                        url   = $url
                    }
                    $counters.Tactics++
                }
                'attack-pattern' {
                    $tactics = ''
                    if ($obj.kill_chain_phases) {
                        $tactics = (($obj.kill_chain_phases | Where-Object { $_.kill_chain_name -eq 'mitre-attack' } | ForEach-Object { $_.phase_name }) -join ', ')
                    }
                    $platforms   = if ($obj.x_mitre_platforms)    { ($obj.x_mitre_platforms    -join ', ') } else { '' }
                    $datasources = if ($obj.x_mitre_data_sources) { ($obj.x_mitre_data_sources -join ', ') } else { '' }
                    $isSub       = if ($obj.x_mitre_is_subtechnique) { 1 } else { 0 }
                    $parentExt   = ''
                    if ($isSub -and $extId -match '^(T\d+)\.\d+$') { $parentExt = $matches[1] }

                    Invoke-SqliteQuery -SQLiteConnection $conn -Query @"
INSERT OR REPLACE INTO Techniques (StixId, ExternalId, Name, IsSubtechnique, ParentExternalId, Tactics, Platforms, DataSources, Detection, Description, Url)
VALUES (@id, @ext, @name, @sub, @parent, @tac, @plat, @ds, @det, @desc, @url)
"@ -SqlParameters @{
                        id     = [string]$obj.id
                        ext    = $extId
                        name   = [string]$obj.name
                        sub    = $isSub
                        parent = $parentExt
                        tac    = $tactics
                        plat   = $platforms
                        ds     = $datasources
                        det    = [string]$obj.x_mitre_detection
                        desc   = [string]$obj.description
                        url    = $url
                    }
                    $counters.Techniques++
                }
                'intrusion-set' {
                    $aliases = if ($obj.aliases) { ($obj.aliases -join ', ') } else { '' }
                    Invoke-SqliteQuery -SQLiteConnection $conn -Query @"
INSERT OR REPLACE INTO AttackGroups (StixId, ExternalId, Name, Aliases, Description, Url)
VALUES (@id, @ext, @name, @al, @desc, @url)
"@ -SqlParameters @{
                        id   = [string]$obj.id
                        ext  = $extId
                        name = [string]$obj.name
                        al   = $aliases
                        desc = [string]$obj.description
                        url  = $url
                    }
                    $counters.Groups++
                }
                { $_ -eq 'malware' -or $_ -eq 'tool' } {
                    $aliases   = if ($obj.x_mitre_aliases)   { ($obj.x_mitre_aliases   -join ', ') } else { '' }
                    $platforms = if ($obj.x_mitre_platforms) { ($obj.x_mitre_platforms -join ', ') } else { '' }
                    Invoke-SqliteQuery -SQLiteConnection $conn -Query @"
INSERT OR REPLACE INTO Software (StixId, ExternalId, Name, Type, Aliases, Platforms, Description, Url)
VALUES (@id, @ext, @name, @t, @al, @plat, @desc, @url)
"@ -SqlParameters @{
                        id   = [string]$obj.id
                        ext  = $extId
                        name = [string]$obj.name
                        t    = [string]$obj.type
                        al   = $aliases
                        plat = $platforms
                        desc = [string]$obj.description
                        url  = $url
                    }
                    $counters.Software++
                }
                'course-of-action' {
                    Invoke-SqliteQuery -SQLiteConnection $conn -Query @"
INSERT OR REPLACE INTO Mitigations (StixId, ExternalId, Name, Description, Url)
VALUES (@id, @ext, @name, @desc, @url)
"@ -SqlParameters @{
                        id   = [string]$obj.id
                        ext  = $extId
                        name = [string]$obj.name
                        desc = [string]$obj.description
                        url  = $url
                    }
                    $counters.Mitigations++
                }
                'relationship' {
                    Invoke-SqliteQuery -SQLiteConnection $conn -Query @"
INSERT INTO Relationships (SourceId, TargetId, RelType, Description)
VALUES (@s, @t, @r, @d)
"@ -SqlParameters @{
                        s = [string]$obj.source_ref
                        t = [string]$obj.target_ref
                        r = [string]$obj.relationship_type
                        d = [string]$obj.description
                    }
                    $counters.Relationships++
                }
            }
        }

        Invoke-SqliteQuery -SQLiteConnection $conn -Query "COMMIT;"
        Invoke-SqliteQuery -SQLiteConnection $conn -Query @"
INSERT OR REPLACE INTO FeedMeta (FeedName, LastUpdated, RecordCount)
VALUES ('MITRE-ATTACK', @d, @c)
"@ -SqlParameters @{ d = (Get-Date).ToString('o'); c = ($counters.Values | Measure-Object -Sum).Sum }

        Write-Host "MITRE ingest complete:" -ForegroundColor Green
        $counters.GetEnumerator() | ForEach-Object { Write-Host ("  {0,-15} {1}" -f $_.Key, $_.Value) }
    }
    finally {
        $conn.Close()
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }
}

# GUI HELPERS------------------------------------
function Set-DarkTitleBar([System.Windows.Forms.Form]$f) {
    try {
        $val = 1
        [void][Native.Dwm]::DwmSetWindowAttribute($f.Handle, 20, [ref]$val, 4) # DWMWA_USE_IMMERSIVE_DARK_MODE
    } catch {}
}

function Set-DarkTheme {
    param([System.Windows.Forms.Control]$Ctrl)
    $t = $script:Theme
    $Ctrl.BackColor = $t.Bg
    $Ctrl.ForeColor = $t.Fg
  
	if ($Ctrl -is [System.Windows.Forms.DataGridView]) {
        $g = $Ctrl
        $g.BackgroundColor                                  = $t.Bg
        $g.GridColor                                        = $t.Border
        $g.BorderStyle                                      = 'FixedSingle'
        $g.EnableHeadersVisualStyles                        = $false
        $g.ColumnHeadersDefaultCellStyle.BackColor          = $t.BgPanel
        $g.ColumnHeadersDefaultCellStyle.ForeColor          = $t.Accent
        $g.ColumnHeadersDefaultCellStyle.SelectionBackColor = $t.BgPanel
        $g.ColumnHeadersDefaultCellStyle.SelectionForeColor = $t.Accent
        $g.ColumnHeadersBorderStyle                         = 'Single'
        $g.DefaultCellStyle.BackColor                       = $t.Bg
        $g.DefaultCellStyle.ForeColor                       = $t.Fg
        $g.DefaultCellStyle.SelectionBackColor              = $t.SelBg
        $g.DefaultCellStyle.SelectionForeColor              = $t.SelFg
        $g.AlternatingRowsDefaultCellStyle.BackColor        = $t.BgAlt
        $g.AlternatingRowsDefaultCellStyle.ForeColor        = $t.Fg
        $g.RowHeadersDefaultCellStyle.BackColor             = $t.BgPanel
        $g.RowHeadersDefaultCellStyle.ForeColor             = $t.Fg
    }
    elseif ($Ctrl -is [System.Windows.Forms.Button]) {
        $Ctrl.FlatStyle                  = 'Flat'
        $Ctrl.FlatAppearance.BorderColor = $script:Theme.Border
        $Ctrl.BackColor                  = $script:Theme.BgPanel
        $Ctrl.ForeColor                  = $script:Theme.Accent
    }
    elseif ($Ctrl -is [System.Windows.Forms.TextBox]) {
        $Ctrl.BorderStyle = 'FixedSingle'
        $Ctrl.BackColor   = $script:Theme.BgPanel
        $Ctrl.ForeColor   = $script:Theme.Fg
    }
    elseif ($Ctrl -is [System.Windows.Forms.TabControl]) {
        $Ctrl.DrawMode = 'OwnerDrawFixed'
        $Ctrl.SizeMode = 'Fixed'
        $Ctrl.ItemSize = New-Object System.Drawing.Size(140, 28)
        $Ctrl.Add_DrawItem({
            param($s, $e)
            $tc = $s
            $t  = $script:Theme
            $page = $tc.TabPages[$e.Index]
            $isSel = ($e.Index -eq $tc.SelectedIndex)
            $bg = if ($isSel) { $t.BgPanel } else { $t.Bg }
            $fg = if ($isSel) { $t.Accent }  else { $t.FgDim }
             
            # --- Create a correct RectangleF for drawing ---
            $rect = New-Object System.Drawing.RectangleF($e.Bounds.X, $e.Bounds.Y, $e.Bounds.Width, $e.Bounds.Height)
             
            $brushBg = New-Object System.Drawing.SolidBrush($bg)
            $brushFg = New-Object System.Drawing.SolidBrush($fg)
            $e.Graphics.FillRectangle($brushBg, $e.Bounds)
              
            $sf = New-Object System.Drawing.StringFormat
            $sf.Alignment = 'Center'; $sf.LineAlignment = 'Center'
               
            # --- Use the new RectangleF object in the call ---
            $e.Graphics.DrawString($page.Text, $tc.Font, $brushFg, $rect, $sf)
               
            $brushBg.Dispose(); $brushFg.Dispose(); $sf.Dispose()
        })
    }


    foreach ($child in $Ctrl.Controls) { Set-DarkTheme -Ctrl $child }
}

# ---------- GUI ----------
function Show-Gui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # --- Dark IR theme palette (matches IR HTML template) ---
    $script:Theme = @{
        Bg        = [System.Drawing.ColorTranslator]::FromHtml('#0d1117')
        BgAlt     = [System.Drawing.ColorTranslator]::FromHtml('#161b22')
        BgPanel   = [System.Drawing.ColorTranslator]::FromHtml('#1c2128')
        Border    = [System.Drawing.ColorTranslator]::FromHtml('#30363d')
        Fg        = [System.Drawing.ColorTranslator]::FromHtml('#e6edf3')
        FgDim     = [System.Drawing.ColorTranslator]::FromHtml('#8b949e')
        Accent    = [System.Drawing.ColorTranslator]::FromHtml('#58a6ff')
        AccentAlt = [System.Drawing.ColorTranslator]::FromHtml('#39d353')
        SelBg     = [System.Drawing.ColorTranslator]::FromHtml('#1f6feb')
        SelFg     = [System.Drawing.ColorTranslator]::FromHtml('#ffffff')
    }

    # --- Dark titlebar on Win10 1809+/Win11 ---
    Add-Type -Namespace Native -Name Dwm -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@

    $form               = New-Object System.Windows.Forms.Form
    $form.Text          = "MITRE ATT&CK Explorer  -  $script:DbPath"
    $form.Size          = New-Object System.Drawing.Size(1280, 820)
    $form.MinimumSize   = New-Object System.Drawing.Size(1200, 700)
    $form.StartPosition = 'CenterScreen'
    $form.Font          = New-Object System.Drawing.Font('Consolas', 9)
    $form.BackColor     = $script:Theme.Bg
    $form.ForeColor     = $script:Theme.Fg
    $form.Add_HandleCreated({ Set-DarkTitleBar $form })

    $tabs                = New-Object System.Windows.Forms.TabControl
    $tabs.Dock           = 'Fill'
    $form.Controls.Add($tabs)

    # Factory for a standard filter+grid tab
    function New-GridTab {
        param(
            [string]$Title,
            [string]$BaseQuery,
            [string[]]$FilterColumns
        )

        $tab           = New-Object System.Windows.Forms.TabPage $Title
        $tab.BackColor = $script:Theme.Bg
        $tab.ForeColor = $script:Theme.Fg
        $tabs.TabPages.Add($tab)

        $top           = New-Object System.Windows.Forms.Panel
        $top.Dock      = 'Top'
        $top.Height    = 44
        $top.BackColor = $script:Theme.BgAlt
        $tab.Controls.Add($top)

        $lbl           = New-Object System.Windows.Forms.Label
        $lbl.Text      = "SEARCH >"
        $lbl.Location  = New-Object System.Drawing.Point(10, 14)
        $lbl.AutoSize  = $true
        $lbl.ForeColor = $script:Theme.Accent
        $top.Controls.Add($lbl)

        $txt           = New-Object System.Windows.Forms.TextBox
        $txt.Location  = New-Object System.Drawing.Point(80, 11)
        $txt.Width     = 420
        $top.Controls.Add($txt)

        $btn           = New-Object System.Windows.Forms.Button
        $btn.Text      = "Filter"
        $btn.Location  = New-Object System.Drawing.Point(510, 10)
        $btn.Width     = 80
        $top.Controls.Add($btn)

        $clr           = New-Object System.Windows.Forms.Button
        $clr.Text      = "Clear"
        $clr.Location  = New-Object System.Drawing.Point(596, 10)
        $clr.Width     = 80
        $top.Controls.Add($clr)

        $cnt           = New-Object System.Windows.Forms.Label
        $cnt.Location  = New-Object System.Drawing.Point(690, 14)
        $cnt.AutoSize  = $true
        $cnt.ForeColor = $script:Theme.FgDim
        $top.Controls.Add($cnt)

        $grid                     = New-Object System.Windows.Forms.DataGridView
        $grid.Dock                = 'Fill'
        $grid.ReadOnly            = $true
        $grid.AllowUserToAddRows  = $false
        $grid.SelectionMode       = 'FullRowSelect'
        $grid.AutoSizeColumnsMode = 'AllCells'
        $grid.RowHeadersVisible   = $false
        $grid.MultiSelect         = $false
        $tab.Controls.Add($grid)
        $grid.BringToFront()

        # Stash references on the grid's .Tag so handlers can find them via sender
        $grid.Tag = @{ Query = $BaseQuery; Cols = $FilterColumns; Txt = $txt; Cnt = $cnt }

        $loadData = {
            param($g, $searchTerm)
            try {
                $meta = $g.Tag
                $q = $meta.Query
                if ($searchTerm) {
                    $likes = $meta.Cols | ForEach-Object { "$_ LIKE @s" }
                    # Inject WHERE before ORDER BY if present
                    if ($q -match '\sORDER BY\s') {
                        $q = $q -replace '(\sORDER BY\s)', " WHERE ($($likes -join ' OR '))`$1"
                    } else {
                        $q += " WHERE " + ($likes -join ' OR ')
                    }
                    $rows = Invoke-SqliteQuery -DataSource $script:DbPath -Query $q -SqlParameters @{ s = "%$searchTerm%" }
                } else {
                    $rows = Invoke-SqliteQuery -DataSource $script:DbPath -Query $q
                }
                $dt = New-Object System.Data.DataTable
                if ($rows) {
                    $first = $rows | Select-Object -First 1
                    foreach ($p in $first.PSObject.Properties) { [void]$dt.Columns.Add($p.Name, [string]) }
                    foreach ($r in $rows) {
                        $dr = $dt.NewRow()
                        foreach ($p in $r.PSObject.Properties) {
                            $val = $p.Value
                            if ($null -ne $val -and $val.ToString().Length -gt 300) {
                                $dr[$p.Name] = $val.ToString().Substring(0, 297) + '...'
                            } else {
                                $dr[$p.Name] = [string]$val
                            }
                        }
                        [void]$dt.Rows.Add($dr)
                    }
                }
                $g.DataSource = $dt
                $meta.Cnt.Text = "$($dt.Rows.Count) rows"
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Load failed:`n$_", 'Error', 'OK', 'Error') | Out-Null
            }
        }

        # Expose a 0-arg loader on the grid so the tab-change handler can
        # auto-refresh this tab without knowing the local closures here.
        # Preserves the user's current search term across re-loads.
        $grid.Tag.Loader = { & $loadData $grid $txt.Text }.GetNewClosure()

        # Bind handlers WITH closures so $grid / $loadData are captured
        $btn.Add_Click({ & $loadData $grid $txt.Text }.GetNewClosure())
        $clr.Add_Click({ $txt.Text = ''; & $loadData $grid $null }.GetNewClosure())
        $txt.Add_KeyDown({
            param($s, $e)
            if ($e.KeyCode -eq 'Enter') {
                & $loadData $grid $txt.Text
                $e.SuppressKeyPress = $true
            }
        }.GetNewClosure())

        # Double-click: use $s (sender) -- no closure needed, no null refs
        $grid.Add_CellDoubleClick({
            param($s, $e)
            try {
                if ($e.RowIndex -lt 0) { return }
                $g = $s
                $row = $g.Rows[$e.RowIndex]

                $detail = New-Object System.Windows.Forms.Form
                $detail.Text = "Detail - $($g.Columns[0].Name): $($row.Cells[0].Value)"
                $detail.Size = New-Object System.Drawing.Size(900, 600)
                $detail.StartPosition = 'CenterParent'
                $detail.BackColor = $script:Theme.Bg
                $detail.ForeColor = $script:Theme.Fg
                $detail.Add_HandleCreated({ Set-DarkTitleBar $detail }.GetNewClosure())

                $tb = New-Object System.Windows.Forms.TextBox
                $tb.Multiline   = $true
                $tb.ScrollBars  = 'Vertical'
                $tb.Dock        = 'Fill'
                $tb.ReadOnly    = $true
                $tb.Font        = New-Object System.Drawing.Font('Consolas', 10)
                $tb.BackColor   = $script:Theme.Bg
                $tb.ForeColor   = $script:Theme.Fg
                $tb.BorderStyle = 'None'

                $sb = New-Object System.Text.StringBuilder
                for ($i = 0; $i -lt $g.Columns.Count; $i++) {
                    $colName = $g.Columns[$i].Name
                    $cellValue = $row.Cells[$i].Value
                    [void]$sb.AppendLine("${colName}:")
                    [void]$sb.AppendLine("  $cellValue")
                    [void]$sb.AppendLine()
                }
                $tb.Text = $sb.ToString()
                $detail.Controls.Add($tb)
                [void]$detail.ShowDialog()
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Detail view failed:`n$_", 'Error', 'OK', 'Error') | Out-Null
            }
        })

        & $loadData $grid $null
    }

    # ============================================================
    # Dashboard landing tab (first tab - analyst home view)
    # ============================================================
    $dashTab = New-Object System.Windows.Forms.TabPage 'Dashboard'
    $tabs.TabPages.Add($dashTab)

    # --- Header strip (title + view refresh on row 1, feed-update buttons on row 2) ---
    $dashHeader = New-Object System.Windows.Forms.Panel
    $dashHeader.Dock = 'Top'
    $dashHeader.Height = 80
    $dashTab.Controls.Add($dashHeader)

    $titleLbl = New-Object System.Windows.Forms.Label
    $titleLbl.Text = 'SOC OPERATIONS DASHBOARD'
    $titleLbl.Font = New-Object System.Drawing.Font('Consolas', 12, [System.Drawing.FontStyle]::Bold)
    $titleLbl.Location = New-Object System.Drawing.Point(12, 11)
    $titleLbl.AutoSize = $true
    $dashHeader.Controls.Add($titleLbl)

    $refreshBtn = New-Object System.Windows.Forms.Button
    $refreshBtn.Text = 'Refresh View'
    $refreshBtn.Width = 110
    $refreshBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $refreshBtn.Location = New-Object System.Drawing.Point(1160, 10)
    $dashHeader.Controls.Add($refreshBtn)

    $lastRefreshLbl = New-Object System.Windows.Forms.Label
    $lastRefreshLbl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $lastRefreshLbl.Location = New-Object System.Drawing.Point(920, 14)
    $lastRefreshLbl.AutoSize = $true
    $dashHeader.Controls.Add($lastRefreshLbl)

    # Row 2: feed-update buttons (left) + job status (right, anchored)
    $btnUpdateKev           = New-Object System.Windows.Forms.Button
    $btnUpdateKev.Text      = 'Update KEV'
    $btnUpdateKev.Width     = 110
    $btnUpdateKev.Location  = New-Object System.Drawing.Point(12, 44)
    $dashHeader.Controls.Add($btnUpdateKev)

    $btnUpdateCve           = New-Object System.Windows.Forms.Button
    $btnUpdateCve.Text      = 'Update CVE'
    $btnUpdateCve.Width     = 110
    $btnUpdateCve.Location  = New-Object System.Drawing.Point(128, 44)
    $dashHeader.Controls.Add($btnUpdateCve)

    $btnUpdateMitre          = New-Object System.Windows.Forms.Button
    $btnUpdateMitre.Text     = 'Update MITRE'
    $btnUpdateMitre.Width    = 130
    $btnUpdateMitre.Location = New-Object System.Drawing.Point(244, 44)
    $dashHeader.Controls.Add($btnUpdateMitre)

    $jobStatusLbl          = New-Object System.Windows.Forms.Label
    $jobStatusLbl.Location = New-Object System.Drawing.Point(390, 48)
    $jobStatusLbl.AutoSize = $true
    $dashHeader.Controls.Add($jobStatusLbl)

    # --- KPI strip: TableLayoutPanel so tiles reflow with form width ---
    $kpiStrip             = New-Object System.Windows.Forms.TableLayoutPanel
    $kpiStrip.Dock        = 'Top'
    $kpiStrip.Height      = 120
    $kpiStrip.ColumnCount = 4
    $kpiStrip.RowCount    = 1
    $kpiStrip.Padding     = New-Object System.Windows.Forms.Padding(8, 10, 8, 10)
    for ($i = 0; $i -lt 4; $i++) {
        [void]$kpiStrip.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle ([System.Windows.Forms.SizeType]::Percent, 25)))
    }
    [void]$kpiStrip.RowStyles.Add((New-Object System.Windows.Forms.RowStyle ([System.Windows.Forms.SizeType]::Percent, 100)))
    $dashTab.Controls.Add($kpiStrip)

    # Custom-painted border so KPI tiles match Theme.Border (#30363d)
    # instead of the system gray that BorderStyle='FixedSingle' produces.
    $kpiBorderPaint = {
        param($s, $e)
        $pen = New-Object System.Drawing.Pen([System.Drawing.ColorTranslator]::FromHtml('#30363d'), 1)
        $r   = New-Object System.Drawing.Rectangle(0, 0, ($s.Width - 1), ($s.Height - 1))
        $e.Graphics.DrawRectangle($pen, $r)
        $pen.Dispose()
    }

    $newKpiTile = {
        param([string]$Caption)
        $tile             = New-Object System.Windows.Forms.Panel
        $tile.Dock        = 'Fill'
        $tile.Margin      = New-Object System.Windows.Forms.Padding(4, 0, 4, 0)
        $tile.BorderStyle = 'None'
        $tile.Add_Paint($kpiBorderPaint)

        $cap = New-Object System.Windows.Forms.Label
        $cap.Name     = 'Caption'
        $cap.Text     = $Caption
        $cap.Font     = New-Object System.Drawing.Font('Consolas', 8, [System.Drawing.FontStyle]::Bold)
        $cap.Location = New-Object System.Drawing.Point(10, 10)
        $cap.AutoSize = $true
        $tile.Controls.Add($cap)

        $val = New-Object System.Windows.Forms.Label
        $val.Name     = 'Value'
        $val.Text     = '--'
        $val.Font     = New-Object System.Drawing.Font('Consolas', 22, [System.Drawing.FontStyle]::Bold)
        $val.Location = New-Object System.Drawing.Point(10, 28)
        $val.AutoSize = $true
        $tile.Controls.Add($val)

        $sub = New-Object System.Windows.Forms.Label
        $sub.Name     = 'Sub'
        $sub.Text     = ''
        $sub.Font     = New-Object System.Drawing.Font('Consolas', 8)
        $sub.Location = New-Object System.Drawing.Point(10, 70)
        $sub.AutoSize = $true
        $tile.Controls.Add($sub)
        return $tile
    }

    $kpiFeed = & $newKpiTile 'FEED STATUS'
    $kpiKev  = & $newKpiTile 'KEV CATALOG (TOTAL)'
    $kpiCve  = & $newKpiTile 'CRITICAL CVES (CACHED)'
    $kpiRan  = & $newKpiTile 'KEVS - RANSOMWARE'
    $kpiStrip.Controls.Add($kpiFeed, 0, 0)
    $kpiStrip.Controls.Add($kpiKev,  1, 0)
    $kpiStrip.Controls.Add($kpiCve,  2, 0)
    $kpiStrip.Controls.Add($kpiRan,  3, 0)

    # --- Body: vertical split (Newest KEVs | right column) ---
    $dashBody = New-Object System.Windows.Forms.SplitContainer
    $dashBody.Dock        = 'Fill'
    $dashBody.Orientation = 'Vertical'
    $dashTab.Controls.Add($dashBody)
    try { $dashBody.SplitterDistance = 700 } catch {}
    $dashBody.BringToFront()

    # Left: Newest KEVs
    $kevHdr           = New-Object System.Windows.Forms.Label
    $kevHdr.Text      = 'NEWEST KEVS'
    $kevHdr.Dock      = 'Top'
    $kevHdr.Height    = 24
    $kevHdr.Font      = New-Object System.Drawing.Font('Consolas', 9, [System.Drawing.FontStyle]::Bold)
    $kevHdr.TextAlign = 'MiddleLeft'
    $kevHdr.Padding   = New-Object System.Windows.Forms.Padding(8, 4, 0, 0)
    $dashBody.Panel1.Controls.Add($kevHdr)

    $newKevGrid                     = New-Object System.Windows.Forms.DataGridView
    $newKevGrid.Dock                = 'Fill'
    $newKevGrid.ReadOnly            = $true
    $newKevGrid.AllowUserToAddRows  = $false
    $newKevGrid.SelectionMode       = 'FullRowSelect'
    $newKevGrid.AutoSizeColumnsMode = 'AllCells'
    $newKevGrid.RowHeadersVisible   = $false
    $newKevGrid.MultiSelect         = $false
    $dashBody.Panel1.Controls.Add($newKevGrid)
    $newKevGrid.BringToFront()

    # Right: horizontal split (Feed Health top, Critical CVEs bottom)
    $rightSplit             = New-Object System.Windows.Forms.SplitContainer
    $rightSplit.Dock        = 'Fill'
    $rightSplit.Orientation = 'Horizontal'
    $dashBody.Panel2.Controls.Add($rightSplit)
    try { $rightSplit.SplitterDistance = 220 } catch {}
    $rightSplit.BringToFront()

    $feedHdr           = New-Object System.Windows.Forms.Label
    $feedHdr.Text      = 'FEED HEALTH'
    $feedHdr.Dock      = 'Top'
    $feedHdr.Height    = 24
    $feedHdr.Font      = New-Object System.Drawing.Font('Consolas', 9, [System.Drawing.FontStyle]::Bold)
    $feedHdr.TextAlign = 'MiddleLeft'
    $feedHdr.Padding   = New-Object System.Windows.Forms.Padding(8, 4, 0, 0)
    $rightSplit.Panel1.Controls.Add($feedHdr)

    $feedGrid                     = New-Object System.Windows.Forms.DataGridView
    $feedGrid.Dock                = 'Fill'
    $feedGrid.ReadOnly            = $true
    $feedGrid.AllowUserToAddRows  = $false
    $feedGrid.AutoSizeColumnsMode = 'Fill'
    $feedGrid.RowHeadersVisible   = $false
    $rightSplit.Panel1.Controls.Add($feedGrid)
    $feedGrid.BringToFront()

    $critHdr           = New-Object System.Windows.Forms.Label
    $critHdr.Text      = 'CRITICAL CVES (CVSS >= 9.0)'
    $critHdr.Dock      = 'Top'
    $critHdr.Height    = 24
    $critHdr.Font      = New-Object System.Drawing.Font('Consolas', 9, [System.Drawing.FontStyle]::Bold)
    $critHdr.TextAlign = 'MiddleLeft'
    $critHdr.Padding   = New-Object System.Windows.Forms.Padding(8, 4, 0, 0)
    $rightSplit.Panel2.Controls.Add($critHdr)

    $critCveGrid                     = New-Object System.Windows.Forms.DataGridView
    $critCveGrid.Dock                = 'Fill'
    $critCveGrid.ReadOnly            = $true
    $critCveGrid.AllowUserToAddRows  = $false
    $critCveGrid.SelectionMode       = 'FullRowSelect'
    $critCveGrid.AutoSizeColumnsMode = 'AllCells'
    $critCveGrid.RowHeadersVisible   = $false
    $rightSplit.Panel2.Controls.Add($critCveGrid)
    $critCveGrid.BringToFront()

    # --- Refresh logic ---
    $refreshDash = {
        try {
            $t = $script:Theme

            # Reduce visible flicker while we re-paint every dashboard surface.
            $dashTab.SuspendLayout()

            # Re-apply explicit colors after Set-DarkTheme has flattened them.
            # Goal: every direct child of dashHeader paints in BgAlt so the
            # whole strip reads as a single unbroken band.
            $dashHeader.BackColor      = $t.BgAlt
            $kpiStrip.BackColor        = $t.Bg
            $titleLbl.ForeColor        = $t.Accent
            $titleLbl.BackColor        = $t.BgAlt
            $lastRefreshLbl.ForeColor  = $t.FgDim
            $lastRefreshLbl.BackColor  = $t.BgAlt
            $jobStatusLbl.BackColor    = $t.BgAlt
            foreach ($b in @($refreshBtn, $btnUpdateKev, $btnUpdateCve, $btnUpdateMitre)) {
                $b.FlatStyle                  = 'Flat'
                $b.FlatAppearance.BorderColor = $t.Border
                $b.FlatAppearance.BorderSize  = 1
                $b.BackColor                  = $t.BgPanel
                $b.ForeColor                  = $t.Accent
            }
            foreach ($tile in @($kpiFeed, $kpiKev, $kpiCve, $kpiRan)) {
                $tile.BackColor                       = $t.BgPanel
                $tile.Controls['Caption'].ForeColor   = $t.FgDim
                $tile.Controls['Caption'].BackColor   = $t.BgPanel
                $tile.Controls['Value'].BackColor     = $t.BgPanel
                $tile.Controls['Sub'].ForeColor       = $t.FgDim
                $tile.Controls['Sub'].BackColor       = $t.BgPanel
                # Tile painted via Add_Paint draws over BackColor; ensure the
                # paint is current.
                $tile.Invalidate()
            }
            foreach ($hdr in @($kevHdr, $feedHdr, $critHdr)) {
                $hdr.ForeColor = $t.Accent
                $hdr.BackColor = $t.BgAlt
            }

            $db = $script:DbPath
            if (-not (Test-Path $db)) {
                $lastRefreshLbl.Text = 'DB not found - run feed scripts first'
                return
            }

            # ---- Feed health ----
            $feeds = Invoke-SqliteQuery -DataSource $db -Query "SELECT FeedName, LastUpdated, RecordCount FROM FeedMeta"
            $now = Get-Date
            $feedTable = New-Object System.Data.DataTable
            [void]$feedTable.Columns.Add('Feed',        [string])
            [void]$feedTable.Columns.Add('LastUpdated', [string])
            [void]$feedTable.Columns.Add('Age',         [string])
            [void]$feedTable.Columns.Add('Records',     [string])
            [void]$feedTable.Columns.Add('Status',      [string])
            $stale = 0
            foreach ($f in $feeds) {
                $dt = $null
                try { $dt = [DateTime]::Parse($f.LastUpdated) } catch {}
                $age = ''; $status = 'OK'
                if ($dt) {
                    $hours = [int]($now - $dt).TotalHours
                    $age = if ($hours -lt 48) { "$hours h" } else { "$([int]($hours/24)) d" }
                    # MITRE refreshes infrequently; CVE/KEV should be daily
                    if ($f.FeedName -like '*MITRE*') {
                        if ($hours -gt 720) { $status = 'STALE'; $stale++ }
                    } else {
                        if ($hours -gt 48)  { $status = 'STALE'; $stale++ }
                    }
                } else { $status = 'UNKNOWN'; $stale++ }
                $row = $feedTable.NewRow()
                $row.Feed        = [string]$f.FeedName
                $row.LastUpdated = if ($dt) { $dt.ToString('yyyy-MM-dd HH:mm') } else { '' }
                $row.Age         = $age
                $row.Records     = [string]$f.RecordCount
                $row.Status      = $status
                [void]$feedTable.Rows.Add($row)
            }
            $feedGrid.DataSource = $feedTable

            # KPI 1 - feed status
            $tot = $feedTable.Rows.Count
            $okCount = [Math]::Max(0, $tot - $stale)
            $kpiFeed.Controls['Value'].Text      = if ($tot -gt 0) { "$okCount/$tot OK" } else { '--' }
            $kpiFeed.Controls['Sub'].Text        = if ($tot -eq 0) { 'no feeds ingested yet' }
                                                    elseif ($stale -gt 0) { "$stale stale feed(s)" }
                                                    else { 'all feeds fresh' }
            $kpiFeed.Controls['Value'].ForeColor = if ($stale -gt 0 -or $tot -eq 0) { [System.Drawing.Color]::FromArgb(0xff, 0xa6, 0x57) } else { $t.AccentAlt }

            # KPI 2 - KEV total
            $kev = (Invoke-SqliteQuery -DataSource $db -Query "SELECT COUNT(*) AS C FROM KEVs").C
            $kpiKev.Controls['Value'].Text      = "$kev"
            $kpiKev.Controls['Value'].ForeColor = $t.Accent
            $kpiKev.Controls['Sub'].Text        = 'CISA known-exploited'

            # KPI 3 - critical CVEs (CVSS >= 9.0)
            $crit = (Invoke-SqliteQuery -DataSource $db -Query "SELECT COUNT(*) AS C FROM CVEs WHERE CvssScore >= 9.0").C
            $kpiCve.Controls['Value'].Text      = "$crit"
            $kpiCve.Controls['Value'].ForeColor = if ($crit -gt 0) { [System.Drawing.Color]::FromArgb(0xff, 0xa6, 0x57) } else { $t.Accent }
            $kpiCve.Controls['Sub'].Text        = 'CVSS >= 9.0 in cache'

            # KPI 4 - ransomware-linked KEVs
            $ran = (Invoke-SqliteQuery -DataSource $db -Query "SELECT COUNT(*) AS C FROM KEVs WHERE KnownRansomware = 'Known'").C
            $kpiRan.Controls['Value'].Text      = "$ran"
            $kpiRan.Controls['Value'].ForeColor = if ($ran -gt 0) { [System.Drawing.Color]::FromArgb(0xff, 0x6b, 0x6b) } else { $t.Accent }
            $kpiRan.Controls['Sub'].Text        = 'ransomware-linked'

            # ---- Newest KEVs ----
            $nk = Invoke-SqliteQuery -DataSource $db -Query "SELECT DateAdded, CveId, VendorProject, Product, VulnName, KnownRansomware FROM KEVs ORDER BY DateAdded DESC LIMIT 25"
            $kevTbl = New-Object System.Data.DataTable
            if ($nk) {
                foreach ($p in ($nk | Select-Object -First 1).PSObject.Properties) { [void]$kevTbl.Columns.Add($p.Name, [string]) }
                foreach ($r in $nk) {
                    $row = $kevTbl.NewRow()
                    foreach ($p in $r.PSObject.Properties) { $row[$p.Name] = [string]$p.Value }
                    [void]$kevTbl.Rows.Add($row)
                }
            }
            $newKevGrid.DataSource = $kevTbl

            # ---- Critical CVEs ----
            $cc = Invoke-SqliteQuery -DataSource $db -Query "SELECT CveId, CvssScore, Severity, substr(Description,1,160) AS Snippet FROM CVEs WHERE CvssScore >= 9.0 ORDER BY Published DESC LIMIT 25"
            $ccTbl = New-Object System.Data.DataTable
            if ($cc) {
                foreach ($p in ($cc | Select-Object -First 1).PSObject.Properties) { [void]$ccTbl.Columns.Add($p.Name, [string]) }
                foreach ($r in $cc) {
                    $row = $ccTbl.NewRow()
                    foreach ($p in $r.PSObject.Properties) { $row[$p.Name] = [string]$p.Value }
                    [void]$ccTbl.Rows.Add($row)
                }
            }
            $critCveGrid.DataSource = $ccTbl

            $lastRefreshLbl.Text = "Last refresh: $($now.ToString('HH:mm:ss'))"
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Dashboard refresh failed:`n$_", 'Dashboard Error', 'OK', 'Error') | Out-Null
        } finally {
            try { $dashTab.ResumeLayout($true) } catch {}
        }
    }
    $refreshBtn.Add_Click({ & $refreshDash }.GetNewClosure())

    # ---- Feed-update launcher (spawns a child PowerShell window) ----
    $psExe       = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
    $cveKevPath  = Join-Path $PSScriptRoot 'Update-CveKevFeed.ps1'
    $mitrePath   = Join-Path $PSScriptRoot 'MitreAttackExplorer.ps1'

    $startUpdate = {
        param([string]$ScriptPath, [string]$ExtraArgs, [string]$Caption)
        if (-not (Test-Path $ScriptPath)) {
            $jobStatusLbl.Text = "Script not found: $ScriptPath"
            $jobStatusLbl.ForeColor = [System.Drawing.Color]::FromArgb(0xff, 0x6b, 0x6b)
            return
        }
        try {
            # Run the script, brief countdown, then auto-close.
            # The dashboard's tab-change handler also auto-refreshes, so the
            # analyst doesn't have to interact with this window at all.
            $cmd = "Set-Location -LiteralPath '$PSScriptRoot'; " +
                   "Write-Host '====== $Caption ======' -ForegroundColor Cyan; " +
                   "& '$ScriptPath' $ExtraArgs; " +
                   "Write-Host ''; " +
                   "Write-Host 'Done. Closing window...' -ForegroundColor Green; " +
                   "for (`$__i=5; `$__i -ge 1; `$__i--) { Write-Host (`"  closing in `${__i}s (Ctrl+C to keep open)`") -ForegroundColor DarkGray; Start-Sleep -Seconds 1 }"
            $argsList = @(
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-Command', $cmd
            )
            $proc = Start-Process -FilePath $psExe -ArgumentList $argsList -PassThru -WorkingDirectory $PSScriptRoot
            $jobStatusLbl.Text      = "Started: $Caption (pid $($proc.Id)) - refresh view when done"
            $jobStatusLbl.ForeColor = $script:Theme.AccentAlt
        } catch {
            $jobStatusLbl.Text      = "Failed to launch: $_"
            $jobStatusLbl.ForeColor = [System.Drawing.Color]::FromArgb(0xff, 0x6b, 0x6b)
        }
    }

    $btnUpdateKev.Add_Click({
        & $startUpdate $cveKevPath '-SkipCves' 'CISA KEV refresh'
    }.GetNewClosure())

    $btnUpdateCve.Add_Click({
        # NVD API key is read from $env:NVD_API_KEY by Update-CveKevFeed.ps1.
        # Setting it persistently:
        #   [Environment]::SetEnvironmentVariable('NVD_API_KEY','<key>','User')
        & $startUpdate $cveKevPath '-SkipKevs' 'NVD CVE refresh (last 30d)'
    }.GetNewClosure())

    $btnUpdateMitre.Add_Click({
        & $startUpdate $mitrePath '-Update -NoGui' 'MITRE ATT&CK framework refresh'
    }.GetNewClosure())

    # Reposition right-anchored header controls when the panel resizes
    $dashHeader.Add_Resize({
        if ($dashHeader.Width -gt 380) {
            $refreshBtn.Location     = New-Object System.Drawing.Point(($dashHeader.Width - 125), 10)
            $lastRefreshLbl.Location = New-Object System.Drawing.Point(($dashHeader.Width - 360), 14)
        }
    }.GetNewClosure())

    # Initial paint after Set-DarkTheme has applied (Form.Shown fires after that)
    $form.Add_Shown({ & $refreshDash }.GetNewClosure())

    # ============================================================
    # End dashboard tab
    # ============================================================

    # ============================================================
    # Tactics / Techniques / Sub-techniques / Groups / Software / Mitigations
    # ============================================================

    New-GridTab -Title 'Tactics' `
                -BaseQuery 'SELECT ExternalId, Name, ShortName, Description, Url FROM Tactics ORDER BY ExternalId' `
                -FilterColumns @('ExternalId','Name','ShortName','Description')

    New-GridTab -Title 'Techniques' `
                -BaseQuery 'SELECT ExternalId, Name, Tactics, Platforms, DataSources, Description, Url FROM Techniques WHERE IsSubtechnique = 0 ORDER BY ExternalId' `
                -FilterColumns @('ExternalId','Name','Tactics','Platforms','DataSources','Description')

    New-GridTab -Title 'Sub-techniques' `
                -BaseQuery 'SELECT ExternalId, Name, ParentExternalId, Tactics, Platforms, DataSources, Description, Url FROM Techniques WHERE IsSubtechnique = 1 ORDER BY ParentExternalId, ExternalId' `
                -FilterColumns @('ExternalId','Name','ParentExternalId','Tactics','Platforms','DataSources','Description')

    New-GridTab -Title 'Groups' `
                -BaseQuery 'SELECT ExternalId, Name, Aliases, Description, Url FROM AttackGroups ORDER BY ExternalId' `
                -FilterColumns @('ExternalId','Name','Aliases','Description')

    New-GridTab -Title 'Software' `
                -BaseQuery 'SELECT ExternalId, Name, Type, Aliases, Platforms, Description, Url FROM Software ORDER BY ExternalId' `
                -FilterColumns @('ExternalId','Name','Type','Aliases','Platforms','Description')

    New-GridTab -Title 'Mitigations' `
                -BaseQuery 'SELECT ExternalId, Name, Description, Url FROM Mitigations ORDER BY ExternalId' `
                -FilterColumns @('ExternalId','Name','Description')

    # Apply dark theme recursively after all tabs and controls are in place
    Set-DarkTheme -Ctrl $form

    [void]$form.ShowDialog()
}

# ============================================================
# Top-level dispatcher
# ============================================================
Initialize-SecIntelSchema

# Refresh MITRE data if the user asked for it, or if the Tactics table is empty
$needIngest = $Update.IsPresent
if (-not $needIngest) {
    try {
        $tacticCount = (Invoke-SqliteQuery -DataSource $script:DbPath -Query 'SELECT COUNT(*) AS C FROM Tactics').C
        if (-not $tacticCount -or [int]$tacticCount -eq 0) { $needIngest = $true }
    } catch {
        $needIngest = $true
    }
}
if ($needIngest) {
    Update-MitreData
}

if (-not $NoGui) {
    Show-Gui
}