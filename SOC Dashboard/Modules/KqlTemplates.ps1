<#
.SYNOPSIS
    DB-backed KQL template store + CRUD for the SOC Dashboard.

.DESCRIPTION
    Wraps the KqlTemplates table (defined in SecIntel.Schema.ps1) with
    typed CRUD functions and exposes a backward-compatible
    $kqlTemplates ordered hashtable for legacy callers in
    SocDashboard.ps1. Dot-source order:

        . (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
        Ensure-PSSQLite
        Initialize-SecIntelSchema      # creates table + seeds from data.json
        . (Join-Path $PSScriptRoot 'KqlTemplates.ps1')

    After dot-sourcing, the caller's scope has:

        $kqlTemplates                  Ordered @{ name = kql }
        Get-KqlTemplate                Read (single, all, by tag)
        Set-KqlTemplate                Insert or update
        Remove-KqlTemplate             Delete (protected on IsBuiltIn)
        Import-KqlTemplatesFromJson    Re-import from a data.json file

    Tags are stored as JSON array strings in the Tags column; the
    CRUD functions transparently encode / decode between PowerShell
    string[] and JSON. This matches the convention already used by
    KqlQueries.Tags and Iocs.Tags.

.NOTES
    PowerShell 5.1+. No admin rights. Depends on SecIntel.Schema.ps1.
#>

# --------------------------------------------------------------
# Internal: row -> object converter (decodes Tags JSON)
# --------------------------------------------------------------
function ConvertFrom-KqlTemplateRow {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Row)
    process {
        if (-not $Row) { return }
        # ConvertFrom-Json returns an array as a single pipeline element on
        # PS 5.1, so piping through @() double-wraps it. Use -InputObject
        # to avoid the pipe, then normalize to a real string[].
        $tags = @()
        if ($Row.Tags) {
            try {
                $parsed = ConvertFrom-Json -InputObject $Row.Tags -ErrorAction Stop
                if ($null -ne $parsed) {
                    if ($parsed -is [array]) { $tags = [string[]]$parsed }
                    else                     { $tags = [string[]]@($parsed) }
                }
            } catch { $tags = @() }
        }
        [pscustomobject]@{
            TemplateId   = [int]$Row.TemplateId
            Name         = [string]$Row.Name
            Description  = [string]$Row.Description
            Tags         = $tags
            Kql          = [string]$Row.Kql
            Author       = [string]$Row.Author
            IsBuiltIn    = ([int]$Row.IsBuiltIn -eq 1)
            Created      = [string]$Row.Created
            LastModified = [string]$Row.LastModified
        }
    }
}

# --------------------------------------------------------------
# Public: Get-KqlTemplate
# --------------------------------------------------------------
function Get-KqlTemplate {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param(
        [Parameter(ParameterSetName = 'ByName', Mandatory)]
        [string]$Name,

        [Parameter(ParameterSetName = 'All')]
        [switch]$All,

        [Parameter(ParameterSetName = 'ByTag')]
        [string[]]$Tags
    )

    if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        $r = Invoke-SqliteQuery -DataSource $script:DbPath `
                -Query "SELECT * FROM KqlTemplates WHERE Name = @n" `
                -SqlParameters @{ n = $Name } | Select-Object -First 1
        return ($r | ConvertFrom-KqlTemplateRow)
    }

    $rows = Invoke-SqliteQuery -DataSource $script:DbPath `
                -Query "SELECT * FROM KqlTemplates ORDER BY IsBuiltIn DESC, Name"

    if ($PSCmdlet.ParameterSetName -eq 'ByTag' -and $Tags) {
        $wanted = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]$Tags, [System.StringComparer]::OrdinalIgnoreCase)
        $rows = $rows | Where-Object {
            $t = $_ | ConvertFrom-KqlTemplateRow
            foreach ($tag in $t.Tags) { if ($wanted.Contains($tag)) { return $true } }
            $false
        }
    }
    return ($rows | ConvertFrom-KqlTemplateRow)
}

# --------------------------------------------------------------
# Public: Set-KqlTemplate (upsert by Name)
# --------------------------------------------------------------
function Set-KqlTemplate {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Kql,
        [string]$Description = '',
        [string[]]$Tags = @(),
        [string]$Author,
        [switch]$BuiltIn
    )
    if (-not $PSCmdlet.ShouldProcess("KqlTemplates row '$Name'", 'upsert')) { return }

    $now      = (Get-Date).ToString('o')
    $tagsJson = ConvertTo-SecIntelTagsJson -Tags $Tags
    $isBi     = if ($BuiltIn) { 1 } else { 0 }
    if (-not $Author) { $Author = if ($BuiltIn) { 'lab/templates/data.json' } else { $env:USERNAME } }

    # Check for existing row to preserve Created when updating
    $existing = Invoke-SqliteQuery -DataSource $script:DbPath `
                    -Query "SELECT TemplateId, Created FROM KqlTemplates WHERE Name = @n" `
                    -SqlParameters @{ n = $Name } | Select-Object -First 1

    if ($existing) {
        Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
UPDATE KqlTemplates
SET Description = @d, Tags = @tg, Kql = @k, Author = @a,
    IsBuiltIn = @bi, LastModified = @m
WHERE Name = @n
"@ -SqlParameters @{
            n  = $Name
            d  = $Description
            tg = $tagsJson
            k  = $Kql
            a  = $Author
            bi = $isBi
            m  = $now
        }
        return [int]$existing.TemplateId
    }

    Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT INTO KqlTemplates
    (Name, Description, Tags, Kql, Author, IsBuiltIn, Created, LastModified)
VALUES
    (@n, @d, @tg, @k, @a, @bi, @c, @m)
"@ -SqlParameters @{
        n  = $Name
        d  = $Description
        tg = $tagsJson
        k  = $Kql
        a  = $Author
        bi = $isBi
        c  = $now
        m  = $now
    }
    # last_insert_rowid() runs on a fresh connection in PSSQLite's
    # default mode and would always return 0; re-query by Name instead.
    $r = Invoke-SqliteQuery -DataSource $script:DbPath `
            -Query "SELECT TemplateId FROM KqlTemplates WHERE Name = @n" `
            -SqlParameters @{ n = $Name } | Select-Object -First 1
    return [int]$r.TemplateId
}

# --------------------------------------------------------------
# Public: Remove-KqlTemplate
#   Refuses to delete IsBuiltIn=1 rows unless -Force is passed.
# --------------------------------------------------------------
function Remove-KqlTemplate {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$Name,
        [switch]$Force
    )
    $existing = Invoke-SqliteQuery -DataSource $script:DbPath `
                    -Query "SELECT TemplateId, IsBuiltIn FROM KqlTemplates WHERE Name = @n" `
                    -SqlParameters @{ n = $Name } | Select-Object -First 1
    if (-not $existing) {
        Write-Warning "No KQL template named '$Name'."
        return $false
    }
    if ([int]$existing.IsBuiltIn -eq 1 -and -not $Force) {
        Write-Warning ("'{0}' is a built-in template. Pass -Force to delete it." -f $Name)
        return $false
    }
    if (-not $PSCmdlet.ShouldProcess("KqlTemplates row '$Name'", 'delete')) { return $false }

    Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "DELETE FROM KqlTemplates WHERE Name = @n" `
        -SqlParameters @{ n = $Name }
    return $true
}

# --------------------------------------------------------------
# Public: Import-KqlTemplatesFromJson
#   On-demand import (or re-import) from a data.json file. Used
#   for refreshing built-ins after a website update.
#
#   - User-authored rows (IsBuiltIn=0) are never touched.
#   - Built-in rows are inserted if absent. With -OverwriteBuiltIn,
#     existing built-ins are updated to match the JSON.
# --------------------------------------------------------------
function Import-KqlTemplatesFromJson {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$OverwriteBuiltIn
    )
    if (-not (Test-Path $Path)) {
        throw "File not found: $Path"
    }
    try {
        $data = Get-Content -Raw $Path | ConvertFrom-Json
    } catch {
        throw ("Failed to parse {0}: {1}" -f $Path, $_.Exception.Message)
    }

    $now      = (Get-Date).ToString('o')
    $created  = if ($data.updated) { $data.updated } else { $now }
    $tplList  = @($data.templates)
    $inserted = 0
    $updated  = 0
    $skipped  = 0

    foreach ($t in $tplList) {
        if (-not $t.name -or -not $t.kql) { $skipped++; continue }
        if (-not $PSCmdlet.ShouldProcess("KqlTemplates row '$($t.name)'", 'import')) { continue }

        $existing = Invoke-SqliteQuery -DataSource $script:DbPath `
                        -Query "SELECT TemplateId, IsBuiltIn FROM KqlTemplates WHERE Name = @n" `
                        -SqlParameters @{ n = $t.name } | Select-Object -First 1

        $tagsJson = ConvertTo-SecIntelTagsJson -Tags ([string[]]$t.tags)

        if ($existing) {
            if ([int]$existing.IsBuiltIn -ne 1) {
                # User-authored row with the same name; skip to protect user data
                $skipped++
                Write-Verbose ("Skipped '{0}' (user-authored template with same name)." -f $t.name)
                continue
            }
            if (-not $OverwriteBuiltIn) {
                $skipped++
                continue
            }
            Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
UPDATE KqlTemplates
SET Description = @d, Tags = @tg, Kql = @k, Author = @a, LastModified = @m
WHERE Name = @n AND IsBuiltIn = 1
"@ -SqlParameters @{
                n  = $t.name
                d  = $t.description
                tg = $tagsJson
                k  = $t.kql
                a  = $Path
                m  = $now
            }
            $updated++
        } else {
            Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT INTO KqlTemplates
    (Name, Description, Tags, Kql, Author, IsBuiltIn, Created, LastModified)
VALUES
    (@n, @d, @tg, @k, @a, 1, @c, @m)
"@ -SqlParameters @{
                n  = $t.name
                d  = $t.description
                tg = $tagsJson
                k  = $t.kql
                a  = $Path
                c  = $created
                m  = $now
            }
            $inserted++
        }
    }
    [pscustomobject]@{
        Inserted = $inserted
        Updated  = $updated
        Skipped  = $skipped
        Total    = $tplList.Count
    }
}

# --------------------------------------------------------------
# Backward-compat: populate $kqlTemplates ordered hashtable.
# Existing consumer at SocDashboard.ps1 line ~2107 expects:
#   $kqlTemplates.Keys     -> template names
#   $kqlTemplates[$name]   -> raw KQL string
# Defensive: if the DB or table is unavailable (e.g., dot-source
# happens before Initialize-SecIntelSchema), leave it empty.
# --------------------------------------------------------------
$kqlTemplates = [ordered]@{}
try {
    if ($script:DbPath -and (Test-Path $script:DbPath)) {
        foreach ($row in (Get-KqlTemplate -All)) {
            $kqlTemplates[$row.Name] = $row.Kql
        }
    }
} catch {
    Write-Warning ("KqlTemplates: failed to populate `$kqlTemplates from DB: {0}" -f $_.Exception.Message)
}
