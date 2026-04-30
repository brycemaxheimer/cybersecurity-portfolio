<#
.SYNOPSIS
    Import CVE -> MITRE ATT&CK technique mappings into SecIntel DB.

.DESCRIPTION
    Reads a CSV file with columns:
        CveId, TechniqueId, Source, Confidence, Mapping

    Header is required. Source/Confidence/Mapping are optional - missing
    values fall back to defaults from the parameters.

    Suggested data sources:

    1. Center for Threat-Informed Defense - "Mappings Explorer"
       https://center-for-threat-informed-defense.github.io/mappings-explorer/
       Export CSV from their UI, or pull JSON from their GitHub repo and
       transform with a small script.

    2. NVD CWE -> ATT&CK derived mapping (via CWE-ATT&CK bridge from MITRE)

    3. Analyst-curated entries from your own investigations
       (use Source='analyst' so they're distinguishable)

    The schema table is keyed on (CveId, TechniqueId, Source) so multiple
    mapping sources can coexist for the same CVE - the dashboard's pivot
    panel can then show all of them ranked by Confidence.

.PARAMETER Path
    Path to a CSV file. Defaults to %USERPROFILE%\SecIntel\cve_attack_map.csv.

.PARAMETER Source
    Default Source label for rows that don't supply one. Default 'analyst'.

.PARAMETER Confidence
    Default Confidence for rows that don't supply one. Default 'medium'.

.EXAMPLE
    .\Update-CveAttackMap.ps1 -Path .\ctid_mappings.csv -Source center-for-tid

.EXAMPLE
    # Quick analyst entry from prior IR work:
    'CveId,TechniqueId,Confidence,Mapping
CVE-2026-20817,T1068,high,primary
CVE-2026-20817,T1003.001,high,secondary' | Set-Content .\my_map.csv
    .\Update-CveAttackMap.ps1 -Path .\my_map.csv -Source analyst
#>

[CmdletBinding()]
param(
    [string]$Path       = (Join-Path $env:USERPROFILE 'SecIntel\cve_attack_map.csv'),
    [string]$Source     = 'analyst',
    [string]$Confidence = 'medium'
)

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
Ensure-PSSQLite
Initialize-SecIntelSchema

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Path)) {
    Write-Host "Mapping CSV not found: $Path" -ForegroundColor Yellow
    Write-Host "Expected columns: CveId, TechniqueId, Source, Confidence, Mapping" -ForegroundColor DarkGray
    Write-Host "Example row:    CVE-2024-12345,T1059.001,center-for-tid,high,primary" -ForegroundColor DarkGray
    return
}

$rows = Import-Csv -Path $Path
Write-Host "Loaded $($rows.Count) mapping rows from $Path" -ForegroundColor Cyan

# Validate header
$expected = @('CveId','TechniqueId')
$actualCols = $rows | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
foreach ($col in $expected) {
    if ($actualCols -notcontains $col) {
        throw "CSV is missing required column '$col'. Got columns: $($actualCols -join ', ')"
    }
}

$inserted = 0
$skipped  = 0

Invoke-SqliteQuery -DataSource $script:DbPath -Query "BEGIN TRANSACTION"
try {
    foreach ($r in $rows) {
        $cve  = ($r.CveId       -as [string]).Trim()
        $tech = ($r.TechniqueId -as [string]).Trim()
        if (-not $cve -or -not $tech) { $skipped++; continue }

        $src  = if ($r.PSObject.Properties.Match('Source').Count     -and $r.Source)     { $r.Source     } else { $Source     }
        $conf = if ($r.PSObject.Properties.Match('Confidence').Count -and $r.Confidence) { $r.Confidence } else { $Confidence }
        $map  = if ($r.PSObject.Properties.Match('Mapping').Count    -and $r.Mapping)    { $r.Mapping    } else { 'primary'   }

        Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT OR REPLACE INTO CveTechniqueMap (CveId, TechniqueId, Source, Confidence, Mapping)
VALUES (@c, @t, @s, @conf, @map)
"@ -SqlParameters @{ c = $cve; t = $tech; s = $src; conf = $conf; map = $map }
        $inserted++
    }
    Invoke-SqliteQuery -DataSource $script:DbPath -Query "COMMIT"
} catch {
    Invoke-SqliteQuery -DataSource $script:DbPath -Query "ROLLBACK"
    throw
}

Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT OR REPLACE INTO FeedMeta (FeedName, LastUpdated, RecordCount) VALUES ('CveTechniqueMap', @ts, @cnt)
"@ -SqlParameters @{ ts = (Get-Date).ToString('o'); cnt = $inserted }

Write-Host "CVE -> ATT&CK import complete: $inserted upserted, $skipped skipped." -ForegroundColor Green
