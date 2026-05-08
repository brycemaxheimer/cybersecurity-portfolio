<#
.SYNOPSIS
    Load a CSV file into a table in kql_lab.db.

.DESCRIPTION
    Conventions
    -----------
    - The CSV header row must use names that match the target table's
      columns (case-sensitive).  Extra columns are ignored with a warning.
      Missing columns become NULL.
    - Empty cells are stored as NULL, not empty string.
    - Booleans accept: true/false, 1/0, yes/no.
    - Datetimes are kept verbatim as TEXT.  Use ISO-8601 like
      '2026-04-29T13:55:02Z' so KQL/ADX can re-parse cleanly.
    - 'dynamic' columns expect a JSON literal.  Invalid JSON is still
      stored, just verbatim.

.PARAMETER Table
    Target table name (case-sensitive).

.PARAMETER CsvPath
    Path to the CSV file to load.

.PARAMETER DatabasePath
    Path to kql_lab.db.  Defaults to alongside this script.

.PARAMETER Truncate
    Empty the table first.  Default is to append.

.EXAMPLE
    .\Import-KqlLabCsv.ps1 -Table SecurityEvent -CsvPath .\samples\SecurityEvent.csv
    .\Import-KqlLabCsv.ps1 -Table DeviceProcessEvents -CsvPath .\samples\DeviceProcessEvents.csv -Truncate
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Table,
    [Parameter(Mandatory)] [string] $CsvPath,
    [string] $DatabasePath = (Join-Path $PSScriptRoot 'kql_lab.db'),
    [switch] $Truncate
)

if (-not (Get-Module -ListAvailable -Name PSSQLite)) {
    throw "PSSQLite module not found.  Run Build-KqlLabDb.ps1 first - it installs it."
}
Import-Module PSSQLite -ErrorAction Stop

if (-not (Test-Path -LiteralPath $DatabasePath)) {
    throw "Database not found: $DatabasePath  (run Build-KqlLabDb.ps1)"
}
if (-not (Test-Path -LiteralPath $CsvPath)) {
    throw "CSV not found: $CsvPath"
}

$boolTrue  = @('true','1','yes','y','t')
$boolFalse = @('false','0','no','n','f')

function Convert-CellValue {
    param(
        [AllowNull()] [string] $Value,
        [string] $SqlType,
        [string] $KqlType
    )
    if ($null -eq $Value) { return $null }
    $v = $Value.Trim()
    if ($v -eq '') { return $null }
    try {
        switch ($KqlType) {
            'bool' {
                $lo = $v.ToLowerInvariant()
                if ($boolTrue  -contains $lo) { return 1 }
                if ($boolFalse -contains $lo) { return 0 }
                return $null
            }
            'dynamic' {
                # Keep as text; users typically supply JSON.
                return $v
            }
            default {
                switch ($SqlType) {
                    'INTEGER' { return [int64]([double]::Parse($v,
                                  [System.Globalization.CultureInfo]::InvariantCulture)) }
                    'REAL'    { return [double]::Parse($v,
                                  [System.Globalization.CultureInfo]::InvariantCulture) }
                    default   { return $v }
                }
            }
        }
    } catch {
        return $null
    }
}

# Pull schema for the requested table.
$schemaRows = Invoke-SqliteQuery -DataSource $DatabasePath `
    -Query 'SELECT col_name, kql_type, sql_type FROM __schema__ WHERE table_name = @t ORDER BY ordinal' `
    -SqlParameters @{ t = $Table }

if (-not $schemaRows) {
    throw "No such table: $Table"
}
$schemaMap = @{}
foreach ($r in $schemaRows) {
    $schemaMap[$r.col_name] = [pscustomobject]@{
        KqlType = $r.kql_type
        SqlType = $r.sql_type
    }
}

# Read CSV header to figure out the recognized vs ignored columns.
# Import-Csv returns objects; we want the first row's property names.
$rows = Import-Csv -LiteralPath $CsvPath
if (-not $rows) {
    Write-Host "CSV is empty (no data rows).  Nothing to load."
    return
}
$headers    = $rows[0].psobject.Properties.Name
$recognized = @($headers | Where-Object { $schemaMap.ContainsKey($_) })
$ignored    = @($headers | Where-Object { -not $schemaMap.ContainsKey($_) })

if ($ignored.Count -gt 0) {
    Write-Warning ("Ignoring unknown CSV columns: " + ($ignored -join ', '))
}
if ($recognized.Count -eq 0) {
    throw "No CSV columns match table $Table"
}

# Open one connection, batch in a transaction for speed.
$conn = New-SQLiteConnection -DataSource $DatabasePath
try {
    if ($Truncate) {
        Invoke-SqliteQuery -SQLiteConnection $conn -Query "DELETE FROM `"$Table`";"
    }

    $colList     = ($recognized | ForEach-Object { '"' + $_ + '"' }) -join ', '
    $paramNames  = ($recognized | ForEach-Object { '@' + ($_ -replace '\W','_') })
    $placeholders = $paramNames -join ', '
    $insertSql   = "INSERT INTO `"$Table`" ($colList) VALUES ($placeholders);"

    Invoke-SqliteQuery -SQLiteConnection $conn -Query 'BEGIN TRANSACTION;'
    $count = 0
    foreach ($row in $rows) {
        $params = @{}
        for ($i = 0; $i -lt $recognized.Count; $i++) {
            $colName  = $recognized[$i]
            $paramKey = ($colName -replace '\W','_')
            $type     = $schemaMap[$colName]
            $params[$paramKey] = Convert-CellValue -Value $row.$colName `
                -SqlType $type.SqlType -KqlType $type.KqlType
        }
        Invoke-SqliteQuery -SQLiteConnection $conn -Query $insertSql `
            -SqlParameters $params | Out-Null
        $count++
    }
    Invoke-SqliteQuery -SQLiteConnection $conn -Query 'COMMIT;'

    Write-Host "Loaded $count rows into $Table from $(Split-Path -Leaf $CsvPath)"
} catch {
    Invoke-SqliteQuery -SQLiteConnection $conn -Query 'ROLLBACK;' -ErrorAction SilentlyContinue
    throw
} finally {
    $conn.Close()
    $conn.Dispose()
}