#Requires -Version 7.0
<#
.SYNOPSIS
    Parse and semantically check KQL queries with Microsoft's Kusto.Language.

.DESCRIPTION
    Reads a JSON array of {id, query}, analyzes each query against the table
    schemas in kql_schema.json (Defender XDR / Sentinel), and writes a JSON
    array of {id, ok, diagnostics[]} to stdout.

    Kusto.Language.dll comes from the Microsoft.Azure.Kusto.Language NuGet
    package, downloaded at build time by fetch_kusto_language.ps1. Its license
    does not allow redistribution, so it is never committed.

.EXAMPLE
    pwsh -NoProfile -File tools/validate_kql.ps1 -InputPath queries.json `
        -DllPath .cache/kusto/Kusto.Language.dll -SchemaPath config/kql_schema.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputPath,
    [Parameter(Mandatory)][string]$DllPath,
    [Parameter(Mandatory)][string]$SchemaPath
)

$ErrorActionPreference = 'Stop'
Add-Type -Path (Resolve-Path $DllPath)

$schema = Get-Content -Raw -Path $SchemaPath | ConvertFrom-Json -AsHashtable
$tables = [System.Collections.Generic.List[Kusto.Language.Symbols.Symbol]]::new()
foreach ($name in $schema.Keys) {
    $tables.Add([Kusto.Language.Symbols.TableSymbol]::new($name, [string]$schema[$name]))
}
$db = [Kusto.Language.Symbols.DatabaseSymbol]::new('db', $tables)
$globals = [Kusto.Language.GlobalState]::Default.WithDatabase($db)

$queries = Get-Content -Raw -Path $InputPath | ConvertFrom-Json
$results = foreach ($q in $queries) {
    $code = [Kusto.Language.KustoCode]::ParseAndAnalyze([string]$q.query, $globals)
    $diags = @($code.GetDiagnostics() | Where-Object { $_.Severity -in 'Error', 'Warning' } | ForEach-Object {
            [ordered]@{
                severity = [string]$_.Severity
                code     = [string]$_.Code
                message  = [string]$_.Message
                start    = $_.Start
                length   = $_.Length
            }
        })
    [ordered]@{
        id          = [string]$q.id
        ok          = -not ($diags | Where-Object { $_.severity -eq 'Error' })
        diagnostics = $diags
    }
}
ConvertTo-Json -InputObject @($results) -Depth 5 -Compress
