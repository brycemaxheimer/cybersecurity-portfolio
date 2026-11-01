#Requires -Version 7.0
<#
.SYNOPSIS
    Download Microsoft.Azure.Kusto.Language from nuget.org at build time.

.DESCRIPTION
    The package license does not allow redistribution, so the DLL is fetched
    here, checked against the SHA-512 that nuget.org publishes for it
    (catalog "packageHash"), and extracted to .cache/kusto/Kusto.Language.dll
    (gitignored). It is never committed.
#>
[CmdletBinding()]
param(
    [string]$Version = '12.4.1',
    # packageHash (SHA-512, base64) from the nuget.org catalog entry. Update both together.
    [string]$Sha512Base64 = 'g/g/N/Co7MtUcx/4uk86BLHapY8dJ4HI7ci4kJ3fMCUsm3ymDtcmlZAdAPbnXtleG4ffNXmV5/kWDRLwtM15hQ==',
    [string]$OutDir = (Join-Path $PSScriptRoot '..' '.cache' 'kusto')
)

$ErrorActionPreference = 'Stop'
$dll = Join-Path $OutDir 'Kusto.Language.dll'
if (Test-Path $dll) {
    Write-Host "Kusto.Language already present: $dll"
    return
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$id = 'microsoft.azure.kusto.language'
$url = "https://api.nuget.org/v3-flatcontainer/$id/$Version/$id.$Version.nupkg"
$pkg = Join-Path $OutDir "$id.$Version.nupkg"

Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $pkg -UseBasicParsing

$hex = (Get-FileHash -Algorithm SHA512 -Path $pkg).Hash
$actual = [Convert]::ToBase64String([Convert]::FromHexString($hex))
if ($actual -ne $Sha512Base64) {
    Remove-Item $pkg -Force
    throw "SHA-512 mismatch for $id $Version. Expected $Sha512Base64, got $actual."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($pkg)
try {
    $entry = $zip.Entries | Where-Object { $_.FullName -eq 'lib/netstandard2.0/Kusto.Language.dll' } | Select-Object -First 1
    if (-not $entry) { throw 'lib/netstandard2.0/Kusto.Language.dll not found in package' }
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dll, $true)
}
finally {
    $zip.Dispose()
}
Remove-Item $pkg -Force
Write-Host "Extracted $dll"
