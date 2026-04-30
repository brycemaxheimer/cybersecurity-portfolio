<#
.SYNOPSIS
    Local settings store for SecIntel: DPAPI-protected secrets, plain
    preferences, and Watchlists CRUD.

.DESCRIPTION
    Settings live in the AppSettings table. Secrets (API keys) are
    encrypted with the Windows Data Protection API (CurrentUser scope) so
    they're tied to your Windows profile - file moves to other machines
    will not leak them.

    Functions:
        Set-AppSetting / Get-AppSetting / Remove-AppSetting
        Set-AppSecret  / Get-AppSecret    (DPAPI wrappers)
        New-Watchlist  / Get-Watchlist    / Remove-Watchlist
        Add-WatchlistItem / Remove-WatchlistItem / Get-WatchlistItems
        Get-WatchlistAsKqlDatatable       (emit `let X = datatable(...)`)

.NOTES
    PowerShell 5.1+. Dot-source SecIntel.Schema.ps1 first.
#>

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')

Add-Type -AssemblyName System.Security

# ============================================================
# DPAPI helpers (CurrentUser scope - tied to Windows profile)
# ============================================================
function Protect-DpapiString {
    param([Parameter(Mandatory)][string]$Plain)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Plain)
    $enc   = [System.Security.Cryptography.ProtectedData]::Protect(
                $bytes, $null,
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [Convert]::ToBase64String($enc)
}

function Unprotect-DpapiString {
    param([Parameter(Mandatory)][string]$Cipher)
    try {
        $enc   = [Convert]::FromBase64String($Cipher)
        $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
                    $enc, $null,
                    [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    } catch {
        Write-Warning "DPAPI decryption failed for cipher: $_"
        return $null
    }
}

# ============================================================
# AppSettings CRUD
# ============================================================
function Set-AppSetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT OR REPLACE INTO AppSettings (Name, Value, IsSecret, Updated) VALUES (@n,@v,0,@u)
"@ -SqlParameters @{ n=$Name; v=$Value; u=(Get-Date).ToString('o') }
}

function Get-AppSetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Default = $null
    )
    $r = Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "SELECT Value, IsSecret FROM AppSettings WHERE Name=@n" `
        -SqlParameters @{ n=$Name } | Select-Object -First 1
    if (-not $r) { return $Default }
    if ([int]$r.IsSecret -eq 1) { return Unprotect-DpapiString $r.Value }
    return $r.Value
}

function Remove-AppSetting {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    Invoke-SqliteQuery -DataSource $script:DbPath -Query "DELETE FROM AppSettings WHERE Name=@n" `
        -SqlParameters @{ n=$Name }
}

function Set-AppSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    $enc = Protect-DpapiString $Value
    Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT OR REPLACE INTO AppSettings (Name, Value, IsSecret, Updated) VALUES (@n,@v,1,@u)
"@ -SqlParameters @{ n=$Name; v=$enc; u=(Get-Date).ToString('o') }
}

function Get-AppSecret {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    $r = Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "SELECT Value, IsSecret FROM AppSettings WHERE Name=@n" `
        -SqlParameters @{ n=$Name } | Select-Object -First 1
    if (-not $r -or [int]$r.IsSecret -ne 1) { return $null }
    return Unprotect-DpapiString $r.Value
}

# ============================================================
# Watchlists CRUD
# ============================================================
function New-Watchlist {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$ItemType    = 'generic',
        [string]$Description = ''
    )
    $now = (Get-Date).ToString('o')
    Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT OR REPLACE INTO Watchlists (Name, ItemType, Description, Created, LastModified)
VALUES (@n,@t,@d,@c,@m)
"@ -SqlParameters @{ n=$Name; t=$ItemType; d=$Description; c=$now; m=$now }
    return [int](Invoke-SqliteQuery -DataSource $script:DbPath -Query "SELECT last_insert_rowid() AS Id").Id
}

function Get-Watchlist {
    [CmdletBinding()]
    param([string]$Name)
    if ($Name) {
        return Invoke-SqliteQuery -DataSource $script:DbPath `
            -Query "SELECT * FROM Watchlists WHERE Name=@n" `
            -SqlParameters @{ n=$Name } | Select-Object -First 1
    }
    return Invoke-SqliteQuery -DataSource $script:DbPath -Query "SELECT * FROM Watchlists ORDER BY Name"
}

function Remove-Watchlist {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    $wl = Get-Watchlist -Name $Name
    if (-not $wl) { return }
    Invoke-SqliteQuery -DataSource $script:DbPath -Query "DELETE FROM WatchlistItems WHERE WatchlistId=@id" -SqlParameters @{ id=$wl.WatchlistId }
    Invoke-SqliteQuery -DataSource $script:DbPath -Query "DELETE FROM Watchlists     WHERE WatchlistId=@id" -SqlParameters @{ id=$wl.WatchlistId }
}

function Get-WatchlistItems {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    $wl = Get-Watchlist -Name $Name
    if (-not $wl) { return @() }
    return Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "SELECT Value, Note, AddedAt FROM WatchlistItems WHERE WatchlistId=@id ORDER BY Value" `
        -SqlParameters @{ id = $wl.WatchlistId }
}

function Add-WatchlistItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value,
        [string]$Note = ''
    )
    $wl = Get-Watchlist -Name $Name
    if (-not $wl) { throw "Watchlist '$Name' not found. Create it with New-Watchlist first." }
    $now = (Get-Date).ToString('o')
    Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT OR REPLACE INTO WatchlistItems (WatchlistId, Value, Note, AddedAt) VALUES (@w,@v,@n,@a)
"@ -SqlParameters @{ w=$wl.WatchlistId; v=$Value; n=$Note; a=$now }
    Invoke-SqliteQuery -DataSource $script:DbPath -Query "UPDATE Watchlists SET LastModified=@m WHERE WatchlistId=@id" -SqlParameters @{ m=$now; id=$wl.WatchlistId }
}

function Remove-WatchlistItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    $wl = Get-Watchlist -Name $Name
    if (-not $wl) { return }
    Invoke-SqliteQuery -DataSource $script:DbPath -Query "DELETE FROM WatchlistItems WHERE WatchlistId=@w AND Value=@v" `
        -SqlParameters @{ w=$wl.WatchlistId; v=$Value }
}

# ============================================================
# Emit a Watchlist as a KQL `let X = datatable(...)` block.
# Pastes directly into KQL Builder output.
# ============================================================
function Get-WatchlistAsKqlDatatable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$VarName    = $null,
        [string]$ColumnName = 'Value'
    )
    $items = Get-WatchlistItems -Name $Name
    if (-not $items) { return "// Watchlist '$Name' is empty" }

    $vname = if ($VarName) { $VarName } else { (($Name -replace '[^A-Za-z0-9]','') + 'List') }
    $literals = $items | ForEach-Object {
        '"' + ($_.Value -replace '\\','\\' -replace '"','\"') + '"'
    }
    return "let $vname = datatable($($ColumnName):string) [`n    $([string]::Join(",`n    ", $literals))`n];"
}
