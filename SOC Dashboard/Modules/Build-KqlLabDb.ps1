<#
.SYNOPSIS
    Builds a SQLite database whose tables mirror the Microsoft Sentinel /
    Log Analytics common table schemas described in CommonTableSchema.txt.

.DESCRIPTION
    Why SQLite for KQL practice?
    SQLite cannot natively execute KQL.  This database lets you:
      1. Stage realistic test rows in tables that match the production
         schemas exactly (column names + KQL-derived types).
      2. Sanity-check CSV row shapes before pushing to a real Kusto/ADX
         cluster, the Sentinel demo workspace, or an ADX-Free instance.
      3. Optionally translate KQL queries to ANSI SQL to verify logic.

    For real KQL execution against this same data, point your queries at:
      - https://aka.ms/LADemo       (Sentinel/Log Analytics demo workspace)
      - https://aka.ms/kustofree    (Azure Data Explorer Free cluster -
                                     load your own CSVs and run native KQL)

    Requires the PSSQLite module.  Installed automatically to the
    CurrentUser scope; no admin rights needed.

.PARAMETER SchemaPath
    Path to CommonTableSchema.txt.  Defaults to alongside this script.

.PARAMETER DatabasePath
    Path to the .db file to create.  Defaults to alongside this script.

.PARAMETER Force
    Overwrite an existing database without prompting.

.EXAMPLE
    .\Build-KqlLabDb.ps1
    .\Build-KqlLabDb.ps1 -Force
    .\Build-KqlLabDb.ps1 -SchemaPath .\CommonTableSchema.txt -DatabasePath .\kql_lab.db
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $SchemaPath   = (Join-Path $PSScriptRoot 'CommonTableSchema.txt'),
    [string] $DatabasePath = (Join-Path $PSScriptRoot 'kql_lab.db'),
    [switch] $Force
)

# ---------------------------------------------------------------------------
# Module bootstrap.  PSSQLite installs cleanly into CurrentUser scope.
# ---------------------------------------------------------------------------
function Initialize-PSSQLite {
    if (Get-Module -ListAvailable -Name PSSQLite) {
        Import-Module PSSQLite -ErrorAction Stop
        return
    }
    Write-Host 'PSSQLite module not found - installing into CurrentUser scope...'

    # TLS 1.2 is required by PowerShell Gallery on older Windows PowerShell.
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }

    # Ensure the gallery is reachable; trust it for the install only.
    $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if ($null -ne $repo -and $repo.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    }

    Install-Module -Name PSSQLite -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    Import-Module PSSQLite -ErrorAction Stop
}

# ---------------------------------------------------------------------------
# KQL type -> SQLite affinity.  SQLite is loosely typed but the affinity
# still drives indexing decisions and reads cleanly in tooling.
# ---------------------------------------------------------------------------
$script:KqlToSqlite = @{
    'string'   = 'TEXT'
    'int'      = 'INTEGER'
    'long'     = 'INTEGER'
    'real'     = 'REAL'
    'bool'     = 'INTEGER'   # 0/1
    'datetime' = 'TEXT'      # ISO-8601 strings
    'dynamic'  = 'TEXT'      # JSON-encoded
}

function ConvertTo-SqliteType { param([string] $KqlType)
    if ($script:KqlToSqlite.ContainsKey($KqlType)) {
        return $script:KqlToSqlite[$KqlType]
    }
    return 'TEXT'
}

# ---------------------------------------------------------------------------
# Schema parser.  One table per line, format:
#   TableName <whitespace> - col1:type1, col2:type2, ...
# ---------------------------------------------------------------------------
function Get-TableDefinitions { param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Schema file not found: $Path"
    }

    $defs = New-Object System.Collections.Generic.List[object]
    foreach ($line in Get-Content -LiteralPath $Path) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $dashIdx = $line.IndexOf('-')
        if ($dashIdx -lt 1) { continue }

        $tableName = $line.Substring(0, $dashIdx).Trim()
        $tail      = $line.Substring($dashIdx + 1)
        if ([string]::IsNullOrWhiteSpace($tableName)) { continue }

        $cols = New-Object System.Collections.Generic.List[object]
        foreach ($raw in $tail.Split(',')) {
            $raw = $raw.Trim()
            if (-not $raw -or -not $raw.Contains(':')) { continue }
            $colonIdx = $raw.LastIndexOf(':')
            $colName  = $raw.Substring(0, $colonIdx).Trim()
            $colKql   = $raw.Substring($colonIdx + 1).Trim()
            $cols.Add([pscustomobject]@{
                Name     = $colName
                KqlType  = $colKql
                SqlType  = ConvertTo-SqliteType $colKql
            })
        }
        if ($cols.Count -gt 0) {
            $defs.Add([pscustomobject]@{
                Name    = $tableName
                Columns = $cols
            })
        }
    }
    return $defs
}

# ---------------------------------------------------------------------------
# Build.
# ---------------------------------------------------------------------------
Initialize-PSSQLite

if (Test-Path -LiteralPath $DatabasePath) {
    if (-not $Force) {
        $resp = Read-Host "Database '$DatabasePath' exists.  Overwrite? [y/N]"
        if ($resp -notmatch '^(y|yes)$') {
            Write-Host 'Aborted.'
            return
        }
    }
    if ($PSCmdlet.ShouldProcess($DatabasePath, 'Remove-Item')) {
        Remove-Item -LiteralPath $DatabasePath -Force
    }
}

# Open one connection for the entire build.  Faster, and avoids the
# file-create race when multiple Invoke-SqliteQuery calls hit a missing file.
$conn = New-SQLiteConnection -DataSource $DatabasePath

try {
    # __schema__ is metadata used by Import-KqlLabCsv.ps1 to coerce types.
    Invoke-SqliteQuery -SQLiteConnection $conn -Query @"
CREATE TABLE __schema__ (
    table_name TEXT NOT NULL,
    col_name   TEXT NOT NULL,
    kql_type   TEXT NOT NULL,
    sql_type   TEXT NOT NULL,
    ordinal    INTEGER NOT NULL,
    PRIMARY KEY (table_name, col_name)
);
"@

    $tables   = Get-TableDefinitions -Path $SchemaPath
    $colTotal = 0
    $pivots   = @('Computer','DeviceName','Account','AccountName',
                  'UserPrincipalName','EventID','ActionType')

    Invoke-SqliteQuery -SQLiteConnection $conn -Query 'BEGIN TRANSACTION;'
    foreach ($t in $tables) {
        $colDefs = ($t.Columns | ForEach-Object {
            '"' + $_.Name + '" ' + $_.SqlType
        }) -join ",`n    "

        $ddl = "CREATE TABLE `"$($t.Name)`" (`n    $colDefs`n);"
        Invoke-SqliteQuery -SQLiteConnection $conn -Query $ddl

        $names = $t.Columns | ForEach-Object { $_.Name }
        if ($names -contains 'TimeGenerated') {
            Invoke-SqliteQuery -SQLiteConnection $conn -Query `
                "CREATE INDEX `"ix_$($t.Name)_time`" ON `"$($t.Name)`" (`"TimeGenerated`");"
        }
        foreach ($p in $pivots) {
            if ($names -contains $p) {
                Invoke-SqliteQuery -SQLiteConnection $conn -Query `
                    "CREATE INDEX `"ix_$($t.Name)_$p`" ON `"$($t.Name)`" (`"$p`");"
            }
        }

        $ordinal = 0
        foreach ($c in $t.Columns) {
            Invoke-SqliteQuery -SQLiteConnection $conn `
                -Query 'INSERT INTO __schema__ VALUES (@t,@c,@k,@s,@o);' `
                -SqlParameters @{
                    t = $t.Name; c = $c.Name; k = $c.KqlType
                    s = $c.SqlType; o = $ordinal
                } | Out-Null
            $ordinal++
        }
        $colTotal += $t.Columns.Count
        Write-Host ('  + {0,-22}  ({1} cols)' -f $t.Name, $t.Columns.Count)
    }
    Invoke-SqliteQuery -SQLiteConnection $conn -Query 'COMMIT;'

    Write-Host ''
    Write-Host ("Created $DatabasePath with $($tables.Count) tables and $colTotal columns.")
} finally {
    $conn.Close()
    $conn.Dispose()
}

# SIG # Begin signature block
# MIIcCwYJKoZIhvcNAQcCoIIb/DCCG/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDHU+jPDCK5WuTR
# qWApA0fRrA8izb8iyEdC1JDt5HZDIqCCFlAwggMSMIIB+qADAgECAhAtZQe+Ow97
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
# FTAvBgkqhkiG9w0BCQQxIgQgzr9iAp/KqOsK+JceIg2J1JkciolokuQ8nVca28Hx
# PcAwDQYJKoZIhvcNAQEBBQAEggEAZYbDGeDSm4AkIjzACuqCSr+CHVk1wfh/c1bM
# 4y/PtuhZ2m1Cz69mNhhKnqB+wo99Oq6zfm/9WviOzAen4m7cQLzUCDNVOIK1v/3H
# cbcifmXk8wEykBaeC/1YeMUkcHUDJUW65EcZOFuZfQtK7fZz+e1hiChmocxOoDkG
# V2lWqqgMsPH6HNpCFvAzpC53Adhm1qUuzGdXp+YppNPOfnXWZwGk0gIcSRgWq8kJ
# 1XOIczlvv0lniS+h0i8d0WgiOyRWWCXZLzZR5Urndja07VGjh+8Q7ZhAve9Ym2JU
# 2KEO/HeMAD398+/IgU0/jeWwGXLTsaNLt48VGiUwQX0w4OccmaGCAyYwggMiBgkq
# hkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeV
# dGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0yNjA0MjkxNzI5MjZaMC8GCSqGSIb3DQEJBDEiBCDk86M3
# IyeP3tUahULXLw4df5qlA0sVWJNVFVTm6tqT/jANBgkqhkiG9w0BAQEFAASCAgA0
# JlgZbzgCMf/tEuzUYIYztmTiwjJojIif+QHU8ZSdfo9oBq53i+0vH2huzjfkE8Ke
# qOLnCo13G+zwX9J3bSC1rok+CvVWWzf7tEAzWv6DoIZwFHK1yF5D5AiQPaPy95HN
# ggVz5bPlo6PxZ96jnQQpuby3Nk2YvnID4KrKKGq2xAN0NFz87utQrGO9txiK/7Rf
# CnAeEUKWcj/YqH0sbmSdBcho2/t3Neb6IG7vImlZjVY9f5CNNiSR5JP53OoTL4VG
# Ah/cRY4fHbcZHL7i3tvShEpWp7FmKG55Q5uETUWbfHXckjKgdSaC6ytq7svxbhsE
# Ka5QyacIqm5Zh2u3jgXLebnxu932BtPIVcSa6D6cv8yVGLnbOzW9BnyEeO5jD/HZ
# P/UD5akR2EL6Ha6c/4Ms0Y4aQ/oStojo/i2hWH8Acvqde6VA2MW/rWsjKyabGN0+
# uNC5oM8o1PnCuhxOMQPloaCljfA7S9g4tIVAhbcR0Qkz6TV2Mn8asbYsfLt8xVlY
# zniYAohnidP8VRvyx6orCTb99k4zTspTM5bboO/jtyPUyqT8QnH2ECACMMhRip65
# rVzOv8oVzLOcqLIHXpn5mrVbXdRfCD5TYsFcc37opu6dNKJf8J9CRJKClfT8uRjF
# dwcNR/UiD3/BUAXZaYuCrkf0VHFo8HhCgdn1+TG7xA==
# SIG # End signature block
