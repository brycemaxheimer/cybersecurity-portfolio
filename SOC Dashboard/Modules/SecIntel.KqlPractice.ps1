<#
.SYNOPSIS
    Practice question loader, runner, and grader for the SOC Dashboard.

.DESCRIPTION
    Loads the 30 hand-authored questions and their pre-validated gold
    results out of either:
      1. SOC Dashboard\Data\practice\{questions,gold-results}.json
         (default - ships with the dashboard)
      2. <repo>\lab\practice\{questions,gold-results}.json
         (fallback - shared with the browser practice page)

    Per-question state lives in secintel.db.KqlPracticeState. Submissions
    lock the row (locked-pass / locked-fail) so the analyst can't iterate
    on a question after submitting; "Test Run" leaves state mutable.

    Grading uses the static anchor 2026-04-29T13:52:40Z (gold-results
    metadata - the ADX cluster's logical "now" when the gold was
    generated). Invoke-PracticeQuery sets that anchor on every run so
    `ago()` / `now()` returns the same value as the gold harness.

    Comparison is type-aware: datetimes are formatted as ISO Z with
    second precision before compare; numbers stringify to invariant
    culture; nulls and empty strings are treated equally; arrays /
    objects round-trip through Compress JSON. Ordered questions
    require row-position match; unordered sort both sides first.

.NOTES
    Dot-source SecIntel.Schema.ps1 + SecIntel.KqlLab.ps1 + Invoke-KqlPS.ps1
    first.
#>

. (Join-Path $PSScriptRoot 'SecIntel.Schema.ps1')
. (Join-Path $PSScriptRoot 'SecIntel.KqlLab.ps1')
# Dot-source Invoke-KqlPS at module load so its 2k+ lines of parser /
# evaluator land in the calling script's scope. Lazy-loading inside a
# function would put them in the function scope and they'd vanish on
# return - that bug exists in any earlier draft of this module.
. (Join-Path $PSScriptRoot 'Invoke-KqlPS.ps1')

# ============================================================
# Paths + data caches.
# ============================================================
$script:PracticeAnchor = [datetime]::Parse(
    '2026-04-29T13:52:40Z',
    [cultureinfo]::InvariantCulture,
    [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
    [System.Globalization.DateTimeStyles]::AdjustToUniversal)

$script:PracticeQuestionsCache = $null
$script:PracticeGoldCache      = $null
$script:PracticeKqlCtx         = $null

function Get-PracticeDataFile {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$FileName)
    $candidates = @(
        (Join-Path $PSScriptRoot ('..\Data\practice\' + $FileName))
        (Join-Path $PSScriptRoot ('..\..\lab\practice\' + $FileName))
    )
    foreach ($p in $candidates) {
        $r = Resolve-Path -LiteralPath $p -ErrorAction SilentlyContinue
        if ($r) { return $r.Path }
    }
    throw "Practice data file not found: $FileName (looked in: $($candidates -join '; '))"
}

# ============================================================
# Load + cache the question bank.
# ============================================================
function Get-PracticeQuestions {
    [CmdletBinding()] param([switch]$Refresh)
    if ($Refresh) { $script:PracticeQuestionsCache = $null }
    if ($null -eq $script:PracticeQuestionsCache) {
        $path = Get-PracticeDataFile -FileName 'questions.json'
        # ConvertFrom-Json on a JSON array already emits an Object[]
        # to the pipeline. Wrapping with @() here would re-package it
        # as a 1-element array containing that array, which makes
        # `foreach ($q in Get-PracticeQuestions)` set $q to the inner
        # array (collapsing every $q.<prop> access to Object[]).
        $script:PracticeQuestionsCache = Get-Content -Raw $path | ConvertFrom-Json
    }
    return $script:PracticeQuestionsCache
}

function Get-PracticeGoldResults {
    [CmdletBinding()] param([switch]$Refresh)
    if ($Refresh) { $script:PracticeGoldCache = $null }
    if ($null -eq $script:PracticeGoldCache) {
        $path = Get-PracticeDataFile -FileName 'gold-results.json'
        $script:PracticeGoldCache = Get-Content -Raw $path | ConvertFrom-Json
    }
    return $script:PracticeGoldCache
}

function Get-PracticeQuestion {
    [CmdletBinding()] param([Parameter(Mandatory)][int]$Number)
    foreach ($q in Get-PracticeQuestions) {
        if ([int]$q.number -eq $Number) { return $q }
    }
    return $null
}

function Get-PracticeGoldForQuestion {
    [CmdletBinding()] param([Parameter(Mandatory)][int]$Number)
    $g = Get-PracticeGoldResults
    return $g.questions.([string]$Number)
}

# ============================================================
# Per-question state CRUD against secintel.db.KqlPracticeState.
# ============================================================
function Get-PracticeQuestionState {
    [CmdletBinding()] param([Parameter(Mandatory)][int]$Number)
    $row = Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "SELECT * FROM KqlPracticeState WHERE QuestionNumber=@n" `
        -SqlParameters @{ n = $Number } | Select-Object -First 1
    if (-not $row) {
        return [pscustomobject]@{
            QuestionNumber = $Number
            Status         = 'untouched'
            LastQuery      = $null
            LastScoreJson  = $null
            LastRunAt      = $null
            SubmittedAt    = $null
        }
    }
    return $row
}

function Set-PracticeQuestionState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Number,
        [Parameter(Mandatory)][ValidateSet('untouched','attempted','locked-pass','locked-fail')][string]$Status,
        [string]$Query,
        [string]$ScoreJson,
        [switch]$IsSubmission
    )
    $now = (Get-Date).ToString('o')
    $submittedAt = if ($IsSubmission) { $now } else { $null }
    Invoke-SqliteQuery -DataSource $script:DbPath -Query @"
INSERT INTO KqlPracticeState (QuestionNumber, Status, LastQuery, LastScoreJson, LastRunAt, SubmittedAt)
VALUES (@n, @s, @q, @sj, @r, @sa)
ON CONFLICT(QuestionNumber) DO UPDATE SET
    Status        = excluded.Status,
    LastQuery     = excluded.LastQuery,
    LastScoreJson = excluded.LastScoreJson,
    LastRunAt     = excluded.LastRunAt,
    SubmittedAt   = COALESCE(excluded.SubmittedAt, KqlPracticeState.SubmittedAt)
"@ -SqlParameters @{
        n  = $Number
        s  = $Status
        q  = $Query
        sj = $ScoreJson
        r  = $now
        sa = $submittedAt
    }
}

function Reset-PracticeQuestionState {
    [CmdletBinding()] param([Parameter(Mandatory)][int]$Number)
    Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "DELETE FROM KqlPracticeState WHERE QuestionNumber=@n" `
        -SqlParameters @{ n = $Number }
}

function Get-PracticeProgressSummary {
    [CmdletBinding()] param()
    $rows = Invoke-SqliteQuery -DataSource $script:DbPath `
        -Query "SELECT Status, COUNT(*) AS N FROM KqlPracticeState GROUP BY Status"
    $byStatus = @{
        'untouched'    = 0
        'attempted'    = 0
        'locked-pass'  = 0
        'locked-fail'  = 0
    }
    foreach ($r in $rows) { $byStatus[$r.Status] = [int]$r.N }
    $total  = (Get-PracticeQuestions).Count
    $passed = $byStatus['locked-pass']
    [pscustomobject]@{
        Total       = $total
        Passed      = $passed
        Failed      = $byStatus['locked-fail']
        Attempted   = $byStatus['attempted']
        Untouched   = $total - $byStatus['attempted'] - $byStatus['locked-pass'] - $byStatus['locked-fail']
        ByStatus    = $byStatus
    }
}

# ============================================================
# KQL execution. Lazy-init a single context per session and
# keep it pinned to the practice anchor. The TableCache inside
# the context persists across queries so repeat practice runs
# don't re-stream rows from SQLite.
# ============================================================
function Get-PracticeKqlContext {
    [CmdletBinding()] param([switch]$Refresh)
    if ($Refresh) { $script:PracticeKqlCtx = $null }
    if ($null -eq $script:PracticeKqlCtx) {
        if (-not (Test-Path -LiteralPath $script:KqlLabDbPath)) {
            throw "Lab DB not built: $script:KqlLabDbPath. Run Initialize-KqlLab first."
        }
        $script:PracticeKqlCtx = New-KqlContext `
            -DatabasePath $script:KqlLabDbPath `
            -ReferenceTime $script:PracticeAnchor
    }
    return $script:PracticeKqlCtx
}

function Invoke-PracticeQuery {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Query)
    $ctx = Get-PracticeKqlContext
    # Invoke-Kql already protects its array output with a leading comma.
    # Re-wrapping here would produce a 1-element array containing the
    # row array, which collapses Test-PracticeAnswer's row count to 1.
    return (Invoke-Kql -Context $ctx -Query $Query)
}

# ============================================================
# Cell normalization. Both user output and gold rows go through
# this to produce a stable string representation that can be
# compared verbatim.
#
# DateTime rule: format as 'yyyy-MM-ddTHH:mm:ssZ' UTC, no
# fractional seconds, matching gold-results.json shape.
# ============================================================
function _NormalizePracticeCell {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [System.DBNull]) { return '' }
    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString(
            'yyyy-MM-ddTHH:mm:ssZ',
            [cultureinfo]::InvariantCulture)
    }
    if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
    if ($Value -is [double] -or $Value -is [single]) {
        return ([double]$Value).ToString('R', [cultureinfo]::InvariantCulture)
    }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [int32]) {
        return ([long]$Value).ToString([cultureinfo]::InvariantCulture)
    }
    if ($Value -is [string]) {
        # Gold strings sometimes encode datetimes already; pass
        # them through unchanged. Trim trailing whitespace only.
        return $Value.TrimEnd()
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return ($Value | ConvertTo-Json -Compress -Depth 10)
    }
    if ($Value -is [pscustomobject] -or $Value -is [hashtable]) {
        return ($Value | ConvertTo-Json -Compress -Depth 10)
    }
    return [string]$Value
}

# Convert one user row (PSCustomObject) to a string array in the
# gold's column order. Missing properties become empty strings.
function _ProjectUserRowToGoldCols {
    param($UserRow, [object[]]$GoldColumns)
    $out = New-Object string[] $GoldColumns.Count
    for ($i = 0; $i -lt $GoldColumns.Count; $i++) {
        $name = $GoldColumns[$i].name
        $v = $null
        if ($UserRow -and $UserRow.PSObject -and $UserRow.PSObject.Properties[$name]) {
            $v = $UserRow.$name
        }
        $out[$i] = _NormalizePracticeCell $v
    }
    return ,$out
}

function _ProjectGoldRowToStrings {
    param([object[]]$GoldRow)
    $out = New-Object string[] $GoldRow.Count
    for ($i = 0; $i -lt $GoldRow.Count; $i++) {
        $out[$i] = _NormalizePracticeCell $GoldRow[$i]
    }
    return ,$out
}

# ============================================================
# Grade a user query against the gold contract.
# Returns a verdict object usable as the locked score record.
# ============================================================
function Test-PracticeAnswer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$QuestionNumber,
        [Parameter(Mandatory)][string]$Query
    )

    $gold = Get-PracticeGoldForQuestion -Number $QuestionNumber
    if (-not $gold) {
        throw "No gold result for question $QuestionNumber"
    }

    $verdict = [ordered]@{
        QuestionNumber = $QuestionNumber
        Verdict        = 'fail'
        Reason         = $null
        UserRowCount   = 0
        GoldRowCount   = [int]$gold.rowCount
        ColumnsExpected = @($gold.columns | ForEach-Object { $_.name })
        ColumnsGot     = @()
        FirstMismatch  = $null
        Ordered        = [bool]$gold.ordered
        ExecutionMs    = 0
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $userRows = @(Invoke-PracticeQuery -Query $Query)
    } catch {
        $sw.Stop()
        $verdict.Verdict = 'fail'
        $verdict.Reason  = "Query error: $($_.Exception.Message)"
        $verdict.ExecutionMs = [int]$sw.Elapsed.TotalMilliseconds
        return [pscustomobject]$verdict
    }
    $sw.Stop()
    $verdict.ExecutionMs  = [int]$sw.Elapsed.TotalMilliseconds
    $verdict.UserRowCount = $userRows.Count

    if ($userRows.Count -gt 0) {
        $verdict.ColumnsGot = @($userRows[0].PSObject.Properties.Name)
    }

    if ($userRows.Count -ne [int]$gold.rowCount) {
        $verdict.Reason = "row count mismatch: got $($userRows.Count), expected $($gold.rowCount)"
        return [pscustomobject]$verdict
    }

    # Build normalized matrices.
    $goldRows = @($gold.rows | ForEach-Object { ,(_ProjectGoldRowToStrings -GoldRow $_) })
    $userRowsNorm = @($userRows | ForEach-Object { ,(_ProjectUserRowToGoldCols -UserRow $_ -GoldColumns $gold.columns) })

    if (-not [bool]$gold.ordered) {
        # Sort by joined string for unordered comparison.
        $goldRows     = @($goldRows     | Sort-Object { $_ -join "`t" })
        $userRowsNorm = @($userRowsNorm | Sort-Object { $_ -join "`t" })
    }

    for ($i = 0; $i -lt $goldRows.Count; $i++) {
        $g = $goldRows[$i]
        $u = $userRowsNorm[$i]
        for ($j = 0; $j -lt $g.Count; $j++) {
            if ($g[$j] -ne $u[$j]) {
                $verdict.FirstMismatch = [pscustomobject]@{
                    RowIndex = $i
                    ColumnIndex = $j
                    Column   = $gold.columns[$j].name
                    Got      = $u[$j]
                    Expected = $g[$j]
                }
                $verdict.Reason = "row $($i+1), column '$($gold.columns[$j].name)': got '$($u[$j])', expected '$($g[$j])'"
                return [pscustomobject]$verdict
            }
        }
    }

    $verdict.Verdict = 'pass'
    $verdict.Reason  = 'all rows match gold'
    return [pscustomobject]$verdict
}

# ============================================================
# Format-helpers for the dashboard UI.
# ============================================================
function Format-PracticeVerdict {
    [CmdletBinding()] param([Parameter(Mandatory)]$Verdict)
    $emoji = if ($Verdict.Verdict -eq 'pass') { 'PASS' } else { 'FAIL' }
    $reason = if ($Verdict.Reason) { $Verdict.Reason } else { '' }
    "[{0}] Q{1} - rows {2}/{3} - {4}ms - {5}" -f `
        $emoji,
        $Verdict.QuestionNumber,
        $Verdict.UserRowCount,
        $Verdict.GoldRowCount,
        $Verdict.ExecutionMs,
        $reason
}

# Files are dot-sourced; Export-ModuleMember would fail outside a module context.
