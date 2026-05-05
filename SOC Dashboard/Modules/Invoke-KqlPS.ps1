<#
.SYNOPSIS
    A scoped Kusto Query Language (KQL) interpreter in pure PowerShell.

.DESCRIPTION
    Loads tables from kql_lab.db (or any SQLite DB whose schema lives in a
    `__schema__` table) and executes a subset of KQL natively against rows
    held in memory as [PSCustomObject[]].

    Mental model matches the KQL guide exactly: every operator is a function
    that takes a table and returns a new table.  The pipe character `|`
    chains them.  Each step's output is the next step's input.

    Supported tabular operators
    ---------------------------
    take, limit, top, where, project, project-keep, project-rename,
    project-away, extend, summarize ... by ..., order by / sort by,
    distinct, union, join kind=inner|leftouter|leftanti|innerunique,
    parse with, mv-expand, materialize (passthrough), getschema, render
    (passthrough).

    Supported scalar functions
    --------------------------
    ago, now, bin, datetime, todatetime, format_datetime, datetime_part,
    count, countif, dcount, min, max, sum, avg, arg_max, make_set,
    make_list, take_any, iff, iif, case, tostring, toint, toreal,
    tolower, toupper, strlen, substring, isempty, isnotempty, isnull,
    isnotnull, replace_string, split, extract, extract_all, parse_json,
    dynamic, array_length, array_index_of, indexof, startswith, endswith,
    contains, has, has_any, has_all, strcat, trim, isnotempty.

    Supported operators
    -------------------
    ==, !=, <, >, <=, >=, =~, !~, has, has_cs, has_any, has_all,
    contains, contains_cs, startswith, endswith, !endswith, !startswith,
    !contains, !has, matches regex, in, !in, in~, between (a..b),
    !between, and, or, +, -, *, /, %.

    Out of scope (raises a clear error)
    -----------------------------------
    mv-apply, evaluate bag_unpack, series_*, user-defined functions
    with parameters, external_table.

.EXAMPLE
    # One-liner against the lab DB
    Import-Module .\Invoke-KqlPS.ps1 -Force
    $ctx = New-KqlContext -DatabasePath .\kql_lab.db
    Invoke-Kql -Context $ctx -Query 'SecurityEvent | where EventID == 4625 | take 5'

.EXAMPLE
    # Multi-line query with let
    Invoke-Kql -Context $ctx -Query @'
        let SuspiciousTools = dynamic(["mimikatz", "rubeus"]);
        DeviceProcessEvents
        | where TimeGenerated > ago(24h)
        | where ProcessCommandLine has_any (SuspiciousTools)
        | project TimeGenerated, DeviceName, FileName
    '@ | Format-Table

.NOTES
    The "current time" anchor for ago()/now() is set when the context is
    created and frozen for the session.  This keeps queries reproducible
    against the static sample data, where TimeGenerated is set relative
    to 2026-04-29T14:00:00Z.  Override with -ReferenceTime on
    New-KqlContext, or call Set-KqlReferenceTime later.
#>

# Set strict mode disabled - we work with sparse PSObjects where many
# properties are absent.  Strict mode 2/3 raises on missing properties.
Set-StrictMode -Off

# =====================================================================
# SECTION 1 - Lexer
# =====================================================================
#
# Tokens produced (each token is a [pscustomobject] with Kind / Value /
# Pos):
#   IDENT       a bareword that is not a reserved keyword
#   STRING      string literal (raw or escaped)
#   NUMBER      integer or floating point
#   DURATION    1h, 5m, 30s, 7d, 200ms - value is a [TimeSpan]
#   PIPE        |
#   COMMA       ,
#   SEMI        ;
#   LPAREN      (
#   RPAREN      )
#   LBRACK      [
#   RBRACK      ]
#   LBRACE      {
#   RBRACE      }
#   DOT         .
#   RANGE       ..
#   ASSIGN      =
#   OP          a comparison/string operator (==, !=, =~, has, etc.)
#   KEYWORD     reserved word: where, project, summarize, by, order, ...
#
# Error rule: unknown character → throw with position context.
# ---------------------------------------------------------------------

$script:KqlKeywords = @(
    'where','project','project-keep','project-rename','project-away',
    'project-reorder','extend','summarize','by','order','sort','asc',
    'desc','take','limit','top','distinct','union','join','kind','on',
    'let','parse','with','mv-expand','mv-apply','getschema','materialize',
    'render','between','and','or','not','true','false','null','dynamic',
    'matches','regex','in','print'
)

# Multi-character operators sorted longest-first so the lexer matches
# the longest variant.  '!endswith' must be tried before 'endswith' etc.
$script:KqlOperators = @(
    '!endswith','!startswith','!contains','!has','!between','!in~','!in',
    '==','!=','<=','>=','=~','!~','&&','||',
    '..','<','>','+','-','*','/','%'
)

# Word-form operators that appear inside expressions.  The lexer leaves
# these as IDENT and the parser disambiguates them by position.
$script:KqlWordOps = @(
    'has','has_cs','has_any','has_all','contains','contains_cs',
    'startswith','endswith','in','in~','between','matches'
)

function Get-KqlTokens {
    [CmdletBinding()]
    param([string] $Query)

    $tokens = New-Object System.Collections.Generic.List[object]
    $i      = 0
    $n      = $Query.Length

    while ($i -lt $n) {
        $c = $Query[$i]

        # --- whitespace / line endings ---
        if ([char]::IsWhiteSpace($c)) { $i++; continue }

        # --- comment '// ...' to end of line ---
        if ($c -eq '/' -and ($i + 1) -lt $n -and $Query[$i + 1] -eq '/') {
            while ($i -lt $n -and $Query[$i] -ne "`n") { $i++ }
            continue
        }

        # --- raw string '@"..."' ---
        if ($c -eq '@' -and ($i + 1) -lt $n -and $Query[$i + 1] -eq '"') {
            $start = $i; $i += 2
            $sb = [System.Text.StringBuilder]::new()
            while ($i -lt $n -and $Query[$i] -ne '"') {
                [void]$sb.Append($Query[$i]); $i++
            }
            if ($i -ge $n) { throw "Unterminated raw string at position $start" }
            $i++   # consume closing quote
            $tokens.Add([pscustomobject]@{ Kind='STRING'; Value=$sb.ToString(); Pos=$start; Raw=$true })
            continue
        }

        # --- regular string '"..."' with backslash escapes ---
        if ($c -eq '"' -or $c -eq "'") {
            $quote = $c
            $start = $i; $i++
            $sb = [System.Text.StringBuilder]::new()
            while ($i -lt $n -and $Query[$i] -ne $quote) {
                if ($Query[$i] -eq '\' -and ($i + 1) -lt $n) {
                    $esc = $Query[$i + 1]
                    switch ($esc) {
                        'n'      { [void]$sb.Append("`n") }
                        't'      { [void]$sb.Append("`t") }
                        'r'      { [void]$sb.Append("`r") }
                        '\'      { [void]$sb.Append('\') }
                        '"'      { [void]$sb.Append('"') }
                        "'"      { [void]$sb.Append("'") }
                        default  { [void]$sb.Append($esc) }
                    }
                    $i += 2
                } else {
                    [void]$sb.Append($Query[$i]); $i++
                }
            }
            if ($i -ge $n) { throw "Unterminated string at position $start" }
            $i++   # consume closing quote
            $tokens.Add([pscustomobject]@{ Kind='STRING'; Value=$sb.ToString(); Pos=$start; Raw=$false })
            continue
        }

        # --- number, possibly followed by a duration unit ---
        if ([char]::IsDigit($c) -or
            ($c -eq '-' -and ($i + 1) -lt $n -and [char]::IsDigit($Query[$i + 1]) -and
             ($tokens.Count -eq 0 -or $tokens[$tokens.Count - 1].Kind -in @('OP','PIPE','COMMA','LPAREN','LBRACK','ASSIGN','KEYWORD')))) {
            $start = $i
            if ($Query[$i] -eq '-') { $i++ }
            while ($i -lt $n -and ([char]::IsDigit($Query[$i]) -or $Query[$i] -eq '.')) {
                # Stop at '..' range operator, never include it as part of a number.
                if ($Query[$i] -eq '.' -and ($i + 1) -lt $n -and $Query[$i + 1] -eq '.') { break }
                $i++
            }
            $numStr = $Query.Substring($start, $i - $start)
            # Try to attach a duration unit.  Order matters: 'ms' before 'm'.
            $unit = $null
            foreach ($u in @('microseconds','milliseconds','seconds','minutes','hours','days',
                             'tick','ticks','d','h','m','s','ms')) {
                if ($i + $u.Length -le $n) {
                    $candidate = $Query.Substring($i, $u.Length)
                    if ($candidate -ceq $u) {
                        # ensure followed by non-identifier char
                        $next = if ($i + $u.Length -lt $n) { $Query[$i + $u.Length] } else { ' ' }
                        if (-not ([char]::IsLetterOrDigit($next) -or $next -eq '_')) {
                            $unit = $u; $i += $u.Length; break
                        }
                    }
                }
            }
            if ($unit) {
                $val = [double]::Parse($numStr, [System.Globalization.CultureInfo]::InvariantCulture)
                $ts  = switch ($unit) {
                    'd'            { [TimeSpan]::FromDays($val) }
                    'days'         { [TimeSpan]::FromDays($val) }
                    'h'            { [TimeSpan]::FromHours($val) }
                    'hours'        { [TimeSpan]::FromHours($val) }
                    'm'            { [TimeSpan]::FromMinutes($val) }
                    'minutes'      { [TimeSpan]::FromMinutes($val) }
                    's'            { [TimeSpan]::FromSeconds($val) }
                    'seconds'      { [TimeSpan]::FromSeconds($val) }
                    'ms'           { [TimeSpan]::FromMilliseconds($val) }
                    'milliseconds' { [TimeSpan]::FromMilliseconds($val) }
                    'microseconds' { [TimeSpan]::FromTicks([long]($val * 10)) }
                    'tick'         { [TimeSpan]::FromTicks([long]$val) }
                    'ticks'        { [TimeSpan]::FromTicks([long]$val) }
                }
                $tokens.Add([pscustomobject]@{ Kind='DURATION'; Value=$ts; Pos=$start })
            } else {
                # Numeric literal
                if ($numStr.Contains('.')) {
                    $val = [double]::Parse($numStr, [System.Globalization.CultureInfo]::InvariantCulture)
                } else {
                    $val = [long]::Parse($numStr, [System.Globalization.CultureInfo]::InvariantCulture)
                }
                $tokens.Add([pscustomobject]@{ Kind='NUMBER'; Value=$val; Pos=$start })
            }
            continue
        }

        # --- multi-char operators ---
        $matched = $false
        foreach ($op in $script:KqlOperators) {
            $L = $op.Length
            if ($i + $L -le $n -and $Query.Substring($i, $L) -ceq $op) {
                if ($op -eq '..') {
                    $tokens.Add([pscustomobject]@{ Kind='RANGE'; Value='..'; Pos=$i })
                } else {
                    $tokens.Add([pscustomobject]@{ Kind='OP'; Value=$op; Pos=$i })
                }
                $i += $L; $matched = $true; break
            }
        }
        if ($matched) { continue }

        # --- single-char punctuation ---
        # NB: `continue` inside a `switch` block in PS does NOT continue the
        # surrounding while loop, so we use an if/elseif chain instead.
        $puncMatched = $false
        if     ($c -eq '|') { $tokens.Add([pscustomobject]@{ Kind='PIPE';   Value='|'; Pos=$i }); $i++; $puncMatched=$true }
        elseif ($c -eq ',') { $tokens.Add([pscustomobject]@{ Kind='COMMA';  Value=','; Pos=$i }); $i++; $puncMatched=$true }
        elseif ($c -eq ';') { $tokens.Add([pscustomobject]@{ Kind='SEMI';   Value=';'; Pos=$i }); $i++; $puncMatched=$true }
        elseif ($c -eq '(') { $tokens.Add([pscustomobject]@{ Kind='LPAREN'; Value='('; Pos=$i }); $i++; $puncMatched=$true }
        elseif ($c -eq ')') { $tokens.Add([pscustomobject]@{ Kind='RPAREN'; Value=')'; Pos=$i }); $i++; $puncMatched=$true }
        elseif ($c -eq '[') { $tokens.Add([pscustomobject]@{ Kind='LBRACK'; Value='['; Pos=$i }); $i++; $puncMatched=$true }
        elseif ($c -eq ']') { $tokens.Add([pscustomobject]@{ Kind='RBRACK'; Value=']'; Pos=$i }); $i++; $puncMatched=$true }
        elseif ($c -eq '{') { $tokens.Add([pscustomobject]@{ Kind='LBRACE'; Value='{'; Pos=$i }); $i++; $puncMatched=$true }
        elseif ($c -eq '}') { $tokens.Add([pscustomobject]@{ Kind='RBRACE'; Value='}'; Pos=$i }); $i++; $puncMatched=$true }
        elseif ($c -eq '.') { $tokens.Add([pscustomobject]@{ Kind='DOT';    Value='.'; Pos=$i }); $i++; $puncMatched=$true }
        elseif ($c -eq '=') { $tokens.Add([pscustomobject]@{ Kind='ASSIGN'; Value='='; Pos=$i }); $i++; $puncMatched=$true }
        elseif ($c -eq '!') { throw "Unexpected '!' at position $i (expected !=, !~, !endswith, etc.)" }
        if ($puncMatched) { continue }

        # --- identifier / keyword ---
        # KQL allows hyphen inside operator names like 'project-keep' and
        # 'mv-expand'.  We match identifier start + alnum/underscore, then
        # check for hyphenated continuation only against the keyword list.
        if ([char]::IsLetter($c) -or $c -eq '_') {
            $start = $i
            while ($i -lt $n -and ([char]::IsLetterOrDigit($Query[$i]) -or $Query[$i] -eq '_')) { $i++ }
            $word = $Query.Substring($start, $i - $start)
            # Try to extend with -hyphen forms.
            if ($i -lt $n -and $Query[$i] -eq '-') {
                $hyphenStart = $i; $j = $i + 1
                while ($j -lt $n -and ([char]::IsLetterOrDigit($Query[$j]) -or $Query[$j] -eq '_')) { $j++ }
                $extended = $Query.Substring($start, $j - $start)
                if ($script:KqlKeywords -contains $extended) {
                    $word = $extended; $i = $j
                }
            }
            $kind = if ($script:KqlKeywords -contains $word) { 'KEYWORD' } else { 'IDENT' }
            $tokens.Add([pscustomobject]@{ Kind=$kind; Value=$word; Pos=$start })
            continue
        }

        throw "Unrecognized character '$c' at position $i"
    }

    $tokens.Add([pscustomobject]@{ Kind='EOF'; Value=$null; Pos=$n })
    return ,$tokens.ToArray()
}

# =====================================================================
# SECTION 2 - Parser
# =====================================================================
#
# The parser is recursive descent.  It maintains an index into the token
# stream as a hashtable so nested calls share state without globals.
#
# AST shape: every node is a [pscustomobject] with an `Op` field plus
# whatever payload that node needs.  Tabular nodes carry their child
# pipeline; expression nodes carry left/right/args.
# ---------------------------------------------------------------------

function _Peek  { param($state, [int] $offset = 0) $state.Tokens[$state.Pos + $offset] }
function _Take  { param($state) $tk = $state.Tokens[$state.Pos]; $state.Pos++; return $tk }
function _Expect {
    param($state, [string] $kind, [string] $value = $null)
    $tk = _Peek $state
    if ($tk.Kind -ne $kind) {
        throw "Expected $kind at position $($tk.Pos), got $($tk.Kind) '$($tk.Value)'"
    }
    if ($value -and $tk.Value -cne $value) {
        throw "Expected '$value' at position $($tk.Pos), got '$($tk.Value)'"
    }
    return _Take $state
}
function _Match {
    param($state, [string] $kind, [string] $value = $null)
    $tk = _Peek $state
    if ($tk.Kind -ne $kind) { return $null }
    if ($value -and $tk.Value -cne $value) { return $null }
    return _Take $state
}

function ConvertFrom-KqlTokens {
    [CmdletBinding()]
    param([object[]] $Tokens)

    $state = @{ Tokens = $Tokens; Pos = 0 }

    # Top-level: zero or more `let` bindings, then a tabular expression.
    $bindings = New-Object System.Collections.Generic.List[object]
    while ((_Peek $state).Kind -eq 'KEYWORD' -and (_Peek $state).Value -eq 'let') {
        $bindings.Add((_ParseLet $state))
    }
    $body = _ParseTabular $state

    # Allow trailing semicolons, then EOF.
    while ((_Peek $state).Kind -eq 'SEMI') { [void] (_Take $state) }
    if ((_Peek $state).Kind -ne 'EOF') {
        $tk = _Peek $state
        throw "Unexpected $($tk.Kind) '$($tk.Value)' at position $($tk.Pos)"
    }

    return [pscustomobject]@{
        Op       = 'Query'
        Bindings = $bindings.ToArray()
        Body     = $body
    }
}

function _ParseLet {
    param($state)
    [void] (_Expect $state 'KEYWORD' 'let')
    $name = (_Expect $state 'IDENT').Value
    [void] (_Expect $state 'ASSIGN')
    # The body may be a tabular expression (table | ...) or a scalar
    # expression (a duration, a string, a dynamic literal, etc.).
    # We try tabular first if next token is an IDENT followed by a PIPE
    # or starts with `materialize(`/`(`. Otherwise scalar.
    $tk1 = _Peek $state
    $tk2 = _Peek $state 1
    $isTabular = $false
    if ($tk1.Kind -eq 'IDENT' -and $tk2.Kind -eq 'PIPE') { $isTabular = $true }
    elseif ($tk1.Kind -eq 'KEYWORD' -and $tk1.Value -eq 'materialize') { $isTabular = $true }
    elseif ($tk1.Kind -eq 'LPAREN') {
        # could be a parenthesized tabular subquery or a scalar in parens.
        # heuristic: peek for a PIPE before the matching close paren.
        $depth = 0; $k = $state.Pos
        while ($k -lt $state.Tokens.Length) {
            $t = $state.Tokens[$k]
            if ($t.Kind -eq 'LPAREN') { $depth++ }
            elseif ($t.Kind -eq 'RPAREN') { $depth--; if ($depth -eq 0) { break } }
            elseif ($t.Kind -eq 'PIPE' -and $depth -eq 1) { $isTabular = $true; break }
            $k++
        }
    }

    if ($isTabular) {
        $value = _ParseTabular $state
        $kind  = 'Tabular'
    } else {
        $value = _ParseExpression $state
        $kind  = 'Scalar'
    }
    [void] (_Expect $state 'SEMI')
    return [pscustomobject]@{ Op='Let'; Name=$name; ValueKind=$kind; Value=$value }
}

# A tabular expression: <source> ( | <operator> )*
# Source is either a table identifier, a parenthesized tabular subquery,
# `union (...)`, `materialize(...)`, or a referenced let-bound name.
function _ParseTabular {
    param($state)

    $current = _ParseTabularSource $state
    while ((_Peek $state).Kind -eq 'PIPE') {
        [void] (_Take $state)
        $op = _ParseOperator $state
        # Each operator records the previous chain as its 'Source' so we
        # have a fully-linked AST (handy for materialize and inspection).
        $op | Add-Member -NotePropertyName 'Source' -NotePropertyValue $current -Force
        $current = $op
    }
    return $current
}

function _ParseTabularSource {
    param($state)

    $tk = _Peek $state

    # union as a top-level source: `union (T1), (T2), (T3)`
    if (($tk.Kind -eq 'IDENT' -or $tk.Kind -eq 'KEYWORD') -and $tk.Value -eq 'union') {
        [void] (_Take $state)
        $branches = New-Object System.Collections.Generic.List[object]
        do {
            [void] (_Expect $state 'LPAREN')
            $branches.Add((_ParseTabular $state))
            [void] (_Expect $state 'RPAREN')
        } while ((_Match $state 'COMMA'))
        return [pscustomobject]@{ Op='Union'; Branches=$branches.ToArray(); Source=$null }
    }

    if ($tk.Kind -eq 'KEYWORD' -and $tk.Value -eq 'materialize') {
        [void] (_Take $state)
        [void] (_Expect $state 'LPAREN')
        $inner = _ParseTabular $state
        [void] (_Expect $state 'RPAREN')
        return [pscustomobject]@{ Op='Materialize'; Inner=$inner; Source=$null }
    }

    if ($tk.Kind -eq 'LPAREN') {
        [void] (_Take $state)
        $inner = _ParseTabular $state
        [void] (_Expect $state 'RPAREN')
        return $inner
    }

    if ($tk.Kind -eq 'IDENT') {
        [void] (_Take $state)
        return [pscustomobject]@{ Op='TableRef'; Name=$tk.Value; Source=$null }
    }

    throw "Expected a table name or '(' at position $($tk.Pos), got $($tk.Kind) '$($tk.Value)'"
}

# Operator dispatch.  Most are keywords; a few are word-form ('mv-expand').
function _ParseOperator {
    param($state)
    $tk = _Peek $state
    if ($tk.Kind -ne 'KEYWORD' -and $tk.Kind -ne 'IDENT') {
        throw "Expected an operator after '|' at position $($tk.Pos), got $($tk.Kind) '$($tk.Value)'"
    }
    [void] (_Take $state)
    switch ($tk.Value) {
        'where'           { return _ParseWhere   $state }
        'project'         { return _ParseProject $state -Mode 'project' }
        'project-keep'    { return _ParseProject $state -Mode 'keep' }
        'project-rename'  { return _ParseProjectRename $state }
        'project-away'    { return _ParseProjectAway   $state }
        'project-reorder' { return _ParseProject $state -Mode 'reorder' }
        'extend'          { return _ParseExtend $state }
        'summarize'       { return _ParseSummarize $state }
        'order'           { [void] (_Expect $state 'KEYWORD' 'by'); return _ParseOrderBy $state }
        'sort'            { [void] (_Expect $state 'KEYWORD' 'by'); return _ParseOrderBy $state }
        'take'            { return [pscustomobject]@{ Op='Take'; Count=(_Expect $state 'NUMBER').Value } }
        'limit'           { return [pscustomobject]@{ Op='Take'; Count=(_Expect $state 'NUMBER').Value } }
        'top'             { return _ParseTop $state }
        'distinct'        { return _ParseDistinct $state }
        'union'           {
            $branches = New-Object System.Collections.Generic.List[object]
            do {
                [void] (_Expect $state 'LPAREN')
                $branches.Add((_ParseTabular $state))
                [void] (_Expect $state 'RPAREN')
            } while ((_Match $state 'COMMA'))
            return [pscustomobject]@{ Op='UnionAfter'; Branches=$branches.ToArray() }
        }
        'join'            { return _ParseJoin $state }
        'parse'           { return _ParseParse $state }
        'mv-expand'       { return _ParseMvExpand $state }
        'getschema'       { return [pscustomobject]@{ Op='GetSchema' } }
        'render'          { while ((_Peek $state).Kind -notin @('PIPE','EOF','SEMI')) { [void] (_Take $state) }
                            return [pscustomobject]@{ Op='Render' } }
        'materialize'     {
            [void] (_Expect $state 'LPAREN')
            $inner = _ParseTabular $state
            [void] (_Expect $state 'RPAREN')
            return [pscustomobject]@{ Op='MaterializeAfter'; Inner=$inner }
        }
        default { throw "Unknown operator '$($tk.Value)' at position $($tk.Pos)" }
    }
}

function _ParseWhere {
    param($state)
    $expr = _ParseExpression $state
    return [pscustomobject]@{ Op='Where'; Predicate=$expr }
}

# project / project-keep / project-reorder
# Each item is either: <ident>, or <newName> = <expression>
function _ParseProject {
    param($state, [string] $Mode)
    $items = New-Object System.Collections.Generic.List[object]
    do {
        $name = (_Expect $state 'IDENT').Value
        if ((_Peek $state).Kind -eq 'ASSIGN') {
            [void] (_Take $state)
            $expr = _ParseExpression $state
            $items.Add([pscustomobject]@{ Name=$name; Expr=$expr })
        } else {
            $items.Add([pscustomobject]@{ Name=$name; Expr=[pscustomobject]@{ Op='Col'; Name=$name } })
        }
    } while ((_Match $state 'COMMA'))
    return [pscustomobject]@{ Op='Project'; Mode=$Mode; Items=$items.ToArray() }
}

function _ParseProjectRename {
    param($state)
    $items = New-Object System.Collections.Generic.List[object]
    do {
        $newName = (_Expect $state 'IDENT').Value
        [void] (_Expect $state 'ASSIGN')
        $oldName = (_Expect $state 'IDENT').Value
        $items.Add([pscustomobject]@{ NewName=$newName; OldName=$oldName })
    } while ((_Match $state 'COMMA'))
    return [pscustomobject]@{ Op='ProjectRename'; Items=$items.ToArray() }
}

function _ParseProjectAway {
    param($state)
    $cols = New-Object System.Collections.Generic.List[string]
    do { $cols.Add((_Expect $state 'IDENT').Value) } while ((_Match $state 'COMMA'))
    return [pscustomobject]@{ Op='ProjectAway'; Columns=$cols.ToArray() }
}

function _ParseExtend {
    param($state)
    $items = New-Object System.Collections.Generic.List[object]
    do {
        $name = (_Expect $state 'IDENT').Value
        [void] (_Expect $state 'ASSIGN')
        $expr = _ParseExpression $state
        $items.Add([pscustomobject]@{ Name=$name; Expr=$expr })
    } while ((_Match $state 'COMMA'))
    return [pscustomobject]@{ Op='Extend'; Items=$items.ToArray() }
}

function _ParseSummarize {
    param($state)
    $aggs = New-Object System.Collections.Generic.List[object]
    # First token after summarize is either an aggregator (count(), name=count(),...) or 'by'.
    $needsAgg = (_Peek $state).Kind -ne 'KEYWORD' -or (_Peek $state).Value -ne 'by'
    if ($needsAgg) {
        do {
            $tk = _Peek $state
            $alias = $null
            # Try: <ident> = <call>
            if ($tk.Kind -eq 'IDENT' -and (_Peek $state 1).Kind -eq 'ASSIGN') {
                $alias = (_Take $state).Value
                [void] (_Expect $state 'ASSIGN')
            }
            $expr = _ParseExpression $state
            if (-not $alias) { $alias = _DeriveAggAlias $expr }
            $aggs.Add([pscustomobject]@{ Alias=$alias; Expr=$expr })
        } while ((_Match $state 'COMMA'))
    }

    $by = New-Object System.Collections.Generic.List[object]
    if ((_Peek $state).Kind -eq 'KEYWORD' -and (_Peek $state).Value -eq 'by') {
        [void] (_Take $state)
        do {
            # `by` keys can be plain idents OR expressions like bin(TimeGenerated, 1h).
            # Optional alias too: `Hour = bin(TimeGenerated, 1h)`.
            $tk1 = _Peek $state; $tk2 = _Peek $state 1
            $alias = $null
            if ($tk1.Kind -eq 'IDENT' -and $tk2.Kind -eq 'ASSIGN') {
                $alias = (_Take $state).Value
                [void] (_Expect $state 'ASSIGN')
            }
            $expr = _ParseExpression $state
            if (-not $alias) {
                if ($expr.Op -eq 'Col') { $alias = $expr.Name }
                elseif ($expr.Op -eq 'Call' -and $expr.Name -eq 'bin' -and $expr.Args.Length -ge 1 -and $expr.Args[0].Op -eq 'Col') {
                    $alias = $expr.Args[0].Name
                } else {
                    $alias = "by_$($by.Count)"
                }
            }
            $by.Add([pscustomobject]@{ Alias=$alias; Expr=$expr })
        } while ((_Match $state 'COMMA'))
    }

    return [pscustomobject]@{ Op='Summarize'; Aggs=$aggs.ToArray(); By=$by.ToArray() }
}

function _DeriveAggAlias {
    param($expr)
    if ($expr.Op -eq 'Call') {
        if ($expr.Args.Length -gt 0 -and $expr.Args[0].Op -eq 'Col') {
            return "$($expr.Name)_$($expr.Args[0].Name)"
        }
        return "$($expr.Name)_"
    }
    return 'agg'
}

function _ParseOrderBy {
    param($state)
    $keys = New-Object System.Collections.Generic.List[object]
    do {
        $expr = _ParseExpression $state
        $direction = 'desc'
        $tk = _Peek $state
        if ($tk.Kind -eq 'KEYWORD' -and $tk.Value -in @('asc','desc')) {
            $direction = (_Take $state).Value
        }
        $keys.Add([pscustomobject]@{ Expr=$expr; Direction=$direction })
    } while ((_Match $state 'COMMA'))
    return [pscustomobject]@{ Op='OrderBy'; Keys=$keys.ToArray() }
}

function _ParseTop {
    param($state)
    $count = (_Expect $state 'NUMBER').Value
    [void] (_Expect $state 'KEYWORD' 'by')
    $expr = _ParseExpression $state
    $direction = 'desc'
    $tk = _Peek $state
    if ($tk.Kind -eq 'KEYWORD' -and $tk.Value -in @('asc','desc')) {
        $direction = (_Take $state).Value
    }
    return [pscustomobject]@{ Op='Top'; Count=$count; Expr=$expr; Direction=$direction }
}

function _ParseDistinct {
    param($state)
    $cols = New-Object System.Collections.Generic.List[string]
    do { $cols.Add((_Expect $state 'IDENT').Value) } while ((_Match $state 'COMMA'))
    return [pscustomobject]@{ Op='Distinct'; Columns=$cols.ToArray() }
}

function _ParseJoin {
    param($state)
    $kind = 'innerunique'
    if ((_Peek $state).Kind -eq 'KEYWORD' -and (_Peek $state).Value -eq 'kind') {
        [void] (_Take $state)
        [void] (_Expect $state 'ASSIGN')
        $kind = (_Expect $state 'IDENT').Value
    }
    # Right side: parenthesized tabular OR bare table name
    $tk = _Peek $state
    if ($tk.Kind -eq 'LPAREN') {
        [void] (_Take $state)
        $right = _ParseTabular $state
        [void] (_Expect $state 'RPAREN')
    } elseif ($tk.Kind -eq 'IDENT') {
        [void] (_Take $state)
        $right = [pscustomobject]@{ Op='TableRef'; Name=$tk.Value; Source=$null }
    } else {
        throw "Expected '(' or table name after join kind at position $($tk.Pos)"
    }
    [void] (_Expect $state 'KEYWORD' 'on')
    $keys = New-Object System.Collections.Generic.List[string]
    do { $keys.Add((_Expect $state 'IDENT').Value) } while ((_Match $state 'COMMA'))
    return [pscustomobject]@{ Op='Join'; Kind=$kind; Right=$right; Keys=$keys.ToArray() }
}

function _ParseParse {
    param($state)
    $col = (_Expect $state 'IDENT').Value
    [void] (_Expect $state 'KEYWORD' 'with')
    # Pattern: alternating literal strings (or '*' wildcards) and named
    # captures (with optional :type annotation).
    $parts = New-Object System.Collections.Generic.List[object]
    while ($true) {
        $tk = _Peek $state
        if ($tk.Kind -eq 'STRING') {
            [void] (_Take $state)
            $parts.Add([pscustomobject]@{ Kind='Lit'; Value=$tk.Value })
        } elseif ($tk.Kind -eq 'OP' -and $tk.Value -eq '*') {
            [void] (_Take $state)
            $parts.Add([pscustomobject]@{ Kind='Star' })
        } elseif ($tk.Kind -eq 'IDENT') {
            [void] (_Take $state)
            $name = $tk.Value; $type = 'string'
            # optional ':type'
            $tk2 = _Peek $state
            if ($tk2.Kind -eq 'IDENT' -and $tk2.Value -eq ':') {
                # this branch unused in practice; kept for safety
            }
            # KQL syntax 'User:string' is two tokens because ':' is not a
            # token we generate.  Instead, the lexer treats 'User:string'
            # as IDENT 'User' then we look for an OP that contains ':'?
            # We can't lex ':' ourselves so instead we accept the form
            # `User string` (the previous lexer treats ':string' as part
            # of an ident if hyphenless; but ':' is unrecognized).
            # PRAGMATIC FIX: rewrite the source on entry to convert
            # 'X:type' patterns inside `parse with` into 'X type'.
            # See the entry function PreProcessParseTypes.
            if ($tk2.Kind -eq 'IDENT' -and $tk2.Value -in @('string','int','long','real','bool','datetime','dynamic','double')) {
                [void] (_Take $state); $type = $tk2.Value
            }
            $parts.Add([pscustomobject]@{ Kind='Var'; Name=$name; Type=$type })
        } else {
            break
        }
    }
    return [pscustomobject]@{ Op='Parse'; Column=$col; Parts=$parts.ToArray() }
}

function _ParseMvExpand {
    param($state)
    # Form: `mv-expand X` or `mv-expand X = Expr`
    $name = (_Expect $state 'IDENT').Value
    if ((_Peek $state).Kind -eq 'ASSIGN') {
        [void] (_Take $state)
        $expr = _ParseExpression $state
    } else {
        $expr = [pscustomobject]@{ Op='Col'; Name=$name }
    }
    return [pscustomobject]@{ Op='MvExpand'; Name=$name; Expr=$expr }
}

# ---------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------
# Precedence (low to high):
#   Or
#   And
#   Comparison and string ops
#   Additive (+, -)
#   Multiplicative (*, /, %)
#   Unary (not, -)
#   Member access (a.b), index (a[i])
#   Primary (literals, idents, calls, parens, dynamic, range/between args)

function _ParseExpression { param($state) return _ParseOr $state }

function _ParseOr {
    param($state)
    $left = _ParseAnd $state
    while (((_Peek $state).Kind -eq 'KEYWORD' -and (_Peek $state).Value -eq 'or') -or
           ((_Peek $state).Kind -eq 'OP' -and (_Peek $state).Value -eq '||')) {
        [void] (_Take $state)
        $right = _ParseAnd $state
        $left = [pscustomobject]@{ Op='BinOp'; Operator='or'; Left=$left; Right=$right }
    }
    return $left
}

function _ParseAnd {
    param($state)
    $left = _ParseNot $state
    while (((_Peek $state).Kind -eq 'KEYWORD' -and (_Peek $state).Value -eq 'and') -or
           ((_Peek $state).Kind -eq 'OP' -and (_Peek $state).Value -eq '&&')) {
        [void] (_Take $state)
        $right = _ParseNot $state
        $left = [pscustomobject]@{ Op='BinOp'; Operator='and'; Left=$left; Right=$right }
    }
    return $left
}

function _ParseNot {
    param($state)
    $tk = _Peek $state
    if ($tk.Kind -eq 'KEYWORD' -and $tk.Value -eq 'not') {
        [void] (_Take $state)
        # `not(expr)` requires parens by KQL convention but we accept
        # parens-optional and also `not expr`.
        if ((_Peek $state).Kind -eq 'LPAREN') {
            [void] (_Take $state)
            $inner = _ParseExpression $state
            [void] (_Expect $state 'RPAREN')
        } else {
            $inner = _ParseNot $state
        }
        return [pscustomobject]@{ Op='UnaryOp'; Operator='not'; Operand=$inner }
    }
    return _ParseComparison $state
}

function _ParseComparison {
    param($state)
    $left = _ParseAddition $state
    while ($true) {
        $tk = _Peek $state
        $op = $null
        if ($tk.Kind -eq 'OP' -and $tk.Value -in @('==','!=','<','>','<=','>=','=~','!~',
                                                    '!endswith','!startswith','!contains','!has','!in','!between')) {
            $op = (_Take $state).Value
        } elseif ($tk.Kind -eq 'IDENT' -and $tk.Value -in @('has','has_cs','has_any','has_all','contains',
                                                            'contains_cs','startswith','endswith','in','in~','between')) {
            $op = (_Take $state).Value
        } elseif ($tk.Kind -eq 'KEYWORD' -and $tk.Value -eq 'in') {
            $op = (_Take $state).Value
        } elseif ($tk.Kind -eq 'KEYWORD' -and $tk.Value -eq 'between') {
            $op = (_Take $state).Value
        } elseif ($tk.Kind -eq 'KEYWORD' -and $tk.Value -eq 'matches') {
            [void] (_Take $state)
            [void] (_Expect $state 'KEYWORD' 'regex')
            $right = _ParseAddition $state
            $left = [pscustomobject]@{ Op='BinOp'; Operator='matches regex'; Left=$left; Right=$right }
            continue
        }
        if (-not $op) { break }

        # `between (a..b)` and `!between (a..b)` take a parenthesized
        # range expression.  `in (a, b, c)` takes a parenthesized list.
        if ($op -eq 'between' -or $op -eq '!between') {
            [void] (_Expect $state 'LPAREN')
            $a = _ParseExpression $state
            [void] (_Expect $state 'RANGE')
            $b = _ParseExpression $state
            [void] (_Expect $state 'RPAREN')
            $left = [pscustomobject]@{ Op='Between'; Negate=($op -eq '!between'); Value=$left; Lower=$a; Upper=$b }
            continue
        }
        if ($op -eq 'in' -or $op -eq '!in' -or $op -eq 'in~') {
            [void] (_Expect $state 'LPAREN')
            # Either a single expression that is a dynamic/let array, or a list of literals
            $items = New-Object System.Collections.Generic.List[object]
            do { $items.Add((_ParseExpression $state)) } while ((_Match $state 'COMMA'))
            [void] (_Expect $state 'RPAREN')
            $left = [pscustomobject]@{ Op='In'; Operator=$op; Value=$left; Items=$items.ToArray() }
            continue
        }
        # has_any / has_all take a parenthesized list or single expression
        if ($op -in @('has_any','has_all')) {
            [void] (_Expect $state 'LPAREN')
            $items = New-Object System.Collections.Generic.List[object]
            do { $items.Add((_ParseExpression $state)) } while ((_Match $state 'COMMA'))
            [void] (_Expect $state 'RPAREN')
            $left = [pscustomobject]@{ Op='HasAny'; All=($op -eq 'has_all'); Value=$left; Items=$items.ToArray() }
            continue
        }
        $right = _ParseAddition $state
        $left = [pscustomobject]@{ Op='BinOp'; Operator=$op; Left=$left; Right=$right }
    }
    return $left
}

function _ParseAddition {
    param($state)
    $left = _ParseMultiplication $state
    while ((_Peek $state).Kind -eq 'OP' -and (_Peek $state).Value -in @('+','-')) {
        $op = (_Take $state).Value
        $right = _ParseMultiplication $state
        $left = [pscustomobject]@{ Op='BinOp'; Operator=$op; Left=$left; Right=$right }
    }
    return $left
}

function _ParseMultiplication {
    param($state)
    $left = _ParseUnary $state
    while ((_Peek $state).Kind -eq 'OP' -and (_Peek $state).Value -in @('*','/','%')) {
        $op = (_Take $state).Value
        $right = _ParseUnary $state
        $left = [pscustomobject]@{ Op='BinOp'; Operator=$op; Left=$left; Right=$right }
    }
    return $left
}

function _ParseUnary {
    param($state)
    if ((_Peek $state).Kind -eq 'OP' -and (_Peek $state).Value -eq '-') {
        [void] (_Take $state)
        $op = _ParseUnary $state
        return [pscustomobject]@{ Op='UnaryOp'; Operator='-'; Operand=$op }
    }
    return _ParsePostfix $state
}

function _ParsePostfix {
    param($state)
    $left = _ParsePrimary $state
    while ($true) {
        $tk = _Peek $state
        if ($tk.Kind -eq 'DOT') {
            [void] (_Take $state)
            $name = (_Expect $state 'IDENT').Value
            $left = [pscustomobject]@{ Op='Member'; Target=$left; Name=$name }
        } elseif ($tk.Kind -eq 'LBRACK') {
            [void] (_Take $state)
            $idx = _ParseExpression $state
            [void] (_Expect $state 'RBRACK')
            $left = [pscustomobject]@{ Op='Index'; Target=$left; Index=$idx }
        } else { break }
    }
    return $left
}

function _ParsePrimary {
    param($state)
    $tk = _Peek $state
    switch ($tk.Kind) {
        'STRING'   { [void] (_Take $state); return [pscustomobject]@{ Op='Literal'; Value=$tk.Value } }
        'NUMBER'   { [void] (_Take $state); return [pscustomobject]@{ Op='Literal'; Value=$tk.Value } }
        'DURATION' { [void] (_Take $state); return [pscustomobject]@{ Op='Literal'; Value=$tk.Value } }
        'KEYWORD'  {
            switch ($tk.Value) {
                'true'    { [void] (_Take $state); return [pscustomobject]@{ Op='Literal'; Value=$true } }
                'false'   { [void] (_Take $state); return [pscustomobject]@{ Op='Literal'; Value=$false } }
                'null'    { [void] (_Take $state); return [pscustomobject]@{ Op='Literal'; Value=$null } }
                'dynamic' {
                    [void] (_Take $state)
                    [void] (_Expect $state 'LPAREN')
                    # dynamic([1,2,3]) or dynamic({"a":1}) - we only support the array form for now
                    if ((_Peek $state).Kind -eq 'LBRACK') {
                        [void] (_Take $state)
                        $items = New-Object System.Collections.Generic.List[object]
                        if ((_Peek $state).Kind -ne 'RBRACK') {
                            do { $items.Add((_ParseExpression $state)) } while ((_Match $state 'COMMA'))
                        }
                        [void] (_Expect $state 'RBRACK')
                        [void] (_Expect $state 'RPAREN')
                        return [pscustomobject]@{ Op='DynamicArray'; Items=$items.ToArray() }
                    }
                    if ((_Peek $state).Kind -eq 'STRING') {
                        $sv = (_Take $state).Value
                        [void] (_Expect $state 'RPAREN')
                        # Try to parse as JSON, else just keep as string
                        try { return [pscustomobject]@{ Op='Literal'; Value=(ConvertFrom-Json $sv -ErrorAction Stop) } }
                        catch { return [pscustomobject]@{ Op='Literal'; Value=$sv } }
                    }
                    throw "Unsupported dynamic() form at position $($tk.Pos)"
                }
                default { throw "Unexpected keyword '$($tk.Value)' at position $($tk.Pos) in expression" }
            }
        }
        'LPAREN' {
            [void] (_Take $state)
            $inner = _ParseExpression $state
            [void] (_Expect $state 'RPAREN')
            return $inner
        }
        'IDENT' {
            [void] (_Take $state)
            $name = $tk.Value
            if ((_Peek $state).Kind -eq 'LPAREN') {
                [void] (_Take $state)
                $args = New-Object System.Collections.Generic.List[object]
                if ((_Peek $state).Kind -ne 'RPAREN') {
                    do {
                        # special-case: `arg_max(col, *)` accepts a bare *
                        if ((_Peek $state).Kind -eq 'OP' -and (_Peek $state).Value -eq '*') {
                            [void] (_Take $state)
                            $args.Add([pscustomobject]@{ Op='Star' })
                        } else {
                            $args.Add((_ParseExpression $state))
                        }
                    } while ((_Match $state 'COMMA'))
                }
                [void] (_Expect $state 'RPAREN')
                return [pscustomobject]@{ Op='Call'; Name=$name; Args=$args.ToArray() }
            }
            return [pscustomobject]@{ Op='Col'; Name=$name }
        }
        default { throw "Unexpected $($tk.Kind) '$($tk.Value)' at position $($tk.Pos) in expression" }
    }
}

# ---------------------------------------------------------------------
# Parse-time pre-processor: KQL `User:string` inside `parse with` is
# tricky because ':' is not a regular token.  We rewrite occurrences of
# `<ident>:<typename>` to `<ident> <typename>` ONLY when they appear
# inside a `parse ... with` segment, since elsewhere ':' is invalid.
# This is a textual rewrite over the source string before lexing.
# ---------------------------------------------------------------------
function _RewriteParseTypes {
    param([string] $Query)
    # Matches `IDENT:type_word` not preceded by '/' (avoiding URLs in strings is hard
    # - but strings are quoted, and inside string literals our regex won't match unquoted patterns).
    # Conservative: only inside likely-parse contexts we accept the rewrite,
    # but the rewrite is also harmless elsewhere because there's no other use of 'X:int' in KQL syntax.
    return [regex]::Replace(
        $Query,
        '(?<![\w/])(?<id>[A-Za-z_][A-Za-z0-9_]*)\:(?<ty>string|int|long|real|bool|datetime|dynamic|double)\b',
        '${id} ${ty}'
    )
}

# =====================================================================
# SECTION 3 - Expression evaluator
# =====================================================================
#
# Two evaluation modes:
#   - Row-scalar: evaluate against a single row [PSCustomObject]
#   - Group:      evaluate against a group of rows (for aggregates)
# Aggregator functions detect they are in group mode by reading
# $env.GroupRows; otherwise they treat $env.Row as the input.
#
# `env` is a hashtable: @{ Row = ...; GroupRows = ...; Bindings = ...;
#                          Context = ... }
# ---------------------------------------------------------------------

function Invoke-KqlExpr {
    param($Node, $Env)

    switch ($Node.Op) {
        'Literal'      { return $Node.Value }
        'Star'         { throw "'*' not allowed in this position" }
        'Col' {
            if ($null -ne $Env.Row -and $Env.Row.PSObject.Properties[$Node.Name]) {
                return $Env.Row.PSObject.Properties[$Node.Name].Value
            }
            if ($Env.Bindings -and $Env.Bindings.ContainsKey($Node.Name)) {
                return $Env.Bindings[$Node.Name]
            }
            return $null
        }
        'Member' {
            $target = Invoke-KqlExpr $Node.Target $Env
            if ($null -eq $target) { return $null }
            # If it's a JSON string, parse on the fly.
            if ($target -is [string]) {
                try { $target = $target | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
            }
            if ($target -is [pscustomobject]) {
                if ($target.PSObject.Properties[$Node.Name]) {
                    return $target.PSObject.Properties[$Node.Name].Value
                }
                return $null
            }
            if ($target -is [hashtable]) { return $target[$Node.Name] }
            return $null
        }
        'Index' {
            $t = Invoke-KqlExpr $Node.Target $Env
            $i = Invoke-KqlExpr $Node.Index  $Env
            if ($null -eq $t) { return $null }
            if ($t -is [System.Array] -or $t -is [System.Collections.IList]) {
                $idx = [int]$i
                if ($idx -lt 0) { $idx = $t.Count + $idx }
                if ($idx -lt 0 -or $idx -ge $t.Count) { return $null }
                return $t[$idx]
            }
            if ($t -is [string] -and $i -is [string]) {
                # string keyed access on stringified JSON
                try { $obj = $t | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
                if ($obj.PSObject.Properties[$i]) { return $obj.PSObject.Properties[$i].Value }
                return $null
            }
            return $null
        }
        'DynamicArray' {
            $arr = New-Object object[] $Node.Items.Length
            for ($k = 0; $k -lt $Node.Items.Length; $k++) { $arr[$k] = Invoke-KqlExpr $Node.Items[$k] $Env }
            return ,$arr
        }
        'UnaryOp' {
            $v = Invoke-KqlExpr $Node.Operand $Env
            switch ($Node.Operator) {
                'not' { return -not (_AsBool $v) }
                '-'   { return -1 * $v }
            }
        }
        'BinOp' {
            $l = Invoke-KqlExpr $Node.Left  $Env
            # Short-circuit logicals
            if ($Node.Operator -eq 'and') {
                if (-not (_AsBool $l)) { return $false }
                return _AsBool (Invoke-KqlExpr $Node.Right $Env)
            }
            if ($Node.Operator -eq 'or') {
                if (_AsBool $l) { return $true }
                return _AsBool (Invoke-KqlExpr $Node.Right $Env)
            }
            $r = Invoke-KqlExpr $Node.Right $Env
            return Invoke-KqlBinOp $Node.Operator $l $r
        }
        'Between' {
            $v = Invoke-KqlExpr $Node.Value $Env
            $a = Invoke-KqlExpr $Node.Lower $Env
            $b = Invoke-KqlExpr $Node.Upper $Env
            $inRange = (_Compare $v $a) -ge 0 -and (_Compare $v $b) -le 0
            if ($Node.Negate) { return -not $inRange } else { return $inRange }
        }
        'In' {
            $v = Invoke-KqlExpr $Node.Value $Env
            # If single argument is itself an array (dynamic or let-bound), flatten it.
            $list = New-Object System.Collections.Generic.List[object]
            foreach ($it in $Node.Items) {
                $val = Invoke-KqlExpr $it $Env
                if ($val -is [System.Array] -or $val -is [System.Collections.IList]) {
                    foreach ($x in $val) { $list.Add($x) }
                } else { $list.Add($val) }
            }
            $caseInsensitive = ($Node.Operator -eq 'in~')
            $found = $false
            foreach ($x in $list) {
                if ($caseInsensitive -and $v -is [string] -and $x -is [string]) {
                    if ([string]::Equals($v, $x, [System.StringComparison]::OrdinalIgnoreCase)) { $found = $true; break }
                } else {
                    if ($v -eq $x) { $found = $true; break }
                }
            }
            if ($Node.Operator -eq '!in') { return -not $found }
            return $found
        }
        'HasAny' {
            $v = Invoke-KqlExpr $Node.Value $Env
            if ($null -eq $v) { return $false }
            $vs = [string]$v
            $list = New-Object System.Collections.Generic.List[string]
            foreach ($it in $Node.Items) {
                $val = Invoke-KqlExpr $it $Env
                if ($val -is [System.Array] -or $val -is [System.Collections.IList]) {
                    foreach ($x in $val) { $list.Add([string]$x) }
                } else { $list.Add([string]$val) }
            }
            if ($Node.All) {
                foreach ($term in $list) { if (-not (_HasTerm $vs $term)) { return $false } }
                return $true
            } else {
                foreach ($term in $list) { if (_HasTerm $vs $term) { return $true } }
                return $false
            }
        }
        'Call' {
            return Invoke-KqlFunction $Node.Name $Node.Args $Env
        }
        default { throw "Unknown expression node $($Node.Op)" }
    }
}

function _AsBool { param($v)
    if ($null -eq $v) { return $false }
    if ($v -is [bool]) { return $v }
    if ($v -is [int] -or $v -is [long] -or $v -is [double]) { return $v -ne 0 }
    if ($v -is [string]) { return $v -ne '' }
    return $true
}

function _Compare { param($a, $b)
    if ($null -eq $a -and $null -eq $b) { return 0 }
    if ($null -eq $a) { return -1 }
    if ($null -eq $b) { return 1 }
    if ($a -is [datetime] -and $b -is [datetime]) {
        if ($a -lt $b) { return -1 } elseif ($a -gt $b) { return 1 } else { return 0 }
    }
    if ($a -is [datetime] -and $b -is [string]) { return _Compare $a ([datetime]::Parse($b, [cultureinfo]::InvariantCulture)) }
    if ($a -is [string] -and $b -is [datetime]) { return _Compare ([datetime]::Parse($a, [cultureinfo]::InvariantCulture)) $b }
    if ($a -is [TimeSpan] -and $b -is [TimeSpan]) {
        if ($a -lt $b) { return -1 } elseif ($a -gt $b) { return 1 } else { return 0 }
    }
    if (($a -is [double] -or $a -is [int] -or $a -is [long]) -and ($b -is [double] -or $b -is [int] -or $b -is [long])) {
        if ($a -lt $b) { return -1 } elseif ($a -gt $b) { return 1 } else { return 0 }
    }
    # Fall through: use default comparison via [Comparer]::Default
    try { return [System.Collections.Comparer]::Default.Compare($a, $b) } catch { return 0 }
}

function Invoke-KqlBinOp { param([string] $Op, $L, $R)
    switch ($Op) {
        '==' {
            # Case-sensitive equality, with type-aware compare to avoid
            # the silent string-to-int trap from the schema gotcha.
            if ($L -is [string] -and $R -is [string]) { return [string]::Equals($L, $R, [System.StringComparison]::Ordinal) }
            return $L -ceq $R
        }
        '!=' {
            if ($L -is [string] -and $R -is [string]) { return -not [string]::Equals($L, $R, [System.StringComparison]::Ordinal) }
            return $L -cne $R
        }
        '=~' {
            if ($null -eq $L -or $null -eq $R) { return $L -eq $R }
            return [string]::Equals([string]$L, [string]$R, [System.StringComparison]::OrdinalIgnoreCase)
        }
        '!~' {
            if ($null -eq $L -or $null -eq $R) { return $L -ne $R }
            return -not [string]::Equals([string]$L, [string]$R, [System.StringComparison]::OrdinalIgnoreCase)
        }
        '<'  { return (_Compare $L $R) -lt  0 }
        '<=' { return (_Compare $L $R) -le  0 }
        '>'  { return (_Compare $L $R) -gt  0 }
        '>=' { return (_Compare $L $R) -ge  0 }
        '+'  { if ($L -is [datetime] -and $R -is [TimeSpan]) { return $L.Add($R) } return $L + $R }
        '-'  {
            if ($L -is [datetime] -and $R -is [datetime]) { return $L - $R }
            if ($L -is [datetime] -and $R -is [TimeSpan]) { return $L.Subtract($R) }
            return $L - $R
        }
        '*'  { return $L * $R }
        '/'  { return $L / $R }
        '%'  { return $L % $R }
        'has'         { return _HasTerm ([string]$L) ([string]$R) -CaseInsensitive }
        'has_cs'      { return _HasTerm ([string]$L) ([string]$R) }
        '!has'        { return -not (_HasTerm ([string]$L) ([string]$R) -CaseInsensitive) }
        'contains'    { if ($null -eq $L) { return $false } return ([string]$L).IndexOf([string]$R, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 }
        'contains_cs' { if ($null -eq $L) { return $false } return ([string]$L).Contains([string]$R) }
        '!contains'   { if ($null -eq $L) { return $true  } return ([string]$L).IndexOf([string]$R, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 }
        'startswith'   { if ($null -eq $L) { return $false } return ([string]$L).StartsWith([string]$R, [System.StringComparison]::OrdinalIgnoreCase) }
        '!startswith'  { if ($null -eq $L) { return $true  } return -not ([string]$L).StartsWith([string]$R, [System.StringComparison]::OrdinalIgnoreCase) }
        'endswith'     { if ($null -eq $L) { return $false } return ([string]$L).EndsWith([string]$R, [System.StringComparison]::OrdinalIgnoreCase) }
        '!endswith'    { if ($null -eq $L) { return $true  } return -not ([string]$L).EndsWith([string]$R, [System.StringComparison]::OrdinalIgnoreCase) }
        'matches regex' {
            if ($null -eq $L) { return $false }
            return [regex]::IsMatch([string]$L, [string]$R)
        }
        default { throw "Unsupported binary operator '$Op'" }
    }
}

function _HasTerm {
    param([string] $Source, [string] $Term, [switch] $CaseInsensitive)
    if ([string]::IsNullOrEmpty($Source) -or [string]::IsNullOrEmpty($Term)) { return $false }
    # KQL `has` matches a whole-term substring.  A term is a maximal run
    # of alphanumeric/underscore characters.  We construct a regex with
    # word-style boundaries that respect KQL's tokenization.
    $opts = if ($CaseInsensitive) { [System.Text.RegularExpressions.RegexOptions]::IgnoreCase } else { [System.Text.RegularExpressions.RegexOptions]::None }
    $pattern = '(^|[^A-Za-z0-9_])' + [regex]::Escape($Term) + '($|[^A-Za-z0-9_])'
    return [regex]::IsMatch($Source, $pattern, $opts)
}

# =====================================================================
# SECTION 4 - Built-in functions
# =====================================================================

function Invoke-KqlFunction { param([string] $Name, [object[]] $ArgList, $Env)

    # Aggregate functions detect group context first.  When $Env.GroupRows
    # is non-null we are inside a `summarize` aggregator.
    $isGroup = $null -ne $Env.GroupRows
    switch ($Name) {
        'count' {
            if ($isGroup) { return $Env.GroupRows.Count }
            return 0
        }
        'countif' {
            if (-not $isGroup) { throw "countif() only valid inside summarize" }
            $pred = $ArgList[0]
            $n = 0
            foreach ($r in $Env.GroupRows) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                if (_AsBool (Invoke-KqlExpr $pred $sub)) { $n++ }
            }
            return $n
        }
        'dcount' {
            if (-not $isGroup) { throw "dcount() only valid inside summarize" }
            $colExpr = $ArgList[0]
            $set = New-Object System.Collections.Generic.HashSet[object]
            foreach ($r in $Env.GroupRows) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $v = Invoke-KqlExpr $colExpr $sub
                if ($null -ne $v) { [void] $set.Add($v) }
            }
            return $set.Count
        }
        'min' {
            if (-not $isGroup) { throw "min() only valid inside summarize" }
            $colExpr = $ArgList[0]
            $best = $null; $haveBest = $false
            foreach ($r in $Env.GroupRows) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $v = Invoke-KqlExpr $colExpr $sub
                if ($null -eq $v) { continue }
                if (-not $haveBest -or ((_Compare $v $best) -lt 0)) { $best = $v; $haveBest = $true }
            }
            return $best
        }
        'max' {
            if (-not $isGroup) { throw "max() only valid inside summarize" }
            $colExpr = $ArgList[0]
            $best = $null; $haveBest = $false
            foreach ($r in $Env.GroupRows) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $v = Invoke-KqlExpr $colExpr $sub
                if ($null -eq $v) { continue }
                if (-not $haveBest -or ((_Compare $v $best) -gt 0)) { $best = $v; $haveBest = $true }
            }
            return $best
        }
        'sum' {
            if (-not $isGroup) { throw "sum() only valid inside summarize" }
            $colExpr = $ArgList[0]; $acc = 0
            foreach ($r in $Env.GroupRows) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $v = Invoke-KqlExpr $colExpr $sub
                if ($null -ne $v) { $acc = $acc + $v }
            }
            return $acc
        }
        'avg' {
            if (-not $isGroup) { throw "avg() only valid inside summarize" }
            $colExpr = $ArgList[0]; $sum = 0.0; $n = 0
            foreach ($r in $Env.GroupRows) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $v = Invoke-KqlExpr $colExpr $sub
                if ($null -ne $v) { $sum += [double]$v; $n++ }
            }
            if ($n -eq 0) { return $null }
            return $sum / $n
        }
        'take_any' {
            if (-not $isGroup) { throw "take_any() only valid inside summarize" }
            $colExpr = $ArgList[0]
            foreach ($r in $Env.GroupRows) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $v = Invoke-KqlExpr $colExpr $sub
                if ($null -ne $v) { return $v }
            }
            return $null
        }
        'arg_max' {
            if (-not $isGroup) { throw "arg_max() only valid inside summarize" }
            $colExpr = $ArgList[0]
            $bestVal = $null; $bestRow = $null; $haveBest = $false
            foreach ($r in $Env.GroupRows) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $v = Invoke-KqlExpr $colExpr $sub
                if ($null -eq $v) { continue }
                if (-not $haveBest -or ((_Compare $v $bestVal) -gt 0)) { $bestVal = $v; $bestRow = $r; $haveBest = $true }
            }
            # Special-cased by the summarize operator when $ArgList[1] is Star
            if ($ArgList.Length -gt 1 -and $ArgList[1].Op -eq 'Star') {
                return [pscustomobject]@{ __ArgMaxStar=$true; Row=$bestRow; Value=$bestVal }
            }
            # arg_max(col, otherCol) returns otherCol from the winning row
            if ($ArgList.Length -gt 1) {
                if ($null -eq $bestRow) { return $null }
                $sub = @{ Row=$bestRow; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                return Invoke-KqlExpr $ArgList[1] $sub
            }
            return $bestVal
        }
        'arg_min' {
            if (-not $isGroup) { throw "arg_min() only valid inside summarize" }
            $colExpr = $ArgList[0]
            $bestVal = $null; $bestRow = $null; $haveBest = $false
            foreach ($r in $Env.GroupRows) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $v = Invoke-KqlExpr $colExpr $sub
                if ($null -eq $v) { continue }
                if (-not $haveBest -or ((_Compare $v $bestVal) -lt 0)) { $bestVal = $v; $bestRow = $r; $haveBest = $true }
            }
            if ($ArgList.Length -gt 1 -and $ArgList[1].Op -eq 'Star') {
                return [pscustomobject]@{ __ArgMinStar=$true; Row=$bestRow; Value=$bestVal }
            }
            if ($ArgList.Length -gt 1) {
                if ($null -eq $bestRow) { return $null }
                $sub = @{ Row=$bestRow; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                return Invoke-KqlExpr $ArgList[1] $sub
            }
            return $bestVal
        }
        'make_set' {
            if (-not $isGroup) { throw "make_set() only valid inside summarize" }
            $colExpr = $ArgList[0]
            $cap = if ($ArgList.Length -gt 1) { [int](Invoke-KqlExpr $ArgList[1] $Env) } else { 1048576 }
            $set = New-Object System.Collections.Generic.HashSet[object]
            $list = New-Object System.Collections.Generic.List[object]
            foreach ($r in $Env.GroupRows) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $v = Invoke-KqlExpr $colExpr $sub
                if ($null -eq $v) { continue }
                if ($set.Add($v)) { $list.Add($v); if ($list.Count -ge $cap) { break } }
            }
            return ,$list.ToArray()
        }
        'make_list' {
            if (-not $isGroup) { throw "make_list() only valid inside summarize" }
            $colExpr = $ArgList[0]
            $cap = if ($ArgList.Length -gt 1) { [int](Invoke-KqlExpr $ArgList[1] $Env) } else { 1048576 }
            $list = New-Object System.Collections.Generic.List[object]
            foreach ($r in $Env.GroupRows) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $v = Invoke-KqlExpr $colExpr $sub
                if ($null -eq $v) { continue }
                $list.Add($v); if ($list.Count -ge $cap) { break }
            }
            return ,$list.ToArray()
        }
    }

    # ----- non-aggregate scalar functions -----
    # Most take simple positional args.  We evaluate them once.
    $vals = @($ArgList | ForEach-Object { if ($_.Op -eq 'Star') { $_ } else { Invoke-KqlExpr $_ $Env } })

    switch ($Name) {
        'ago'           { return $Env.Context.ReferenceTime - [TimeSpan]$vals[0] }
        'now'           { return $Env.Context.ReferenceTime }
        'datetime'      {
            $v = $vals[0]
            if ($v -is [datetime]) { return $v }
            if ($v -is [string]) { return [datetime]::Parse($v, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal) }
            return [datetime]$v
        }
        'todatetime'    {
            if ($null -eq $vals[0]) { return $null }
            $v = $vals[0]
            if ($v -is [datetime]) { return $v }
            try { return [datetime]::Parse([string]$v, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal) }
            catch { return $null }
        }
        'totimespan'    { return [TimeSpan]$vals[0] }
        'tostring'      { if ($null -eq $vals[0]) { return $null } return [string]$vals[0] }
        'toint'         { if ($null -eq $vals[0] -or $vals[0] -eq '') { return $null } try { return [long]([double]$vals[0]) } catch { return $null } }
        'tolong'        { if ($null -eq $vals[0] -or $vals[0] -eq '') { return $null } try { return [long]([double]$vals[0]) } catch { return $null } }
        'toreal'        { if ($null -eq $vals[0] -or $vals[0] -eq '') { return $null } try { return [double]$vals[0] } catch { return $null } }
        'todouble'      { if ($null -eq $vals[0] -or $vals[0] -eq '') { return $null } try { return [double]$vals[0] } catch { return $null } }
        'tobool'        { if ($null -eq $vals[0]) { return $null } return _AsBool $vals[0] }
        'tolower'       { if ($null -eq $vals[0]) { return $null } return ([string]$vals[0]).ToLowerInvariant() }
        'toupper'       { if ($null -eq $vals[0]) { return $null } return ([string]$vals[0]).ToUpperInvariant() }
        'strlen'        { if ($null -eq $vals[0]) { return 0 } return ([string]$vals[0]).Length }
        'isempty'       { return ($null -eq $vals[0] -or ([string]$vals[0]) -eq '') }
        'isnotempty'    { return -not ($null -eq $vals[0] -or ([string]$vals[0]) -eq '') }
        'isnull'        { return $null -eq $vals[0] }
        'isnotnull'     { return $null -ne $vals[0] }
        'iff'           { if (_AsBool $vals[0]) { return $vals[1] } else { return $vals[2] } }
        'iif'           { if (_AsBool $vals[0]) { return $vals[1] } else { return $vals[2] } }
        'case' {
            for ($k = 0; $k -lt $vals.Length - 1; $k += 2) {
                if (_AsBool $vals[$k]) { return $vals[$k + 1] }
            }
            return $vals[$vals.Length - 1]
        }
        'bin' {
            $v = $vals[0]; $unit = $vals[1]
            if ($null -eq $v -or $null -eq $unit) { return $null }
            if ($v -is [datetime] -and $unit -is [TimeSpan]) {
                $ticks = [long]([math]::Floor($v.Ticks / [double]$unit.Ticks)) * $unit.Ticks
                return [datetime]::new($ticks, $v.Kind)
            }
            if (($v -is [int] -or $v -is [long] -or $v -is [double]) -and ($unit -is [int] -or $unit -is [long] -or $unit -is [double])) {
                return [math]::Floor($v / $unit) * $unit
            }
            throw "bin() argument types not supported"
        }
        'replace_string' {
            if ($null -eq $vals[0]) { return $null }
            return ([string]$vals[0]).Replace([string]$vals[1], [string]$vals[2])
        }
        'replace_regex' {
            if ($null -eq $vals[0]) { return $null }
            return [regex]::Replace([string]$vals[0], [string]$vals[1], [string]$vals[2])
        }
        'split' {
            if ($null -eq $vals[0]) { return ,@() }
            return ,([string]$vals[0]).Split([string[]]@([string]$vals[1]), [StringSplitOptions]::None)
        }
        'extract' {
            $pattern = [string]$vals[0]; $idx = [int]$vals[1]; $src = [string]$vals[2]
            $m = [regex]::Match($src, $pattern)
            if (-not $m.Success) { return '' }
            if ($idx -lt 0 -or $idx -gt $m.Groups.Count - 1) { return '' }
            return $m.Groups[$idx].Value
        }
        'extract_all' {
            $pattern = [string]$vals[0]; $src = [string]$vals[1]
            $matches = [regex]::Matches($src, $pattern)
            $arr = @()
            foreach ($m in $matches) { $arr += ,$m.Groups[1].Value }
            return ,$arr
        }
        'parse_json'    {
            if ($null -eq $vals[0]) { return $null }
            try { return ($vals[0] | ConvertFrom-Json -ErrorAction Stop) } catch { return $null }
        }
        'parse_xml'     {
            if ($null -eq $vals[0]) { return $null }
            try { return [xml]$vals[0] } catch { return $null }
        }
        'array_length'  {
            if ($null -eq $vals[0]) { return 0 }
            if ($vals[0] -is [System.Array] -or $vals[0] -is [System.Collections.IList]) { return $vals[0].Count }
            return 0
        }
        'array_index_of' {
            if ($null -eq $vals[0]) { return -1 }
            $arr = $vals[0]; $target = $vals[1]; $i = 0
            foreach ($x in $arr) {
                if ($x -eq $target) { return $i }
                $i++
            }
            return -1
        }
        'datetime_part' {
            $part = [string]$vals[0]; $dt = $vals[1]
            if ($null -eq $dt) { return $null }
            switch ($part.ToLower()) {
                'year'   { return $dt.Year }
                'month'  { return $dt.Month }
                'day'    { return $dt.Day }
                'hour'   { return $dt.Hour }
                'minute' { return $dt.Minute }
                'second' { return $dt.Second }
                'week_of_year' { return [System.Globalization.CultureInfo]::InvariantCulture.Calendar.GetWeekOfYear($dt, [System.Globalization.CalendarWeekRule]::FirstFourDayWeek, [System.DayOfWeek]::Monday) }
                default { throw "Unknown datetime_part '$part'" }
            }
        }
        'format_datetime' {
            if ($null -eq $vals[0]) { return $null }
            return ([datetime]$vals[0]).ToString([string]$vals[1])
        }
        'startofday'   { return ([datetime]$vals[0]).Date }
        'startofhour'  { $d = [datetime]$vals[0]; return [datetime]::new($d.Year,$d.Month,$d.Day,$d.Hour,0,0,$d.Kind) }
        'startofweek'  { $d = [datetime]$vals[0]; $diff = (([int]$d.DayOfWeek) - [int][DayOfWeek]::Sunday + 7) % 7; return $d.Date.AddDays(-$diff) }
        'strcat'       { return ($vals | ForEach-Object { [string]$_ }) -join '' }
        'substring'    {
            $s = [string]$vals[0]; $start = [int]$vals[1]
            $len = if ($vals.Length -ge 3) { [int]$vals[2] } else { $s.Length - $start }
            if ($start -lt 0) { $start = 0 }
            if ($start + $len -gt $s.Length) { $len = $s.Length - $start }
            if ($len -le 0) { return '' }
            return $s.Substring($start, $len)
        }
        'trim'         { if ($null -eq $vals[0]) { return $null } return ([string]$vals[0]).Trim() }
        'indexof'      {
            if ($null -eq $vals[0]) { return -1 }
            return ([string]$vals[0]).IndexOf([string]$vals[1])
        }
        'startswith'   { if ($null -eq $vals[0]) { return $false } return ([string]$vals[0]).StartsWith([string]$vals[1], [System.StringComparison]::OrdinalIgnoreCase) }
        'endswith'     { if ($null -eq $vals[0]) { return $false } return ([string]$vals[0]).EndsWith([string]$vals[1], [System.StringComparison]::OrdinalIgnoreCase) }
        'contains'     { if ($null -eq $vals[0]) { return $false } return ([string]$vals[0]).IndexOf([string]$vals[1], [System.StringComparison]::OrdinalIgnoreCase) -ge 0 }
        'has'          { return _HasTerm ([string]$vals[0]) ([string]$vals[1]) -CaseInsensitive }
        'has_any'      {
            $src = [string]$vals[0]
            $list = New-Object System.Collections.Generic.List[string]
            for ($k = 1; $k -lt $vals.Length; $k++) {
                $v = $vals[$k]
                if ($v -is [System.Array] -or $v -is [System.Collections.IList]) {
                    foreach ($x in $v) { $list.Add([string]$x) }
                } else { $list.Add([string]$v) }
            }
            foreach ($t in $list) { if (_HasTerm $src $t -CaseInsensitive) { return $true } }
            return $false
        }
        'coalesce'     {
            foreach ($v in $vals) { if ($null -ne $v) { return $v } }
            return $null
        }
        'hash'         { if ($null -eq $vals[0]) { return $null } return [string]$vals[0].GetHashCode() }
        'pack_array'   { return ,$vals }
        default { throw "Unsupported function '$Name'" }
    }
}

# =====================================================================
# SECTION 5 - Tabular operators
# =====================================================================

function Invoke-KqlAst {
    param($Node, $Env)

    # `Source` chain: every operator carries its predecessor in $Node.Source.
    # Sources of zero (TableRef, Materialize-as-source, Union-as-source)
    # have $null Source.  We evaluate Source first, then apply this op.
    if ($Node.PSObject.Properties['Source'] -and $null -ne $Node.Source) {
        $input = Invoke-KqlAst $Node.Source $Env
    } else {
        $input = $null
    }

    switch ($Node.Op) {
        'Query' {
            # Top-level: process let bindings, then evaluate body.
            $newEnv = @{
                Row=$null; GroupRows=$null;
                Bindings = if ($Env.Bindings) { @{} + $Env.Bindings } else { @{} }
                Context  = $Env.Context
            }
            foreach ($b in $Node.Bindings) {
                if ($b.ValueKind -eq 'Scalar') {
                    $newEnv.Bindings[$b.Name] = Invoke-KqlExpr $b.Value $newEnv
                } else {
                    $newEnv.Bindings[$b.Name] = Invoke-KqlAst $b.Value $newEnv
                }
            }
            return Invoke-KqlAst $Node.Body $newEnv
        }

        'TableRef' {
            # Resolve from let-bindings first, then from the data context.
            if ($Env.Bindings.ContainsKey($Node.Name)) {
                $tab = $Env.Bindings[$Node.Name]
                if ($null -eq $tab) { return @() }
                # Bindings holding row arrays come back as array; if they're
                # a single scalar, treat as empty.
                if ($tab -is [System.Array] -or $tab -is [System.Collections.IList]) { return $tab }
                return @($tab)
            }
            return Get-KqlTable -Context $Env.Context -Name $Node.Name
        }

        'Materialize'      { return Invoke-KqlAst $Node.Inner $Env }
        'MaterializeAfter' { return Invoke-KqlAst $Node.Inner $Env }
        'Union' {
            $rows = New-Object System.Collections.Generic.List[object]
            foreach ($branch in $Node.Branches) {
                $r = Invoke-KqlAst $branch $Env
                foreach ($row in $r) { $rows.Add($row) }
            }
            return ,$rows.ToArray()
        }
        'UnionAfter' {
            $rows = New-Object System.Collections.Generic.List[object]
            foreach ($row in $input) { $rows.Add($row) }
            foreach ($branch in $Node.Branches) {
                $r = Invoke-KqlAst $branch $Env
                foreach ($row in $r) { $rows.Add($row) }
            }
            return ,$rows.ToArray()
        }
        'Take'    { return ,( @($input) | Select-Object -First ([int]$Node.Count) ) }
        'GetSchema' {
            if ($input.Count -eq 0) { return ,@() }
            $props = $input[0].PSObject.Properties
            $rows = New-Object System.Collections.Generic.List[object]
            foreach ($p in $props) {
                $rows.Add([pscustomobject]@{ ColumnName=$p.Name; ColumnType=$p.Value.GetType().Name })
            }
            return ,$rows.ToArray()
        }
        'Render' { return ,$input }

        'Where' {
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($r in $input) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                if (_AsBool (Invoke-KqlExpr $Node.Predicate $sub)) { $out.Add($r) }
            }
            return ,$out.ToArray()
        }

        'Project' {
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($r in $input) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $newRow = [ordered]@{}
                foreach ($it in $Node.Items) {
                    $newRow[$it.Name] = Invoke-KqlExpr $it.Expr $sub
                }
                $out.Add([pscustomobject]$newRow)
            }
            return ,$out.ToArray()
        }

        'ProjectRename' {
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($r in $input) {
                $newRow = [ordered]@{}
                $renameMap = @{}
                foreach ($it in $Node.Items) { $renameMap[$it.OldName] = $it.NewName }
                foreach ($p in $r.PSObject.Properties) {
                    $name = if ($renameMap.ContainsKey($p.Name)) { $renameMap[$p.Name] } else { $p.Name }
                    $newRow[$name] = $p.Value
                }
                $out.Add([pscustomobject]$newRow)
            }
            return ,$out.ToArray()
        }

        'ProjectAway' {
            $out = New-Object System.Collections.Generic.List[object]
            $drop = @{}; foreach ($c in $Node.Columns) { $drop[$c] = $true }
            foreach ($r in $input) {
                $newRow = [ordered]@{}
                foreach ($p in $r.PSObject.Properties) {
                    if (-not $drop.ContainsKey($p.Name)) { $newRow[$p.Name] = $p.Value }
                }
                $out.Add([pscustomobject]$newRow)
            }
            return ,$out.ToArray()
        }

        'Extend' {
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($r in $input) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                # Build a NEW row that copies all old props then sets/overrides extended.
                $newRow = [ordered]@{}
                foreach ($p in $r.PSObject.Properties) { $newRow[$p.Name] = $p.Value }
                foreach ($it in $Node.Items) { $newRow[$it.Name] = Invoke-KqlExpr $it.Expr $sub }
                $out.Add([pscustomobject]$newRow)
            }
            return ,$out.ToArray()
        }

        'OrderBy' {
            if ($input.Count -le 1) { return ,$input }
            # Compute composite sort key per row, then sort once.
            $arr = @($input)
            $keys = New-Object 'object[][]' $arr.Length
            for ($i = 0; $i -lt $arr.Length; $i++) {
                $sub = @{ Row=$arr[$i]; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $row = New-Object 'object[]' $Node.Keys.Length
                for ($k = 0; $k -lt $Node.Keys.Length; $k++) {
                    $row[$k] = Invoke-KqlExpr $Node.Keys[$k].Expr $sub
                }
                $keys[$i] = $row
            }
            $idx = 0..($arr.Length - 1)
            $idx = $idx | Sort-Object -Property @{ Expression = {
                $a = $_; $b = $args[0]; 0 } } # placeholder; we do manual sort below
            # Manual stable sort using an in-memory comparer.
            $sorted = @($idx)
            $cmp = {
                param($A, $B)
                for ($k = 0; $k -lt $Node.Keys.Length; $k++) {
                    $cv = _Compare $keys[$A][$k] $keys[$B][$k]
                    if ($Node.Keys[$k].Direction -eq 'desc') { $cv = -$cv }
                    if ($cv -ne 0) { return $cv }
                }
                return 0
            }
            # PowerShell's Sort-Object comparer integration is awkward; do array sort.
            $list = New-Object System.Collections.Generic.List[int]
            for ($i = 0; $i -lt $arr.Length; $i++) { $list.Add($i) }
            $list.Sort([System.Comparison[int]]$cmp)
            $out = New-Object 'object[]' $arr.Length
            for ($i = 0; $i -lt $list.Count; $i++) { $out[$i] = $arr[$list[$i]] }
            return ,$out
        }

        'Top' {
            # ORDER BY then take.
            $synthOrder = [pscustomobject]@{ Op='OrderBy'; Keys=@([pscustomobject]@{ Expr=$Node.Expr; Direction=$Node.Direction }); Source=$null }
            $sorted = Invoke-KqlAst $synthOrder (@{ Row=$null; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context; Input=$input })
            # Workaround: we can't pass input via env, so do it inline.
            $arr = @($input)
            if ($arr.Count -le 1) { return ,$arr }
            $keys = New-Object 'object[]' $arr.Length
            for ($i = 0; $i -lt $arr.Length; $i++) {
                $sub = @{ Row=$arr[$i]; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $keys[$i] = Invoke-KqlExpr $Node.Expr $sub
            }
            $idxList = New-Object System.Collections.Generic.List[int]
            for ($i = 0; $i -lt $arr.Length; $i++) { $idxList.Add($i) }
            $cmp = {
                param($A, $B)
                $c = _Compare $keys[$A] $keys[$B]
                if ($Node.Direction -eq 'desc') { $c = -$c }
                return $c
            }
            $idxList.Sort([System.Comparison[int]]$cmp)
            $count = [Math]::Min([int]$Node.Count, $arr.Length)
            $out = New-Object 'object[]' $count
            for ($i = 0; $i -lt $count; $i++) { $out[$i] = $arr[$idxList[$i]] }
            return ,$out
        }

        'Distinct' {
            $seen = New-Object System.Collections.Generic.HashSet[string]
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($r in $input) {
                $parts = New-Object System.Collections.Generic.List[string]
                foreach ($c in $Node.Columns) {
                    $v = if ($r.PSObject.Properties[$c]) { $r.PSObject.Properties[$c].Value } else { '' }
                    $parts.Add(([string]$v))
                }
                $key = $parts -join "`u{1F}"
                if ($seen.Add($key)) {
                    # output only the distinct columns
                    $newRow = [ordered]@{}
                    foreach ($c in $Node.Columns) {
                        $newRow[$c] = if ($r.PSObject.Properties[$c]) { $r.PSObject.Properties[$c].Value } else { $null }
                    }
                    $out.Add([pscustomobject]$newRow)
                }
            }
            return ,$out.ToArray()
        }

        'Summarize' {
            $arr = @($input)
            # If no `by`, single group.
            if ($Node.By.Length -eq 0) {
                $groupRows = $arr
                $sub = @{ Row=$null; GroupRows=$groupRows; Bindings=$Env.Bindings; Context=$Env.Context }
                $row = [ordered]@{}
                foreach ($a in $Node.Aggs) {
                    $v = Invoke-KqlExpr $a.Expr $sub
                    if ($v -is [pscustomobject] -and $v.PSObject.Properties['__ArgMaxStar']) {
                        # arg_max(col, *) - copy all columns from winning row
                        if ($null -ne $v.Row) {
                            foreach ($p in $v.Row.PSObject.Properties) { $row[$p.Name] = $p.Value }
                        }
                        $row[$a.Alias] = $v.Value
                    } else { $row[$a.Alias] = $v }
                }
                return ,@([pscustomobject]$row)
            }

            # Group rows by composite key built from `by` expressions.
            $groups = [ordered]@{}     # key -> [List[Row]]
            $keysFor = @{}             # key -> ordered hashtable of by-values
            foreach ($r in $arr) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $kparts = New-Object System.Collections.Generic.List[string]
                $kvals  = [ordered]@{}
                foreach ($b in $Node.By) {
                    $v = Invoke-KqlExpr $b.Expr $sub
                    $kvals[$b.Alias] = $v
                    $kparts.Add(([string]$v))
                }
                $key = $kparts -join "`u{1F}"
                if (-not $groups.Contains($key)) {
                    $groups[$key] = New-Object System.Collections.Generic.List[object]
                    $keysFor[$key] = $kvals
                }
                $groups[$key].Add($r)
            }

            $out = New-Object System.Collections.Generic.List[object]
            foreach ($key in $groups.Keys) {
                $groupRows = $groups[$key]
                $sub = @{ Row=$null; GroupRows=$groupRows; Bindings=$Env.Bindings; Context=$Env.Context }
                $row = [ordered]@{}
                foreach ($k in $keysFor[$key].Keys) { $row[$k] = $keysFor[$key][$k] }
                foreach ($a in $Node.Aggs) {
                    $v = Invoke-KqlExpr $a.Expr $sub
                    if ($v -is [pscustomobject] -and $v.PSObject.Properties['__ArgMaxStar']) {
                        if ($null -ne $v.Row) {
                            foreach ($p in $v.Row.PSObject.Properties) {
                                if (-not $row.Contains($p.Name)) { $row[$p.Name] = $p.Value }
                            }
                        }
                        $row[$a.Alias] = $v.Value
                    } else { $row[$a.Alias] = $v }
                }
                $out.Add([pscustomobject]$row)
            }
            return ,$out.ToArray()
        }

        'Join' {
            $right = Invoke-KqlAst $Node.Right $Env
            $kind = $Node.Kind
            $keys = $Node.Keys

            # Build right-side index: composite key -> [List[Row]]
            $rightIdx = @{}
            foreach ($r in $right) {
                $kparts = New-Object System.Collections.Generic.List[string]
                foreach ($k in $keys) {
                    $v = if ($r.PSObject.Properties[$k]) { $r.PSObject.Properties[$k].Value } else { '' }
                    $kparts.Add(([string]$v))
                }
                $key = $kparts -join "`u{1F}"
                if (-not $rightIdx.ContainsKey($key)) { $rightIdx[$key] = New-Object System.Collections.Generic.List[object] }
                $rightIdx[$key].Add($r)
            }

            $out = New-Object System.Collections.Generic.List[object]
            $seenLeftKeys = @{}
            foreach ($l in $input) {
                $kparts = New-Object System.Collections.Generic.List[string]
                $missing = $false
                foreach ($k in $keys) {
                    if (-not $l.PSObject.Properties[$k]) { $missing = $true; break }
                    $kparts.Add(([string]$l.PSObject.Properties[$k].Value))
                }
                $key = $kparts -join "`u{1F}"

                $matches = if (-not $missing -and $rightIdx.ContainsKey($key)) { $rightIdx[$key] } else { $null }

                switch ($kind) {
                    'leftanti' {
                        if ($null -eq $matches) { $out.Add($l) }
                    }
                    'leftsemi' {
                        if ($null -ne $matches) { $out.Add($l) }
                    }
                    'innerunique' {
                        if ($null -ne $matches -and -not $seenLeftKeys.ContainsKey($key)) {
                            $seenLeftKeys[$key] = $true
                            foreach ($r in $matches) { $out.Add((_MergeRows $l $r $keys)) }
                        }
                    }
                    'inner' {
                        if ($null -ne $matches) {
                            foreach ($r in $matches) { $out.Add((_MergeRows $l $r $keys)) }
                        }
                    }
                    'leftouter' {
                        if ($null -ne $matches) {
                            foreach ($r in $matches) { $out.Add((_MergeRows $l $r $keys)) }
                        } else {
                            $out.Add((_MergeRows $l $null $keys))
                        }
                    }
                    'rightouter' {
                        if ($null -ne $matches) {
                            foreach ($r in $matches) { $out.Add((_MergeRows $l $r $keys)) }
                        }
                    }
                    'fullouter' {
                        if ($null -ne $matches) {
                            foreach ($r in $matches) { $out.Add((_MergeRows $l $r $keys)) }
                        } else {
                            $out.Add((_MergeRows $l $null $keys))
                        }
                    }
                    default { throw "Unsupported join kind '$kind'" }
                }
            }
            # fullouter / rightouter: include unmatched right rows
            if ($kind -in @('rightouter','fullouter')) {
                $leftIdx = @{}
                foreach ($l in $input) {
                    $kparts = New-Object System.Collections.Generic.List[string]
                    foreach ($k in $keys) {
                        $kparts.Add(([string](if ($l.PSObject.Properties[$k]) { $l.PSObject.Properties[$k].Value } else { '' })))
                    }
                    $leftIdx[$kparts -join "`u{1F}"] = $true
                }
                foreach ($key in $rightIdx.Keys) {
                    if (-not $leftIdx.ContainsKey($key)) {
                        foreach ($r in $rightIdx[$key]) { $out.Add((_MergeRows $null $r $keys)) }
                    }
                }
            }
            return ,$out.ToArray()
        }

        'Parse' {
            # Build a regex from the parts.  Vars become non-greedy named groups,
            # except typed numeric vars use digit patterns so trailing-* wildcards
            # don't gobble the rest of the line.
            $pat = '^'
            $names = New-Object System.Collections.Generic.List[object]
            for ($k = 0; $k -lt $Node.Parts.Length; $k++) {
                $part = $Node.Parts[$k]
                switch ($part.Kind) {
                    'Lit'  { $pat += [regex]::Escape($part.Value) }
                    'Star' { $pat += '.*?' }
                    'Var'  {
                        $isLast = ($k -eq $Node.Parts.Length - 1)
                        # Type-aware patterns - constrain so trailing-* wildcard
                        # doesn't swallow ' ssh2' into Port:int etc.
                        $tpat = switch ($part.Type) {
                            'int'      { '-?\d+' }
                            'long'     { '-?\d+' }
                            'real'     { '-?\d+\.?\d*' }
                            'double'   { '-?\d+\.?\d*' }
                            'bool'     { 'true|false' }
                            'datetime' { '\S+' }
                            default    { if ($isLast) { '.*' } else { '.*?' } }
                        }
                        $pat += "(?<$($part.Name)>$tpat)"
                        $names.Add($part)
                    }
                }
            }
            # If last part is not Star, don't anchor end (leave dangling).
            if ($Node.Parts.Length -gt 0 -and $Node.Parts[-1].Kind -eq 'Star') { $pat += '.*$' }
            $rx = [regex]::new($pat, [System.Text.RegularExpressions.RegexOptions]::Singleline)

            $out = New-Object System.Collections.Generic.List[object]
            foreach ($r in $input) {
                $src = if ($r.PSObject.Properties[$Node.Column]) { [string]$r.PSObject.Properties[$Node.Column].Value } else { '' }
                $m = $rx.Match($src)
                $newRow = [ordered]@{}
                foreach ($p in $r.PSObject.Properties) { $newRow[$p.Name] = $p.Value }
                foreach ($v in $names) {
                    if ($m.Success) {
                        $val = $m.Groups[$v.Name].Value
                        switch ($v.Type) {
                            'int'      { try { $val = [int]$val } catch { $val = $null } }
                            'long'     { try { $val = [long]$val } catch { $val = $null } }
                            'real'     { try { $val = [double]$val } catch { $val = $null } }
                            'double'   { try { $val = [double]$val } catch { $val = $null } }
                            'datetime' { try { $val = [datetime]$val } catch { $val = $null } }
                            'bool'     { $val = _AsBool $val }
                            default    { } # string
                        }
                        $newRow[$v.Name] = $val
                    } else {
                        $newRow[$v.Name] = $null
                    }
                }
                $out.Add([pscustomobject]$newRow)
            }
            return ,$out.ToArray()
        }

        'MvExpand' {
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($r in $input) {
                $sub = @{ Row=$r; GroupRows=$null; Bindings=$Env.Bindings; Context=$Env.Context }
                $val = Invoke-KqlExpr $Node.Expr $sub
                if ($null -eq $val) { continue }
                if (-not ($val -is [System.Array] -or $val -is [System.Collections.IList])) { $val = @($val) }
                foreach ($x in $val) {
                    $newRow = [ordered]@{}
                    foreach ($p in $r.PSObject.Properties) {
                        if ($p.Name -ne $Node.Name) { $newRow[$p.Name] = $p.Value }
                    }
                    $newRow[$Node.Name] = $x
                    $out.Add([pscustomobject]$newRow)
                }
            }
            return ,$out.ToArray()
        }

        default { throw "Unsupported AST node $($Node.Op)" }
    }
}

function _MergeRows {
    param($Left, $Right, [string[]] $JoinKeys)
    $newRow = [ordered]@{}
    if ($null -ne $Left) {
        foreach ($p in $Left.PSObject.Properties) { $newRow[$p.Name] = $p.Value }
    }
    if ($null -ne $Right) {
        foreach ($p in $Right.PSObject.Properties) {
            $name = $p.Name
            # KQL right-side columns that collide get a "1" suffix; if it's a join key, skip the dup.
            if ($newRow.Contains($name)) {
                if ($JoinKeys -contains $name) { continue }
                $name = $name + '1'
            }
            $newRow[$name] = $p.Value
        }
    }
    return [pscustomobject]$newRow
}

# =====================================================================
# SECTION 6 - Context / data loading / public cmdlets
# =====================================================================

function New-KqlContext {
    [CmdletBinding()]
    param(
        [string] $DatabasePath = (Join-Path $PSScriptRoot 'kql_lab.db'),
        [datetime] $ReferenceTime = [datetime]::Parse('2026-04-29T14:00:00Z',
            [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
            [System.Globalization.DateTimeStyles]::AdjustToUniversal),
        [hashtable] $InMemoryTables
    )
    if (-not (Test-Path -LiteralPath $DatabasePath) -and -not $InMemoryTables) {
        throw "Database not found: $DatabasePath  (or supply -InMemoryTables)"
    }
    return [pscustomobject]@{
        DatabasePath = $DatabasePath
        ReferenceTime = $ReferenceTime
        TableCache = @{}
        InMemoryTables = if ($InMemoryTables) { $InMemoryTables } else { @{} }
    }
}

function Set-KqlReferenceTime {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)] [datetime] $ReferenceTime)
    $Context.ReferenceTime = $ReferenceTime
}

function Get-KqlTable {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)] [string] $Name)
    if ($Context.InMemoryTables.ContainsKey($Name)) { return ,$Context.InMemoryTables[$Name] }
    if ($Context.TableCache.ContainsKey($Name)) { return ,$Context.TableCache[$Name] }
    if (-not (Get-Module -Name PSSQLite)) { Import-Module PSSQLite -ErrorAction Stop }

    # Pull schema so we can coerce types coming back from SQLite (which
    # is loosely typed).  Datetimes become real [datetime], dynamic
    # JSON columns get parsed lazily on first access.
    $schema = Invoke-SqliteQuery -DataSource $Context.DatabasePath `
        -Query 'SELECT col_name, kql_type FROM __schema__ WHERE table_name = @t ORDER BY ordinal' `
        -SqlParameters @{ t = $Name }
    if (-not $schema) { throw "Unknown table: $Name" }
    $coerce = @{}
    foreach ($s in $schema) { $coerce[$s.col_name] = $s.kql_type }

    $rows = @( Invoke-SqliteQuery -DataSource $Context.DatabasePath -Query "SELECT * FROM `"$Name`"" )
    $out = New-Object 'object[]' $rows.Count
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $r = $rows[$i]
        $clean = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) {
            $name = $p.Name; $val = $p.Value
            if ([System.DBNull]::Value -eq $val) { $val = $null }
            if ($null -ne $val -and $coerce.ContainsKey($name)) {
                switch ($coerce[$name]) {
                    'datetime' {
                        try { $val = [datetime]::Parse([string]$val, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal) }
                        catch { }
                    }
                    'bool' { try { $val = [bool][int]$val } catch { } }
                    'int'  { try { $val = [int]$val } catch { } }
                    'long' { try { $val = [long]$val } catch { } }
                    'real' { try { $val = [double]$val } catch { } }
                    'dynamic' {
                        # JSON in SQLite is just text; parse to a native object so
                        # mv-expand and member access work without the user having
                        # to call parse_json() everywhere.
                        $sv = [string]$val
                        if ($sv.StartsWith('[') -or $sv.StartsWith('{')) {
                            try { $val = ConvertFrom-Json $sv -ErrorAction Stop } catch { }
                        }
                    }
                }
            }
            $clean[$name] = $val
        }
        $out[$i] = [pscustomobject]$clean
    }
    $Context.TableCache[$Name] = $out
    return ,$out
}

function Invoke-Kql {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string] $Query
    )
    # Pre-process `User:string` style annotations inside parse/extract operators.
    $rewritten = _RewriteParseTypes -Query $Query
    $tokens = Get-KqlTokens -Query $rewritten
    $ast    = ConvertFrom-KqlTokens -Tokens $tokens

    $env = @{
        Row = $null; GroupRows = $null
        Bindings = @{}; Context = $Context
    }
    $rows = Invoke-KqlAst -Node $ast -Env $env
    return ,$rows
}

# Export public functions only when loaded as a module.  Dot-sourcing the
# script (`. ./Invoke-KqlPS.ps1`) is also supported and skips the export.
if ($MyInvocation.MyCommand.ScriptBlock.Module) {
    Export-ModuleMember -Function New-KqlContext, Set-KqlReferenceTime, Get-KqlTable, Invoke-Kql
}

# SIG # Begin signature block
# MIIcCwYJKoZIhvcNAQcCoIIb/DCCG/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCgsQdbTRJYj0ak
# CCky/ufPFXsxAlSqIRsBHe4w/woMpKCCFlAwggMSMIIB+qADAgECAhAtZQe+Ow97
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
# FTAvBgkqhkiG9w0BCQQxIgQgFQ5zKHa/uOKBJnLsdeNgOVbt32dHXwyOEBRrvCpb
# bBkwDQYJKoZIhvcNAQEBBQAEggEAiyEhdyYFTL8QbrMVNIGdea/OEhQ8ycPwZ8lG
# 2DeP+2gwwX8lSyk+cz4vpv7USyojs1+1IlEg/LdGpCBj40SLjCHGi22Payi0yjIE
# a5IALTNWXJ59w6WkJDKvMLlAbVTDqdKFXx1ud14tUuxlmPcaC+8M9Qv7n6m5Ilx0
# IqJJzezWjlTMQBAjK97+SDB4j+1pVUQqlCW8oRDKaKZzJzpHptV3lBeYWiu8saQ+
# ZYsomHlfmWYrK+DXepEcGYBU+122/3vV4X816u1pVAviyudDdeBgcWDg0lvNZCdx
# O3ZGk0AP9/yu+P1RO/paeUnsgngtCWFpvPVeW3mEp2lUH0ECc6GCAyYwggMiBgkq
# hkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeV
# dGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0yNjA0MjkxNzI5MjdaMC8GCSqGSIb3DQEJBDEiBCAuFTm4
# 09aIKDBQDy/0M5PrHm8GZFZ+9bzi7wYIQJOFHTANBgkqhkiG9w0BAQEFAASCAgAF
# yn0J0OtweohttkjcaQptZ79Tf/10fnFQYikPO6NDBm3wumqX0rJ5O3psENHEwSkk
# QVu1buARgbizyoGl2AijoTyIiFhDRiTOyit7HWkxzSw02g1Y2Ab20IgnRNFGsG32
# 7iS4NwlidCtLZMdQHyqdsgd6EOHS0uLyH1YaJgObrKFAchUGDT6G2ZmeFk4ryV4X
# 47RyairAxptvHj7VqNBMkSE/RfmlOsjOPaBk9kbWCV9XYgFwkFnzEsXe2Y2GJE+G
# bOqD77FC48VWhygK9EzevrrjyCEciCkmqqHtbPXQJwYF8GgODfKFTvyYFqLAKya6
# Jo8l2JvJnk+wAml4vGq4dBfEhIrIV9XHEjIvpmZYJ8NzaJxYxp58q7Cb+oy/CzCg
# xSPk3RclLybZMYAPyy9TW/+n3ule611MqixXmh26j8hF36vBE2sAE1vvg92dovwD
# NHPdTWdzhP1qG8grd0xkTE6prw2HhR00RHH0/hUGe8yR1l5tRk4/9wiKJBOtqOpq
# nCejyzg7pIqNffivHZ18/UuTsJ2jCrlAgYlBJvDUlSTloLtrU9tdLP7wQpeyHz13
# xv4kh3TC3Idsx+sXiDGHyuHrcnjgIl994PmhR0TlJiqhtwSGD8ppKChRobU8GOwi
# YcZYybD6Lawth6x9gjWLXfw6OLsY+n0x4eZ8kkDk0Q==
# SIG # End signature block
