/* engine.js — KQL engine for the lab playground.
 *
 * Pragmatic subset of KQL, translated to SQLite SQL and executed via sql.js.
 *
 * Supported operators:
 *   where, project, project-keep, project-away, extend,
 *   summarize ... by, count, top N by, take/limit, distinct,
 *   order/sort by, let bindings (scalar only).
 *
 * Supported scalar ops:
 *   ==, !=, <, >, <=, >=, contains, !contains, contains_cs, !contains_cs,
 *   startswith, !startswith, endswith, !endswith, has, !has,
 *   in, !in, between, and, or, not.
 *
 * Supported functions:
 *   ago, now, datetime, bin, tolower, toupper, strlen, isempty,
 *   isnotempty, isnull, isnotnull, iff, strcat, count, dcount, sum,
 *   avg, min, max, countif, sumif.
 *
 * Anything outside this surface throws KqlError("unsupported: ...") with
 * a clear message — better than silently returning wrong results.
 */
(function (global) {
    'use strict';

    function KqlError(msg, pos) {
        var e = new Error(msg);
        e.name = 'KqlError';
        e.pos = pos;
        return e;
    }

    /* ============================================================
       LEXER
       ============================================================ */
    // KEYWORDS reserved purely as language structure (cannot be used as
    // identifiers or function names). 'count' is intentionally NOT here:
    // it's both a pipeline operator AND a scalar/aggregate function, so it
    // must lex as IDENT and be recognized contextually by the parser.
    var KEYWORDS = {
        where: 1, project: 1, 'project-keep': 1, 'project-away': 1,
        extend: 1, summarize: 1, by: 1, top: 1, take: 1,
        limit: 1, distinct: 1, order: 1, sort: 1, asc: 1, desc: 1,
        let: 1, true: 1, false: 1, null: 1, and: 1, or: 1, not: 1,
        between: 1, on: 1, in: 1, 'mv-expand': 1
    };

    // Pipeline operators that lex as IDENT. parseOp() consults this when it
    // can't find a KEYWORD operator. Currently just 'count', but more dual-
    // use names can be added here without breaking expression parsing.
    var IDENT_OPS = { count: 1, join: 1, parse: 1 };

    // Word-shaped operators (lex as IDENT, then promote to OP).
    var WORD_OPS = {
        contains: 1, '!contains': 1, contains_cs: 1, '!contains_cs': 1,
        startswith: 1, '!startswith': 1,
        endswith: 1, '!endswith': 1,
        has: 1, '!has': 1
    };

    // Operator tokens, longest first so the lexer matches greedy.
    var OPS = [
        '!contains_cs', '!startswith_cs', '!endswith_cs',
        '!contains', '!startswith', '!endswith', '!has',
        'contains_cs', 'startswith_cs', 'endswith_cs',
        'contains', 'startswith', 'endswith', 'has',
        '==', '!=', '<=', '>=', '<', '>', '!in', 'in',
        '+', '-', '*', '/', '%',
        '..', '.',
    ];

    function tokenize(src) {
        var tokens = [];
        var i = 0;
        var n = src.length;

        function pushTok(kind, value, pos) { tokens.push({ kind: kind, value: value, pos: pos }); }

        while (i < n) {
            var ch = src[i];

            // Whitespace
            if (/\s/.test(ch)) { i++; continue; }

            // Single-line comment // ...
            if (ch === '/' && src[i + 1] === '/') {
                while (i < n && src[i] !== '\n') i++;
                continue;
            }

            // String literal: 'foo' or "foo" with backslash escapes
            if (ch === "'" || ch === '"') {
                var quote = ch;
                var start = i;
                var s = '';
                i++;
                while (i < n && src[i] !== quote) {
                    if (src[i] === '\\' && i + 1 < n) {
                        var nx = src[i + 1];
                        if (nx === 'n') s += '\n';
                        else if (nx === 't') s += '\t';
                        else if (nx === 'r') s += '\r';
                        else s += nx;
                        i += 2;
                    } else {
                        s += src[i++];
                    }
                }
                if (i >= n) throw KqlError('unterminated string', start);
                i++; // closing quote
                pushTok('STRING', s, start);
                continue;
            }

            // Number / duration: 123, 1.5, 5m, 1h, 30s, 7d
            if (/[0-9]/.test(ch)) {
                var nstart = i;
                var num = '';
                while (i < n && /[0-9.]/.test(src[i])) num += src[i++];
                // Duration suffix?
                var suf = '';
                if (i < n && /[a-zA-Z]/.test(src[i])) {
                    while (i < n && /[a-zA-Z]/.test(src[i])) suf += src[i++];
                    if (/^(d|h|m|s|ms|microsecond|tick)$/i.test(suf)) {
                        pushTok('DURATION', { num: parseFloat(num), unit: suf.toLowerCase() }, nstart);
                        continue;
                    }
                    // Not a recognized suffix — back up
                    i -= suf.length;
                }
                pushTok('NUMBER', parseFloat(num), nstart);
                continue;
            }

            // Identifier or keyword
            if (/[a-zA-Z_]/.test(ch)) {
                var istart = i;
                while (i < n && /[a-zA-Z0-9_]/.test(src[i])) i++;
                // Look ahead for hyphenated keywords (project-keep / project-away)
                var raw = src.slice(istart, i);
                if ((raw === 'project' || raw === 'mv') && src[i] === '-') {
                    var j = i + 1;
                    while (j < n && /[a-zA-Z]/.test(src[j])) j++;
                    var hy = src.slice(istart, j);
                    if (hy === 'project-keep' || hy === 'project-away' || hy === 'mv-expand' || hy === 'mv-apply') {
                        i = j;
                        pushTok('KEYWORD', hy, istart);
                        continue;
                    }
                }
                if (WORD_OPS[raw]) pushTok('OP', raw, istart);
                else if (KEYWORDS[raw]) pushTok('KEYWORD', raw, istart);
                else pushTok('IDENT', raw, istart);
                continue;
            }

            // Multi-char operators
            var matched = false;
            for (var k = 0; k < OPS.length; k++) {
                var op = OPS[k];
                if (src.substr(i, op.length) === op) {
                    // make sure 'in', 'has' etc. aren't matched as ops if followed by ident chars
                    if (/^[a-zA-Z]/.test(op)) {
                        var prev = src[i - 1];
                        var after = src[i + op.length];
                        if ((prev && /[a-zA-Z0-9_]/.test(prev)) || (after && /[a-zA-Z0-9_]/.test(after))) continue;
                    }
                    pushTok('OP', op, i);
                    i += op.length;
                    matched = true;
                    break;
                }
            }
            if (matched) continue;

            // Single-char punctuation
            if ('|(),;[]{}=:'.indexOf(ch) >= 0) {
                pushTok('PUNCT', ch, i);
                i++;
                continue;
            }

            throw KqlError("unexpected character '" + ch + "'", i);
        }

        pushTok('EOF', null, n);
        return tokens;
    }

    /* ============================================================
       PARSER
       ============================================================ */
    function parse(tokens, source) {
        var pos = 0;

        function peek(offset) { return tokens[pos + (offset || 0)]; }
        function consume() { return tokens[pos++]; }
        function expect(kind, value) {
            var t = peek();
            if (t.kind !== kind || (value !== undefined && t.value !== value)) {
                throw KqlError("expected " + (value || kind) + ", got '" + t.value + "'", t.pos);
            }
            return consume();
        }
        function check(kind, value) {
            var t = peek();
            return t.kind === kind && (value === undefined || t.value === value);
        }
        function checkAny(kind, values) {
            var t = peek();
            if (t.kind !== kind) return false;
            for (var i = 0; i < values.length; i++) if (t.value === values[i]) return true;
            return false;
        }
        function eat(kind, value) {
            if (check(kind, value)) return consume();
            return null;
        }

        // --- Top level: optional let-bindings, then a single pipeline ---
        function parseScript() {
            var lets = [];
            while (check('KEYWORD', 'let')) {
                consume();
                var name = expect('IDENT').value;
                expect('PUNCT', '=');
                // Tabular vs scalar: if next is IDENT followed by '|', it's a
                // pipeline binding (let X = SomeTable | ...). Anything else is
                // a scalar expression.
                var t0 = peek(), t1 = peek(1);
                var isTabular = t0 && t0.kind === 'IDENT'
                             && t1 && t1.kind === 'PUNCT' && t1.value === '|';
                if (isTabular) {
                    var pipe1 = parsePipeline();
                    expect('PUNCT', ';');
                    lets.push({ name: name, pipeline: pipe1 });
                } else {
                    var expr = parseExpr();
                    expect('PUNCT', ';');
                    lets.push({ name: name, expr: expr });
                }
            }
            var pipe = parsePipeline();
            eat('PUNCT', ';');
            return { lets: lets, pipeline: pipe };
        }

        function parsePipeline() {
            // Source: either a bare table identifier or a `union (...), (...)`.
            var node;
            if (check('IDENT') && peek().value === 'union') {
                consume(); // 'union'
                var subs = [];
                do {
                    // Optional kind=X / isfuzzy=Y / withsource=... -- ignored.
                    while (check('IDENT') && /^(kind|isfuzzy|withsource)$/.test(peek().value)) {
                        consume();
                        if (check('PUNCT', '=')) {
                            consume();
                            // Skip the value token.
                            if (check('IDENT') || check('STRING') || check('NUMBER')) consume();
                        }
                    }
                    if (check('PUNCT', '(')) {
                        consume();
                        subs.push(parsePipeline());
                        expect('PUNCT', ')');
                    } else {
                        // Bare table name in union arg.
                        subs.push({ source: expect('IDENT').value, ops: [] });
                    }
                } while (eat('PUNCT', ','));
                node = { union: subs, ops: [] };
            } else {
                var srcTok = expect('IDENT');
                node = { source: srcTok.value, ops: [] };
            }
            while (check('PUNCT', '|')) {
                consume();
                node.ops.push(parseOp());
            }
            return node;
        }

        function parseOp() {
            var t = peek();
            // Dual-use IDENT-as-operator (e.g., 'count', 'join', 'parse').
            if (t.kind === 'IDENT' && IDENT_OPS[t.value]) {
                if (t.value === 'count') { consume(); return { kind: 'count' }; }
                if (t.value === 'join')  { consume(); return parseJoin(); }
                if (t.value === 'parse') { consume(); return parseParse(); }
            }
            if (t.kind !== 'KEYWORD') throw KqlError("expected an operator after '|', got '" + t.value + "'", t.pos);
            switch (t.value) {
                case 'where':         consume(); return { kind: 'where', cond: parseExpr() };
                case 'project':       consume(); return { kind: 'project',     cols: parseProjectList() };
                case 'project-keep':  consume(); return { kind: 'projectKeep', cols: parseIdentList() };
                case 'project-away':  consume(); return { kind: 'projectAway', cols: parseIdentList() };
                case 'extend':        consume(); return { kind: 'extend', exprs: parseProjectList() };
                case 'summarize':     consume(); return parseSummarize();
                case 'top':           consume(); return parseTop();
                case 'take':
                case 'limit':         consume(); return { kind: 'take', n: parseExpr() };
                case 'distinct':      consume(); return { kind: 'distinct', cols: parseIdentList() };
                case 'order':
                case 'sort':          consume(); expect('KEYWORD', 'by'); return { kind: 'order', cols: parseOrderList() };
                case 'mv-expand':     consume(); return parseMvExpand();
                default:
                    throw KqlError("unsupported operator: " + t.value, t.pos);
            }
        }

        function parseJoin() {
            // join [kind=K] (rhsPipelineOrTable) on col1 [, col2, ...]
            var jkind = 'inner';
            // Optional kind=K. 'kind' lexes as IDENT.
            if (check('IDENT') && peek().value === 'kind') {
                consume();
                expect('PUNCT', '=');
                jkind = (peek().kind === 'IDENT' ? consume().value : expect('KEYWORD').value);
            }
            // RHS source: either a parenthesized pipeline, or a bare table/CTE name.
            var rhs;
            if (check('PUNCT', '(')) {
                consume();
                rhs = parsePipeline();
                expect('PUNCT', ')');
            } else {
                rhs = { source: expect('IDENT').value, ops: [] };
            }
            expect('KEYWORD', 'on');
            var cols = [];
            do { cols.push(expect('IDENT').value); } while (eat('PUNCT', ','));
            return { kind: 'join', joinKind: jkind, rhs: rhs, cols: cols };
        }

        function parseParse() {
            // parse <srcCol> with [kind=...] "lit1" Var1 "lit2" Var2 ... [*]
            // Optional leading 'kind=simple|relaxed|regex' is ignored here.
            var srcCol = expect('IDENT').value;
            // `with` lexes as IDENT (not in KEYWORDS); accept either form.
            var w = peek();
            if (w && (w.kind === 'IDENT' || w.kind === 'KEYWORD') && w.value === 'with') consume();
            else throw KqlError("parse: expected 'with' after column name, got '" + (w && w.value) + "'", w && w.pos);
            // Optional `kind=simple|relaxed|regex`
            if (check('IDENT') && peek().value === 'kind') {
                consume();
                expect('PUNCT', '=');
                if (check('IDENT')) consume();
            }
            // Sequence: alternating string literal then ident (with optional :type stripped
            // already by the rewriter). Final element may be '*' meaning "swallow rest".
            var parts = [];   // [{kind:'lit', value}|{kind:'var', name}|{kind:'star'}]
            while (true) {
                var tk = peek();
                if (tk.kind === 'STRING') {
                    consume();
                    parts.push({ kind: 'lit', value: tk.value });
                } else if (tk.kind === 'IDENT') {
                    consume();
                    var typ = null;
                    if (check('PUNCT', ':')) {
                        consume();
                        // type ident: string|int|long|real|datetime|bool|guid|dynamic|timespan
                        var tt = peek();
                        if (tt && tt.kind === 'IDENT') { consume(); typ = tt.value.toLowerCase(); }
                    }
                    parts.push({ kind: 'var', name: tk.value, type: typ });
                } else if (tk.kind === 'OP' && tk.value === '*') {
                    consume();
                    parts.push({ kind: 'star' });
                    break;
                } else {
                    break;
                }
            }
            return { kind: 'parse', srcCol: srcCol, parts: parts };
        }

        function parseMvExpand() {
            // mv-expand [Var =] SrcCol [to typeof(...)]   (we ignore the to-typeof clause)
            // First IDENT may be either the var name (with `=`) or the source column.
            var firstName = expect('IDENT').value;
            var varName, srcExpr;
            if (check('PUNCT', '=')) {
                consume();
                varName = firstName;
                // Source can be an expression (most often an ident, occasionally a function call).
                srcExpr = parseExpr();
            } else {
                varName = firstName;
                srcExpr = { kind: 'ident', name: firstName };
            }
            // Optional `to typeof(<type>)` -- consume and discard.
            if (check('IDENT') && peek().value === 'to') {
                consume();
                if (check('IDENT') && peek().value === 'typeof') { consume(); }
                if (check('PUNCT', '(')) {
                    consume();
                    if (check('IDENT')) consume();
                    expect('PUNCT', ')');
                }
            }
            return { kind: 'mv-expand', varName: varName, srcExpr: srcExpr };
        }

        function parseProjectList() {
            var items = [];
            do {
                // Optional alias=expr or just an expression
                var first = peek();
                if (first.kind === 'IDENT' && peek(1) && peek(1).kind === 'PUNCT' && peek(1).value === '=') {
                    var alias = consume().value;
                    consume(); // '='
                    var e = parseExpr();
                    items.push({ alias: alias, expr: e });
                } else {
                    var ex = parseExpr();
                    items.push({ alias: ex.kind === 'ident' ? ex.name : null, expr: ex });
                }
            } while (eat('PUNCT', ','));
            return items;
        }

        function parseIdentList() {
            var ids = [];
            do { ids.push(expect('IDENT').value); } while (eat('PUNCT', ','));
            return ids;
        }

        function parseOrderList() {
            var list = [];
            do {
                var col = expect('IDENT').value;
                var dir = 'desc';
                if (eat('KEYWORD', 'asc')) dir = 'asc';
                else if (eat('KEYWORD', 'desc')) dir = 'desc';
                list.push({ col: col, dir: dir });
            } while (eat('PUNCT', ','));
            return list;
        }

        function parseSummarize() {
            // summarize Aggs...  by  cols...
            var aggs = parseProjectList();
            var by = [];
            if (eat('KEYWORD', 'by')) {
                do {
                    var first = peek();
                    if (first.kind === 'IDENT' && peek(1) && peek(1).kind === 'PUNCT' && peek(1).value === '=') {
                        var alias = consume().value;
                        consume();
                        by.push({ alias: alias, expr: parseExpr() });
                    } else {
                        var ex = parseExpr();
                        var alias = ex.kind === 'ident' ? ex.name : null;
                        // KQL: `summarize ... by bin(TimeGenerated, ...)` names
                        // the output column TimeGenerated (the inner ident).
                        if (!alias && ex.kind === 'call' && ex.name &&
                                ex.name.toLowerCase() === 'bin' &&
                                ex.args && ex.args[0] && ex.args[0].kind === 'ident') {
                            alias = ex.args[0].name;
                        }
                        by.push({ alias: alias, expr: ex });
                    }
                } while (eat('PUNCT', ','));
            }
            return { kind: 'summarize', aggs: aggs, by: by };
        }

        function parseTop() {
            var n = parseExpr();
            expect('KEYWORD', 'by');
            var col = expect('IDENT').value;
            var dir = 'desc';
            if (eat('KEYWORD', 'asc')) dir = 'asc';
            else if (eat('KEYWORD', 'desc')) dir = 'desc';
            return { kind: 'top', n: n, col: col, dir: dir };
        }

        // --- Expressions: precedence-climbing recursive descent ---
        function parseExpr()   { return parseOr(); }
        function parseOr()     { return parseBin('KEYWORD', ['or'], parseAnd); }
        function parseAnd()    { return parseBin('KEYWORD', ['and'], parseNot); }
        function parseNot() {
            if (eat('KEYWORD', 'not')) return { kind: 'unop', op: 'not', expr: parseNot() };
            return parseCompare();
        }

        function parseBin(kind, values, next) {
            var left = next();
            while (true) {
                var t = peek();
                if (t.kind !== kind) break;
                var matched = false;
                for (var i = 0; i < values.length; i++) if (t.value === values[i]) { matched = true; break; }
                if (!matched) break;
                consume();
                left = { kind: 'binop', op: t.value, left: left, right: next() };
            }
            return left;
        }

        // Compare operators include both OP tokens (==, contains, ...) and KEYWORD 'in'/'!in'/'between'
        var CMP_OPS = [
            '==', '!=', '<', '>', '<=', '>=',
            'contains', '!contains', 'contains_cs', '!contains_cs',
            'startswith', '!startswith', 'endswith', '!endswith',
            'has', '!has'
        ];
        function parseCompare() {
            var left = parseAdd();
            // 'between (a .. b)'
            if (check('KEYWORD', 'between')) {
                consume();
                expect('PUNCT', '(');
                var lo = parseAdd();
                expect('OP', '..');
                var hi = parseAdd();
                expect('PUNCT', ')');
                return { kind: 'between', expr: left, lo: lo, hi: hi };
            }
            // 'in'/'!in' (...)
            if (checkAny('KEYWORD', ['in']) || checkAny('OP', ['in', '!in'])) {
                var negated = false;
                var t = consume();
                if (t.value === '!in') negated = true;
                expect('PUNCT', '(');
                var values = [];
                if (!check('PUNCT', ')')) {
                    do { values.push(parseAdd()); } while (eat('PUNCT', ','));
                }
                expect('PUNCT', ')');
                return { kind: 'in', expr: left, values: values, negated: negated };
            }
            // Standard binary compare
            var pk = peek();
            if (pk.kind === 'OP' && CMP_OPS.indexOf(pk.value) >= 0) {
                consume();
                var right = parseAdd();
                return { kind: 'binop', op: pk.value, left: left, right: right };
            }
            return left;
        }

        function parseAdd() {
            var left = parseMul();
            while (true) {
                var t = peek();
                if (t.kind === 'OP' && (t.value === '+' || t.value === '-')) {
                    consume();
                    left = { kind: 'binop', op: t.value, left: left, right: parseMul() };
                } else break;
            }
            return left;
        }
        function parseMul() {
            var left = parseUnary();
            while (true) {
                var t = peek();
                if (t.kind === 'OP' && (t.value === '*' || t.value === '/' || t.value === '%')) {
                    consume();
                    left = { kind: 'binop', op: t.value, left: left, right: parseUnary() };
                } else break;
            }
            return left;
        }
        function parseUnary() {
            if (check('OP', '-')) { consume(); return { kind: 'unop', op: '-', expr: parsePrimary() }; }
            return parsePrimary();
        }

        function parsePrimary() {
            var t = peek();
            if (t.kind === 'STRING')   { consume(); return { kind: 'string', value: t.value }; }
            if (t.kind === 'NUMBER')   { consume(); return { kind: 'number', value: t.value }; }
            if (t.kind === 'DURATION') { consume(); return { kind: 'duration', num: t.value.num, unit: t.value.unit }; }
            if (t.kind === 'KEYWORD' && (t.value === 'true' || t.value === 'false')) {
                consume(); return { kind: 'bool', value: t.value === 'true' };
            }
            if (t.kind === 'KEYWORD' && t.value === 'null') {
                consume(); return { kind: 'null' };
            }
            if (t.kind === 'PUNCT' && t.value === '(') {
                consume();
                var e = parseExpr();
                expect('PUNCT', ')');
                return e;
            }
            if (t.kind === 'IDENT') {
                consume();
                if (check('PUNCT', '(')) {
                    consume();
                    // Special case: datetime(YYYY-MM-DD[Thh:mm:ssZ]) -- KQL allows
                    // a bareword datetime literal here. Reconstruct it from the
                    // raw token sequence between the parens and synthesize a
                    // string arg. Bail to normal parsing if it doesn't look right.
                    var lname = t.value.toLowerCase();
                    if ((lname === 'datetime' || lname === 'todatetime') && peek() && peek().kind === 'NUMBER' && source) {
                        // Reconstruct from raw source: scan forward until matching ')'
                        var startPos = peek().pos;
                        var depth = 1;
                        var endPos = startPos;
                        while (endPos < source.length) {
                            var ch = source[endPos];
                            if (ch === '(') depth++;
                            else if (ch === ')') { depth--; if (depth === 0) break; }
                            endPos++;
                        }
                        var raw = source.slice(startPos, endPos).trim();
                        if (/^\d{4}-\d{2}-\d{2}/.test(raw)) {
                            // Advance token cursor past everything inside the parens.
                            while (pos < tokens.length && peek().pos < endPos) consume();
                            expect('PUNCT', ')');
                            return { kind: 'call', name: t.value, args: [{ kind: 'string', value: raw }] };
                        }
                    }
                    var args = [];
                    if (!check('PUNCT', ')')) {
                        do {
                            // arg_max/arg_min special form: `*` denotes "all
                            // columns of the matching row". Captured as a
                            // sentinel AST node and handled in translate.
                            if (check('OP', '*')) {
                                consume();
                                args.push({ kind: 'star' });
                            } else {
                                args.push(parseExpr());
                            }
                        } while (eat('PUNCT', ','));
                    }
                    expect('PUNCT', ')');
                    return _applyFields({ kind: 'call', name: t.value, args: args });
                }
                return _applyFields({ kind: 'ident', name: t.value });
            }
            throw KqlError("unexpected token '" + t.value + "'", t.pos);
        }

        // Post-fix dotted accessors: turn `LocationDetails.countryOrRegion`
        // into a `field` AST node that the translator emits as json_extract.
        // The lexer treats '.' as an OP token (used elsewhere for floats /
        // ranges); we only consume it when it's followed by an IDENT here.
        function _applyFields(node) {
            while (check('OP', '.') && peek(1) && peek(1).kind === 'IDENT') {
                consume();              // '.'
                var nm = consume().value;
                node = { kind: 'field', expr: node, name: nm };
            }
            return node;
        }

        return parseScript();
    }

    /* ============================================================
       TRANSLATOR — KQL AST -> SQLite SQL
       ============================================================ */
    var KQL2SQL_OP = {
        '==': '=',  '!=': '!=',  '<': '<',  '>': '>',  '<=': '<=',  '>=': '>=',
        '+': '+',   '-': '-',    '*': '*',  '/': '/',  '%': '%',
        'and': 'AND', 'or': 'OR'
    };

    function quoteIdent(name) { return '"' + name.replace(/"/g, '""') + '"'; }
    function escapeStr(s) { return "'" + String(s).replace(/'/g, "''") + "'"; }
    function escapeLike(s) { return String(s).replace(/[%_\\]/g, '\\$&'); }

    function translate(script, scope) {
        // scope: { lets: { name -> sqlExpr }, currentSchema: { col -> kqlType } }
        scope = scope || {};
        scope.lets = scope.lets || {};

        // Resolve let-bindings: scalar -> stash SQL expr, tabular -> emit CTE.
        var ctes = [];
        if (script.lets) {
            for (var i = 0; i < script.lets.length; i++) {
                var L = script.lets[i];
                if (L.pipeline) {
                    var subSql = translate({ lets: [], pipeline: L.pipeline }, scope);
                    ctes.push(quoteIdent(L.name) + ' AS (' + subSql + ')');
                } else {
                    scope.lets[L.name] = exprSql(L.expr, scope);
                }
            }
        }

        var p = script.pipeline || script;
        var sql;
        if (p.union) {
            var parts = p.union.map(function (sub) {
                return translate({ lets: [], pipeline: sub }, scope);
            });
            sql = '(' + parts.join(' UNION ALL ') + ')';
        } else {
            sql = 'SELECT * FROM ' + quoteIdent(p.source);
        }
        var aliasNum = 0;

        for (var k = 0; k < p.ops.length; k++) {
            var op = p.ops[k];
            var a = 't' + aliasNum++;
            switch (op.kind) {
                case 'where':
                    sql = 'SELECT * FROM (' + sql + ') AS ' + a + ' WHERE ' + exprSql(op.cond, scope);
                    break;
                case 'project':
                    sql = 'SELECT ' + projectListSql(op.cols, scope) + ' FROM (' + sql + ') AS ' + a;
                    break;
                case 'projectKeep':
                    sql = 'SELECT ' + op.cols.map(quoteIdent).join(', ') + ' FROM (' + sql + ') AS ' + a;
                    break;
                case 'projectAway':
                    // Resolve via "SELECT * minus columns" — we don't know full columns without schema,
                    // so we emit a comment. The runtime handles this by post-filtering.
                    sql = 'SELECT * FROM (' + sql + ') AS ' + a + ' /*PROJECT_AWAY:' + op.cols.join(',') + '*/';
                    break;
                case 'extend': {
                    // Extend keeps all original columns plus the new ones. SQLite needs all columns named.
                    var extendList = op.exprs.map(function (e) {
                        return exprSql(e.expr, scope) + ' AS ' + quoteIdent(e.alias || '_ext');
                    }).join(', ');
                    sql = 'SELECT *, ' + extendList + ' FROM (' + sql + ') AS ' + a;
                    break;
                }
                case 'summarize': {
                    // Special form: summarize arg_max(orderCol, *) by groupCols
                    // returns one row per group with all original columns from
                    // the row that has max(orderCol). Emit ROW_NUMBER() over
                    // a partition; post-strip the helper column.
                    var argstar = null;
                    if (op.aggs.length === 1) {
                        var e0 = op.aggs[0].expr;
                        if (e0.kind === 'call' && (e0.name === 'arg_max' || e0.name === 'arg_min')
                                && e0.args.length === 2
                                && e0.args[1].kind === 'star') {
                            argstar = { dir: e0.name === 'arg_max' ? 'DESC' : 'ASC', orderCol: exprSql(e0.args[0], scope) };
                        }
                    }
                    if (argstar) {
                        var partition = op.by.map(function (e) { return exprSql(e.expr, scope); }).join(', ');
                        var partClause = partition ? 'PARTITION BY ' + partition + ' ' : '';
                        sql = 'SELECT * FROM (SELECT *, ROW_NUMBER() OVER (' + partClause +
                              'ORDER BY ' + argstar.orderCol + ' ' + argstar.dir + ') AS "_rn" FROM (' +
                              sql + ') AS ' + a + ') AS ' + a + 'r WHERE "_rn" = 1 /*PROJECT_AWAY:_rn*/';
                        break;
                    }
                    var aggList = op.aggs.map(function (e) {
                        // KQL auto-names a bare aggregate call `<name>_`
                        // (e.g. `count()` -> `count_`, `dcount(x)` -> `dcount_`).
                        var defaultAlias = '_agg';
                        if (!e.alias && e.expr.kind === 'call' && e.expr.name) {
                            defaultAlias = e.expr.name + '_';
                        }
                        return exprSql(e.expr, scope) + ' AS ' + quoteIdent(e.alias || defaultAlias);
                    });
                    var byList = op.by.map(function (e) {
                        return exprSql(e.expr, scope) + ' AS ' + quoteIdent(e.alias || '_by');
                    });
                    var cols = byList.concat(aggList).join(', ');
                    sql = 'SELECT ' + cols + ' FROM (' + sql + ') AS ' + a;
                    if (op.by.length) {
                        sql += ' GROUP BY ' + op.by.map(function (e) { return exprSql(e.expr, scope); }).join(', ');
                    }
                    break;
                }
                case 'count':
                    sql = 'SELECT COUNT(*) AS Count FROM (' + sql + ') AS ' + a;
                    break;
                case 'top': {
                    var col = quoteIdent(op.col);
                    var dir = op.dir === 'asc' ? 'ASC' : 'DESC';
                    sql = 'SELECT * FROM (' + sql + ') AS ' + a +
                          ' ORDER BY ' + col + ' ' + dir +
                          ' LIMIT ' + exprSql(op.n, scope);
                    break;
                }
                case 'take':
                    sql = 'SELECT * FROM (' + sql + ') AS ' + a + ' LIMIT ' + exprSql(op.n, scope);
                    break;
                case 'distinct':
                    sql = 'SELECT DISTINCT ' + op.cols.map(quoteIdent).join(', ') + ' FROM (' + sql + ') AS ' + a;
                    break;
                case 'order': {
                    var ord = op.cols.map(function (c) {
                        return quoteIdent(c.col) + ' ' + (c.dir === 'asc' ? 'ASC' : 'DESC');
                    }).join(', ');
                    sql = 'SELECT * FROM (' + sql + ') AS ' + a + ' ORDER BY ' + ord;
                    break;
                }
                case 'mv-expand': {
                    // Cross-join with json_each over the dynamic column.
                    // SQLite json_each yields rows {key, value, type, ...} for each
                    // array/object element. We project the original row's columns
                    // plus j.value AS <varName>. If the var is the same name as the
                    // source column, KQL semantics REPLACE the source with the
                    // expanded element rather than adding a new column.
                    var srcSql = exprSql(op.srcExpr, scope);
                    sql = "SELECT t.*, j.value AS " + quoteIdent(op.varName) +
                          " FROM (" + sql + ") AS t, json_each(" + srcSql + ") AS j";
                    break;
                }
                case 'parse': {
                    // Build a SQL expression for each var by carving the source column.
                    // For each Var with leading lit `L_before` and trailing lit `L_after`:
                    //   start = INSTR(src, L_before) + LEN(L_before)
                    //   if L_after present: len = INSTR(SUBSTR(src, start), L_after) - 1
                    //   else: take rest of string (NULL length to end)
                    var src1 = quoteIdent(op.srcCol);
                    var assigns = [];
                    var prevLit = null;
                    for (var pi = 0; pi < op.parts.length; pi++) {
                        var part = op.parts[pi];
                        if (part.kind === 'lit') { prevLit = part.value; continue; }
                        if (part.kind === 'star') break;
                        if (part.kind !== 'var') continue;
                        // find next lit (lookahead)
                        var nextLit = null;
                        for (var pj = pi + 1; pj < op.parts.length; pj++) {
                            if (op.parts[pj].kind === 'lit') { nextLit = op.parts[pj].value; break; }
                            if (op.parts[pj].kind === 'star') break;
                        }
                        var litB = prevLit == null ? '' : prevLit;
                        var litBSql = escapeStr(litB);
                        var startExpr = 'INSTR(' + src1 + ', ' + litBSql + ') + ' + litB.length;
                        var bodySql;
                        if (nextLit != null) {
                            var litASql = escapeStr(nextLit);
                            bodySql =
                                'CASE WHEN INSTR(' + src1 + ', ' + litBSql + ')=0 THEN NULL ELSE ' +
                                'SUBSTR(SUBSTR(' + src1 + ', ' + startExpr + '), 1, ' +
                                'NULLIF(INSTR(SUBSTR(' + src1 + ', ' + startExpr + '), ' + litASql + ') - 1, -1)) END';
                        } else {
                            bodySql = 'CASE WHEN INSTR(' + src1 + ', ' + litBSql + ')=0 THEN NULL ELSE ' +
                                      'SUBSTR(' + src1 + ', ' + startExpr + ') END';
                        }
                        // Apply type cast if a `:type` annotation was present.
                        // SQLite CAST AS INTEGER parses leading digit prefix, so
                        // `Port:int` extracts "40738" from "40738 ssh2".
                        if (part.type === 'int' || part.type === 'long') {
                            bodySql = 'CAST(' + bodySql + ' AS INTEGER)';
                        } else if (part.type === 'real' || part.type === 'double') {
                            bodySql = 'CAST(' + bodySql + ' AS REAL)';
                        }
                        assigns.push(bodySql + ' AS ' + quoteIdent(part.name));
                    }
                    if (assigns.length === 0) {
                        // Nothing to extract; pass-through.
                        sql = 'SELECT * FROM (' + sql + ') AS ' + a;
                    } else {
                        sql = 'SELECT *, ' + assigns.join(', ') + ' FROM (' + sql + ') AS ' + a;
                    }
                    break;
                }
                case 'join': {
                    var rhsSql = translate({ lets: [], pipeline: op.rhs }, scope);
                    var colList = op.cols.map(quoteIdent).join(', ');
                    if (op.joinKind === 'leftanti') {
                        var conds = op.cols.map(function (c) {
                            return 'L.' + quoteIdent(c) + ' = R.' + quoteIdent(c);
                        }).join(' AND ');
                        sql = 'SELECT L.* FROM (' + sql + ') AS L WHERE NOT EXISTS (SELECT 1 FROM (' +
                              rhsSql + ') AS R WHERE ' + conds + ')';
                    } else if (op.joinKind === 'leftsemi') {
                        var conds2 = op.cols.map(function (c) {
                            return 'L.' + quoteIdent(c) + ' = R.' + quoteIdent(c);
                        }).join(' AND ');
                        sql = 'SELECT L.* FROM (' + sql + ') AS L WHERE EXISTS (SELECT 1 FROM (' +
                              rhsSql + ') AS R WHERE ' + conds2 + ')';
                    } else if (op.joinKind === 'leftouter') {
                        sql = 'SELECT * FROM (' + sql + ') AS L LEFT JOIN (' + rhsSql + ') AS R USING (' + colList + ')';
                    } else {
                        // inner (KQL default 'innerunique' close enough for our subset)
                        sql = 'SELECT * FROM (' + sql + ') AS L INNER JOIN (' + rhsSql + ') AS R USING (' + colList + ')';
                    }
                    break;
                }
                default:
                    throw KqlError('unsupported pipeline op: ' + op.kind);
            }
        }

        if (ctes.length) sql = 'WITH ' + ctes.join(', ') + ' ' + sql;
        return sql;
    }

    function projectListSql(items, scope) {
        return items.map(function (e) {
            var ex = exprSql(e.expr, scope);
            if (e.alias && e.alias !== ex.replace(/^"|"$/g, '')) {
                return ex + ' AS ' + quoteIdent(e.alias);
            }
            // bare ident — emit as ident, no AS needed
            if (e.expr.kind === 'ident') return quoteIdent(e.expr.name);
            return ex + (e.alias ? ' AS ' + quoteIdent(e.alias) : '');
        }).join(', ');
    }

    function exprSql(node, scope) {
        switch (node.kind) {
            case 'string':   return escapeStr(node.value);
            case 'number':   return String(node.value);
            case 'bool':     return node.value ? '1' : '0';
            case 'null':     return 'NULL';
            case 'ident':    return resolveIdent(node.name, scope);
            case 'duration': return durationSeconds(node) + '';
            case 'unop':
                if (node.op === '-')   return '(-' + exprSql(node.expr, scope) + ')';
                if (node.op === 'not') return '(NOT ' + exprSql(node.expr, scope) + ')';
                throw KqlError('unsupported unary op ' + node.op);
            case 'binop':    return binopSql(node, scope);
            case 'call':     return callSql(node, scope);
            case 'field': {
                // Build a json_extract path. Handle chained .a.b.c by walking
                // back through nested 'field' nodes.
                var path = [];
                var cur = node;
                while (cur.kind === 'field') {
                    path.unshift(cur.name);
                    cur = cur.expr;
                }
                var base = exprSql(cur, scope);
                return "json_extract(" + base + ", '$." + path.join('.') + "')";
            }
            case 'in':       return inSql(node, scope);
            case 'between':
                return '(' + exprSql(node.expr, scope) + ' BETWEEN ' + exprSql(node.lo, scope) +
                       ' AND ' + exprSql(node.hi, scope) + ')';
        }
        throw KqlError('unsupported expr kind: ' + node.kind);
    }

    function resolveIdent(name, scope) {
        if (scope && scope.lets && scope.lets.hasOwnProperty(name)) return '(' + scope.lets[name] + ')';
        return quoteIdent(name);
    }

    // Heuristic: walk every schema-defined table and ask whether `name` is
    // registered as a datetime column anywhere. Used by binopSql to reject
    // 'datetime > "..."' style accidents that SQLite would silently lex-
    // compare and pass.
    function _isDatetimeColumn(name) {
        var Sch = (typeof window !== 'undefined' && window.KqlSchema)
               || (typeof global !== 'undefined' && global && global.KqlSchema)
               || null;
        if (!Sch) return false;
        var names = Object.keys(Sch);
        for (var i = 0; i < names.length; i++) {
            var t = Sch[names[i]];
            if (!t || !t.columns) continue;
            for (var j = 0; j < t.columns.length; j++) {
                if (t.columns[j].name === name && t.columns[j].type === 'datetime') return true;
            }
        }
        return false;
    }

    function binopSql(node, scope) {
        var op = node.op;
        // Reject comparing a datetime-typed column to a bare string literal.
        // Real Kusto raises a type error; SQLite would silently lex-compare
        // TEXT and "succeed" for the wrong reason -- e.g. TimeGenerated >
        // "2026-04-25" passes every '2026-04-29T...Z' row because 'T' (84)
        // > '-' lexicographically. Force an explicit datetime() wrap.
        if ((op === '>' || op === '<' || op === '>=' || op === '<=' || op === '==' || op === '!=') &&
                node.left  && node.left.kind  === 'ident' &&
                node.right && node.right.kind === 'string' &&
                _isDatetimeColumn(node.left.name)) {
            throw KqlError("type error: '" + node.left.name + "' is datetime; wrap the right-hand side in datetime(...) (e.g. datetime(" + node.right.value + "))");
        }
        var L = exprSql(node.left, scope);
        var R = exprSql(node.right, scope);
        // Datetime subtraction: text-stored TimeGenerated columns can't be
        // subtracted directly (SQLite returns 0 for non-numeric strings).
        // Heuristic: if both operands are idents (column refs), assume both
        // are datetime-text and convert via JULIANDAY -> seconds delta. KQL
        // duration values are also represented in seconds in our subset,
        // so `<a> - <b> <= 5m` lines up because 5m -> 300 seconds.
        if (op === '-' && node.left.kind === 'ident' && node.right.kind === 'ident') {
            return '((JULIANDAY(' + L + ') - JULIANDAY(' + R + ')) * 86400)';
        }
        if (KQL2SQL_OP[op]) return '(' + L + ' ' + KQL2SQL_OP[op] + ' ' + R + ')';

        // String predicates - case-insensitive by default in KQL
        var likeStr = function (val, pattern) {
            return '(LOWER(CAST(' + L + " AS TEXT)) LIKE LOWER(" + pattern + ") ESCAPE '\\')";
        };
        var rawString = function (n) {
            if (n.kind === 'string') return n.value;
            return null;
        };
        var rs = rawString(node.right);

        switch (op) {
            case 'contains':
                if (rs !== null) return likeStr(L, escapeStr('%' + escapeLike(rs) + '%'));
                return '(INSTR(LOWER(CAST(' + L + ' AS TEXT)), LOWER(CAST(' + R + ' AS TEXT))) > 0)';
            case '!contains':
                if (rs !== null) return '(NOT ' + likeStr(L, escapeStr('%' + escapeLike(rs) + '%')) + ')';
                return '(INSTR(LOWER(CAST(' + L + ' AS TEXT)), LOWER(CAST(' + R + ' AS TEXT))) = 0)';
            case 'contains_cs':
                if (rs !== null) return '(CAST(' + L + ' AS TEXT) LIKE ' + escapeStr('%' + escapeLike(rs) + '%') + " ESCAPE '\\')";
                return '(INSTR(CAST(' + L + ' AS TEXT), CAST(' + R + ' AS TEXT)) > 0)';
            case '!contains_cs':
                if (rs !== null) return '(CAST(' + L + ' AS TEXT) NOT LIKE ' + escapeStr('%' + escapeLike(rs) + '%') + " ESCAPE '\\')";
                return '(INSTR(CAST(' + L + ' AS TEXT), CAST(' + R + ' AS TEXT)) = 0)';
            case 'startswith':
                if (rs !== null) return likeStr(L, escapeStr(escapeLike(rs) + '%'));
                break;
            case '!startswith':
                if (rs !== null) return '(NOT ' + likeStr(L, escapeStr(escapeLike(rs) + '%')) + ')';
                break;
            case 'endswith':
                if (rs !== null) return likeStr(L, escapeStr('%' + escapeLike(rs)));
                break;
            case '!endswith':
                if (rs !== null) return '(NOT ' + likeStr(L, escapeStr('%' + escapeLike(rs))) + ')';
                break;
            case 'has':
                // True term match via custom kql_has() registered in runtime.js.
                // Old space-padding hack failed for `-EncodedCommand`,
                // `mimikatz.exe`, etc. Term boundaries = non-[A-Za-z0-9_].
                if (rs !== null) {
                    return "(kql_has(CAST(" + L + " AS TEXT), " + escapeStr(rs) + ") = 1)";
                }
                break;
            case '!has':
                if (rs !== null) {
                    return "(kql_has(CAST(" + L + " AS TEXT), " + escapeStr(rs) + ") = 0)";
                }
                break;
        }
        throw KqlError("unsupported operator '" + op + "' (or RHS must be a literal string)");
    }

    function inSql(node, scope) {
        var L = exprSql(node.expr, scope);
        if (node.values.length === 0) return node.negated ? '1=1' : '0=1';
        var vs = node.values.map(function (v) { return exprSql(v, scope); }).join(', ');
        return '(' + L + (node.negated ? ' NOT IN (' : ' IN (') + vs + '))';
    }

    function durationSeconds(node) {
        var n = node.num;
        switch (node.unit) {
            case 'd': return n * 86400;
            case 'h': return n * 3600;
            case 'm': return n * 60;
            case 's': return n;
            case 'ms': return n / 1000;
            default: return n;
        }
    }

    /* ---- Function calls ---- */
    function callSql(node, scope) {
        var name = node.name.toLowerCase();
        var args = node.args.map(function (a) { return exprSql(a, scope); });
        switch (name) {
            // Time
            case 'now':       return "DATETIME('now')";
            case 'ago': {
                if (node.args.length !== 1) throw KqlError("ago() expects 1 arg");
                if (node.args[0].kind === 'duration') {
                    var s = durationSeconds(node.args[0]);
                    return "DATETIME('now', '" + (-s) + " seconds')";
                }
                // Generic: subtract seconds (assumes arg is seconds)
                return "DATETIME('now', '-' || (" + args[0] + ") || ' seconds')";
            }
            case 'datetime': {
                if (node.args.length !== 1 || node.args[0].kind !== 'string') {
                    throw KqlError("datetime() expects a single string literal");
                }
                return escapeStr(node.args[0].value);
            }
            case 'bin': {
                if (node.args.length !== 2) throw KqlError("bin() expects 2 args");
                var col = args[0];
                var grain = node.args[1];
                if (grain.kind !== 'duration') throw KqlError("bin() second arg must be a duration");
                var gs = durationSeconds(grain);
                // Bin to nearest gs-second boundary, then emit ISO 8601 with T/Z
                // so the output matches stored TimeGenerated format ('...T...Z').
                // SQLite's default DATETIME() yields '2026-04-29 08:15:00' which
                // breaks both row-content compares and downstream filters.
                return "STRFTIME('%Y-%m-%dT%H:%M:%SZ', CAST(STRFTIME('%s'," + col + ")/" + gs + " AS INTEGER) * " + gs + ", 'unixepoch')";
            }

            // String
            case 'tolower':   return 'LOWER(' + args[0] + ')';
            case 'toupper':   return 'UPPER(' + args[0] + ')';
            case 'strlen':    return 'LENGTH(' + args[0] + ')';
            case 'strcat':    return '(' + args.join(' || ') + ')';
            case 'substring': {
                // KQL: substring(s, start [, length])  -- 0-indexed
                if (args.length === 2) return 'SUBSTR(' + args[0] + ', ' + args[1] + '+1)';
                return 'SUBSTR(' + args[0] + ', ' + args[1] + '+1, ' + args[2] + ')';
            }

            // Predicates
            case 'isempty':    return '(' + args[0] + " IS NULL OR CAST(" + args[0] + " AS TEXT) = '')";
            case 'isnotempty': return '(' + args[0] + " IS NOT NULL AND CAST(" + args[0] + " AS TEXT) <> '')";
            case 'isnull':     return '(' + args[0] + ' IS NULL)';
            case 'isnotnull':  return '(' + args[0] + ' IS NOT NULL)';
            case 'iff': case 'iif':
                return '(CASE WHEN ' + args[0] + ' THEN ' + args[1] + ' ELSE ' + args[2] + ' END)';
            case 'replace_string':
                return 'REPLACE(' + args[0] + ', ' + args[1] + ', ' + args[2] + ')';
            case 'split':
                // KQL split(text, sep [, idx]) -> JSON array string. Custom JS
                // function (registered in runtime.js) so mv-expand can feed
                // its output into json_each().
                return 'kql_split(' + args[0] + ', ' + args[1] + ')';
            case 'matches_regex':
                // Bridge for `<col> matches regex "pat"`. The parser turns
                // it into matches_regex(col, "pat") via the rewriter below.
                return 'kql_regex(' + args[0] + ', ' + args[1] + ')';
            case 'case': {
                // case(p1, v1, p2, v2, ..., default)
                if (args.length < 3 || args.length % 2 === 0) {
                    throw KqlError('case() expects an odd number of args (>=3): pred, val, ..., default');
                }
                var parts = ['CASE'];
                for (var ci = 0; ci + 1 < args.length; ci += 2) {
                    parts.push('WHEN ' + args[ci] + ' THEN ' + args[ci + 1]);
                }
                parts.push('ELSE ' + args[args.length - 1] + ' END');
                return '(' + parts.join(' ') + ')';
            }

            // Aggregates
            case 'count':   return 'COUNT(*)';
            case 'dcount':  return 'COUNT(DISTINCT ' + args[0] + ')';
            case 'sum':     return 'SUM(' + args[0] + ')';
            case 'avg':     return 'AVG(' + args[0] + ')';
            case 'min':     return 'MIN(' + args[0] + ')';
            case 'max':     return 'MAX(' + args[0] + ')';
            case 'countif': return 'SUM(CASE WHEN ' + args[0] + ' THEN 1 ELSE 0 END)';
            case 'sumif':   return 'SUM(CASE WHEN ' + args[1] + ' THEN ' + args[0] + ' ELSE 0 END)';

            // Type coercion
            case 'tostring': return 'CAST(' + args[0] + ' AS TEXT)';
            case 'toint':
            case 'tolong':   return 'CAST(' + args[0] + ' AS INTEGER)';
            case 'toreal':
            case 'todouble': return 'CAST(' + args[0] + ' AS REAL)';
            case 'tobool':   return '(CASE WHEN ' + args[0] + ' THEN 1 ELSE 0 END)';
            case 'make_set': {
                // make_set(col [, maxItems]) -> deduped JSON array.
                // SQLite json_group_array(DISTINCT col) handles the dedup;
                // the optional cap is applied via kql_cap_json (registered
                // in runtime.js) which slices the JSON array after the
                // aggregate finishes.
                var ms = 'json_group_array(DISTINCT ' + args[0] + ')';
                if (args.length >= 2) return 'kql_cap_json(' + ms + ', ' + args[1] + ')';
                return ms;
            }
            case 'make_list': {
                // make_list(col [, maxItems]) -> JSON array, dup-preserving.
                var ml = 'json_group_array(' + args[0] + ')';
                if (args.length >= 2) return 'kql_cap_json(' + ml + ', ' + args[1] + ')';
                return ml;
            }
            case 'todatetime':
                // CSV TimeGenerated is stored as ISO text ('2026-04-29T12:50:00Z').
                // SQLite's DATETIME() would normalize to '2026-04-29 12:52:40'
                // (space, no T, no Z), which fails lexicographic comparison
                // against the stored 'T...Z' format -- 'T' (84) > ' ' (32) makes
                // every row pass the filter. Pass the string through so both
                // sides stay in matching ISO form. Mirrors datetime() above.
                return args[0];

            default:
                throw KqlError("unsupported function: " + node.name + "()");
        }
    }

    /* ============================================================
       PUBLIC API
       ============================================================ */
    function compile(source) {
        var tokens = tokenize(source);
        var ast = parse(tokens, source);
        var sql = translate(ast);
        // Handle project-away post-rewrite (we don't know full schema here, so leave as comment)
        return { ast: ast, sql: sql };
    }

    global.KqlEngine = {
        tokenize: tokenize,
        parse: parse,
        translate: translate,
        compile: compile,
        KqlError: KqlError,
    };

})(window);
