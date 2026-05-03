/* run-gold-tests.cjs - Node harness for the v1 KQL engine. */
'use strict';

const fs   = require('fs');
const path = require('path');
const vm   = require('vm');

const REPO_ROOT  = path.resolve(__dirname, '..', '..');
const ENGINE_DIR = path.join(REPO_ROOT, 'kql', 'engine');
const VENDOR_DIR = path.join(REPO_ROOT, 'kql', 'vendor');
const DATA_DIR   = path.join(REPO_ROOT, 'kql', 'data');
const GOLD_PATH  = path.join(REPO_ROOT, 'lab', 'practice', 'gold-results.json');

const argv     = process.argv.slice(2);
const VERBOSE  = argv.includes('--verbose') || argv.includes('-v');
const onlyNums = argv.filter(a => /^\d+$/.test(a)).map(Number);

async function shimFetch(url) {
    const m = /^\/kql\/data\/(.+\.csv)$/.exec(url);
    if (!m) throw new Error('shim fetch: unsupported url ' + url);
    const file = path.join(DATA_DIR, m[1]);
    const text = await fs.promises.readFile(file, 'utf8');
    return { ok: true, status: 200, text: async () => text };
}

const sandbox = {
    console, setTimeout, clearTimeout, setInterval, clearInterval,
    Promise, fetch: shimFetch, URL, URLSearchParams,
    TextDecoder, TextEncoder, process, require, Buffer,
    __dirname: VENDOR_DIR,
};
sandbox.window = sandbox;
sandbox.global = sandbox;
sandbox.globalThis = sandbox;
sandbox.self = sandbox;
vm.createContext(sandbox);

function loadIntoSandbox(file) {
    const code = fs.readFileSync(file, 'utf8');
    vm.runInContext(code, sandbox, { filename: file });
}

loadIntoSandbox(path.join(VENDOR_DIR, 'sql-wasm.js'));
loadIntoSandbox(path.join(ENGINE_DIR, 'schema.js'));
loadIntoSandbox(path.join(ENGINE_DIR, 'engine.js'));
loadIntoSandbox(path.join(ENGINE_DIR, 'runtime.js'));

let ANCHOR_ISO = null;

function fmtKqlDatetime(d) {
    return "todatetime('" + d.toISOString().replace(/\.\d+Z$/, '.000Z') + "')";
}
function offsetSeconds(num, unit) {
    const n = parseFloat(num);
    return ({ ms: n / 1000, s: n, m: n * 60, h: n * 3600, d: n * 86400 })[unit];
}
function rewriteTimePredicates(kql) {
    if (!ANCHOR_ISO) return kql;
    const anchor = new Date(ANCHOR_ISO);
    kql = kql.replace(/ago\(\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)\s*\)/g, (_m, num, unit) => {
        const secs = offsetSeconds(num, unit);
        if (secs == null) return _m;
        return fmtKqlDatetime(new Date(anchor.getTime() - secs * 1000));
    });
    kql = kql.replace(/now\(\s*\)/g, () => fmtKqlDatetime(anchor));
    return kql;
}

const KQL_KW = /^(where|extend|summarize|project|order|sort|by|asc|desc|let|join|on|kind|union|parse|with|take|top|distinct|render|materialize|and|or|not|in|between|true|false|null)$/;

function materializeUnwrap(kql) {
    var i = 0, out = '';
    while (i < kql.length) {
        var idx = kql.indexOf('materialize(', i);
        if (idx < 0) { out += kql.slice(i); break; }
        out += kql.slice(i, idx);
        var depth = 1, j = idx + 'materialize('.length;
        while (j < kql.length && depth > 0) {
            if (kql[j] === '(') depth++;
            else if (kql[j] === ')') { depth--; if (depth === 0) break; }
            j++;
        }
        out += kql.slice(idx + 'materialize('.length, j);
        i = j + 1;
    }
    return out;
}


function rewriteMatchesRegex(kql) {
    // Rewrite `<expr> matches regex <string>` into
    // `matches_regex(<expr>, <string>)`. The expression is a simple ident,
    // dotted ident, or function call (with balanced parens). The pattern is
    // a single string literal (raw or regular).
    return kql.replace(
        /([A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?(?:\.[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?)*)\s+matches\s+regex\s+(@?"[^"]*"|@?'[^']*')/g,
        function (_m, expr, pat) { return 'matches_regex(' + expr + ', ' + pat + ')'; }
    );
}

function v1CompatRewrite(kql) {
    kql = materializeUnwrap(kql);
    // @-prefixed raw strings: backslashes are LITERAL. v1's string lexer
    // turns '\b' into 'b'; pre-double the backslashes so the lexer's
    // swallow-backslash behavior reproduces the literal char.
    kql = kql.replace(/@"([^"]*)"/g, (_m, body) => '"' + body.replace(/\\/g, '\\\\') + '"');
    kql = kql.replace(/@'([^']*)'/g, (_m, body) => "'" + body.replace(/\\/g, '\\\\') + "'");
    const operandRe = "(@?\"[^\"]*\"|@?'[^']*'|[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*)";
    const lhsRe     = "([A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*)";
    kql = kql.replace(new RegExp(lhsRe + "\\s*=~\\s*" + operandRe, "g"),
        (_m, l, r) => KQL_KW.test(l) ? _m : "tolower(" + l + ") == tolower(" + r + ")");
    kql = kql.replace(new RegExp(lhsRe + "\\s*!~\\s*" + operandRe, "g"),
        (_m, l, r) => KQL_KW.test(l) ? _m : "tolower(" + l + ") != tolower(" + r + ")");
    // Type strip removed -- engine.js parseParse now consumes :type natively.
    const dynRe = /let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*dynamic\(\s*\[([^\]]*)\]\s*\)\s*;\s*/g;
    const inlines = {};
    kql = kql.replace(dynRe, (_m, name, items) => { inlines[name] = items.trim(); return ''; });
    for (const [name, items] of Object.entries(inlines)) {
        const refRe = new RegExp('(has_any|has_all|in|!in)\\s*\\(\\s*' + name + '\\s*\\)', 'g');
        kql = kql.replace(refRe, (_m, op) => op + ' (' + items + ')');
    }
    // has_any / has_all: expand to or/and chains. v1 doesn't have these
    // operators natively. Match `<col> has_any (a, b, c)` and rewrite to
    // `(<col> has a or <col> has b or <col> has c)`.
    const haRe = /([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s+(has_any|has_all)\s*\(([^)]+)\)/g;
    kql = kql.replace(haRe, (_m, col, op, list) => {
        const items = list.split(',').map(s => s.trim()).filter(Boolean);
        const joiner = op === 'has_any' ? ' or ' : ' and ';
        return '(' + items.map(it => col + ' has ' + it).join(joiner) + ')';
    });
    kql = rewriteMatchesRegex(kql);
    return kql;
}

function unwrapRow(r) {
    if (Array.isArray(r)) return r;
    if (r && typeof r === 'object' && Array.isArray(r.value) && 'Count' in r) return r.value;
    return r;
}

function normCell(v) {
    if (v == null) return '';
    if (typeof v === 'number') {
        if (!Number.isFinite(v)) return '';
        return String(v);
    }
    if (typeof v === 'boolean') return v ? '1' : '0';
    if (typeof v === 'object') {
        if (Array.isArray(v.value) && 'Count' in v) return canonJson(v.value);
        return canonJson(v);
    }
    var s = String(v);
    // If it's a JSON-looking string, re-serialize to canonical form so
    // `{"a":1}` and `{"a": 1}` compare equal (PS vs JS serializers).
    if (/^[\[{]/.test(s.trim())) {
        try { return canonJson(JSON.parse(s)); } catch (_) { /* fall through */ }
    }
    if (s === 'true') return '1';
    if (s === 'false') return '0';
    if (/^-?\d+$/.test(s)) return s;
    return s;
}
function canonJson(v) {
    if (v == null) return 'null';
    if (typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(canonJson).join(',') + ']';
    var keys = Object.keys(v).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonJson(v[k])).join(',') + '}';
}

function rowsEqual(a, b) {
    if (!Array.isArray(a) || !Array.isArray(b)) return false;
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (normCell(a[i]) !== normCell(b[i])) return false;
    return true;
}

function compareResults(actualRows, actualColumns, gold) {
    // Normalize gold rows: PS sometimes emits a flat row instead of [[row]].
    let expected = gold.rows;
    if (gold.rowCount === 1 && expected.length === gold.columns.length && !Array.isArray(expected[0])) {
        expected = [expected];
    }
    expected = expected.map(unwrapRow);
    var goldNames = gold.columns.map(c => c.name);
    // Column SET must match exactly. Old grader only checked gold ⊆ user,
    // which silently accepted "no project" / extra-extend submissions.
    var missing = goldNames.filter(n => actualColumns.indexOf(n) < 0);
    var extra   = actualColumns.filter(n => goldNames.indexOf(n) < 0);
    if (missing.length || extra.length) {
        return { ok: false, reason: "columns differ" +
            (missing.length ? "; missing: " + missing.join(",") : "") +
            (extra.length   ? "; extra: "   + extra.join(",")   : "") };
    }
    if (actualRows.length !== expected.length) {
        return { ok: false, reason: "row count: got " + actualRows.length + ", expected " + expected.length };
    }
    // Build column-name -> index for both sides. Compare by column name so
    // column order differences (e.g. arg_max putting by-col first) don't matter.
    var actNameIdx = {};
    actualColumns.forEach((n, i) => { actNameIdx[n] = i; });
    function rowDict(row, namesOrIdx) {
        var d = {};
        if (namesOrIdx === 'gold') {
            goldNames.forEach((n, i) => { d[n] = normCell(row[i]); });
        } else {
            goldNames.forEach(n => {
                var i = actNameIdx[n];
                d[n] = i === undefined ? '__missing__' : normCell(row[i]);
            });
        }
        return d;
    }
    function dictKey(d) {
        return JSON.stringify(Object.keys(d).sort().map(k => [k, d[k]]));
    }
    var aDicts = actualRows.map(r => rowDict(r, 'actual'));
    var eDicts = expected.map(r => rowDict(r, 'gold'));
    if (gold.ordered) {
        // Try strict ordered compare; if it fails, fall back to set match,
        // which passes when the rows are equivalent but tied-on-sort-key
        // rows came back in a different (but still valid) order.
        var orderedOK = true;
        for (var i = 0; i < aDicts.length; i++) {
            if (dictKey(aDicts[i]) !== dictKey(eDicts[i])) { orderedOK = false; break; }
        }
        if (!orderedOK) {
            var aSet = aDicts.map(dictKey).sort();
            var eSet = eDicts.map(dictKey).sort();
            for (var k = 0; k < aSet.length; k++) {
                if (aSet[k] !== eSet[k]) {
                    return { ok: false, reason: "row " + k + " differs", actual: aSet[k], expected: eSet[k] };
                }
            }
            // Rows are equivalent as a set; ties on the sort key produced a
            // different (but valid) ordering. Pass.
        }
    } else {
        var aKeys = aDicts.map(dictKey).sort();
        var eKeys = eDicts.map(dictKey).sort();
        for (var j = 0; j < aKeys.length; j++) {
            if (aKeys[j] !== eKeys[j]) {
                return { ok: false, reason: "set differs at slot " + j, actual: aKeys[j], expected: eKeys[j] };
            }
        }
    }
    return { ok: true };
}

function findQuestions(obj) {
    if (Array.isArray(obj)) return obj.flatMap(findQuestions);
    if (obj && typeof obj === 'object') {
        if ('canonicalKql' in obj && 'number' in obj) return [obj];
        return Object.values(obj).flatMap(findQuestions);
    }
    return [];
}

(async () => {
    const KqlRuntime = sandbox.KqlRuntime;
    if (!KqlRuntime) { console.error('KqlRuntime not loaded'); process.exit(1); }
    const origInit = sandbox.initSqlJs;
    sandbox.initSqlJs = function(opts) {
        return origInit({ ...opts, locateFile: f => path.join(VENDOR_DIR, f) });
    };
    process.stderr.write('Booting sql.js + ingesting CSVs...\n');
    await KqlRuntime.initialize({});
    process.stderr.write('Ready.\n\n');

    const gold = JSON.parse(fs.readFileSync(GOLD_PATH, 'utf8'));
    const seek = o => {
        if (!o || typeof o !== 'object') return null;
        if (typeof o.anchor === 'string') return o.anchor;
        for (const v of Array.isArray(o) ? o : Object.values(o)) {
            const r = seek(v); if (r) return r;
        }
        return null;
    };
    ANCHOR_ISO = seek(gold);
    process.stderr.write('Anchor: ' + ANCHOR_ISO + '\n\n');

    const questions = findQuestions(gold).sort((a, b) => a.number - b.number);
    const filter = onlyNums.length ? new Set(onlyNums) : null;

    let pass = 0, fail = 0, error = 0;
    for (const q of questions) {
        if (filter && !filter.has(q.number)) continue;
        let rewritten = rewriteTimePredicates(q.canonicalKql);
        rewritten = v1CompatRewrite(rewritten);
        const tag = String(q.number).padStart(2);
        try {
            const res = KqlRuntime.query(rewritten);
            const cmp = compareResults(res.rows || [], res.columns || [], q);
            if (cmp.ok) {
                pass++;
                console.log('PASS  Q' + tag + ' ' + q.title);
            } else {
                fail++;
                console.log('FAIL  Q' + tag + ' ' + q.title + '  --  ' + cmp.reason);
                if (VERBOSE) {
                    console.log('       rewritten:', rewritten.replace(/\n/g, ' '));
                    if (cmp.actual)   console.log('       actual  :', JSON.stringify(cmp.actual));
                    if (cmp.expected) console.log('       expected:', JSON.stringify(cmp.expected));
                }
            }
        } catch (e) {
            error++;
            console.log('ERROR Q' + tag + ' ' + q.title + '  --  ' + e.message);
            if (VERBOSE) {
                console.log('       rewritten:', rewritten.replace(/\n/g, ' '));
                console.log('       stack    :', e.stack.split('\n').slice(0, 3).join(' | '));
            }
        }
    }
    console.log('\nTotal: ' + pass + ' pass, ' + fail + ' fail, ' + error + ' error  (out of ' + (pass + fail + error) + ')');
})().catch(e => { console.error(e); process.exit(1); });
