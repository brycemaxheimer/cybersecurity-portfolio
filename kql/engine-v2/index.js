/* ==========================================================================
 * KQL engine v2 — public API
 *
 * Public API (window.KqlEngineV2):
 *   ready()              -> Promise<void>
 *   setAnchor(isoString) -> void          (pin now() to a fixed timestamp)
 *   getAnchor()          -> string | null
 *   run(kqlString)       -> Promise<{ columns, rows, elapsedMs, rewrittenKql }>
 *
 * Architecture:
 *   While the JS port of Invoke-KqlPS.ps1 is in progress, v2 is a thin
 *   adapter over the existing v1 runtime (KqlRuntime). KqlRuntime handles
 *   sql.js + CSV ingestion + KQL-to-SQL translation; we wrap its surface
 *   to match the contract the practice page expects, and add the time
 *   anchor + native fast-path that v2 will eventually fill in.
 * ========================================================================== */

import { tokenize } from './lexer.js';
import { parse }    from './parser.js';
import { execute }  from './executor.js';

const ENGINE_VERSION = '0.1.2-shim';

// ----------------------------------------------------------------------------
// Bootstrap KqlRuntime exactly once. runtime.js exposes window.KqlRuntime
// once the script tag loads. The practice page loads schema.js + engine.js
// + runtime.js BEFORE this module, so by ready() time the globals exist.
// ----------------------------------------------------------------------------

let _readyPromise = null;

function _initRuntime() {
    if (_readyPromise) return _readyPromise;
    _readyPromise = (async () => {
        let attempts = 0;
        while ((!window.KqlRuntime || !window.KqlEngine || !window.KqlSchema) && attempts < 50) {
            await new Promise(r => setTimeout(r, 100));
            attempts++;
        }
        if (!window.KqlRuntime) throw new Error('KqlRuntime missing -- /kql/engine/runtime.js may not have loaded.');
        if (!window.KqlEngine)  throw new Error('KqlEngine missing -- /kql/engine/engine.js may not have loaded.');
        if (!window.KqlSchema)  throw new Error('KqlSchema missing -- /kql/engine/schema.js may not have loaded.');
        await window.KqlRuntime.initialize({ onProgress: () => {} });
    })();
    return _readyPromise;
}

// ----------------------------------------------------------------------------
// Time-anchor rewriter
//
// Lab data has timestamps from a fixed storyline (~2026-04-29 14:00 UTC).
// Letting `ago(N)` resolve against the user's real wall clock means every
// query that uses ago() returns 0 rows. So before forwarding to KqlRuntime
// we substitute ago(N) / now() against the gold contract's anchor -- the
// same trick Test-KqlAnswers.ps1 uses.
// ----------------------------------------------------------------------------

let _anchorIso = null;

function _formatKqlDatetime(d) {
    return "todatetime('" + d.toISOString().replace(/\.\d+Z$/, '.000Z') + "')";
}
function _offsetSeconds(num, unit) {
    const n = parseFloat(num);
    if (unit === 'ms') return n / 1000;
    if (unit === 's')  return n;
    if (unit === 'm')  return n * 60;
    if (unit === 'h')  return n * 3600;
    if (unit === 'd')  return n * 86400;
    return null;
}
function rewriteTimePredicates(kql) {
    if (!_anchorIso) return kql;
    const anchor = new Date(_anchorIso);
    kql = kql.replace(/ago\(\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)\s*\)/g, (_m, num, unit) => {
        const secs = _offsetSeconds(num, unit);
        if (secs == null) return _m;
        return _formatKqlDatetime(new Date(anchor.getTime() - secs * 1000));
    });
    kql = kql.replace(/now\(\s*\)/g, () => _formatKqlDatetime(anchor));
    kql = kql.replace(/now\(\s*-\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)\s*\)/g, (_m, num, unit) => {
        const secs = _offsetSeconds(num, unit);
        if (secs == null) return _m;
        return _formatKqlDatetime(new Date(anchor.getTime() - secs * 1000));
    });
    return kql;
}


// ----------------------------------------------------------------------------
// v1-compat rewrites
//
// The v1 engine doesn't understand certain KQL surface bits. Until those
// land natively in v2, we string-rewrite them into v1-friendly equivalents
// before forwarding the query. Each rewrite is conservative -- it leaves
// non-matching text alone -- so unrelated queries are unaffected.
// ----------------------------------------------------------------------------

// 1) Raw-string literals  @"..." / @'...'  ->  "..." / '...'
//    KQL @-prefix means "treat backslashes literally". v1 string literals
//    don't interpret backslash escapes anyway, so dropping the @ is safe.
function _rewriteRawStrings(kql) {
    // @-prefixed raw strings: backslashes are LITERAL. v1's string lexer turns
    // '\b' into 'b'; pre-double the backslashes so the lexer's swallow-
    // backslash behavior reproduces the literal char. (Q20 'corp\bryce'.)
    kql = kql.replace(/@"([^"]*)"/g, function(_m, body) { return '"' + body.replace(/\\/g, '\\\\') + '"'; });
    kql = kql.replace(/@'([^']*)'/g, function(_m, body) { return "'" + body.replace(/\\/g, '\\\\') + "'"; });
    return kql;
}

// 2) Case-insensitive equality   col =~ x   ->   tolower(col) == tolower(x)
//    Same for !~.  v1 supports tolower; both sides get lowered so equality
//    is case-insensitive in the same sense KQL =~ defines.
function _rewriteEqTilde(kql) {
    const operandRe = '(@?"[^"]*"|@?\'[^\']*\'|[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*)';
    const lhsRe = '([A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*)';
    kql = kql.replace(new RegExp(lhsRe + '\\s*=~\\s*' + operandRe, 'g'),
        (_m, l, r) => /^(where|extend|summarize|project|order|sort|by|asc|desc|let|join|on|kind|union|parse|with|take|top|distinct|render|materialize|and|or|not|in|between|true|false|null)$/.test(l) ? _m : `tolower(${l}) == tolower(${r})`);
    kql = kql.replace(new RegExp(lhsRe + '\\s*!~\\s*' + operandRe, 'g'),
        (_m, l, r) => /^(where|extend|summarize|project|order|sort|by|asc|desc|let|join|on|kind|union|parse|with|take|top|distinct|render|materialize|and|or|not|in|between|true|false|null)$/.test(l) ? _m : `tolower(${l}) != tolower(${r})`);
    return kql;
}

// 3) Strip type annotations inside `parse ... with` clauses.
//    Form: User:string  /  Port:int  ->  User  /  Port
//    Affects parse, parse-where, and the `extract` family. Conservative:
//    we only strip a known list of KQL types, never guess.
function _rewriteParseTypes(kql) {
    return kql.replace(
        /(\b[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(string|int|long|real|datetime|bool|guid|dynamic|timespan)\b/g,
        '$1');
}

// 4) Inline simple `let X = dynamic([...]);`  references in `has_any/has_all/in`.
//    Q12-style pattern. We don't try to inline lets that bind tabular
//    expressions (Q16/17/18/21/23/29) -- those need real v2 support.
function _rewriteDynamicLetInline(kql) {
    // Find: let NAME = dynamic([ ... ]);
    const re = /let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*dynamic\(\s*\[([^\]]*)\]\s*\)\s*;\s*/g;
    let inlines = {};
    kql = kql.replace(re, (_m, name, items) => {
        inlines[name] = items.trim();
        return '';
    });
    if (Object.keys(inlines).length === 0) return kql;
    // Replace `has_any (NAME)` / `has_all (NAME)` / `in (NAME)` with the items list.
    for (const [name, items] of Object.entries(inlines)) {
        const refRe = new RegExp('(has_any|has_all|in|!in)\\s*\\(\\s*' + name + '\\s*\\)', 'g');
        kql = kql.replace(refRe, (_m, op) => `${op} (${items})`);
    }
    return kql;
}


// 5) has_any / has_all -> chained `has` with or/and. v1 doesn't support these
//    operators natively; expand `<col> has_any (a, b, c)` into
//    `(<col> has a or <col> has b or <col> has c)`. Run AFTER dynamic let
//    inlining so the items list is a literal-only.
function _rewriteHasAnyAll(kql) {
    var haRe = /([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s+(has_any|has_all)\s*\(([^)]+)\)/g;
    return kql.replace(haRe, function(_m, col, op, list) {
        var items = list.split(',').map(function(s){ return s.trim(); }).filter(Boolean);
        var joiner = op === 'has_any' ? ' or ' : ' and ';
        return '(' + items.map(function(it){ return col + ' has ' + it; }).join(joiner) + ')';
    });
}

function _v1CompatRewrite(kql) {
    kql = _rewriteRawStrings(kql);
    kql = _rewriteEqTilde(kql);
    kql = _rewriteParseTypes(kql);
    kql = _rewriteDynamicLetInline(kql);
    kql = _rewriteHasAnyAll(kql);
    return kql;
}

// ----------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------

const api = {
    version: ENGINE_VERSION,

    async ready() {
        await _initRuntime();
    },

    setAnchor(isoString) {
        _anchorIso = isoString || null;
    },

    getAnchor() { return _anchorIso; },

    async run(kqlString) {
        await _initRuntime();
        const t0 = performance.now();

        let rewritten = rewriteTimePredicates(kqlString);
        rewritten = _v1CompatRewrite(rewritten);

        // Native v2 path (parser stub returns allNative=false today -> always falls through).
        try {
            const tokens = tokenize(rewritten);
            const ast    = parse(tokens);
            if (ast && ast.allNative) {
                const result = execute(ast, { runtime: window.KqlRuntime });
                return {
                    columns:      result.columns,
                    rows:         result.rows,
                    elapsedMs:    performance.now() - t0,
                    rewrittenKql: rewritten,
                };
            }
        } catch (e) { /* fall through to v1 */ }

        // v1 fallback. KqlRuntime.query is synchronous; it throws on errors.
        const res = window.KqlRuntime.query(rewritten);
        return {
            columns:      res.columns || [],
            rows:         res.rows    || [],
            elapsedMs:    performance.now() - t0,
            rewrittenKql: rewritten,
        };
    },
};

window.KqlEngineV2 = api;
