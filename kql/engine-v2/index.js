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

        const rewritten = rewriteTimePredicates(kqlString);

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
