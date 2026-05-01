/* ==========================================================================
 * KQL engine v2 — public API
 *
 * Public API (window.KqlEngineV2):
 *   ready()           -> Promise<void>            // ensures runtime is initialized
 *   run(kqlString)    -> Promise<{
 *                          columns: string[],
 *                          rows:    any[][],
 *                          elapsedMs: number
 *                        }>
 *
 * Architecture:
 *   While the JS port of Invoke-KqlPS.ps1 is in progress, v2 is a thin
 *   adapter over the existing v1 runtime (KqlRuntime). KqlRuntime already
 *   handles sql.js + CSV ingestion + KQL-to-SQL translation; we just wrap
 *   its surface to match the contract the practice page expects.
 *
 * As operators land in /kql/engine-v2/{lexer,parser,executor,functions}.js,
 * the run() function will short-circuit: try v2-native first, fall back to
 * KqlRuntime only when the AST has unimplemented operators.
 * ========================================================================== */

import { tokenize } from './lexer.js';
import { parse }    from './parser.js';
import { execute }  from './executor.js';

const ENGINE_VERSION = '0.1.1-shim';

// ----------------------------------------------------------------------------
// Bootstrap KqlRuntime exactly once.
//
// runtime.js exposes window.KqlRuntime once the script tag loads. Practice
// page index.html loads runtime.js + its deps (sql-wasm.js, schema.js,
// engine.js) BEFORE this module, so by the time ready() is called all the
// globals exist.
// ----------------------------------------------------------------------------

let _readyPromise = null;

function _initRuntime() {
    if (_readyPromise) return _readyPromise;
    _readyPromise = (async () => {
        // Wait briefly for the v1 globals if they haven't loaded yet (race
        // against module-script execution timing).
        let attempts = 0;
        while ((!window.KqlRuntime || !window.KqlEngine || !window.KqlSchema) && attempts < 50) {
            await new Promise(r => setTimeout(r, 100));
            attempts++;
        }
        if (!window.KqlRuntime) throw new Error('KqlRuntime missing -- /kql/engine/runtime.js may not have loaded.');
        if (!window.KqlEngine)  throw new Error('KqlEngine missing -- /kql/engine/engine.js may not have loaded.');
        if (!window.KqlSchema)  throw new Error('KqlSchema missing -- /kql/engine/schema.js may not have loaded.');

        // KqlRuntime.initialize loads sql.js, fetches the 16 CSVs from
        // /kql/data/, and ingests them. Idempotent — safe to call multiple
        // times via this guard.
        await window.KqlRuntime.initialize({ onProgress: () => {} });
    })();
    return _readyPromise;
}

// ----------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------

const api = {
    version: ENGINE_VERSION,

    async ready() {
        await _initRuntime();
    },

    async run(kqlString) {
        await _initRuntime();
        const t0 = performance.now();

        // Step 1: try the native v2 path. parse() currently always returns
        //   { allNative: false } so this falls through to v1. As operators
        //   land in executor.js, parse() flips allNative=true for the chains
        //   it can handle natively and we begin running queries here.
        try {
            const tokens = tokenize(kqlString);
            const ast    = parse(tokens);
            if (ast && ast.allNative) {
                const result = execute(ast, { runtime: window.KqlRuntime });
                return {
                    columns:   result.columns,
                    rows:      result.rows,
                    elapsedMs: performance.now() - t0,
                };
            }
        } catch (e) {
            // v2 not capable yet -> fall through.
        }

        // Step 2: delegate to the v1 runtime.
        // KqlRuntime.query is synchronous; it throws on errors.
        const res = window.KqlRuntime.query(kqlString);
        return {
            columns:   res.columns || [],
            rows:      res.rows    || [],
            elapsedMs: performance.now() - t0,
        };
    },
};

window.KqlEngineV2 = api;
