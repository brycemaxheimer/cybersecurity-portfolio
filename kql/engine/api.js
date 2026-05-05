/* ==========================================================================
 * KQL engine - public browser API (window.KqlEngineApi)
 *
 * Wraps the v1 KqlRuntime + the shared rewrite layer behind the small surface
 * the practice page expects. v2 was a stub that always fell back to v1, so it
 * was removed; this is the single, canonical entry point.
 *
 * Public:
 *   ready()                -> Promise<void>
 *   setAnchor(isoString)   -> void   (pin now()/ago() to a fixed timestamp)
 *   getAnchor()            -> string | null
 *   run(kqlString)         -> Promise<{ columns, rows, elapsedMs, rewrittenKql }>
 *
 * Load order (in HTML):
 *   sql-wasm.js -> engine/schema.js -> engine/engine.js -> engine/runtime.js
 *   -> engine/rewrite.js -> engine/api.js
 * ========================================================================== */
(function () {
    'use strict';

    var ENGINE_VERSION = '1.0.0';
    var _readyPromise  = null;

    function _initRuntime() {
        if (_readyPromise) return _readyPromise;
        _readyPromise = (async function () {
            // Bail out early on isolated browsers (Menlo / Zscaler CBI / etc.)
            // that strip WASM. window.KqlEnv is set by /kql/engine/diagnose.js
            // and may be absent on pages that don't load it -- treat that as
            // permissive (match prior behavior).
            if (window.KqlEnv && !window.KqlEnv.allReady) {
                var err = new Error(window.KqlEnv.blockingReason || 'KQL engine prerequisites unavailable.');
                err.code = 'KQL_ENV_BLOCKED';
                throw err;
            }
            var attempts = 0;
            while ((!window.KqlRuntime || !window.KqlEngine || !window.KqlSchema) && attempts < 50) {
                await new Promise(function (r) { setTimeout(r, 100); });
                attempts++;
            }
            if (!window.KqlRuntime) throw new Error('KqlRuntime missing -- /kql/engine/runtime.js may not have loaded.');
            if (!window.KqlEngine)  throw new Error('KqlEngine missing -- /kql/engine/engine.js may not have loaded.');
            if (!window.KqlSchema)  throw new Error('KqlSchema missing -- /kql/engine/schema.js may not have loaded.');
            if (!window.KqlRewrite) throw new Error('KqlRewrite missing -- /kql/engine/rewrite.js may not have loaded.');
            await window.KqlRuntime.initialize({ onProgress: function () {} });
        })();
        return _readyPromise;
    }

    var api = {
        version: ENGINE_VERSION,

        async ready() { await _initRuntime(); },

        setAnchor: function (iso) { window.KqlRewrite.setAnchor(iso); },
        getAnchor: function ()    { return window.KqlRewrite.getAnchor(); },

        async run(kqlString) {
            await _initRuntime();
            var t0 = performance.now();
            var rewritten = window.KqlRewrite.rewriteTimePredicates(kqlString);
            rewritten = window.KqlRewrite.v1CompatRewrite(rewritten);
            var res = window.KqlRuntime.query(rewritten);
            return {
                columns:      res.columns || [],
                rows:         res.rows    || [],
                elapsedMs:    performance.now() - t0,
                rewrittenKql: rewritten,
            };
        },
    };

    window.KqlEngineApi = api;
})();
