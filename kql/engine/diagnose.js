/* ==========================================================================
 * KQL engine -- runtime capability diagnostics
 *
 * Some browsers and enterprise web-isolation / RBI products (Menlo, Zscaler
 * CBI, Cloudflare Browser Isolation in DOM-mirror mode, Symantec WSS, etc.)
 * disable WebAssembly, restrict IndexedDB, or strip same-origin fetch
 * responses. When that happens the KQL engine fails silently and the user
 * sees a blank panel.
 *
 * This module probes for those capabilities at load time, sets
 * window.KqlEnv = { wasm, fetch, indexedDB, localStorage, allReady,
 * blockingReason }, and exposes a one-line renderer that other pages
 * (practice, playground) call to swap in an actionable banner instead of
 * the empty engine UI.
 *
 * NOTE: this does NOT bypass any policy. If WASM is blocked by your
 * organization's RBI, the engine genuinely cannot run; we just say so.
 * ========================================================================== */
(function () {
    'use strict';

    var env = {
        wasm:         false,
        fetch:        false,
        indexedDB:    false,
        localStorage: false,
        allReady:     false,
        blockingReason: null,
    };

    // --- WebAssembly -------------------------------------------------------
    // RBI products that strip WASM either remove the global entirely or
    // make WebAssembly.instantiate() reject. The cheap synchronous probe
    // covers both common cases; sql.js init will surface the rest.
    try {
        if (typeof WebAssembly === 'object' && typeof WebAssembly.instantiate === 'function') {
            // 8-byte minimal valid module ("\0asm" + version 1).
            var bytes = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
            if (typeof WebAssembly.Module === 'function') {
                new WebAssembly.Module(bytes);  // throws if synchronous compile is blocked
                env.wasm = true;
            }
        }
    } catch (_) { env.wasm = false; }

    // --- fetch -------------------------------------------------------------
    env.fetch = (typeof fetch === 'function');

    // --- IndexedDB ---------------------------------------------------------
    // Practice page uses this for drafts + scores. RBI sometimes leaves the
    // global present but blocks open(); we discover that lazily on first use.
    env.indexedDB = (typeof indexedDB === 'object' && typeof indexedDB.open === 'function');

    // --- localStorage ------------------------------------------------------
    // The pre-paint theme script touches localStorage in <head>. If that's
    // blocked, themes silently fail. Probe once with a no-op write/read.
    try {
        var k = '__kql_probe__';
        localStorage.setItem(k, '1');
        env.localStorage = (localStorage.getItem(k) === '1');
        localStorage.removeItem(k);
    } catch (_) { env.localStorage = false; }

    // --- Roll-up -----------------------------------------------------------
    if (!env.wasm) {
        env.blockingReason =
            'WebAssembly is unavailable in this browser. The KQL engine relies ' +
            'on sql.js (a WebAssembly build of SQLite). This is a common signal ' +
            'that you are inside a remote-browser-isolation session (Menlo, ' +
            'Zscaler CBI, Symantec WSS, etc.) that strips WASM. The site is not ' +
            'broken; the policy on this network does not allow client-side WASM ' +
            'execution.';
    } else if (!env.fetch) {
        env.blockingReason =
            'fetch() is unavailable. CSV table data cannot be loaded. ' +
            'Try a modern browser without isolation policies.';
    } else {
        env.allReady = true;
    }

    // --- Banner helper -----------------------------------------------------
    // Pages call window.KqlEnv.renderBanner(targetEl, opts?) to replace a
    // container's contents with a friendly explanation. Static HTML, no
    // dependencies, safe to call before any other engine module loads.
    env.renderBanner = function (targetEl, opts) {
        if (!targetEl || env.allReady) return false;
        opts = opts || {};
        var reason = env.blockingReason || 'KQL engine is unavailable in this browser.';
        var caps = [
            ['WebAssembly', env.wasm],
            ['fetch',       env.fetch],
            ['IndexedDB',   env.indexedDB],
            ['localStorage', env.localStorage],
        ];
        var rows = caps.map(function (c) {
            var ok = c[1];
            return '<tr><td style="padding:0.2rem 0.8rem 0.2rem 0;font-family:var(--font-mono);font-size:0.8rem;color:var(--text-2)">'
                 + c[0] + '</td><td style="padding:0.2rem 0;font-family:var(--font-mono);font-size:0.8rem;color:'
                 + (ok ? 'var(--mint-deep)' : 'var(--coral)') + '">'
                 + (ok ? 'available' : 'blocked')
                 + '</td></tr>';
        }).join('');
        targetEl.innerHTML =
            '<div role="status" aria-live="polite" style="border:1px solid var(--amber);background:rgba(233,198,109,0.07);'
            + 'border-radius:var(--radius);padding:1.2rem 1.4rem;margin:1rem 0;color:var(--text-1)">'
            + '<strong style="color:var(--amber);font-family:var(--font-display)">KQL engine cannot start in this browser</strong>'
            + '<p style="margin:0.6rem 0 0;font-size:0.94rem;line-height:1.55">' + reason + '</p>'
            + (opts.fallbackHtml ? '<div style="margin-top:0.8rem">' + opts.fallbackHtml + '</div>' : '')
            + '<details style="margin-top:0.8rem"><summary style="cursor:pointer;font-family:var(--font-mono);font-size:0.82rem;color:var(--text-2)">capability detail</summary>'
            + '<table style="margin-top:0.4rem;border-collapse:collapse"><tbody>' + rows + '</tbody></table></details>'
            + '<p style="margin:0.8rem 0 0;font-size:0.84rem;color:var(--text-3)">'
            + 'Want to run the engine yourself? Clone the repo and open it locally:'
            + ' <a href="https://github.com/brycemaxheimer/cybersecurity-portfolio" style="color:var(--mint-deep)">github.com/brycemaxheimer/cybersecurity-portfolio</a>'
            + '</p>'
            + '</div>';
        return true;
    };

    window.KqlEnv = env;
})();
