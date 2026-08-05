/* ==========================================================================
 * Cloudflare Worker entry for the cybersecurity-portfolio site.
 *
 * Hybrid model:
 *   - Dynamic routes under /api/intel/* are handled here so we can read
 *     env.ABUSEIPDB_KEY (Worker secrets aren't accessible to a pure
 *     static-assets Worker).
 *   - Everything else falls through to env.ASSETS.fetch(request), which
 *     serves the static site rooted at "." per wrangler.jsonc.
 *
 * Set secrets in the Cloudflare dashboard:
 *   Workers & Pages -> cybersecurity-portfolio -> Settings -> Variables and
 *   Secrets. ABUSEIPDB_KEY should be an encrypted "Secret"; INTEL_RATE_LIMIT_PER_MIN
 *   can be a plaintext variable.
 * ========================================================================== */

import { handleLookup } from './functions/api/intel/lookup.js';
import { handleHealth } from './functions/api/intel/health.js';
import { handleRelay } from './functions/api/relay/dispatch.js';

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        if (url.pathname === '/api/intel/lookup') {
            return handleLookup(request, env);
        }
        if (url.pathname === '/api/intel/health') {
            return handleHealth(request, env);
        }

        // Remote task relay. Every path under here verifies a Cloudflare
        // Access assertion inside the handler before doing anything, so it
        // stays closed even if the edge Access policy is missing.
        if (url.pathname.startsWith('/api/relay/')) {
            return handleRelay(request, env, url);
        }

        // Static-asset fallback. The ASSETS binding is declared in
        // wrangler.jsonc and serves files from the project root.
        return env.ASSETS.fetch(request);
    },
};
