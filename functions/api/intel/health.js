/* ==========================================================================
 * GET /api/intel/health  -- which Intel-Lookup providers are configured
 *                          and reachable from this Worker?
 *
 * Reply (200): {
 *   providers: [
 *     { id, label, configured, reachable, detail }
 *   ],
 *   checkedAt: ISO,
 *   elapsedMs: number
 * }
 *
 * "Configured" = required env var is present.
 * "Reachable"  = a HEAD or low-cost GET against the provider returned 2xx-5xx
 *                (i.e. DNS resolves and TCP/TLS works). We do NOT submit a
 *                real lookup -- that would burn quota.
 *
 * Cached at the edge for 60s so repeated demo loads don't repeat probes.
 * ========================================================================== */

async function probe(url, opts = {}) {
    const ctl = new AbortController();
    const t   = setTimeout(() => ctl.abort(), 4000);
    try {
        const r = await fetch(url, { method: opts.method || 'GET', signal: ctl.signal, headers: opts.headers || {} });
        return { ok: true, status: r.status };
    } catch (e) {
        return { ok: false, status: 0, error: String(e.message || e) };
    } finally {
        clearTimeout(t);
    }
}

export async function handleHealth(request, env) {
    const t0 = Date.now();

    const checks = [
        {
            id:    'abuseipdb',
            label: 'AbuseIPDB',
            envVar:'ABUSEIPDB_KEY',
            // Hit /api/v2/check without a key -> 401. Confirms reachability
            // without consuming quota.
            probeUrl: 'https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1',
        },
        {
            id:    'ip-api',
            label: 'ip-api.com (no key)',
            envVar: null,
            probeUrl: 'http://ip-api.com/json/1.1.1.1?fields=status',
        },
    ];

    const providers = await Promise.all(checks.map(async (c) => {
        const configured = c.envVar ? Boolean(env[c.envVar]) : true;
        const p = await probe(c.probeUrl);
        let detail;
        if (!p.ok) {
            detail = `unreachable: ${p.error || 'unknown'}`;
        } else if (c.id === 'abuseipdb' && p.status === 401) {
            detail = 'reachable (401 unauthenticated probe is expected)';
        } else if (p.status >= 200 && p.status < 600) {
            detail = `reachable (HTTP ${p.status})`;
        } else {
            detail = `unexpected status ${p.status}`;
        }
        return {
            id:         c.id,
            label:      c.label,
            configured,
            reachable:  p.ok,
            detail,
        };
    }));

    return new Response(JSON.stringify({
        providers,
        checkedAt: new Date().toISOString(),
        elapsedMs: Date.now() - t0,
    }), {
        status: 200,
        headers: {
            'Content-Type':  'application/json; charset=utf-8',
            'Cache-Control': 'public, max-age=60',
        },
    });
}
