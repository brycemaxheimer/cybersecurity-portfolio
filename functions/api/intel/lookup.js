/* ==========================================================================
 * POST /api/intel/lookup  -- backend Threat-Intel lookup demo
 *
 * Body: { indicator: string, type?: 'auto'|'ip'|'hash'|'domain'|'url' }
 * Reply (200): { indicator, type, results: [{provider, verdict, ...}], elapsedMs }
 * Reply (4xx): { error: string }
 *
 * Why a backend route: API keys (AbuseIPDB, etc.) MUST stay server-side.
 * The browser demo (lab/threat-intel/demo.html) calls THIS endpoint, which
 * adds the key from env and forwards to the upstream provider.
 *
 * Configured via Cloudflare Worker secrets / vars:
 *   ABUSEIPDB_KEY  - https://www.abuseipdb.com/account/api  (required for IP)
 * Optional:
 *   INTEL_RATE_LIMIT_PER_MIN  - default 10 requests/min/IP
 *
 * Routed by worker.js at /api/intel/lookup. Run locally:
 *   wrangler dev --var ABUSEIPDB_KEY=<key>
 * ========================================================================== */

const RE_IPV4   = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const RE_SHA256 = /^[A-Fa-f0-9]{64}$/;
const RE_SHA1   = /^[A-Fa-f0-9]{40}$/;
const RE_MD5    = /^[A-Fa-f0-9]{32}$/;
const RE_DOMAIN = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/;
const RE_URL    = /^https?:\/\/[^\s]{4,2048}$/i;

// Cloudflare's per-isolate map -- lives only as long as the worker isolate.
// Good enough for a demo abuse gate; not durable across regions/restarts.
const RATE_BUCKET = new Map();

function inferType(indicator) {
    const v = indicator.trim();
    if (RE_IPV4.test(v))   return 'ip';
    if (RE_SHA256.test(v)) return 'sha256';
    if (RE_SHA1.test(v))   return 'sha1';
    if (RE_MD5.test(v))    return 'md5';
    if (RE_URL.test(v))    return 'url';
    if (RE_DOMAIN.test(v)) return 'domain';
    return null;
}

function normalizeType(requested, indicator) {
    const inferred = inferType(indicator);
    if (!inferred) return { error: 'Indicator format not recognized' };
    if (!requested || requested === 'auto') return { type: inferred };
    if (requested === 'ip'    && inferred !== 'ip')                                    return { error: `Type 'ip' requested but indicator looks like ${inferred}` };
    if (requested === 'hash'  && !['sha256','sha1','md5'].includes(inferred))          return { error: `Type 'hash' requested but indicator looks like ${inferred}` };
    if (requested === 'url'   && inferred !== 'url')                                   return { error: `Type 'url' requested but indicator looks like ${inferred}` };
    if (requested === 'domain'&& inferred !== 'domain')                                return { error: `Type 'domain' requested but indicator looks like ${inferred}` };
    return { type: inferred };
}

function rateLimitOk(ip, perMin) {
    const now = Date.now();
    const windowMs = 60 * 1000;
    const entry = RATE_BUCKET.get(ip) || { tokens: perMin, refilledAt: now };
    const elapsed = now - entry.refilledAt;
    if (elapsed >= windowMs) {
        entry.tokens = perMin;
        entry.refilledAt = now;
    }
    if (entry.tokens <= 0) {
        RATE_BUCKET.set(ip, entry);
        return false;
    }
    entry.tokens -= 1;
    RATE_BUCKET.set(ip, entry);
    return true;
}

async function callAbuseIPDB(ip, key) {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
    const r = await fetch(url, { headers: { Key: key, Accept: 'application/json' } });
    if (!r.ok) {
        const body = await r.text();
        return { provider: 'abuseipdb', error: `upstream ${r.status}`, detail: body.slice(0, 200) };
    }
    const j = await r.json();
    const d = j.data || {};
    const score = Number(d.abuseConfidenceScore || 0);
    const reps  = Number(d.totalReports || 0);
    const verdict =
        score >= 75 ? 'malicious' :
        score >= 25 ? 'suspicious' :
        'clean';
    return {
        provider:   'abuseipdb',
        verdict,
        score,
        reports:    reps,
        country:    d.countryCode || null,
        usageType:  d.usageType   || null,
        isp:        d.isp         || null,
        isTor:      Boolean(d.isTor),
        lastReport: d.lastReportedAt || null,
        link:       `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`,
    };
}

// Public-domain enrichment: ip-api.com (free, no key, 45 req/min). Useful as
// a baseline geo/asn lookup so the demo still returns something even with
// no AbuseIPDB key configured.
async function callIpApi(ip) {
    const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query`;
    const r = await fetch(url);
    if (!r.ok) return { provider: 'ip-api', error: `upstream ${r.status}` };
    const j = await r.json();
    if (j.status !== 'success') return { provider: 'ip-api', error: j.message || 'lookup failed' };
    return {
        provider:  'ip-api',
        verdict:   'info',
        country:   j.countryCode || null,
        region:    j.regionName  || null,
        city:      j.city        || null,
        isp:       j.isp         || null,
        org:       j.org         || null,
        asn:       j.as          || null,
        link:      `https://ip-api.com/${encodeURIComponent(ip)}`,
    };
}

function jsonResponse(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store',
        },
    });
}

export async function handleLookup(request, env) {
    if (request.method !== 'POST') {
        return jsonResponse({ error: 'POST only' }, 405);
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const limit = Number(env.INTEL_RATE_LIMIT_PER_MIN || 10);
    if (!rateLimitOk(ip, limit)) {
        return jsonResponse({ error: `Rate limit exceeded (${limit}/min). Try again in a minute.` }, 429);
    }

    let body;
    try { body = await request.json(); }
    catch (_) { return jsonResponse({ error: 'Body must be JSON' }, 400); }

    const indicator = String(body.indicator || '').trim();
    if (!indicator)        return jsonResponse({ error: 'indicator is required' }, 400);
    if (indicator.length > 2048) return jsonResponse({ error: 'indicator too long' }, 400);

    const requestedType = body.type ? String(body.type) : 'auto';
    const t = normalizeType(requestedType, indicator);
    if (t.error) return jsonResponse({ error: t.error }, 400);

    const t0 = Date.now();
    const results = [];

    if (t.type === 'ip') {
        if (env.ABUSEIPDB_KEY) {
            results.push(await callAbuseIPDB(indicator, env.ABUSEIPDB_KEY));
        } else {
            results.push({ provider: 'abuseipdb', error: 'ABUSEIPDB_KEY not configured', skipped: true });
        }
        results.push(await callIpApi(indicator));
    } else {
        // No-key providers exist for hashes (NSRL/Circle) and URLs (URLScan
        // public, urlhaus). Wire them as needed; for the demo we just echo
        // the parsed type so the round-trip works without keys.
        results.push({
            provider: 'echo',
            verdict:  'info',
            note:     `Lookup for type '${t.type}' is not yet implemented in this demo. ` +
                      `IP lookups are wired (AbuseIPDB + ip-api.com).`,
        });
    }

    return jsonResponse({
        indicator,
        type:      t.type,
        results,
        elapsedMs: Date.now() - t0,
    });
}
