/* ==========================================================================
 * Cloudflare Access JWT verification for /api/relay/*.
 *
 * Access sits in front of /relay/* and /api/relay/* as an edge policy, so in
 * a correct deployment an unauthenticated request never reaches the Worker at
 * all. This module verifies the assertion a SECOND time inside the Worker.
 *
 * That is deliberate. Edge policies are configured in a dashboard, separately
 * from this repo, and a policy that is scoped to the wrong path (or removed
 * during unrelated Zero Trust work) fails OPEN -- traffic simply flows to the
 * origin as if the gate were never there. Verifying here means the relay fails
 * CLOSED instead: no valid signed assertion, no GitHub token, no dispatch.
 *
 * Verification performed:
 *   1. Token present (Cf-Access-Jwt-Assertion header, or CF_Authorization cookie)
 *   2. Header alg is RS256          -- refuses "none" and HMAC confusion
 *   3. kid matches a key in the team JWKS
 *   4. RSASSA-PKCS1-v1_5 / SHA-256 signature is valid
 *   5. iss == https://<team domain>
 *   6. aud contains the Access application AUD tag
 *   7. exp in the future, iat/nbf not in the future (60s clock skew allowed)
 *   8. email claim is in RELAY_ALLOWED_EMAILS
 *
 * Step 8 matters even though Access already enforces an allowlist: an AUD tag
 * is per-application, and any OTHER Access application in the same team issues
 * tokens from the same signer. Without the aud + email checks a token minted
 * for an unrelated app would verify cryptographically.
 * ========================================================================== */

// JWKS cache, module scope -- lives as long as the isolate. Access rotates
// signing keys periodically, so this is a short TTL rather than a permanent
// memo. A kid miss also forces a refetch regardless of TTL (see getKey).
const JWKS_TTL_MS = 10 * 60 * 1000;
let jwksCache = { keys: null, fetchedAt: 0, domain: null };

const CLOCK_SKEW_S = 60;

function b64urlToBytes(s) {
    const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function b64urlToJson(s) {
    return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
}

function readToken(request) {
    const header = request.headers.get('Cf-Access-Jwt-Assertion');
    if (header) return header.trim();

    // Browser navigations carry the assertion as a cookie instead of a header.
    const cookie = request.headers.get('Cookie') || '';
    for (const part of cookie.split(';')) {
        const [k, ...rest] = part.trim().split('=');
        if (k === 'CF_Authorization' && rest.length) return rest.join('=').trim();
    }
    return null;
}

async function fetchJwks(teamDomain) {
    const url = `https://${teamDomain}/cdn-cgi/access/certs`;
    const r = await fetch(url, { cf: { cacheTtl: 300, cacheEverything: true } });
    if (!r.ok) throw new Error(`JWKS fetch failed: ${r.status}`);
    const body = await r.json();
    if (!body || !Array.isArray(body.keys) || !body.keys.length) {
        throw new Error('JWKS response contained no keys');
    }
    return body.keys;
}

async function getKey(teamDomain, kid) {
    const fresh =
        jwksCache.keys &&
        jwksCache.domain === teamDomain &&
        Date.now() - jwksCache.fetchedAt < JWKS_TTL_MS;

    if (fresh) {
        const hit = jwksCache.keys.find((k) => k.kid === kid);
        if (hit) return hit;
        // Cached but unknown kid -- most likely a rotation mid-TTL. Fall through
        // and refetch rather than rejecting a legitimate freshly-signed token.
    }

    const keys = await fetchJwks(teamDomain);
    jwksCache = { keys, fetchedAt: Date.now(), domain: teamDomain };
    return keys.find((k) => k.kid === kid) || null;
}

/**
 * Verify the Access assertion on a request.
 *
 * Returns { ok: true, email, identity } on success, or
 * { ok: false, status, error } on any failure. The error strings are
 * intentionally coarse -- they are logged, not returned to the browser
 * verbatim, so a prober cannot use them to distinguish failure modes.
 */
export async function verifyAccess(request, env) {
    const teamDomain = (env.RELAY_ACCESS_TEAM_DOMAIN || '').trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
    const expectedAud = (env.RELAY_ACCESS_AUD || '').trim();

    if (!teamDomain || !expectedAud) {
        // Misconfiguration must never degrade into "allow". If the relay is
        // deployed without its Access settings, it is closed.
        return { ok: false, status: 503, error: 'relay auth not configured' };
    }

    const token = readToken(request);
    if (!token) return { ok: false, status: 401, error: 'no assertion' };

    const parts = token.split('.');
    if (parts.length !== 3) return { ok: false, status: 401, error: 'malformed assertion' };

    let header, payload;
    try {
        header = b64urlToJson(parts[0]);
        payload = b64urlToJson(parts[1]);
    } catch (_) {
        return { ok: false, status: 401, error: 'undecodable assertion' };
    }

    // Pin the algorithm. Without this an attacker-supplied "alg":"none" or a
    // symmetric alg verified against the public key would both be accepted.
    if (header.alg !== 'RS256') return { ok: false, status: 401, error: 'unexpected alg' };
    if (!header.kid) return { ok: false, status: 401, error: 'no kid' };

    let jwk;
    try {
        jwk = await getKey(teamDomain, header.kid);
    } catch (e) {
        return { ok: false, status: 503, error: `jwks unavailable: ${e.message}` };
    }
    if (!jwk) return { ok: false, status: 401, error: 'unknown signing key' };

    let key;
    try {
        key = await crypto.subtle.importKey(
            'jwk',
            { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            false,
            ['verify'],
        );
    } catch (_) {
        return { ok: false, status: 401, error: 'key import failed' };
    }

    const signed = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const sig = b64urlToBytes(parts[2]);
    const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, signed);
    if (!valid) return { ok: false, status: 401, error: 'bad signature' };

    // --- Claim checks. Signature alone proves only "some Access app in this
    // --- team issued this", which is not the same as "for THIS app".
    if (payload.iss !== `https://${teamDomain}`) {
        return { ok: false, status: 401, error: 'issuer mismatch' };
    }

    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(expectedAud)) {
        return { ok: false, status: 401, error: 'audience mismatch' };
    }

    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number' || payload.exp + CLOCK_SKEW_S < now) {
        return { ok: false, status: 401, error: 'expired' };
    }
    if (typeof payload.nbf === 'number' && payload.nbf - CLOCK_SKEW_S > now) {
        return { ok: false, status: 401, error: 'not yet valid' };
    }
    if (typeof payload.iat === 'number' && payload.iat - CLOCK_SKEW_S > now) {
        return { ok: false, status: 401, error: 'issued in the future' };
    }

    const email = String(payload.email || '').toLowerCase().trim();
    if (!email) return { ok: false, status: 401, error: 'no email claim' };

    const allowed = String(env.RELAY_ALLOWED_EMAILS || '')
        .split(',')
        .map((s) => s.toLowerCase().trim())
        .filter(Boolean);

    if (!allowed.length) {
        return { ok: false, status: 503, error: 'no allowlist configured' };
    }
    if (!allowed.includes(email)) {
        return { ok: false, status: 403, error: 'email not allowed' };
    }

    return { ok: true, email, identity: payload.sub || null };
}
