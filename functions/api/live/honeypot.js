/* ==========================================================================
 * GET /api/live/honeypot  -- same-origin copy of the public honeypot feed.
 *
 * threats.brycemaxheimer.com/feed.json only allows the production origin in
 * its CORS header, so pages served from preview hosts or `wrangler dev`
 * cannot read it directly. This route fetches it server-side and returns it
 * from the site's own origin. Cached at the edge for 60s.
 * ========================================================================== */

const UPSTREAM = 'https://threats.brycemaxheimer.com/feed.json';
const TTL_SECONDS = 60;

export async function handleHoneypotFeed(request, env, ctx) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
        return new Response('Method not allowed', { status: 405, headers: { Allow: 'GET, HEAD' } });
    }

    const cache = caches.default;
    const key = new Request(new URL('/api/live/honeypot', request.url).toString(), { method: 'GET' });
    const hit = await cache.match(key);
    if (hit) return hit;

    let upstream;
    try {
        upstream = await fetch(UPSTREAM, { headers: { Accept: 'application/json' } });
    } catch (e) {
        return json({ error: 'upstream unreachable' }, 502);
    }
    if (!upstream.ok) return json({ error: 'upstream HTTP ' + upstream.status }, 502);

    const res = new Response(upstream.body, {
        status: 200,
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'public, max-age=' + TTL_SECONDS,
            'X-Content-Type-Options': 'nosniff',
        },
    });
    if (ctx && ctx.waitUntil) ctx.waitUntil(cache.put(key, res.clone()));
    return res;
}

function json(body, status) {
    return new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
    });
}
