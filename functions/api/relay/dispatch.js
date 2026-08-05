/* ==========================================================================
 * /api/relay/* -- authenticated remote task relay.
 *
 * Lets me hand work to Claude Code on this repo from any browser, without
 * needing my own phone or laptop. The browser never holds a credential: it
 * proves identity to Cloudflare Access, and this Worker holds the GitHub
 * token as an encrypted secret.
 *
 *   GET  /api/relay/whoami          -> { email }
 *   GET  /api/relay/tasks           -> recent relay issues (newest first)
 *   GET  /api/relay/thread?n=<num>  -> one issue + its comments
 *   POST /api/relay/task            -> { title, body } create a task
 *   POST /api/relay/reply           -> { number, body } comment on a task
 *
 * A task is a GitHub issue labelled `relay`, with `@claude` in the body so
 * .github/workflows/claude.yml picks it up. Replies are issue comments, which
 * the same workflow answers -- so a task thread is a conversation, just an
 * asynchronous one measured in minutes rather than seconds.
 *
 * Every handler calls verifyAccess() FIRST. There is no unauthenticated path
 * through this file, including the read-only ones: the issue list leaks what
 * I have been working on, so it is gated the same as the writes.
 *
 * Env (see README.md in this directory):
 *   RELAY_ACCESS_TEAM_DOMAIN, RELAY_ACCESS_AUD, RELAY_ALLOWED_EMAILS
 *   RELAY_GITHUB_TOKEN   (secret)  fine-grained PAT, Issues:RW on one repo
 *   RELAY_GITHUB_REPO              "owner/name"
 *   RELAY_RATE_LIMIT_PER_MIN       optional, default 20
 * ========================================================================== */

import { verifyAccess } from './access.js';

const LABEL = 'relay';
const GH_API = 'https://api.github.com';
const UA = 'brycemaxheimer-relay/1.0';

const MAX_TITLE = 200;
const MAX_BODY = 12000;

// Per-identity token bucket. Same in-isolate caveat as the intel routes: this
// is an abuse smoother, not a durable quota. It sits BEHIND Access, so the
// population it limits is already just me -- its real job is capping runaway
// client retries against the GitHub API rate limit.
const RATE_BUCKET = new Map();

function rateLimitOk(key, perMin) {
    const now = Date.now();
    const entry = RATE_BUCKET.get(key) || { tokens: perMin, refilledAt: now };
    if (now - entry.refilledAt >= 60_000) {
        entry.tokens = perMin;
        entry.refilledAt = now;
    }
    if (entry.tokens <= 0) {
        RATE_BUCKET.set(key, entry);
        return false;
    }
    entry.tokens -= 1;
    RATE_BUCKET.set(key, entry);
    return true;
}

function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store',
            'X-Robots-Tag': 'noindex, nofollow',
        },
    });
}

// Reject anything that is not literally owner/name before it reaches a URL
// path. Guards against a mistyped variable turning into a request at an
// attacker-chosen GitHub path.
function repoOk(repo) {
    return /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(repo);
}

async function gh(env, path, init = {}) {
    const r = await fetch(`${GH_API}${path}`, {
        ...init,
        headers: {
            Authorization: `Bearer ${env.RELAY_GITHUB_TOKEN}`,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': UA,
            ...(init.body ? { 'Content-Type': 'application/json' } : {}),
            ...(init.headers || {}),
        },
    });
    return r;
}

function shapeIssue(i) {
    return {
        number: i.number,
        title: i.title,
        state: i.state,
        url: i.html_url,
        comments: i.comments,
        createdAt: i.created_at,
        updatedAt: i.updated_at,
        labels: (i.labels || []).map((l) => (typeof l === 'string' ? l : l.name)),
    };
}

function shapeComment(c) {
    return {
        id: c.id,
        author: c.user ? c.user.login : null,
        // Distinguishes Claude's replies from my own in the UI without
        // hardcoding a bot username that may change.
        isBot: Boolean(c.user && c.user.type === 'Bot'),
        body: c.body || '',
        createdAt: c.created_at,
        url: c.html_url,
    };
}

/* -------------------------------------------------------------------------
 * Route handlers. `auth` is the verified result from verifyAccess().
 * ---------------------------------------------------------------------- */

async function listTasks(env, repo) {
    const r = await gh(env, `/repos/${repo}/issues?labels=${LABEL}&state=all&sort=updated&direction=desc&per_page=20`);
    if (!r.ok) return json({ error: `github ${r.status}` }, 502);
    const items = await r.json();
    // The issues endpoint also returns PRs; a relay task is never a PR.
    return json({ tasks: items.filter((i) => !i.pull_request).map(shapeIssue) });
}

async function getThread(env, repo, numRaw) {
    const n = Number.parseInt(numRaw, 10);
    if (!Number.isInteger(n) || n < 1) return json({ error: 'bad issue number' }, 400);

    const [issueRes, commentsRes] = await Promise.all([
        gh(env, `/repos/${repo}/issues/${n}`),
        gh(env, `/repos/${repo}/issues/${n}/comments?per_page=100`),
    ]);

    if (issueRes.status === 404) return json({ error: 'not found' }, 404);
    if (!issueRes.ok) return json({ error: `github ${issueRes.status}` }, 502);

    const issue = await issueRes.json();

    // Only expose threads this relay created. Without this check the endpoint
    // is a generic "read any issue in the repo" proxy.
    const labels = (issue.labels || []).map((l) => (typeof l === 'string' ? l : l.name));
    if (!labels.includes(LABEL)) return json({ error: 'not found' }, 404);

    const comments = commentsRes.ok ? (await commentsRes.json()).map(shapeComment) : [];
    return json({ task: shapeIssue(issue), comments });
}

async function createTask(env, repo, body, auth) {
    const title = String(body.title || '').trim();
    const detail = String(body.body || '').trim();

    if (!title) return json({ error: 'title is required' }, 400);
    if (title.length > MAX_TITLE) return json({ error: `title exceeds ${MAX_TITLE} chars` }, 400);
    if (!detail) return json({ error: 'body is required' }, 400);
    if (detail.length > MAX_BODY) return json({ error: `body exceeds ${MAX_BODY} chars` }, 400);

    // Best-effort label creation. A 422 here means it already exists, which is
    // the common case and not an error worth failing the dispatch over.
    await gh(env, `/repos/${repo}/labels`, {
        method: 'POST',
        body: JSON.stringify({ name: LABEL, color: '5b8def', description: 'Dispatched from the remote relay' }),
    }).catch(() => {});

    const issueBody =
        `@claude\n\n${detail}\n\n---\n` +
        `<sub>Dispatched via the remote relay by ${auth.email}.</sub>`;

    const r = await gh(env, `/repos/${repo}/issues`, {
        method: 'POST',
        body: JSON.stringify({ title, body: issueBody, labels: [LABEL] }),
    });

    if (!r.ok) {
        const text = await r.text();
        return json({ error: `github ${r.status}`, detail: text.slice(0, 300) }, 502);
    }
    return json({ task: shapeIssue(await r.json()) }, 201);
}

async function replyToTask(env, repo, body, auth) {
    const n = Number.parseInt(body.number, 10);
    const detail = String(body.body || '').trim();

    if (!Number.isInteger(n) || n < 1) return json({ error: 'bad issue number' }, 400);
    if (!detail) return json({ error: 'body is required' }, 400);
    if (detail.length > MAX_BODY) return json({ error: `body exceeds ${MAX_BODY} chars` }, 400);

    // Same containment as getThread: replies only go to relay-created threads.
    const issueRes = await gh(env, `/repos/${repo}/issues/${n}`);
    if (issueRes.status === 404) return json({ error: 'not found' }, 404);
    if (!issueRes.ok) return json({ error: `github ${issueRes.status}` }, 502);
    const issue = await issueRes.json();
    const labels = (issue.labels || []).map((l) => (typeof l === 'string' ? l : l.name));
    if (!labels.includes(LABEL)) return json({ error: 'not found' }, 404);

    const r = await gh(env, `/repos/${repo}/issues/${n}/comments`, {
        method: 'POST',
        body: JSON.stringify({
            body: `@claude\n\n${detail}\n\n---\n<sub>Relay reply from ${auth.email}.</sub>`,
        }),
    });

    if (!r.ok) {
        const text = await r.text();
        return json({ error: `github ${r.status}`, detail: text.slice(0, 300) }, 502);
    }
    return json({ comment: shapeComment(await r.json()) }, 201);
}

/* -------------------------------------------------------------------------
 * Entry point. Routed from worker.js for any /api/relay/* path.
 * ---------------------------------------------------------------------- */

export async function handleRelay(request, env, url) {
    const auth = await verifyAccess(request, env);
    if (!auth.ok) {
        // Log the specific reason; return a generic one. A prober should not
        // be able to tell "expired" from "wrong audience" from "not allowed".
        console.log(`relay auth rejected: ${auth.error}`);
        const status = auth.status === 503 ? 503 : auth.status === 403 ? 403 : 401;
        return json({ error: status === 503 ? 'relay unavailable' : 'unauthorized' }, status);
    }

    const limit = Number(env.RELAY_RATE_LIMIT_PER_MIN || 20);
    if (!rateLimitOk(auth.email, limit)) {
        return json({ error: `Rate limit exceeded (${limit}/min).` }, 429);
    }

    const route = url.pathname.replace(/^\/api\/relay\/?/, '');

    if (route === 'whoami') {
        return json({ email: auth.email });
    }

    const repo = String(env.RELAY_GITHUB_REPO || '').trim();
    if (!env.RELAY_GITHUB_TOKEN || !repoOk(repo)) {
        return json({ error: 'relay backend not configured' }, 503);
    }

    if (request.method === 'GET' && route === 'tasks') {
        return listTasks(env, repo);
    }
    if (request.method === 'GET' && route === 'thread') {
        return getThread(env, repo, url.searchParams.get('n'));
    }

    if (request.method === 'POST' && (route === 'task' || route === 'reply')) {
        let body;
        try {
            body = await request.json();
        } catch (_) {
            return json({ error: 'Body must be JSON' }, 400);
        }
        return route === 'task'
            ? createTask(env, repo, body, auth)
            : replyToTask(env, repo, body, auth);
    }

    return json({ error: 'not found' }, 404);
}
