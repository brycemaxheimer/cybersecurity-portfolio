# /api/relay/* - remote task relay

An unlisted, Access-gated page at [`/relay/`](../../../relay/index.html) that
lets me hand work to Claude Code on this repo from any browser, on a machine
that is not my phone or laptop.

A task is a GitHub issue labelled `relay` with `@claude` in the body.
`.github/workflows/claude.yml` picks it up; replies are issue comments, so a
task thread becomes a conversation. It is **asynchronous** - minutes, not
seconds.

| Route                     | Method | Purpose                                   |
|---------------------------|--------|-------------------------------------------|
| `/api/relay/whoami`       | GET    | Verified identity from the Access token.  |
| `/api/relay/tasks`        | GET    | 20 most recently updated relay issues.    |
| `/api/relay/thread?n=<n>` | GET    | One relay issue plus its comments.        |
| `/api/relay/task`         | POST   | `{title, body}` - dispatch a task.        |
| `/api/relay/reply`        | POST   | `{number, body}` - comment on a task.     |

The browser never holds a credential. It proves identity to Cloudflare Access;
the Worker holds the GitHub token as an encrypted secret.

## Threat model

What this design assumes, and what it deliberately does not defend against.

**The premise is a borrowed or untrusted machine.** That is why there is no
password. A static password typed into a keylogged browser is stolen on first
use and grants standing access. An Access email OTP is single-use and
time-boxed, so capturing it buys an attacker one expiring session rather than
a permanent credential. If the machine is *actively* compromised, the attacker
rides your live session regardless of the auth mechanism - no browser-side
control fixes that. What OTP buys is that the compromise ends when the session
does.

**Defence in depth is the point of verifying twice.** Access is an edge policy
configured in a dashboard, outside this repo. A policy scoped to the wrong
path, or removed during unrelated Zero Trust work, fails *open* - traffic
flows to the origin as if no gate existed. `access.js` re-verifies the signed
assertion inside the Worker, so the relay fails *closed* instead: no valid
assertion, no GitHub token, no dispatch. Misconfiguration returns 503, never
"allow".

**The `aud` check is not redundant.** Every Access application in a team is
signed by the same key. A token minted for any *other* app in the team would
verify cryptographically. Pinning the audience to this app's AUD tag, plus the
email allowlist, is what makes the signature mean "authorised for the relay"
rather than merely "issued by my team".

**Blast radius is bounded by the token, not by the code.** Use a fine-grained
PAT scoped to Issues on this one repository. Then the worst case for a stolen
Worker secret is issue spam in one repo - not code push, not other repos, not
account takeover.

**Known accepted limits:**

- Rate limiting is an in-isolate `Map`, same as the intel routes. It smooths
  runaway client retries; it is not a durable cross-region quota.
- Issue and comment bodies are attacker-influenced on a public repo. The
  front-end renders every remote value with `textContent` and never
  `innerHTML`. Preserve that if you extend the UI - and note that adding
  Markdown rendering would reintroduce exactly the injection path this avoids.
- `/relay/` being unlisted is hygiene, not a control. `noindex` keeps it out
  of search results; it does not keep anyone out of the page.

## Setup

Four steps. The relay returns **503 until all of them are done**, which is the
intended failure mode.

### 1. Cloudflare Access application

Zero Trust dashboard -> Access -> Applications -> Add a self-hosted app.

- **Application domain:** `brycemaxheimer.com`, path `relay`
- **Add a second path** for `api/relay` (both must be covered - the page and
  the API it calls)
- **Policy:** Action *Allow*, include *Emails* -> your address
- **Login method:** One-time PIN (this is the email OTP)
- Copy the **Application Audience (AUD) tag** from the app's overview page

### 2. Worker variables and secrets

Workers & Pages -> cybersecurity-portfolio -> Settings -> Variables and Secrets.

| Name                       | Type      | Value |
|----------------------------|-----------|-------|
| `RELAY_ACCESS_TEAM_DOMAIN` | Variable  | `<team>.cloudflareaccess.com` (no `https://`) |
| `RELAY_ACCESS_AUD`         | Variable  | The AUD tag from step 1 |
| `RELAY_ALLOWED_EMAILS`     | Variable  | Comma-separated; must match the Access policy |
| `RELAY_GITHUB_TOKEN`       | **Secret**| Fine-grained PAT, see step 3 |
| `RELAY_GITHUB_REPO`        | Variable  | `brycemaxheimer/cybersecurity-portfolio` |
| `RELAY_RATE_LIMIT_PER_MIN` | Variable  | Optional, default `20` |

### 3. GitHub token

github.com/settings/personal-access-tokens -> Generate new token.

- **Repository access:** Only select repositories -> this repo alone
- **Permissions:** Issues **Read and write**. Nothing else - not contents,
  not workflows, not metadata beyond what GitHub forces.
- Set an expiry you will actually rotate at. 90 days is reasonable.

### 4. Make dispatched tasks run

The relay files issues; `.github/workflows/claude.yml` is what acts on them.
That workflow needs:

1. The **Claude GitHub App** installed on the repo. Easiest path is to run
   `/install-github-app` from Claude Code, which also verifies the workflow
   against the current action inputs.
2. An **`ANTHROPIC_API_KEY`** repository secret (Settings -> Secrets and
   variables -> Actions).

Use a **dedicated API key with a spend cap** set in the Anthropic console, not
your main key. If it ever leaks, you cap the damage and can revoke it without
disturbing anything else.

## Verify it works

```bash
# Unauthenticated -> 401. If this returns 200, Access is misconfigured.
curl -si https://brycemaxheimer.com/api/relay/whoami | head -1

# In a browser, visit https://brycemaxheimer.com/relay/
# -> Access email OTP prompt
# -> after sign-in, the header shows your verified email
```

Then dispatch a throwaway task ("reply with the current branch name and do not
change any files"), confirm the issue appears with the `relay` label, and
confirm the workflow run starts under the repo's Actions tab.

## Local development

Access assertions cannot be minted locally, so `verifyAccess` will reject
everything under `wrangler dev`. Test the page against the deployed Worker, or
temporarily stub the verifier - **never** commit a stub that bypasses it.

## Revoking access in a hurry

If a session may be compromised, in order of speed:

1. Zero Trust -> Access -> your app -> revoke active sessions
2. Delete the `RELAY_GITHUB_TOKEN` secret (relay goes 503 immediately)
3. Revoke the PAT at github.com/settings/personal-access-tokens
