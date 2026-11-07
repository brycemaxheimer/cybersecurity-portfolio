# intel-brief

A daily, AI-generated threat-intel page for SOC analysts, published at
`intel.brycemaxheimer.com`. Once a day a GitHub Actions job collects free
public sources, uses Claude to rank and summarize them, drafts detections,
renders a static site, and opens a pull request. The edition is checked by
`python -m intel_brief verify`; if every gate passes the job merges its own PR
and the edition publishes itself. A failed gate holds the PR for review instead.

It lives in the `cybersecurity-portfolio` repo but is deployed separately:
Cloudflare Workers Builds deploys `intel-brief/site` to its own static-assets
Worker (`intel-brief`, configured by `intel-brief/wrangler.jsonc`). The
portfolio Worker never serves anything under `intel-brief/` (see the repo's
`.assetsignore`).

Why a second Worker rather than routing by hostname inside the portfolio
Worker: that would need `run_worker_first: true`, and Cloudflare doesn't apply
`_headers` or `_redirects` to responses from Worker code. The portfolio would
lose its CSP and HSTS headers and its redirects.

Each edition has:

- **Top stories** (about 10): what happened, why it matters, affected and fixed
  versions, what to do, and links to the sources.
- **New CISA KEV entries**, with due dates.
- **Early signals**: CVEs that several researchers posted about in the last 24
  hours that aren't in KEV or the news yet.
- **Detections**: an existing SigmaHQ rule when there is one. Otherwise an
  AI-drafted Sigma rule that passed `sigma check`, converted to Defender XDR /
  Sentinel KQL, Splunk SPL and Elastic. The KQL is parsed with Microsoft's
  Kusto.Language. Stories with no behavior to detect get hunting steps and KQL
  hunting queries instead.
- **Explainer**: one security concept behind the day's stories, from a couple of
  paragraphs to a few headed parts depending on how involved it is. Written from
  the model's background knowledge and labelled that way.
- **Good news**: up to four positive developments from the collected news
  (takedowns, arrests, fixes shipped, new defenses), each linked to its sources.
- An **RSS feed** (`/feed.xml`), a **JSON Feed** (`/feed.json`), each edition's
  data (`/editions/<date>/edition.json`) and an **archive**.

## How it works

Each edition covers one day: the whole of the day before its own date, in the
site's timezone, and nothing outside it. The edition dated 6 November reports
5 November. The delay is the point -- a day is usually enough for a first
report to be corrected, confirmed by a vendor advisory, or quietly dropped --
and it means the page never mixes an hour-old claim with one from two days
ago. `config.day_window` is the single definition; the collector gathers by it
and `intel_brief verify` checks each edition against it.

Because the window comes from the date and not from the clock, when the job
actually runs does not change what the edition contains, and rebuilding a past
date reproduces it exactly.

```
collect (plain code)  ->  triage (Haiku 5.5)  ->  write-ups (Opus 5.5 / Sonnet 5.5)
                                               ->  detections  ->  render  ->  verify  ->  PR  ->  merge  ->  deploy
```

| Step | Code | What it does |
|---|---|---|
| 1. Collect | `intel_brief/collect/` | CISA KEV, NVD CVE API 2.0 (high/critical, published on the covered day), FIRST EPSS, MSRC and CISA advisories, news RSS (`config/sources.toml`), new SigmaHQ rules (git history of a shallow clone), PoC repo links (nomi-sec/PoC-in-GitHub index), Bluesky, Mastodon (infosec.exchange), r/netsec, Hacker News. X/Twitter is left out: its API is paid and scraping breaks its terms. |
| 2. Triage | `intel_brief/triage.py` | `claude-haiku-5-5` groups items into stories and labels them: exploitation status, how widely the product is used, platform (Windows, M365/Entra, edge device...). **Code** computes the score from those labels plus KEV, EPSS, CVSS and source count. If the call fails or is refused, code groups items by CVE instead. |
| 3. Write-ups | `intel_brief/writeup.py` | One call per top story with `claude-opus-5-5` (default) or `claude-sonnet-5-5`, so one refusal costs one story, not the edition. |
| 3b. Explainer and good news | `intel_brief/explainer.py` | One call with the write-up model after all write-ups, so it never takes budget from them. It picks a concept tied to the day's stories (skipping concepts from the last 30 editions) and up to 4 good-news items from the collected news and advisories. Good-news entries without a collected source are dropped; links come from the collector. CVE IDs the explainer names that no source mentions are flagged on the page. Settings in `[explainer]` in `config/settings.toml`. |
| 4. Detections | `intel_brief/detections/` | SigmaHQ rule lookup by CVE tag. If there is none, Claude's structured Sigma draft is turned into YAML by code, checked with `sigma check` (one repair attempt), and converted with pySigma (`kusto` + `microsoft_xdr`, `splunk_windows`, `ecs_windows`). All KQL goes through `tools/validate_kql.ps1` (Kusto.Language, with the table schemas in `config/kql_schema.json`). |
| 5. Render | `intel_brief/render/` | Jinja2 templates with autoescaping, no JavaScript (detection format tabs are CSS-only radio buttons), no inline styles, and a strict CSP in `site/_headers`. Playfair Display, Libre Franklin and IBM Plex Mono are self-hosted from `intel_brief/render/static/fonts/` (SIL OFL 1.1, license files alongside; design in `docs/design/red-top-spec.md`), so readers' browsers never contact a font CDN. Pages: latest edition, one page per edition, archive, methodology, RSS, JSON Feed. |

Early signals (`intel_brief/signals.py`) are counted by code, not by a model.
Accounts that post about 15 or more CVEs a day are treated as feed bots, and
posts that name 5 or more CVEs as digests. Neither counts toward a signal.

## Security model

Everything the collector fetches is untrusted. It may contain prompt injection.

- **No tools, JSON only.** Model calls get no tools. They return JSON in fixed
  Pydantic schemas (structured outputs via `client.messages.parse`). Fetched
  content goes inside `<untrusted_items>` / `<untrusted_story>`, JSON-encoded,
  and the system prompts tell the model never to follow instructions in it.
- **Links come from the collector, never the model.** The model refers to sources
  by item ID. Every href is checked against the source's `allowed_hosts`
  (https only, no credentials or odd ports) when collected and again when
  rendered. URLs in model text are replaced with `[link removed]`.
- **Escaping.** All model text is HTML-escaped by Jinja autoescape. Control
  and bidi characters are stripped. The page has no JavaScript, and the CSP is
  `default-src 'none'; style-src 'self'; img-src 'self'`.
- **CVE IDs and scores come from code.** A story's CVEs are the CVEs the collector
  found in its items. The ranking score is computed in `triage.py`.
- **Sigma YAML is built by code** from validated fields. The model never writes
  raw YAML. Condition strings, field names, modifiers and tags are whitelisted.
- **Hunting queries** that contain a hash or IP address not present in any
  source item are dropped, so invented indicators don't get published.
- **Labels.** AI-drafted rules and hunting guidance are marked "AI-generated,
  untested". SigmaHQ rules are marked "SigmaHQ community rule, converted, untested".
- **Summaries and links only.** Feed text goes to the model as context but is
  never published. PoC repos are links only, with a warning.
- **Secrets.** The key is read from `INTEL_BRIEF_ANTHROPIC_API_KEY` (a User
  env var locally, a GitHub Actions secret in CI) and passed to the SDK
  explicitly. It is never written to disk or committed. The code deliberately
  doesn't use `ANTHROPIC_API_KEY`: a user-level `ANTHROPIC_API_KEY` would also
  switch Claude Code on the same machine to API billing.
- **Gated publishing.** The daily workflow opens a PR that touches only
  `intel-brief/data/` and `intel-brief/site/`, then merges it only if
  `intel_brief/verify.py` passes. Those gates are what stands between an
  untrusted feed and the public page, so they are the thing to extend rather
  than loosen: shape, substance, cost, source health, model refusals, and
  whether anything reached the page as markup, as an event handler, or as a
  link off the allowlist. A failure holds the PR, labels it `needs-review`, and
  fails the job. The workflow holds no Cloudflare credentials; Workers Builds
  deploys on merge.
- **Supply chain.** Python dependencies install with `--require-hashes` from
  `requirements.lock`. Actions are pinned by commit SHA. The Kusto.Language
  package is checked against nuget.org's published SHA-512 and is never
  committed, because its license doesn't allow redistribution.

## Cost

`intel_brief/llm.py` enforces a hard cap per run (`config/settings.toml`
`budget.max_cost_usd`, default $2.00, overridable with `--max-cost`). Before
each call it computes the worst case (input estimated at 3 characters per
token, plus `max_tokens` of output, priced at the more expensive of the model
and its refusal fallback). The call is skipped if that could pass the cap.
Stories that miss out keep their facts and links but get no write-up.

Every call's tokens (input, cache write, cache read, output) and cost go to
`data/runs/<date>.json`, which is committed with the edition. The PR body shows
the total.

Other cost details:

- The write-up system prompt is identical for every call and has a cache
  breakpoint. Calls 2 to 10 read it from cache.
- Opus and Sonnet calls use server-side refusal fallback (`fallbacks: "default"`).
  A refusal returns `None` and the story is shown without a write-up.
- Haiku has no server-side fallback, so its refusals are handled in code.
- The cost is priced from the model that actually served the reply. If a
  fallback ran after a partial decline, the declined part may also be billed,
  so the logged total can be slightly low on those rare calls.

Expected cost per day with Opus 5.5: roughly $1 to $1.50 (triage is about $0.01;
the explainer and good news about $0.10 to $0.25).
Sonnet 5.5 costs about half as much.

## Run locally

```powershell
cd "C:\Users\bmaxh\Documents\Github Repositories\cybersecurity-portfolio\intel-brief"
py -3.13 -m venv .venv
.\.venv\Scripts\python -m pip install --require-hashes --no-deps -r requirements.lock
pwsh -File tools\fetch_kusto_language.ps1        # optional: enables the KQL parser check

# Free: collect + fallback triage + render, no model calls
.\.venv\Scripts\python -m intel_brief run --dry-run

# Real run with a $1 cap (needs INTEL_BRIEF_ANTHROPIC_API_KEY in the environment)
.\.venv\Scripts\python -m intel_brief run --max-cost 1.00

# Re-render site/ from data/editions/*.json
.\.venv\Scripts\python -m intel_brief render

# Run the gates that decide whether an edition may publish itself.
# Exit 0 means the daily job would merge it; 1 means it would be held.
.\.venv\Scripts\python -m intel_brief verify --date 2026-11-05

# Tests
.\.venv\Scripts\python -m unittest discover -s tests
```

`--from-cache` reuses `.cache/runs/<date>/collection.json`, so you can rerun
the model steps without collecting again. `--writeup-model claude-sonnet-5-5`
switches the write-up model. Optional `NVD_API_KEY` raises the NVD rate limit.

## Repository layout

```
config/            settings.toml, sources.toml, kql_schema.json (Defender XDR / Sentinel tables)
intel_brief/       the pipeline (collect, triage, writeup, detections, signals, render)
tools/             fetch_kusto_language.ps1, validate_kql.ps1
data/editions/     one JSON per edition (source of truth for the site)
data/runs/         per-run cost and source status
site/              rendered output that gets deployed (committed, so the PR shows exactly what will ship)
wrangler.jsonc     the intel-brief Worker (static assets from ./site, custom domain intel.brycemaxheimer.com)
intel_brief/verify.py                  the gates an edition must pass to publish itself
../.github/workflows/intel-daily.yml   daily build, verify, PR, merge (at the repo root, where GitHub requires it)
../.assetsignore   keeps intel-brief/ out of the portfolio Worker's assets
```

## Remaining setup

These are done by hand, in this order. Each one is outward-facing.

1. **Merge the PR that adds `intel-brief/`** to `main` (it doesn't change
   anything the portfolio serves).
2. **Detach `intel.brycemaxheimer.com` from the portfolio Worker.** Cloudflare
   dashboard, Workers & Pages, `cybersecurity-portfolio`, Settings, Domains &
   Routes: remove the custom domain. A hostname can belong to only one Worker.
3. **Create the `intel-brief` Worker with Workers Builds.** Workers & Pages,
   Create, Import a repository: `brycemaxheimer/cybersecurity-portfolio`.
   - Project name: `intel-brief` (must match `wrangler.jsonc`).
   - Root directory: `intel-brief`.
   - Build command: none. Deploy command: `npx wrangler deploy` (the default).
   - Production branch: `main`.
   The first build deploys `intel-brief/site` and attaches
   `intel.brycemaxheimer.com` from `wrangler.jsonc`, which creates the DNS
   record and certificate. If the build can't attach the domain, add it under
   the Worker's Settings, Domains & Routes instead.
4. **Optional: build watch paths.** So each Worker only rebuilds for its own
   files: on `intel-brief` include `intel-brief/*`; on `cybersecurity-portfolio`
   exclude `intel-brief/*`.
5. **Let Actions open PRs.** Repo Settings, Actions, General, Workflow
   permissions: "Read and write permissions" and tick "Allow GitHub Actions to
   create and approve pull requests".
6. **Add secrets** (Settings, Secrets and variables, Actions):
   - `INTEL_BRIEF_ANTHROPIC_API_KEY`: the dedicated intel-brief API key,
     ideally from a workspace with a monthly spend limit.
   - `NVD_API_KEY` (optional, free from NVD).
   No Cloudflare secrets: Workers Builds deploys, not the workflow.
7. **Protect `main`, but let this workflow merge.** Requiring a PR to merge is
   worth keeping: every edition still arrives as a reviewable diff. What the
   rules must not do is require an approving review, because the daily job
   merges its own PR once the gates pass -- that is what replaced the manual
   review. Under Settings, Branches (or Rules), allow `github-actions[bot]` to
   bypass the pull-request requirement. If the rules refuse the bot, the
   Publish step says so explicitly and the edition waits for a hand merge.
8. **Link it from the portfolio** (optional), for example from the nav.

After that, the daily workflow is scheduled for 10:00 UTC (05:00 EST, 06:00
EDT) and opens an "Intel brief: edition YYYY-MM-DD" PR. Expect it later than
that: GitHub's scheduler is best-effort, and the first five runs started
between 5h53m and 9h32m late. The lateness no longer affects what is in the
edition, only when it appears, because the window is fixed by the edition's
date rather than by the clock. You can also run it by hand
from the Actions tab with a different model, cost cap or date.

## Phase 2 (not built)

- An "early signals" check every few hours that updates the page, or alerts,
  between daily editions.
- Fetching full article text for better write-ups. It would still be
  model-only context and never published.
- Sentinel ASIM output (`sentinel_asim` pipeline) next to Defender XDR.
