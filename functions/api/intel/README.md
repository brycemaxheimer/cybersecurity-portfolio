# /api/intel/* - backend Threat-Intel Lookup

Two route handlers (imported by `worker.js` at the repo root) that power
[/lab/threat-intel/demo.html](../../../lab/threat-intel/demo.html):

| Route                | Method | Purpose |
|----------------------|--------|---------|
| `/api/intel/lookup`  | POST   | Look up an indicator (IP today; hash/domain/URL stubbed). |
| `/api/intel/health`  | GET    | Report which providers are configured + reachable. Cached 60s. |

The browser only ever sees these same-origin endpoints. API keys stay in
Worker secrets and are read inside the handler as `env.<NAME>`.

## Required env vars / secrets

| Name                       | Purpose                                                  | Get one |
|----------------------------|----------------------------------------------------------|---------|
| `ABUSEIPDB_KEY`            | AbuseIPDB API key (free tier 1000 checks/day).           | https://www.abuseipdb.com/account/api |
| `INTEL_RATE_LIMIT_PER_MIN` | Optional. Per-IP rate limit (default `10`).              | - |

ip-api.com is wired with no key (45 req/min from a single source IP).

### Set in production (Cloudflare dashboard)

`Workers & Pages → cybersecurity-portfolio → Settings → Variables and
Secrets → Add variable`. Add `ABUSEIPDB_KEY` as **Secret** (encrypted) and
optionally `INTEL_RATE_LIMIT_PER_MIN` as a plaintext **Variable**.

> If the dashboard still says *"Variables cannot be added to a Worker that
> only has static assets"*, your Worker is missing a `main` entry. Confirm
> `wrangler.jsonc` has `"main": "worker.js"` and redeploy - once any code
> is bound, the Variables tab unlocks.

### Set in local dev

```bash
wrangler dev --var ABUSEIPDB_KEY=<your-key>
# then visit http://localhost:8787/lab/threat-intel/demo.html
```

## Smoke-test from the CLI

```bash
# Health
curl -s https://<your-host>/api/intel/health | jq

# Lookup
curl -sX POST https://<your-host>/api/intel/lookup \
    -H 'Content-Type: application/json' \
    -d '{"indicator":"8.8.8.8"}' | jq
```

## Limits

- Rate gate is per-isolate (in-memory `Map`). Good enough for a public demo;
  Workers KV would be needed for a hard, durable cap across regions.
- Hash / domain / URL paths return an `echo` placeholder today. Wire
  VirusTotal / urlhaus / urlscan when keys are added.
- The PowerShell `SecIntel.ThreatIntel.*` family on the
  [walkthrough page](../../../lab/threat-intel/index.html) covers the full
  provider set and runs locally against your own DPAPI-stored keys.
