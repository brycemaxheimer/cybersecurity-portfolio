# Publishing the brief by 04:00 Eastern

Status: **planned, not implemented.** Nothing in this document is wired up. The
three changes in "The change" are not in the repository; the Worker code here
is inert until someone adds it. Behaviour today is unchanged: the edition is
published by GitHub's own cron, late morning or early afternoon Eastern.

Goal: the edition is live by 04:00–05:00 US Eastern, early enough to feed a
morning DSIR before people arrive.

The code below has been syntax-checked, not run: the Worker snippet parses as
an ES module under `node --check`, and the workflow with the guard applied
parses as YAML with every `if:` on the step it is meant for and every shell
block valid under `bash -n`. Nothing here has been executed against the live
Worker or a real token.

## Why GitHub's cron cannot do it

`schedule` in GitHub Actions is best-effort. It queues the run on shared
infrastructure and can delay it for hours. Measured over the first seven
scheduled runs of this workflow:

| Day | Cron | Started (UTC) | Late by |
|---|---|---|---|
| 11-01 | 11:15 | 17:08 | 5h53m |
| 11-02 | 11:15 | 20:47 | 9h32m |
| 11-03 | 11:15 | 18:27 | 7h12m |
| 11-04 | 11:15 | 18:39 | 7h24m |
| 11-05 | 11:15 | 18:46 | 7h31m |
| 11-06 | 11:15 | 17:58 | 6h43m |
| 11-07 | 10:00 | 16:16 | 6h16m |

Minimum 5.89 h, median 7.21 h, maximum 9.55 h, spread 3.66 h.

There is no cron value that meets the goal, because the run also cannot start
*too* early: an edition covers the previous calendar day in US Eastern, so the
job must start after local midnight or the day it reports has not finished.
That puts the earliest honest cron at 05:00 UTC, and from there:

```
05:00 UTC + 5.89 h (best ever seen)  = 10:53 UTC = 05:53 EST
05:00 UTC + 9.55 h (worst ever seen) = 14:33 UTC = 09:33 EST
```

Even the best case observed misses the window. Moving the cron cannot fix
this; the delay is larger than the gap between local midnight and the
deadline.

## What is already fast

Only the scheduler is slow. Everything downstream is quick, so the deadline is
easy to hit once the job actually starts.

- **`workflow_dispatch` starts immediately.** Run 7 was created at
  `07:35:55Z` and started at `07:35:55Z`: no queue at all. Dispatch is not
  subject to the `schedule` backlog.
- **The job takes about seven minutes.** Run 7: `07:35:55Z` to `07:43:07Z`,
  including collection, triage, write-ups, detections, render, gates, the pull
  request and the self-merge.
- **Cloudflare deploys in one to two minutes.** Measured from merge commit to
  the `Workers Builds: intel-brief` check starting: 1m05s, 1m25s, 1m31s,
  2m12s.

So from trigger to live page is roughly **nine to ten minutes**. Firing at
04:00 Eastern puts the edition up by about 04:10.

## The change

Three parts. The first two make the trigger punctual; the third makes it safe
to keep GitHub's cron as a fallback.

### 1. A scheduled handler on the portfolio Worker

No new Cloudflare project is needed. The `cybersecurity-portfolio` Worker
already has a script and already reads secrets, so the trigger goes there.

Add to `worker.js`, above the default export:

```js
/* ==========================================================================
 * Scheduled trigger for the intel brief.
 *
 * GitHub's own cron is best-effort and has run this workflow 5.9 to 9.6 hours
 * late, which cannot reach an 04:00 Eastern publication. A workflow_dispatch
 * starts within seconds, and build, gates, merge and deploy take about ten
 * minutes, so firing at 04:00 puts the edition up by about 04:10.
 *
 * The cron runs hourly and this returns immediately except at 04:00 in New
 * York, so the publication hour is correct on both sides of a daylight-saving
 * change without a second cron.
 * ========================================================================== */
const DISPATCH_REPO = 'brycemaxheimer/cybersecurity-portfolio';
const DISPATCH_WORKFLOW = 'intel-daily.yml';
const DISPATCH_TZ = 'America/New_York';
const DISPATCH_HOUR = 4;

function hourIn(timeZone, now) {
    return Number(new Intl.DateTimeFormat('en-US', {
        timeZone, hour: 'numeric', hour12: false,
    }).format(now));
}

export async function dispatchEdition(env, now = new Date()) {
    if (hourIn(DISPATCH_TZ, now) !== DISPATCH_HOUR) {
        return { dispatched: false, reason: 'not the publication hour' };
    }
    if (!env.GITHUB_DISPATCH_TOKEN) {
        throw new Error('GITHUB_DISPATCH_TOKEN is not set on this Worker');
    }
    const res = await fetch(
        `https://api.github.com/repos/${DISPATCH_REPO}/actions/workflows/${DISPATCH_WORKFLOW}/dispatches`,
        {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${env.GITHUB_DISPATCH_TOKEN}`,
                Accept: 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28',
                'User-Agent': 'intel-brief-trigger',
                'Content-Type': 'application/json',
            },
            // No inputs: the workflow then uses today's US Eastern date, and
            // the edition covers the day before it.
            body: JSON.stringify({ ref: 'main', inputs: {} }),
        },
    );
    if (!res.ok) {
        throw new Error(`dispatch failed: ${res.status} ${(await res.text()).slice(0, 300)}`);
    }
    return { dispatched: true };
}
```

and add the handler to the existing default export, beside `fetch`:

```js
export default {
    async fetch(request, env, ctx) {
        /* ...unchanged... */
    },

    // Awaited rather than passed to ctx.waitUntil, so a failed dispatch shows
    // as an errored invocation in Cloudflare observability instead of passing
    // silently.
    async scheduled(event, env, ctx) {
        await dispatchEdition(env);
    },
};
```

### 2. The cron trigger

Add to `wrangler.jsonc` at the repository root, as a top-level key:

```jsonc
  // Hourly, because worker.js fires only at 04:00 America/New_York. A fixed
  // UTC hour would drift by one across daylight saving; this does not. The 23
  // no-op invocations a day are far inside the free allowance.
  "triggers": {
    "crons": ["0 * * * *"]
  },
```

The cron takes effect when Workers Builds deploys the Worker, which happens on
the next push to `main`.

### 3. An idempotency guard in the workflow

With the Worker firing at 04:00 and GitHub's cron still set, two runs can
build the same date. Whichever publishes first should win and the other should
stop. This is worth having regardless: it also makes a manual re-run safe.

In `.github/workflows/intel-daily.yml`, add after the **Edition date** step:

```yaml
      # The Worker trigger and the fallback cron can both fire for one date,
      # and a re-run can follow a successful run. The checkout is main's tip,
      # so an edition file here means it is already published.
      - name: Already published?
        id: published
        env:
          DATE: ${{ steps.date.outputs.date }}
        run: |
          if [ -f "data/editions/$DATE.json" ]; then
            echo "::notice::Edition $DATE is already on main; nothing to build."
            echo "skip=true" >> "$GITHUB_OUTPUT"
          else
            echo "skip=false" >> "$GITHUB_OUTPUT"
          fi
```

then gate the four steps that follow it. **Build edition**, **Verify edition**
and **Open review PR** each get:

```yaml
        if: steps.published.outputs.skip == 'false'
```

and the two conditional steps gain the same clause:

```yaml
      - name: Publish
        if: steps.published.outputs.skip == 'false' && steps.gates.outputs.verdict == 'pass' && (github.event_name != 'workflow_dispatch' || inputs.auto_merge)

      - name: Hold for review
        if: steps.published.outputs.skip == 'false' && steps.gates.outputs.verdict != 'pass'
```

**Do not skip the clause on Hold for review.** A skipped step does not fail a
job, so `success()` still holds and the step's existing condition
(`verdict != 'pass'`, with an empty verdict) would be true. Without the extra
clause, every no-op run would end by failing the job and labelling a pull
request that does not exist.

Leave the `schedule:` block as it is. A cron run that arrives hours after the
Worker has published now costs one no-op job, and it is what keeps the brief
going out if the Worker or its token ever stops working.

## The token

A fine-grained personal access token, as narrow as the API allows:

- GitHub, Settings, Developer settings, Personal access tokens, **Fine-grained tokens**
- Resource owner: `brycemaxheimer`
- Repository access: **Only select repositories**, `cybersecurity-portfolio`
- Repository permissions: **Actions: Read and write**. Nothing else. This is
  the permission the "Create a workflow dispatch event" endpoint requires.
- Expiration: pick a finite one and put the renewal in a calendar. When it
  lapses the Worker starts erroring and the brief silently reverts to the
  fallback cron's timing, which is the old behaviour rather than an outage.

Store it on the Worker, not in the repository:

```
npx wrangler secret put GITHUB_DISPATCH_TOKEN
```

or Workers & Pages, `cybersecurity-portfolio`, Settings, Variables and
Secrets, as an encrypted **Secret** (the same page as `ABUSEIPDB_KEY`).

## Order of operations

1. **Prove the token on its own**, before any code. With the token in a shell
   variable:

   ```
   curl -i -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Accept: application/vnd.github+json" \
     -H "X-GitHub-Api-Version: 2022-11-28" \
     https://api.github.com/repos/brycemaxheimer/cybersecurity-portfolio/actions/workflows/intel-daily.yml/dispatches \
     -d '{"ref":"main","inputs":{"date":""}}'
   ```

   `204 No Content` means the credential and the endpoint are right. It also
   starts a real run that will publish an edition, so do this on a day the
   edition has not run yet, or expect the guard from part 3 to no-op it.
2. **Land part 3 first.** The guard is useful on its own and makes everything
   after it safe to repeat.
3. **Add the secret** to the Worker.
4. **Land parts 1 and 2** together and let Workers Builds deploy.
5. **Watch one morning.** Expect a `workflow_dispatch` run at about 09:00 UTC
   in winter (08:00 in summer), finishing seven minutes later, and the page
   live by roughly 04:10 Eastern.

## Checking it worked

```
gh api "repos/brycemaxheimer/cybersecurity-portfolio/actions/workflows/intel-daily.yml/runs?event=workflow_dispatch&per_page=3" \
  --jq '.workflow_runs[] | "\(.run_number) \(.conclusion) started=\(.run_started_at)"'

curl -s -o /dev/null -w "%{http_code}\n" \
  "https://intel.brycemaxheimer.com/editions/$(TZ=America/New_York date +%F)/"
```

The run should start within a minute of the hour, not hours after it. In
Cloudflare, Workers & Pages, `cybersecurity-portfolio`, the Logs or
Observability view shows each scheduled invocation; 23 of the 24 daily ones do
nothing, and the 04:00 one should show no error.

## Rollback

Remove the `triggers` block from `wrangler.jsonc` and push. The Worker stops
being invoked on a schedule and the GitHub cron carries on alone, exactly as
today. The secret can stay; it is unused without the trigger. The guard from
part 3 is independent and worth keeping either way.

## What to watch

- **A lapsed token degrades, it does not break.** The Worker errors, the
  fallback cron still publishes, and the edition is merely late again. That is
  the old behaviour, not an outage, but it is quiet: the sign is the
  publication hour slipping back to late morning.
- **The guard depends on the checkout being main's tip.** It reads
  `data/editions/<date>.json` from the working tree, which is current because
  the checkout step pins `ref: main`. If that pin is ever removed, the guard
  silently stops working, and so does the fix for the stale-workflow push
  rejection it was added for.
- **This does not make GitHub's cron punctual.** The fallback run still
  arrives hours late. It is a safety net, not a second publication.
