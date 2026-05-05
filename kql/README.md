# In-browser KQL engine

A small KQL-over-SQLite interpreter that powers the cheatsheet, playground,
and the practice page. All execution is local to the browser — no Azure
cluster is contacted.

## Layout

```
kql/
  engine/
    schema.js     table column metadata + type hints
    engine.js     KQL -> SQL translator
    runtime.js    sql.js bootstrap, CSV ingestion, query()
    rewrite.js    surface-syntax rewrites (UMD: window + require)
    api.js        public browser surface (window.KqlEngineApi)
  data/           small storyline CSVs (~30-150 rows)
  data-large/    extended CSVs (200-8000 rows) for stress-testing
  vendor/         sql.js (sql-wasm.js, sql-wasm.wasm); see version note below
  test-harness/   Node harnesses that exercise engine + rewrite layer
  cheatsheet/     static cheatsheet HTML
```

## Public surface

```js
await window.KqlEngineApi.ready();
window.KqlEngineApi.setAnchor('2026-04-29T13:52:40Z');  // pin now()/ago()
const { columns, rows, elapsedMs, rewrittenKql } =
    await window.KqlEngineApi.run('SecurityEvent | take 5');
```

## Why a "rewrite" layer

Real Defender / Sentinel KQL contains a few surface-syntax bits the v1 SQL
translator doesn't speak natively. Rather than spread that knowledge across
the runtime, the practice page, and three Node test harnesses, all of it
lives in one UMD module: `engine/rewrite.js`. It handles `materialize(...)`
unwrap, raw-string `@"..."` literals, `=~`/`!~`, `let X = dynamic([...])`
inlining, `has_any` / `has_all` expansion, `matches regex`, and time-anchor
substitution for `now()` / `ago()`.

A previous `engine-v2/` directory began porting Invoke-KqlPS.ps1 to JS, but
the parser/executor never got past the stub stage and always fell back to v1.
It was removed; v1 is canonical. The rewrite module is the one place where
KQL surface bits get translated.

## Running the harnesses

```
node kql/test-harness/run-gold-tests.cjs
node kql/test-harness/run-validation.cjs
node kql/test-harness/regenerate-gold.cjs   # only after data/ changes
```

`run-gold-tests` runs the 30 canonical practice queries against the v1
engine and compares to `lab/practice/gold-results.json`. `run-validation`
runs the 129-case good/possible/partial/bad/verbatim matrix from
`validation-cases.json`. Both must pass after any change to `engine/`,
`rewrite.js`, or `data/`.

## Vendored sql.js

`kql/vendor/sql-wasm.js` + `sql-wasm.wasm` are the upstream sql.js dist.
They are not version-pinned in package metadata; if you upgrade, drop the
new files in place and re-run both harnesses.

Current pinned version: **sql.js v1.10.3** (upstream tag `v1.10.3`; banner
not present in the dist file itself, version tracked in `kql/vendor/README.md`).
Recompute hashes after any upgrade with `sha256sum kql/vendor/sql-wasm.*`:
- `sql-wasm.js`   sha256:`558a72c3ab3415d0e6d243cfd23f9d61543600d59054b4b7b8da3cd65f6b9fd4`
- `sql-wasm.wasm` sha256:`d7e61b828523001f26ce0b3f88dabcf6c12e5e6edf80eb4f08b26ac7b946ff88`

## Remote browser isolation (Menlo, Zscaler CBI, etc.)

The KQL engine runs entirely in the user's browser via WebAssembly (sql.js).
Some enterprise web-isolation products run user sessions in a remote
container and either strip WebAssembly support, restrict `fetch()`, or
disable IndexedDB on the local browser.

Two failure profiles to be aware of:

- **Pixel-streaming / Full-Isolation mode** (Menlo Full Isolation, Cloudflare
  Browser Isolation default). JavaScript executes in the remote container,
  not on the user's machine. From the user's side everything works; from
  ours, we don't even know the session is isolated. No mitigation needed.
- **DOM-mirror mode with API restrictions** (Menlo Read-Only Isolation,
  Symantec WSS, Zscaler CBI in selective modes). Local JS still runs, but
  WASM, IndexedDB, or downloads may be blocked. `kql/engine/diagnose.js`
  probes for these capabilities at page load, sets `window.KqlEnv` with
  per-feature flags, and exposes `KqlEnv.renderBanner(el, opts)` so the
  practice page and playground show an actionable error instead of a blank
  panel. The cheatsheet and walkthrough text stay readable; only
  query execution is disabled.

There is no "bypass" — if the policy on a network forbids client-side WASM,
the engine genuinely cannot run there. The diagnostics make the limitation
visible and point users to running the repo locally.
