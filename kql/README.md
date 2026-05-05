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
