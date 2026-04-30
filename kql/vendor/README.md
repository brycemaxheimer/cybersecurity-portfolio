# /kql/vendor/

This folder holds **sql.js** — the WebAssembly build of SQLite that powers
the KQL playground. Two files are required:

- `sql-wasm.js`   (~800 KB JS loader)
- `sql-wasm.wasm` (~600 KB WASM binary)

Both must be present and committed for the playground to work in production.

## How to fetch them (PowerShell)

```powershell
$dest = "$PSScriptRoot"   # or hard-code: "C:\Users\bmaxh\Documents\cybersecurity-portfolio\kql\vendor"
$ver  = "1.10.3"           # pin a known-good version

Invoke-WebRequest "https://cdn.jsdelivr.net/npm/sql.js@$ver/dist/sql-wasm.js"   -OutFile "$dest\sql-wasm.js"
Invoke-WebRequest "https://cdn.jsdelivr.net/npm/sql.js@$ver/dist/sql-wasm.wasm" -OutFile "$dest\sql-wasm.wasm"
```

After downloading, `git add` them and push.

## Why self-hosted instead of CDN

- No third-party request from a visitor's browser (privacy).
- No CSP allowlist for an external origin (security).
- Site keeps working if jsdelivr/unpkg has an outage.
- ~1.4 MB of one-time payload, cached aggressively after first load.

## Updating

To pick up a new sql.js release: bump `$ver` above, re-run the snippet,
test the playground locally, commit the new binaries.
