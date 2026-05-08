# SOC Dashboard - Review and Roadmap

_Generated 2026-05-08. In-depth review of the `SOC Dashboard/` toolkit, current
state of work-in-progress changes, and a prioritized plan for next steps._

---

## 1. What this is

`SocDashboard.ps1` (2,570 lines) is the entry point for a self-contained,
single-window WPF analyst console. It dot-sources 24 helper scripts under
`SOC Dashboard/Modules/` (10,477 PowerShell lines total). The console runs on
PowerShell 5.1 or 7.x, depends only on PSSQLite (auto-installed to CurrentUser
on first run), and stores everything - feeds, IoC cache, watchlists, secrets -
in a single SQLite file at `%USERPROFILE%\SecIntel\secintel.db`.

There are three thematic surfaces:

1. **Vulnerability intelligence** - NVD CVE pull, CISA KEV catalog, EPSS daily
   scores, and a CVE -> ATT&CK technique mapping table.
2. **MITRE ATT&CK browser** - STIX bundle ingest from MITRE's GitHub raw, with
   tactics/techniques/groups/software/mitigations grids and a relationship
   graph.
3. **Threat intel / IoC triage** - hash, IP, domain, URL, and product
   reputation across VirusTotal, MalwareBazaar, OTX, AbuseIPDB, URLScan,
   CIRCL hashlookup (NSRL), Team Cymru MHR, and NVD product search. Providers
   fan out via a WPF runspace pool, and results are TTL-cached in `IntelCache`
   / `HashIntel`.

A KQL "lab" subsystem is layered on top: a CSV importer that builds a SQLite
database from a Sentinel-style schema, a regex-based KQL-to-SQL translator
(`Invoke-KqlPS.ps1`, 2,144 lines), a WinForms KQL builder GUI, a template
library (currently emptied - see WIP section), and helpers that emit hunt
queries from MITRE techniques or CVEs.

---

## 2. Module map (current functionality)

| File | LOC | Role |
| --- | ---: | --- |
| `SocDashboard.ps1` | 2,570 | WPF entry point. ~1,100 lines of inline XAML, the rest is event wiring + the threat-intel runspace pool. |
| `Modules/Invoke-KqlPS.ps1` | 2,144 | Regex-based KQL parser/translator that emits ANSI SQL for SQLite. Handles `where`, `summarize`, `bin`, `extend`, `datatable` literals, `TimeGenerated`. |
| `Modules/MitreAttackExplorer.ps1` | 949 | Downloads `enterprise-attack.json` from MITRE's GitHub raw, ingests STIX into 6 tables, and exposes a WinForms grid GUI. |
| `Modules/KqlBuilder.ps1` | 878 | WinForms interactive KQL composer; persists saved queries to MS Access (.accdb) when ACE OLEDB is available, falls back to JSON otherwise. |
| `Modules/SecIntel.HashLookup.ps1` | 358 | Hash reputation dispatcher across VT / MalwareBazaar / OTX with verdict-aware TTLs (malicious 7d, clean 30d, unknown 1d). |
| `Modules/SecIntel.UiHelpers.ps1` | 347 | Adds context menus to WPF DataGrids, status bar updates, "diff since last open" snapshots. |
| `Modules/SecIntel.Schema.ps1` | 324 | Single source of truth for the SQLite schema. ~17 tables, idempotent `CREATE TABLE IF NOT EXISTS` DDL, indexes on the common pivots. |
| `Modules/SecIntel.KqlHelpers.ps1` | 375 | Generates hunt queries from MITRE technique IDs or CVE IDs; saved-query CRUD; Sentinel deeplink builder. |
| `Modules/Build-KqlLabDb.ps1` | 369 | Bootstraps the KQL lab DB from a `CommonTableSchema.txt`-style definition; writes a `__schema__` metadata table. |
| `Modules/SecIntel.DailyBrief.ps1` | 275 | Renders a self-contained dark-themed HTML report (no external CSS/JS) summarizing new KEVs/CVEs since `lastseen.kev` / `lastseen.cve`. |
| `Modules/Update-CveKevFeed.ps1` | 291 | Pulls last N days of CVEs from NVD and the full CISA KEV catalog. Resolves NVD key from param, env, or vault. |
| `Modules/SecIntel.Schema.ps1` indexes | - | Indexes on `TimeGenerated`, `Computer`, `EventID`, `Sha256`, `IocValue`, etc. Notable gap: no index on `KEVs.DateAdded` despite ORDER-BY usage. |
| `Modules/SecIntel.Settings.ps1` | 207 | Settings + DPAPI-encrypted secrets CRUD; watchlist CRUD; KQL queries CRUD. DPAPI scope = CurrentUser. |
| `Modules/SecIntel.ThreatIntel.ps1` | 157 | Top-level dispatcher. `Get-IntelProviderPlan` picks providers by IoC type. `Get-ThreatIntelParallel` fans out via runspaces. |
| `Modules/Update-EpssFeed.ps1` | 157 | Daily EPSS score CSV from FIRST.org (gzip), upserts `CVEs.EpssScore` / `EpssPercentile` / `EpssDate`. 12h skip via `FeedMeta`. |
| `Modules/Import-KqlLabCsv.ps1` | 162 | CSV -> SQLite ingest with type coercion (bool: `true/1/yes/y/t`; datetime kept as ISO-8601 text; dynamic stored as JSON text). |
| `Modules/SecIntel.ThreatIntel.UrlScan.ps1` | 160 | URLScan.io: search public corpus first (free), optional `-Submit` polls a new scan for ~30s. |
| `Modules/SecIntel.ThreatIntel.Nist.ps1` | 132 | NVD CPE/product search; verdict from count of recent critical CVEs. |
| `Modules/SecIntel.Http.ps1` | 134 | HTTP wrapper with exponential backoff, jitter, and Retry-After parsing. PS 5.1 + 7.x compatible. |
| `Modules/SecIntel.ThreatIntel.Core.ps1` | 122 | IoC type auto-detection (sha256/sha1/md5 by length, URL by scheme, IPv4/IPv6 by regex, domain fallback) + verdict-aware TTL helpers. |
| `Modules/Update-CveAttackMap.ps1` | 110 | Upserts CSV (CveId, TechniqueId, Source, Confidence) into `CveTechniqueMap`. Multi-source (Center-for-CTID, analyst, etc.). |
| `Modules/SecIntel.ThreatIntel.Nsrl.ps1` | 100 | CIRCL hashlookup - free, no auth. 90-day TTL on known-good (NSRL classifications are stable). |
| `Modules/SecIntel.ThreatIntel.AbuseIPDB.ps1` | 95 | IP reputation; abuseConfidenceScore >= 75 = malicious, >= 25 = suspicious. |
| `Modules/TeamCymru-Hash-Lookup.ps1` | 61 | DNS TXT queries to `hash.cymru.com`. Skips SHA256 (DNS label 63-char limit). |
| `Modules/KqlTemplates.ps1` | 1 | **Currently empty (see WIP).** Was previously a 1,525-line ordered hashtable of pre-built KQL templates. |

### Schema (in `SecIntel.Schema.ps1`)

17 tables, all idempotent `CREATE TABLE IF NOT EXISTS`:

- MITRE: `Tactics`, `Techniques`, `AttackGroups`, `Software`, `Mitigations`, `Relationships`
- Vulns: `CVEs`, `KEVs`, `CveTechniqueMap`
- Intel: `HashIntel`, `IntelCache`, `Iocs`
- Operational: `KqlQueries`, `AppSettings` (with `IsSecret` flag for DPAPI),
  `Watchlists`, `WatchlistItems`, `FeedMeta`

### External I/O

| Endpoint | Auth | Used by |
| --- | --- | --- |
| `raw.githubusercontent.com/.../enterprise-attack.json` | none | `MitreAttackExplorer.ps1` |
| CISA KEV catalog | none | `Update-CveKevFeed.ps1` |
| NVD API (`services.nvd.nist.gov`) | optional key (5 req/30s -> 50 req/30s) | `Update-CveKevFeed.ps1`, `SecIntel.ThreatIntel.Nist.ps1` |
| FIRST.org EPSS | none | `Update-EpssFeed.ps1` |
| `hash.cymru.com` (DNS TXT) | none | `TeamCymru-Hash-Lookup.ps1` |
| VirusTotal v3 | required key | `SecIntel.HashLookup.ps1` |
| MalwareBazaar | required key (since 2024) | `SecIntel.HashLookup.ps1` |
| OTX (AlienVault) | optional key | `SecIntel.HashLookup.ps1` |
| AbuseIPDB | required key | `SecIntel.ThreatIntel.AbuseIPDB.ps1` |
| URLScan.io | optional key (free corpus + paid submit) | `SecIntel.ThreatIntel.UrlScan.ps1` |
| CIRCL hashlookup | none | `SecIntel.ThreatIntel.Nsrl.ps1` |

### Disk artifacts

- `%USERPROFILE%\SecIntel\secintel.db` - main store
- `%USERPROFILE%\SecIntel\KqlBuilder.{accdb,json}` - saved-query store
- `%USERPROFILE%\SecIntel\daily_brief_YYYY-MM-DD.html` - on-demand report
- `$env:TEMP\enterprise-attack.json`, `$env:TEMP\epss_*.csv[.gz]` - transient

---

## 3. Work-in-progress (uncommitted)

`git diff --stat -- "SOC Dashboard"` shows **9 files, 9 insertions, 2,757
deletions**. Two distinct edits:

### a) Authenticode signature stripping (8 files, ~155 lines each)

```
Import-KqlLabCsv.ps1     -155
Invoke-KqlPS.ps1         -155
KqlBuilder.ps1           -155
MitreAttackExplorer.ps1  -155
SecIntel.DailyBrief.ps1  -155
SecIntel.KqlHelpers.ps1  -155
SecIntel.UiHelpers.ps1   -155
TeamCymru-Hash-Lookup.ps1 -155
```

Every diff is identical in shape: the `# SIG # Begin signature block` /
`# SIG # End signature block` PKCS#7 envelope is being removed. Subject CN was
`Bryce SOC Code Signing` (5-year self-signed cert, valid 2026-04-29 to
2031-04-29, countersigned by DigiCert RSA4096 SHA256 timestamp authority).

**Functional impact**: none. Scripts execute identically; this only matters if
you reintroduce `Set-ExecutionPolicy AllSigned` or distribute the modules.

### b) `KqlTemplates.ps1` library cleared (-1,517 lines)

The file is now a single line:

```powershell
$kqlTemplates = [ordered]@{}
```

The previous version had a 1,525-line ordered hashtable of MITRE-tagged
templates (TA0001 Initial Access, TA0002 Execution, TA0004 Privilege
Escalation, TA0009 Collection, plus multi-event mega-queries). Anywhere in
the dashboard that loaded `$kqlTemplates` will now see an empty dropdown.

**Decision needed** - section 5 (B) below.

---

## 4. Risks and smells

Ordered roughly by severity. Items marked DRY refer to copy-pasted logic that
will silently desync.

### High

1. **Empty `KqlTemplates.ps1`** breaks the templates dropdown wherever it is
   consumed in `SocDashboard.ps1`. Fine if intentional ahead of a refactor,
   broken if accidental.
2. **DRY: IoC type detection** is implemented twice. Once in
   `SecIntel.ThreatIntel.Core.ps1::Resolve-IocType`, again inline in a WPF
   click handler in `SocDashboard.ps1` (~line 1500). Comment explains the
   workaround: "the dispatcher's `Resolve-IocType` isn't always visible from
   inside a WPF-dispatched click handler closure". Any regex change must
   land in both places.
3. **DRY: provider plan lookup** is also duplicated. `Get-IntelProviderPlan`
   in `SecIntel.ThreatIntel.ps1` and an inline `$tiPlanByType` hashtable in
   `SocDashboard.ps1` (~line 1612). Adding a provider means editing two
   files.
4. **Runspace pool has no explicit per-task timeout**. The threat-intel tab
   spins up `RunspacePool(1, [providers.Count])`, marshals results back via
   the WPF `Dispatcher`. A hung provider will sit in the pool until the
   PowerShell host is killed. The pool is closed/disposed in catch and
   timer-completion paths, but if the timer never fires the pool leaks.
5. **DPAPI scope is CurrentUser/LocalMachine-coupled.** Documented in
   `README.md`, but no first-run check in code: a database moved from
   machine A user X to machine B user Y will silently fail every secret
   read with a `Write-Warning` and `$null` return. Callers see "missing
   API key" symptoms.

### Medium

6. **KQL parser is regex-based** (~2,144 lines). Edge cases around nested
   parens, string literals containing operators, `summarize` with
   inline `extend`, and `bin()` boundary semantics are likely under-tested.
   A formal grammar (Sprache, ANTLR via PSDotNet, or even hand-written
   recursive descent) would be more defensible. Lower priority because
   this is a learning lab, not a production query engine.
7. **Hardcoded DataSource -> table map** in `SecIntel.KqlHelpers.ps1` line
   ~32 (`$script:KqlTableForDataSource`). 20+ entries. Adding a new table
   = code change + retest. Could move into the DB or a JSON config.
8. **XAML inline (~1,100 lines)** inside `SocDashboard.ps1`. No XAML
   tooling, no syntax validation in the IDE, every UI tweak is a `.ps1`
   diff. Splitting to `SocDashboard.xaml` + `[xml]$xaml = Get-Content` is
   a one-shot mechanical refactor.
9. **No `KEVs.DateAdded` index** despite `ORDER BY DateAdded DESC LIMIT N`
   queries in the daily brief and dashboard KPIs. Cheap fix.
10. **Silent ACE -> JSON fallback** in `KqlBuilder.ps1`. If a user expects
    `.accdb` and the OLEDB driver isn't installed, they get `.json` with no
    notice. A `Write-Host` would suffice.
11. **`Get-AppSecret` swallows DPAPI errors** with `Write-Warning; return
    $null`. A `[switch]$Strict` parameter (or a verbose-only diagnostic
    explaining the likely cause: wrong user profile, copied DB) would help.
12. **No queue/lock around NVD API** rate limit. Two parallel
    `Update-CveKevFeed.ps1` invocations will collectively breach 5 req/30s
    or 50 req/30s. A lockfile in `$env:USERPROFILE\SecIntel\` is enough.

### Low

13. **CRLF/LF normalization warnings** on every modified file. Add
    `* text=auto` and `*.ps1 text eol=crlf` to `.gitattributes`.
14. **CSV import type coercion is undocumented** outside the source.
    `Convert-CellValue` quietly handles `true/false/1/0/yes/no/y/t/f` for
    bool, treats datetimes as opaque ISO-8601 text, stores `dynamic` as raw
    JSON text without validation. A short table in `README.md` would do.
15. **No secret rotation tracking**. `AppSettings` rows have an `Updated`
    column but no `RotationDueDate`. A 90-day staleness warning would be
    cheap.
16. **`KEVs.DateAdded` and `Iocs.LastSeen`** are stored as TEXT. Mixing
    string and numeric collation in date-range queries is an easy footgun.
17. **No tests.** Nothing under `SOC Dashboard/` has automated coverage.
    The KQL parser is the most testable component and the most error-prone.

---

## 5. Plan for next steps

Ordered: decide A and B before any of the rest, since they're cheap and
unblock everything else.

### A. Resolve the signature-stripping diff (today)

Two viable paths:

- **Strip and stay stripped.** Commit the 8 deletions, add `* text=auto` +
  `*.ps1 text eol=crlf` to `.gitattributes` in the same commit, and never
  re-sign. Right call if you're not distributing the toolkit and execution
  policy is `Bypass` or `RemoteSigned` on dev machines.
- **Re-sign on commit.** Add a pre-commit hook that runs
  `Set-AuthenticodeSignature` against the saved cert. Right call if
  `AllSigned` is the eventual target.

Recommendation: **commit the strip** for now. The cert is a self-signed
personal cert (CN `Bryce SOC Code Signing`), not a recognized authority -
there's no trust chain consumers rely on, so signing buys nothing.

### B. Decide the fate of `KqlTemplates.ps1` (today)

Either:

1. **Restore from `git show HEAD:"SOC Dashboard/Modules/KqlTemplates.ps1"`**
   and commit the WIP signature strip without that file. This reverts the
   templates clear.
2. **Move templates to a JSON file** at
   `SOC Dashboard/Data/kql-templates.json`, parse in `KqlTemplates.ps1`,
   and seed from the old hashtable. Easier to version, easier for non-PS
   users to contribute, and the dashboard can reload without restart.
3. **Move templates into the DB** (`KqlTemplates` table) and make the
   builder write/read directly. Heaviest, but cleanest if you also want
   templates to be user-editable from the UI.

Recommendation: **(2) JSON**. Cheapest way to keep them in source control,
diffable, and non-technical-friendly. Keep `$kqlTemplates` as the public
in-memory contract so callers don't change.

### C. Backlog (suggested order)

Quick wins first - each item is < 1 hour and lowers the risk surface.

1. **`.gitattributes`** to stop CRLF warnings on every diff.
2. **Index on `KEVs.DateAdded`** in `SecIntel.Schema.ps1`.
3. **Single source of truth for IoC regex** - either expose
   `Resolve-IocType` from a script-scope hashtable that the WPF closure
   can capture, or hoist the regex into a `$script:IocPatterns` constant
   in the dispatcher and reference from both call sites.
4. **Single source of truth for the provider plan** - same pattern: one
   `$script:ProviderPlanByType` hashtable, both `Get-IntelProviderPlan`
   and the WPF code path read from it.
5. **DPAPI first-run check.** When the dashboard launches, attempt to
   decrypt one known-secret row. If it fails with a CryptographicException,
   pop a one-time warning explaining the user/profile coupling and link to
   `Set-AppSecret`.
6. **`Get-AppSecret -Strict`** parameter that throws instead of returning
   `$null`. Use it from the threat-intel tab where a missing key should
   surface visibly.
7. **`Write-Host` notice in `KqlBuilder.ps1`** when ACE is missing and the
   JSON fallback kicks in.
8. **Document CSV type coercion** in `README.md`.

Medium-effort items (1-4 hours each):

9. **Extract XAML** from `SocDashboard.ps1` to `SocDashboard.xaml`. No
   logic change, just `[xml]$xaml = Get-Content -Raw .../SocDashboard.xaml`
   and `(New-Object System.Xml.XmlNodeReader $xaml)` -> `XamlReader.Load`.
10. **Per-task timeout on the threat-intel runspace pool.** Wrap each
    provider call in a `BeginInvoke` + `AsyncWaitHandle.WaitOne($timeout)`
    pattern; if it doesn't finish, `StopAsync` the runspace and emit a
    `verdict='timeout'` row.
11. **NVD lockfile.** Plain `$env:USERPROFILE\SecIntel\nvd.lock` with
    `New-Item -ItemType File -Force` semantics - if it exists and is < 30s
    old, defer; otherwise touch it and proceed.
12. **Move the DataSource->table map** to `SOC Dashboard/Data/data-sources.json`.
13. **DPAPI rotation column.** Add `RotationDueDate` to `AppSettings` and a
    "Stale keys" panel on the dashboard.

Larger items (1-3 days each):

14. **Tests for `Invoke-KqlPS.ps1`.** Pester tests covering each KQL
    operator currently translated. Probably the highest-leverage
    investment in the whole codebase - it's the most error-prone module
    and the easiest to unit-test (input string, expected SQL, no I/O).
15. **Modularize `SocDashboard.ps1`.** Split the per-tab event wiring out
    into `Modules/Tab.MITRE.ps1`, `Tab.CVE.ps1`, `Tab.ThreatIntel.ps1`,
    `Tab.KqlBuilder.ps1`. Keep `SocDashboard.ps1` as a thin loader.
16. **Replace regex KQL parser** with a proper grammar - Sprache (C#, can
    be loaded via `Add-Type`) or hand-written recursive descent. Defer
    until tests from (14) prove pain.

### D. Out of scope for this branch

- Cross-platform support. DPAPI is Windows-only. Porting to PS 7 on Linux
  would require swapping to `Microsoft.PowerShell.SecretManagement` +
  `SecretStore`. Doable but a separate workstream.
- Multi-user / shared DB. The current model is single-analyst. Adding
  auth, row-level visibility, and a shared backend (Postgres? SQL Server
  LocalDB?) is a much bigger redesign.
- Real-time alerting. There's no daemon mode; everything is on-demand. A
  scheduled-task wrapper around `Update-CveKevFeed` + `Update-EpssFeed` +
  `SecIntel.DailyBrief` would be a Phase-2 follow-up.

---

## 6. Quick reference

```text
Entry point:   SOC Dashboard/SocDashboard.ps1
Run:           powershell -ExecutionPolicy Bypass -File ".\SOC Dashboard\SocDashboard.ps1"
Skip refresh:  add -NoLoad
Set a secret:  . .\SOC Dashboard\Modules\SecIntel.Settings.ps1
               Set-AppSecret -Name 'apikey.virustotal' -Value '<key>'
DB location:   %USERPROFILE%\SecIntel\secintel.db
Daily brief:   . .\SOC Dashboard\Modules\SecIntel.DailyBrief.ps1
               (writes %USERPROFILE%\SecIntel\daily_brief_YYYY-MM-DD.html)
```

Diff stat snapshot used for this review:

```text
9 files changed, 9 insertions(+), 2757 deletions(-)
  KqlTemplates.ps1          | 1526 +----------------------
  Import-KqlLabCsv.ps1      |  155 +--
  Invoke-KqlPS.ps1          |  155 +--
  KqlBuilder.ps1            |  155 +--
  MitreAttackExplorer.ps1   |  155 +--
  SecIntel.DailyBrief.ps1   |  155 +--
  SecIntel.KqlHelpers.ps1   |  155 +--
  SecIntel.UiHelpers.ps1    |  155 +--
  TeamCymru-Hash-Lookup.ps1 |  155 +--
```
