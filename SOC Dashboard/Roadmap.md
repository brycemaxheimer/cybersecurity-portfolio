# SOC Dashboard - Implementation Roadmap

_Companion to `Review.md`. This is the actionable, phased plan for the
decisions made on 2026-05-08 (B = DB-backed templates from the website
JSON; C = all backlog items, Windows-only; D = no shared DB, no
scheduled tasks, but yes auto-start + self-update on launch)._

Phase ordering reflects dependency + risk: cheap reversible wins first,
structural refactors second, the largest deferred items last. Each phase
is independently committable; the dashboard remains usable at every
phase boundary.

---

## Phase 0 - Pre-flight (must pass before Phase 1)

Two PowerShell-host quirks called out by the architect specialists need
empirical confirmation before any of the design patterns below land. ~30
minutes total.

| # | Check | Why | If it fails |
| --- | --- | --- | --- |
| 0.1 | `$script:`-scoped variables defined inside a dot-sourced file are accessible by name from the calling script on PS 5.1 | The DRY fixes for IoC regex and provider plan rely on this | Fall back to `$Global:SecIntel_*` with a naming prefix |
| 0.2 | `Get-Content -Raw` on a UTF-8 + CRLF XAML file round-trips through `[xml]` + `XmlNodeReader` + `XamlReader.Load` cleanly on PS 5.1 | XAML extraction in Phase 4 depends on it | Save XAML as UTF-8-no-BOM and/or LF-only via `.gitattributes` exception |
| 0.3 | `PRAGMA journal_mode=WAL` is currently set in `Initialize-SecIntelSchema` | Wave 1 parallel feed writes need WAL to avoid `SQLITE_BUSY` | Add the PRAGMA to schema init in Phase 1 |

---

## Phase 1 - DB-backed KQL templates (decision B)

**Goal**: replace the empty `KqlTemplates.ps1` stub with a DB-backed
template store, seeded from `lab/templates/data.json`, with full CRUD
exposed to the dashboard UI.

**Effort**: ~6-8 hours total.

### 1.1 Schema additions in `SecIntel.Schema.ps1`

Add to the `$script:SecIntelSchemaDdl` here-string, immediately after
`KqlQueries`:

```sql
CREATE TABLE IF NOT EXISTS KqlTemplates (
    TemplateId    INTEGER PRIMARY KEY AUTOINCREMENT,
    Name          TEXT NOT NULL UNIQUE,
    Description   TEXT,
    Tags          TEXT,            -- JSON array
    Kql           TEXT NOT NULL,
    Author        TEXT,
    IsBuiltIn     INTEGER DEFAULT 0,
    Created       TEXT,
    LastModified  TEXT
);
CREATE INDEX IF NOT EXISTS IX_KqlTmpl_Name ON KqlTemplates(Name);
CREATE INDEX IF NOT EXISTS IX_KqlTmpl_Tags ON KqlTemplates(Tags);
```

Plus an `Import-KqlTemplatesFromJsonIfEmpty` helper called from
`Initialize-SecIntelSchema`. Seeds from
`Resolve-Path (Join-Path $PSScriptRoot '..\..\lab\templates\data.json')`.
Skips silently with `Write-Verbose` if the file is absent (toolkit
distributed without the web lab). Sets `IsBuiltIn = 1` on every seeded
row.

While here: confirm `PRAGMA journal_mode=WAL` is set during init
(Phase 0.3 result).

### 1.2 Rewrite `KqlTemplates.ps1`

Backward-compatibility contract: `$kqlTemplates` must remain an
`[ordered]` hashtable keyed by template name with raw KQL string values.
The current consumer at `SocDashboard.ps1:2107-2112` does not change.

Public functions:
```
Get-KqlTemplate    [-Name <string>] [-All] [-Tags <string[]>]
Set-KqlTemplate    -Name <string> -Kql <string> [-Description] [-Tags] [-Author] [-BuiltIn]
Remove-KqlTemplate -Name <string> [-Force]   # refuses BuiltIn without -Force
Import-KqlTemplatesFromJson -Path <string> [-OverwriteBuiltIn]
```

The dot-source-time block populates `$kqlTemplates` from
`Get-KqlTemplate -All`.

### 1.3 Dashboard UI hooks

- Refactor the template-list population at `SocDashboard.ps1:2107` into
  a named `$refreshTemplatesList` script block so save/delete can call
  it.
- Add a "Save as Template" button on the KQL output panel - opens a
  small WPF dialog (Name / Description / Tags / "use current query
  body"), calls `Set-KqlTemplate`, then `$refreshTemplatesList`.
- Context menu on the template list: "Edit", "Delete", "Copy KQL". The
  Delete item is hidden (or shown disabled) for `IsBuiltIn = 1` rows.
  ToolTip on each `ListBoxItem` shows `Description`.

### 1.4 Sync direction

DB is the single source of truth for the dashboard. `lab/templates/data.json`
is a one-way seed artifact; the dashboard never writes back. A future
optional `Export-KqlTemplatesToJson` cmdlet can do the reverse for
publishing, but is not built in this phase.

### 1.5 Smoke-test checklist

- [ ] Fresh DB - `KqlTemplates` table created, seeded with 5 rows from
      `data.json`, all `IsBuiltIn=1`
- [ ] Re-running init does not re-seed (`COUNT(*)>0` short-circuit works)
- [ ] Dashboard launches, KQL Builder tab shows 5 templates in the list
- [ ] Click a template - KQL appears in the output panel
- [ ] "Save as Template" with a new name persists across restart
- [ ] Delete on a built-in template is blocked; delete on a user
      template works after confirmation

**Commit boundary**: 1 commit at the end of Phase 1. Subject line:
`SOC Dashboard: DB-backed KQL templates seeded from lab/templates/data.json`.

---

## Phase 2 - Quick wins (decision C, items 1-8)

**Goal**: knock out the eight low-risk items in `Review.md` section 5.C
that each take less than an hour and lower the long-tail risk surface.

**Effort**: ~4-5 hours total. Each subitem is independently committable.

| # | Item | Files | Notes |
| --- | --- | --- | --- |
| 2.1 | Index on `KEVs.DateAdded` | `SecIntel.Schema.ps1` | `CREATE INDEX IF NOT EXISTS IX_KEVs_DateAdded ON KEVs(DateAdded)` |
| 2.2 | Single source IoC regex | `SecIntel.ThreatIntel.Core.ps1`, `SocDashboard.ps1` | Promote regex to `$script:IocTypePatterns`, capture by reference in WPF closure (depends on Phase 0.1) |
| 2.3 | Single source provider plan | `SecIntel.ThreatIntel.ps1`, `SocDashboard.ps1` | Expose `$script:ProviderNamesByType`; `$tiPlanByType = $script:ProviderNamesByType` |
| 2.4 | DPAPI first-run check | `SocDashboard.ps1` startup, `SecIntel.Settings.ps1` | On launch, attempt one decrypt of a known secret; on `CryptographicException`, show one-time banner explaining user/profile coupling and link to `Set-AppSecret` |
| 2.5 | `Get-AppSecret -Strict` | `SecIntel.Settings.ps1` | Add `[switch]$Strict`; throws `[CryptographicException]` instead of returning `$null`. Threat-intel tab uses `-Strict` so missing keys surface |
| 2.6 | ACE-to-JSON fallback notice | `KqlBuilder.ps1` | `Write-Host -ForegroundColor Yellow` when ACE OLEDB is missing and JSON path activates |
| 2.7 | Document CSV type coercion | `SOC Dashboard/README.md` | Short table covering bool / datetime / dynamic handling in `Convert-CellValue` |
| 2.8 | Verify all 9 changes | smoke run | Single dashboard launch + click each affected surface |

**Commit boundary**: one commit per subitem (small, atomic) OR one
combined commit at the end (bulk). Recommend per-subitem so history
stays readable.

---

## Phase 3 - Auto-start + self-update on launch (decision D)

**Goal**: dashboard launches automatically at Windows logon (no Task
Scheduler) and refreshes feeds on launch with TTL gates and no UI
freeze.

**Effort**: ~10-14 hours total.

### 3.1 Auto-start: Startup folder shortcut

New scripts at `SOC Dashboard/`:

- **`Install-AutoStart.ps1`** - parameters: `-ScriptPath`, `-Minimized`,
  `-WhatIf`. Creates `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\SecIntel-Dashboard.lnk`
  via `WScript.Shell`. Detects PS host (`powershell.exe` vs `pwsh.exe`),
  uses `-ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive
  -File ...`. Writes `autostart.enabled=true` and `autostart.scriptpath`
  to `AppSettings`. Idempotent. No admin rights.
- **`Uninstall-AutoStart.ps1`** - removes the `.lnk` if present, sets
  `autostart.enabled=false`. Idempotent.

Dashboard UI: a "Launch at login" checkbox in the Settings panel
(creating that panel is part of Phase 4's `Tab.Settings.ps1`; for now,
add a temporary toggle on the existing dashboard tab). On click, calls
`Enable-AutoStart` / `Disable-AutoStart` (in-process versions of the
scripts) using `$PSCommandPath` so the shortcut always points at the
current binary.

Edge cases handled:
- Roaming profile detection (`$env:APPDATA -match '^\\\\'`) -> `Write-Warning`.
- `Get-ExecutionPolicy -Scope MachinePolicy/UserPolicy` of `AllSigned`
  / `Restricted` -> warning "policy will block this shortcut, even with
  Bypass on the command line".
- Stale shortcut after path change -> auto-heals next time the user
  toggles the UI checkbox.

Window state at auto-launch: `WindowStyle=Hidden` on the powershell.exe
launcher, `WindowState=Minimized` + `ShowInTaskbar=$true` on the WPF
window itself. **No `NotifyIcon` / system tray** in this phase
(deferred; ~80-120 lines extra, revisit if the minimized-taskbar UX
proves awkward).

### 3.2 Feed orchestrator (data updates)

New module: `Modules/SecIntel.FeedOrchestrator.ps1`. Function
`Start-FeedRefresh -Window $window` that runs **after** the WPF window
is shown (UI is interactive immediately).

**Sequencing**: two waves, runspace pool size 2.

- **Wave 1** (parallel): CISA KEV + EPSS. Different tables, low write
  contention.
- **Wave 2** (sequential, starts after Wave 1 completes): NVD CVE pull,
  then MITRE ATT&CK.

Each runspace returns a structured object: `@{ FeedName, Success,
SkippedByTtl, ErrorMessage, RecordCount, DurationSec }`.

**TTL defaults** (overridable via `AppSettings`):

| Feed | Default TTL | Setting key |
| --- | --- | --- |
| CISA KEV | 24h | `feed.kev.ttlhours` |
| NVD CVE | 24h | `feed.nvd.ttlhours` |
| EPSS | 12h | `feed.epss.ttlhours` |
| MITRE ATT&CK | 168h (7d) | `feed.mitre.ttlhours` |

Skip conditions (in priority order):
1. `-NoUpdate` CLI flag (alias `-NoLoad` retained)
2. `feed.autorefresh.enabled = false` in `AppSettings`
3. Per-feed TTL not yet expired

NVD API key is resolved via `Get-AppSecret -Name 'apikey.nvd'` and
passed as `-NvdApiKey`. If `$null`, NVD runs at the unauthenticated
rate limit and the status panel shows "NVD: running unauthenticated
(slower - configure API key in Settings)".

### 3.3 Feed status panel

A collapsible status row at the bottom of the main window. Shows:
- Aggregate state (all green checkmark / N warnings / N errors)
- Per-feed timestamp + last record count
- "Force refresh all" button (bypasses TTL)
- "Retry" button per failed feed

Implementation: a WPF `Expander` containing an `ItemsControl` bound to
an `ObservableCollection<FeedStatus>`. Updates marshal back to the UI
thread via `$window.Dispatcher.Invoke()`.

### 3.4 First-run flow

On launch, if `FeedMeta` has zero rows:
1. Show a banner: "First run - loading threat intelligence feeds. This
   may take 60-90 seconds. The dashboard will be interactive while feeds
   load."
2. Status panel auto-expanded.
3. MITRE in particular gets a special note: "MITRE ATT&CK bundle parsing
   on PS 5.1 may take 30-60 seconds."
4. `DispatcherTimer` increments an "elapsed Xs" indicator on each feed
   row so the user can see progress is happening.

### 3.5 Toolkit self-update (code)

**Decision: skip automatic git-based updates.** The work environment
constraints (no guaranteed git in PATH, possible GitHub egress
restrictions, dirty-tree edge cases, security risk of silent code
updates) outweigh the convenience.

Instead, add a "Check for updates" item under Help / Settings that:
- Runs `git rev-parse HEAD` if git is in PATH
- Shows the current SHA in a dialog
- Falls back to "git not available - check for updates manually"

Future enhancement (NOT in this phase): a `version.json` in repo root
fetched via `Invoke-WebRequest` from raw.githubusercontent.com - revisit
only if the user actually requests it.

### 3.6 Smoke-test checklist

- [ ] Install-AutoStart.ps1 creates the .lnk; dashboard launches at next
      logon
- [ ] UI toggle ON->OFF->ON cycle works; AppSetting persists
- [ ] First launch on a fresh DB triggers all 4 feeds; UI is interactive
      throughout
- [ ] Second launch within 24h shows all feeds skipped by TTL
- [ ] -NoUpdate flag suppresses the orchestrator entirely
- [ ] Network unplugged - feeds fail with clear error; dashboard still
      loads from local DB
- [ ] "Force refresh all" bypasses TTL and re-runs every feed

**Commit boundary**: 2-3 commits. (1) Install/Uninstall + UI toggle. (2)
Feed orchestrator + status panel. (3) Check-for-updates dialog.

---

## Phase 4 - Module restructure (decision C, items 9-10, 12, 15)

**Goal**: split the 2,570-line `SocDashboard.ps1` monolith into a thin
loader + per-tab modules. Extract XAML. Establish the cross-tab
communication contract.

**Effort**: ~12-16 hours total. Each tab extraction is independently
committable.

### 4.1 XAML extraction (do first - 30 min)

- Move the inline XAML here-string to `SOC Dashboard/SocDashboard.xaml`.
- `SocDashboard.ps1` loads via:
  ```powershell
  $xamlPath = Join-Path $PSScriptRoot 'SocDashboard.xaml'
  [xml]$xaml = Get-Content -Raw -Path $xamlPath
  $window = [Windows.Markup.XamlReader]::Load(
      (New-Object System.Xml.XmlNodeReader $xaml))
  ```
- `.gitattributes` already covers eol=crlf for `.ps1`; add the same for
  `.xaml`.

### 4.2 SocContext + Tabs/ folder layout

```
SOC Dashboard/
  SocDashboard.ps1            # thin loader: XAML, element bind, dot-source tabs
  SocDashboard.xaml           # extracted UI
  Modules/
    Tabs/
      SocContext.ps1          # initializes $Global:SocContext
      Tab.Dashboard.ps1
      Tab.Mitre.ps1
      Tab.Cves.ps1
      Tab.Kevs.ps1
      Tab.IocSearch.ps1
      Tab.ThreatIntel.ps1
      Tab.KqlBuilder.ps1
      Tab.Settings.ps1
```

`$Global:SocContext` shape:
```powershell
$Global:SocContext = @{
    Window      = $window
    DbPath      = $script:DbPath
    ModulesDir  = $script:ModulesDir
    Settings    = $null      # filled after SecIntel.Settings.ps1 dot-source
    # tabs populate their own cross-tab callbacks here:
    # ThreatIntel = @{ Trigger = { param($val) ... } }
}
```

Each tab module exposes a single entry point named after the tab
(`Initialize-DashboardTab`, `Initialize-MitreTab`, etc.) that wires up
its events using `$Global:SocContext.Window.FindName(...)`. The
script-scope variable explosion in `SocDashboard.ps1:1220-1230` (auto
binding every named element) is removed.

### 4.3 Migration order

| Order | Tab | Effort | Why this order |
| --- | --- | --- | --- |
| 1 | XAML extraction | 0.5h | Mechanical, makes every later diff cleaner |
| 2 | Tab.ThreatIntel.ps1 | 3-4h | Highest complexity (runspace pool + DRY fixes) - if the pattern works here it works anywhere |
| 3 | Tab.Dashboard.ps1 | 1.5h | Data-load only |
| 4 | Tab.Cves.ps1 + Tab.Kevs.ps1 | 1h each | Symmetric; do together |
| 5 | Tab.Mitre.ps1 | 2h | 6 sub-grids but one filter pattern |
| 6 | Tab.IocSearch.ps1 | 1h | Single query, no state |
| 7 | Tab.KqlBuilder.ps1 | 2-3h | Form state + template CRUD wiring |
| 8 | Tab.Settings.ps1 | 1h | New tab; absorbs the temporary auto-start toggle from Phase 3 |

### 4.4 Threat-intel runspace timeout (Review item 10)

While extracting `Tab.ThreatIntel.ps1`, replace the implicit timeout
with explicit `BeginInvoke` + `AsyncWaitHandle.WaitOne($timeoutMs)`. If
a provider doesn't return in 30s (configurable via
`AppSettings:ti.timeout.seconds`), `StopAsync` the runspace and emit a
`verdict='timeout'` row to the results grid.

### 4.5 DataSource-table map externalization (Review item 12)

Move the hardcoded `$script:KqlTableForDataSource` hashtable from
`SecIntel.KqlHelpers.ps1` to `SOC Dashboard/Data/data-sources.json`.
Loaded once at module init.

### 4.6 Smoke-test checklist (per tab extraction)

- [ ] Each tab function still works as it did pre-extraction
- [ ] Cross-tab callbacks (e.g. "send IoC to Threat Intel from a CVE
      grid context menu") still work
- [ ] Runspace pool inside Tab.ThreatIntel still receives the
      ModulesDir argument (does NOT depend on `$Global:SocContext`
      being present inside the runspace)
- [ ] Timeout path on Tab.ThreatIntel produces a clean 'timeout' row
      instead of leaving the pool in a bad state

**Commit boundary**: 1 commit per tab extraction (8 commits total in
this phase, plus 1 for XAML extraction).

---

## Phase 5 - Hardening (decision C, items 11, 13)

**Goal**: NVD lock for parallel-instance safety, DPAPI key rotation
tracking with a "stale keys" panel.

**Effort**: ~3-4 hours total.

### 5.1 NVD API lockfile

In `Update-CveKevFeed.ps1` and `SecIntel.ThreatIntel.Nist.ps1`: before
calling NVD, check `$env:USERPROFILE\SecIntel\nvd.lock`. If it exists
and is < 30 seconds old, defer (the orchestrator gracefully reschedules
to the next launch). Otherwise touch the file with `New-Item -Force`
and proceed. Delete on completion.

Edge case: stale lock from a crashed previous run - the > 30s age check
handles it.

### 5.2 DPAPI rotation tracking

Add to `AppSettings`:
- new column `RotationDueDate TEXT` (nullable - existing rows get
  `NULL`)
- `Set-AppSecret -RotationDays 90` records `RotationDueDate = Date +
  90d`.

New tab section "Stale Keys" inside Tab.Settings - lists every secret
where `RotationDueDate < Now()`. Status bar warning if any are stale.

### 5.3 Smoke-test checklist

- [ ] Two `Update-CveKevFeed.ps1` invocations in parallel - one
      proceeds, the other defers
- [ ] After 30 seconds, lock can be re-acquired
- [ ] Setting a secret with `-RotationDays 90` and then querying
      AppSettings shows the future RotationDueDate
- [ ] Forcing the date to past produces a "stale" warning in the UI

**Commit boundary**: 2 commits. (1) NVD lock. (2) DPAPI rotation column
+ UI panel.

---

## Phase 6 - KQL parser tests (decision C, item 14)

**Goal**: Pester tests for `Invoke-KqlPS.ps1` covering every operator
the regex parser currently handles. This is the highest-leverage
investment in the whole codebase - the most error-prone module and the
easiest to unit-test (input string -> expected SQL, no I/O).

**Effort**: ~16-24 hours, tracked separately as it's open-ended. Can be
done in parallel with Phases 4 and 5; does not block other work.

### 6.1 Test layout

```
SOC Dashboard/
  Tests/
    Invoke-KqlPS.Tests.ps1       # main test file
    fixtures/
      where.json                 # input KQL + expected SQL pairs
      summarize.json
      bin.json
      datatable.json
      extend.json
      project.json
      mv-apply.json
      parse_xml.json
      ...
```

Each fixture file is an array of `{ name, kql, expected_sql, notes? }`
objects. Tests parse the file and emit one `It` block per entry,
producing readable PR diffs when a regression is fixed (the new entry
shows up with its expected_sql).

### 6.2 Coverage targets

Tier 1 (must pass before any parser refactor):
- `where` with `==`, `!=`, `in`, `in~`, `contains`, `startswith`, `has`
- `summarize count() by`, `summarize count() by bin(TimeGenerated, 1h)`
- `extend` with `case()`, `iff()`, `tostring()`, `todouble()`
- `project` and `project-away`
- `datatable(col1:type1, col2:type2) [...]`
- `let` bindings (scalar, datetime, dynamic)

Tier 2 (post-Phase-4, when code is more testable):
- `mv-apply ... on (...)`
- `parse_xml`, `extract`, `extract_all`
- `bag_pack`, `bag_unpack`, `make_bag`, `make_set`
- `next()` window function, `serialize`
- `format_timespan`, `replace_string`

Tier 3 (deferred):
- Complex nested templates from the 5 seed templates as full integration
  tests

### 6.3 Long-term: replace regex parser

Defer until tests in Tiers 1 and 2 pass. Then evaluate:
- Sprache (C# parser combinators, loadable via `Add-Type`)
- Hand-written recursive descent in PS
- Wait for an upstream open-source KQL grammar

Keep this open as a separate project once the test suite is solid
enough to catch regressions.

**Commit boundary**: 1 commit per fixture file added (each commit adds
one operator's tests). Parser changes in response to a failing test
land in their own commit.

---

## Out of scope (per decision D)

- **Cross-platform**: Windows-only, DPAPI stays.
- **Shared DB / multi-user**: not needed currently.
- **Scheduled tasks**: explicitly not used (work environment
  restriction). Auto-start covers the same need via Startup folder.
- **Real-time alerting / daemon mode**: not built. The on-launch feed
  refresh in Phase 3 is the only auto-update mechanism.
- **NotifyIcon / system tray**: deferred from Phase 3. Revisit if the
  minimized-taskbar UX is awkward in practice.

---

## Estimated total effort

| Phase | Effort |
| --- | --- |
| 0 - Pre-flight | 0.5h |
| 1 - DB-backed templates | 6-8h |
| 2 - Quick wins | 4-5h |
| 3 - Auto-start + self-update | 10-14h |
| 4 - Module restructure | 12-16h |
| 5 - Hardening | 3-4h |
| 6 - KQL parser tests | 16-24h (open-ended, can parallelize) |
| **Total** | **52-71 hours** |

Realistic calendar at part-time pace: 4-6 weeks for Phases 0-5; Phase 6
is open-ended after that.

---

## Open questions to resolve before Phase 1

1. **`KqlTemplates` vs existing `KqlQueries` table**: should they merge
   (with an `IsTemplate` flag on `KqlQueries`), or stay separate? The
   architect specialist flagged that they overlap in shape. Default in
   this plan: keep them separate (templates ship with the toolkit;
   saved queries are user runs of a template). Confirm or override.
2. **Built-in template UI policy**: when the user views the template
   list, do built-in (`IsBuiltIn=1`) and user templates appear in one
   list with a visual distinction (e.g., a lock icon), or in two
   separate sections? Default in this plan: one list, lock icon, delete
   disabled.
3. **MITRE update on first launch**: 30-60s parse on PS 5.1 is the
   biggest first-run pain point. Acceptable, or do we need an early
   "skip MITRE for first session" toggle? Default in this plan:
   acceptable, banner explains it.
4. **Roaming profile diagnosis**: should `Install-AutoStart.ps1` block
   on a roaming-profile + local-script-path mismatch, or just warn?
   Default in this plan: warn and continue.
