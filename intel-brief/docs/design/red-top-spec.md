# Red-top redesign: implementation spec

Design reference: artboards **B1b · Red-top** (desktop) and **B1b · Red-top phone (dark)** on the
design canvas "Daily Intel Brief — Look Exploration". This spec turns them into changes to
`intel_brief/render/static/style.css`, `templates/base.html` and `templates/edition.html`.

The goal is a tabloid-style front page: red nameplate band, black nav bar, heavy serif
headlines, a black facts bar, red numerals. Every trust element stays where it is in the
markup and stays visible.

## As implemented (differences from the plan below)

- **Edition strip class.** The stats-and-provenance row is a new `div.edition-strip`.
  `.edition-head` was not repurposed, because archive, methodology and 404 still use it for
  their own h1 and dek.
- **Lead story class.** The lead story class is `lead-story`, not `lead`, because `p.lead`
  already exists (the intro paragraph above Early signals).
- **Text red in dark mode.** Text-coloured reds use `var(--crit)` everywhere: section labels,
  step numerals and the active tab underline. `--brand` (`#9E1118` in dark) is only used as a
  fill, where white text sits on it. As a text colour on `#121212` it would fail AA.
- **Facts bar severity.** The facts bar gets `--facts-crit: #FF8A80` for "Critical" severity
  text, since `--crit` is too dark on the black bar. Measured: 8.07:1 on `#141414` and
  6.63:1 on `#262626`.
- **Font files.** Playfair Display is served unsubsetted (106 KB). Its OFL reserves the font
  name, so subsetting it would count as a modified version needing a rename. Libre Franklin
  has no reserved name and is Latin-subset to 28 KB. The `@font-face` weight ranges are the
  fonts' full axes: 400–900 and 100–900.
- **Top stories rule.** The "Top stories" section head has no top rule, because the edition
  strip's bottom rule sits directly above it. The first archive entry gets the same treatment.

## Hard constraints (unchanged)

- No JavaScript. The detection tabs stay CSS-only (radio inputs + labels).
- One external stylesheet: `assets/style.css`. The CSP is `style-src 'self'`, so no `style=""`
  attributes and no `<style>` blocks. Priority and meter bars stay inline SVG geometry.
- Fonts self-hosted under `assets/fonts/`, SIL OFL 1.1, licence text shipped beside them.
- Light only (`color-scheme: only light`); the dark palette below is kept for reference and is not
  shipped. Every text/background pair below is AA (4.5:1 or better), measured with the WCAG 2
  relative-luminance formula.
- All trust elements stay visible: provenance box, AI-generated line with source support,
  detection origin tags ("AI-generated · untested" / "SigmaHQ rule · untested here"), Kusto
  parser status, the PoC warning, "Counted by code, not AI", collection status, footer
  disclaimer.

## Fonts

| Role | Family | Weights | File(s) to add | Source |
|---|---|---|---|---|
| Display (nameplate, headlines, numerals, section heads) | Playfair Display | 700–900 | `PlayfairDisplay-Variable.woff2` (`font-weight: 700 900`) | `google/fonts` → `ofl/playfairdisplay` |
| Body and UI | Libre Franklin | 400–800 | `LibreFranklin-Variable.woff2` (`font-weight: 400 800`) | `google/fonts` → `ofl/librefranklin` |
| Code, CVE IDs | IBM Plex Mono (keep) | 400, 500 | already in `fonts/` | — |

- Convert the variable TTFs with `pyftsubset <ttf> --flavor=woff2 --layout-features='*' --unicodes=U+0000-00FF,U+0131,U+0152-0153,U+02C6,U+02DA,U+02DC,U+2000-206F,U+20AC,U+2122,U+2190-2193,U+2212`
  (Latin plus punctuation; covers the en dash, middle dot and arrows used on the page).
- The mockups use JetBrains Mono. Keep IBM Plex Mono instead: it is already self-hosted and
  the difference is small at 12–13px.
- Remove `IBMPlexSans-Variable.woff2`, `IBMPlexSerif-500.woff2`, `IBMPlexSerif-600.woff2` and
  their `@font-face` rules once nothing references them.
- Licences: add the OFL text for each family to `fonts/OFL.txt` (one section per family, each
  with its own copyright line) or ship `OFL-PlayfairDisplay.txt` / `OFL-LibreFranklin.txt`.
  Update the comment on line 1 of `style.css`.
- Change the `<link rel="preload">` in `base.html` to `LibreFranklin-Variable.woff2` and add
  a second preload for `PlayfairDisplay-Variable.woff2` (the nameplate is above the fold).

```css
@font-face { font-family: "Playfair Display"; src: url("fonts/PlayfairDisplay-Variable.woff2") format("woff2"); font-weight: 700 900; font-display: swap; }
@font-face { font-family: "Libre Franklin"; src: url("fonts/LibreFranklin-Variable.woff2") format("woff2"); font-weight: 400 800; font-display: swap; }
@font-face { font-family: "IBM Plex Mono"; src: url("fonts/IBMPlexMono-400.woff2") format("woff2"); font-weight: 400; font-display: swap; }
@font-face { font-family: "IBM Plex Mono"; src: url("fonts/IBMPlexMono-500.woff2") format("woff2"); font-weight: 500; font-display: swap; }
```

## CSS variables

Replace the `:root` block and the dark-mode block in `style.css` with the values below.
Variables marked **new** do not exist today; keep every existing variable name so current
rules keep working while they are restyled.

### Light (`:root`)

```css
:root {
  --sans: "Libre Franklin", system-ui, "Segoe UI", Roboto, sans-serif;
  --serif: "Playfair Display", Georgia, "Times New Roman", serif;
  --mono: "IBM Plex Mono", ui-monospace, "Cascadia Code", Consolas, monospace;

  --ground: #FFFFFF;
  --surface: #FFFFFF;
  --surface-2: #F5F5F5;
  --rule: #D0D0D0;
  --rule-soft: #E6E6E6;
  --rule-strong: #141414;     /* new: 3px section rules, boxed "What to do" */
  --ink: #141414;
  --text: #1C1C1C;
  --text-2: #1C1C1C;
  --text-3: #2E2E2E;
  --muted: #4A4A4A;
  --accent: #1A4F8B;          /* links */
  --accent-hover: #123A68;
  --accent-bright: #B3141B;   /* active-nav underline, primary button */

  --brand: #B3141B;           /* new: nameplate band, red numerals, KEV-due cell */
  --brand-text: #FFFFFF;      /* new */

  --crit: #B3141B;  --crit-tint: #FDECEA;
  --high: #9A3D0A;  --high-tint: #FCEBDD;
  --ai: #6F4D00;    --ai-tint: #FFF1D1;  --ai-ink: #4D3400;   /* --ai-ink new: text inside ai-tint pills */
  --info: #1F4E9C;  --info-tint: #EAF1FB;
  --ok: #1E7B3A;    --ok-tint: #E7F5EC;
  --tag: #141414;   --tag-tint: #FFFFFF;
  --watch: #4A4A4A;

  --mast: #B3141B;  --mast-text: #FFFFFF;  --mast-muted: #FFFFFF;
  --bar: #141414;   --bar-text: #FFFFFF;  --bar-muted: #E0E0E0;      /* new: nav bar under the band */
  --facts-bg: #141414; --facts-text: #FFFFFF; --facts-label: #CFCFCF;
  --facts-link: #A9CBFF; --facts-high: #FFB27A; --facts-due: #B3141B;  /* new: black facts bar */

  --code-bg: #1E1E1E;  --code-bar: #2A2A2A;  --code-text: #ECECEC;  --code-bar-text: #D9D9D9;
  --code-rule: #2A2A2A;  --code-ok: #8FE0A8;  --code-bad: #FF9B8F;

  --radius: 0;                /* square corners everywhere */
}
```

### Dark (`@media (prefers-color-scheme: dark)`, not shipped: the site is light only)

```css
@media (prefers-color-scheme: dark) {
  :root {
    --ground: #121212;
    --surface: #1A1A1A;
    --surface-2: #202020;
    --rule: #333333;
    --rule-soft: #262626;
    --rule-strong: #F5F5F5;
    --ink: #F5F5F5;
    --text: #E6E6E6;
    --text-2: #E6E6E6;
    --text-3: #D0D0D0;
    --muted: #A8A8A8;
    --accent: #8FB8F0;
    --accent-hover: #BCD5F7;
    --accent-bright: #B3141B;

    --brand: #9E1118;          /* slightly deeper so the band doesn't glow */
    --brand-text: #FFFFFF;

    --crit: #FF7B72;  --crit-tint: #3A1715;
    --high: #FFAB76;  --high-tint: #3A2210;
    --ai: #F2C14E;    --ai-tint: #33280E;  --ai-ink: #F2C14E;
    --info: #9CC0FF;  --info-tint: #16243A;
    --ok: #7FD69A;    --ok-tint: #12301C;
    --tag: #F5F5F5;   --tag-tint: #1A1A1A;
    --watch: #A8A8A8;

    --mast: #9E1118;
    --bar: #000000;   --bar-text: #FFFFFF;  --bar-muted: #D0D0D0;
    --facts-bg: #262626; --facts-label: #C4C4C4; --facts-due: #9E1118;

    --code-bg: #0A0A0A;  --code-bar: #1F1F1F;  --code-rule: #333333;
  }
}
```

`.tag.crit-solid` keeps its hard-coded `#FFFFFF` on `#B3141B` in both modes (6.92:1).

### Measured contrast (all pass AA)

| Pair | Light | Dark |
|---|---|---|
| text on ground | 17.04 | 15.01 |
| muted on ground / surface | 8.86 / 8.13 (surface-2) | 7.88 / 7.32 |
| link (accent) on ground | 8.28 | 9.17 |
| mast-text on mast | 6.92 | 8.24 |
| crit on ground / crit-tint | 6.92 / 6.06 | 7.43 / 6.34 |
| high on ground | 6.89 | 10.12 |
| ai on ground / ai-tint | 7.67 / 6.85 | 11.16 / 8.63 |
| facts-label / facts-link / facts-high on facts-bg | 11.82 / 11.12 / 10.44 | 8.68 / 9.13 / 8.58 |
| white on facts-due | 6.92 | 8.24 |
| code-text on code-bg | 14.11 | 16.76 |
| code-ok on code-bar | 9.16 | 10.51 |
| info on info-tint | 7.03 | 8.46 |
| ok on ground | 5.32 | 10.69 |

## Markup changes

Class names are the ones in the current templates. "Restyle only" means no template change.

### `base.html`

1. **Masthead becomes two bands.** Replace `<header class="mast">…</header>` with:

   ```html
   <header class="mast">
     <div class="wrap mast-band">
       <a class="brand" href="{{ root or '/' }}">{{ site.title }}</a>
       {% block mast_meta %}{% endblock %}
     </div>
     <div class="mast-bar">
       <div class="wrap">
         <nav aria-label="Site">…same five links, same aria-current logic…</nav>
         <p class="mast-dek">Threat intelligence for teams defending Windows, Microsoft 365 and internet-facing edge devices.</p>
       </div>
     </div>
   </header>
   ```

   - The brand SVG mark is dropped; the nameplate is text only (Playfair 900, 78px desktop,
     40px at ≤760px). Keep `favicon.svg` as is.
   - `.mast-band`: `background: var(--mast); color: var(--brand-text); min-height: 112px`.
   - `.mast-bar`: `background: var(--bar)`; links `var(--bar-muted)`, current page
     `var(--bar-text)` with a 2px underline (`text-underline-offset: 6px`), uppercase 13.5px/700.
     `.mast-dek` is `var(--bar-muted)`, 13px; hide it at ≤760px (it is repeated in the
     meta description).
   - `<meta name="theme-color">` → `#B3141B`.
2. **Footer** (`.foot`): restyle only — `background: var(--bar); color: var(--bar-muted)`;
   links `var(--facts-link)`. Text unchanged.

### `edition.html`

3. **Edition title moves into the band.** Fill the new block:

   ```html
   {% block mast_meta %}
   <div class="mast-meta">
     <p class="eyebrow">{{ ed.date|weekday }} edition</p>
     <h1 id="edition-title">{{ ed.date|longdate }}</h1>
   </div>
   {% endblock %}
   ```

   - The `<h1>` stays the page's only h1 and keeps `id="edition-title"`, so
     `aria-labelledby="edition-title"` still resolves.
   - Pages that don't fill the block (archive, methodology, 404) keep their h1 in `#main`
     as today.
   - Remove the `<div>` with eyebrow/h1/dek from `.edition-head`.
4. **Stats + provenance become one strip.** `.edition-head` keeps its element but now holds
   only `.stats` and `.provenance` as a 5-column grid:
   `grid-template-columns: repeat(4, minmax(0, 1fr)) 2fr`, `border-bottom: 3px solid var(--rule-strong)`.
   - `.stats` uses `display: contents` so its four `div`s are grid items. Each shows the number
     (`dd`, Playfair 900 34px) inline with its label (`dt`, uppercase 12px/800).
   - `.provenance` becomes the 5th cell: no box, no icon, 12.5px. Keep the full text and the
     methodology link.
   - At ≤760px: stats 2×2, provenance spans both columns below them.
5. **Story flags.** In `.story-flags`:
   - move `<span class="rank">` out of `.tags` into `.priority`, rendered as
     `No. {{ "%02d"|format(s.rank) }} · Priority <b>{{ s.score }}</b>`;
   - drop the priority `svg.bar` (the number carries it).

   Tags (`.tag`) become square, uppercase, 800:
   - `.crit-solid`: red fill;
   - `.crit`: 2px `var(--crit)` outline, transparent background;
   - `.info` and the plain category tag: 2px `var(--ink)` outline;
   - `.high`: 2px `var(--high)` outline;
   - `.ai`: unchanged (`--ai` on `--ai-tint`).
6. **Lead story.** Add class `lead` to the first story: `<article class="story{% if loop.first %} lead{% endif %}" …>`.
   - All `.story`: no border or box (`background: none; border: 0; border-radius: 0`); stories
     after the first get `border-top: 3px solid var(--rule-strong); padding-top: 22px`.
   - `.story h3`: Playfair 900, 34px, `line-height: 1.05`. `.story.lead h3`: 64px,
     `letter-spacing: -.02em` (36px at ≤760px).
7. **Facts bar.** `.facts` becomes the black bar: `background: var(--facts-bg); color: var(--facts-text)`;
   `dt` is `var(--facts-label)`, `dd a` is `var(--facts-link)`, `.high` is `var(--facts-high)`.
   - Add class `due` to the KEV-deadline cell when `c0.kev_due` is set:
     `<div{% if c0.kev_due %} class="due"{% endif %}>`. `.facts .due` is
     `background: var(--facts-due)`, all text `#FFFFFF`; `.facts .due .crit` inherits white.
   - `.related` stays directly under the bar (restyle only).
8. **What to do box.** Move the `{% if s.writeup.affected_versions or s.writeup.fixed_versions %}`
   block (`.cols2.versions`) inside `.actions`, after `ol.steps`.
   - `.actions`: `border: 3px solid var(--rule-strong); padding: 16px 18px`.
   - `.actions .label` becomes the box title: Playfair 900 26px, sentence case
     (`text-transform: none`), colour `var(--ink)`.
   - `.steps li::before`: no box — `font: 900 26px/1 var(--serif); color: var(--brand); width: 22px`.
   - `.versions > div`: no border; a 1px `var(--rule)` top border on the pair.
   - When a story has no actions but has versions, keep `.versions` where it is today.
9. **Section labels** (`.label`, "What happened" etc.): uppercase 12px/800, `color: var(--brand)`
   in light and `var(--crit)` in dark. `.sources .label` and `.versions .k` use `var(--ink)`.
10. **AI line.** `.ai-line` becomes an inline pill: `display: inline-block; padding: 4px 10px;
    background: var(--ai-tint); color: var(--ai-ink)`. Text unchanged; `.unsupported` stays
    `var(--crit)`.
11. **PoC details.** `details.poc` restyle only: 2px `var(--high)` border, square; `.warn` stays
    `var(--high-tint)` with `var(--text)`.
12. **Detection panel.** `.detect`: no box; `border-top: 3px solid var(--rule-strong)`.
    - `.detect-head` has a transparent background; `.t` is Playfair 900 22px.
    - The origin tag and the `.why` line stay unchanged.
    - Tabs: the active `label` gets `border-bottom: 3px solid var(--brand)`, uppercase 12px/800.
    - `.code-bar` and `.code pre` use the code variables above. The "Kusto parser: pass" span
      is unchanged.
13. **Section heads** (`.section-head` for Top stories, KEV, Early signals, Also on the radar):
    `border-top: 3px solid var(--rule-strong); border-bottom: 0; padding-top: 10px`; `h2` is
    Playfair 900 30px. Restyle only.
14. **KEV table, early signals, radar, collection status:** restyle only.
    - Square corners via `--radius: 0`, and the new fonts.
    - `.signal .count b` is Playfair 900 in `var(--ai)`.
    - `details.status` gets a 3px top rule.

### Rail (`aside.rail`)

15. **"In this edition" → "Also today".**
    - Change the heading text and loop over `ed.stories[1:]` (the lead is already the first
      thing on the page). Keep `{% if ed.stories|length > 1 %}`.
    - Each `li`: `<b class="num">{{ s.rank }}</b>`, then a tier line `<span class="tier">`
      (Exploited / KEV / PoC, from the same labels as the story tags), then the linked title.
    - `.panel h2` here is a black bar: `background: var(--bar); color: var(--bar-text)`,
      Playfair 900 22px, sentence case.
    - `.num`: Playfair 900 32px, coloured by tier: crit → `var(--brand)`, high → `var(--high)`,
      watch → `var(--muted)`.
    - Drop `.dot` and `.legend`; the tier line and numeral colour replace them, and tier is
      spelled out in words so colour is not the only cue.
    - Optional but recommended: when a story has public PoC repos, add
      `<span class="toc-warn">{{ n }} public PoC repos. Links only, not vetted. Public PoC repos are often fake or backdoored. Don't run them on a work machine.</span>`
      (`var(--high-tint)`, 12px).
16. **KEV deadlines panel.**
    - `border: 3px solid var(--crit)`; heading Playfair 900 22px in `var(--crit)`.
    - Each `.kv` adds the gap: `{{ k.due_date|shortdate }} · {{ gap }} days`.
17. **Early signals mini panel (new).** Add after KEV deadlines when `ed.early_signals`:
    - heading "Early signals";
    - the line "Counted by code, not AI. Chatter is a lead, not confirmation.";
    - one row per signal: author count (Playfair 900 28px, `var(--ai)`), CVE link (mono), then
      CVSS and "PoC" when present.
    - The full Early signals section in `main` stays.
18. **Collection panel**: keep it (it names failed sources). Restyle only; meter fill stays
    `var(--ok)`.
19. **Follow panel.** `.panel.follow`: `background: var(--bar)`.
    - `.btn.primary` is `background: var(--brand); color: #FFFFFF`; hover `#8E1016`.
    - `.btn.ghost` is a 2px white border.
    - `min-height: 44px` stays.
20. **Other editions nav panel**: restyle only.

## Responsive (≤760px)

- Nameplate 40px; `.mast-meta` wraps under it, h1 22px. `.mast-band` min-height auto, padding
  14px 16px.
- `.mast-bar` nav wraps; `.mast-dek` hidden. Nav links keep a 44px tap height.
- Strip: stats 2×2, provenance full width below.
- `.story.lead h3` 36px, other `.story h3` 24px.
- `.facts` 2 columns (current rule), the `.due` cell keeps its red fill.
- `.actions` padding 14px; step numerals 22px.
- The rail stacks under `main` (existing flex-wrap); "Also today" numerals 26px.

## Things to check after implementing

- `tests/test_render.py` still passes. Update any assertion on removed markup: the brand SVG,
  `.dot`/`.legend`, or the h1 position.
- The CSP still holds: `grep -n 'style=' site/` returns nothing.
- Both colour schemes in a browser, at 1280 and 390 wide.
- Keyboard focus is visible on the red band and the black bar. The current
  `outline: 2px solid var(--accent)` is too dark on `#141414`; on `.mast` and `.mast-bar` use
  `outline-color: #FFFFFF`.
- Unrelated copy issue spotted while designing: the Collection panel prints "191 items
  collected", and the write-up rules forbid the word "items". Consider "191 records collected".
