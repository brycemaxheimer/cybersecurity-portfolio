# brycemaxheimer.com

Source for [brycemaxheimer.com](https://brycemaxheimer.com) — a static blog and
scripts showcase. Plain HTML/CSS, posts authored in Markdown, deployed via
Cloudflare Pages.

---

## Repo layout

```
brycemaxheimer-site/
├── index.html              Homepage
├── about.html              About page
├── blog/
│   ├── index.html          Blog listing (manually curated)
│   └── posts/              Compiled HTML posts (output of build.ps1)
├── scripts/
│   └── index.html          Scripts showcase
├── css/
│   └── style.css           Shared stylesheet
├── posts-source/           Markdown source for posts (input to build.ps1)
│   └── *.md
├── build.ps1               Markdown → HTML build script (PowerShell 7+)
├── _headers                Cloudflare Pages security headers
├── _redirects              Cloudflare Pages redirects
├── .gitignore
└── README.md               This file
```

---

## Local preview

Cloudflare Pages serves the folder as static files. To preview locally, point any
static file server at the `brycemaxheimer-site/` folder. The simplest options:

**PowerShell 7+ one-liner (no install needed):**
```powershell
cd "C:\Users\bmaxh\Documents\SOC Dashboard\brycemaxheimer-site"
python -m http.server 8000
# then open http://localhost:8000
```

**Or, if you have Node:**
```powershell
npx serve .
```

---

## Writing a new blog post

1. Create a Markdown file in `posts-source/` named with the URL slug, e.g.
   `posts-source/kql-hunting-with-invoke-kqlps.md`.

2. Add front matter at the top:

   ```markdown
   ---
   title: KQL hunting with Invoke-KqlPS
   date: 2026-05-15
   summary: A short walkthrough of running KQL against a local SQLite lab.
   tags: kql, soc, powershell
   ---

   ## Your first heading

   Write the post body in normal Markdown.
   ```

3. Build:
   ```powershell
   cd "C:\Users\bmaxh\Documents\SOC Dashboard\brycemaxheimer-site"
   ./build.ps1
   ```
   This produces `blog/posts/kql-hunting-with-invoke-kqlps.html`.

4. Add the post to the listing — open `blog/index.html` and copy an existing
   `<li class="card">` block to the top of the list, updating the title, date,
   summary, slug, and tags. (The build script intentionally does NOT touch
   `blog/index.html` so you keep editorial control over what's promoted.)

5. Commit and push:
   ```powershell
   git add .
   git commit -m "post: KQL hunting with Invoke-KqlPS"
   git push
   ```
   Cloudflare Pages will rebuild and deploy within ~30 seconds.

---

## First-time deployment to Cloudflare Pages

Walks you from "files in a folder" to "live at brycemaxheimer.com." You said you
already have: domain registered, Cloudflare account, domain in Cloudflare DNS,
and a GitHub account. So the path below skips DNS setup.

### Step 1 — Get the source onto GitHub

1. Go to https://github.com/new and create a repo. Name suggestions:
   `brycemaxheimer.com` or `personal-site`. Keep it **public** (Cloudflare Pages
   works fine with private too — public is just simpler to share).
2. From a PowerShell prompt:
   ```powershell
   cd "C:\Users\bmaxh\Documents\SOC Dashboard\brycemaxheimer-site"
   git init
   git add .
   git commit -m "initial commit: scaffold site"
   git branch -M main
   git remote add origin https://github.com/<your-username>/<repo-name>.git
   git push -u origin main
   ```

### Step 2 — Create a Cloudflare Pages project

1. Log in at https://dash.cloudflare.com.
2. Left sidebar: **Workers & Pages** → **Create** → **Pages** tab → **Connect to Git**.
3. Authorize Cloudflare to read from your GitHub account.
4. Pick the repo you just pushed.
5. Build settings — **important, since we don't use a framework:**
   - Framework preset: **None**
   - Build command: *(leave blank)*
   - Build output directory: `/` *(or leave blank — defaults to repo root)*
6. Click **Save and Deploy**. First build takes ~20 seconds.
7. You'll get a temporary URL like `brycemaxheimer-com.pages.dev`. Open it and
   confirm the site loads.

> **Note on `build.ps1`:** Cloudflare Pages does NOT run PowerShell during the
> build. Run `build.ps1` locally before each push so the compiled `.html` files
> in `blog/posts/` are checked into Git. They're committed artifacts, not
> generated-at-deploy.

### Step 3 — Attach your custom domain

1. In the Pages project: **Custom domains** → **Set up a custom domain**.
2. Enter `brycemaxheimer.com`. Cloudflare will detect that you already manage
   the DNS for this domain on the same account and offer to wire it up
   automatically — accept.
3. Repeat for `www.brycemaxheimer.com` if you want both apex and www to work
   (recommended).
4. Cloudflare will provision a TLS cert (free, automatic). Within a few minutes
   `https://brycemaxheimer.com` should serve the site.

### Step 4 — Verify the security headers

After the first deploy, hit your site and confirm `_headers` is being applied:
```powershell
curl.exe -sI https://brycemaxheimer.com | Select-String -Pattern "Strict-Transport|X-Frame|Content-Security|Referrer"
```
You should see HSTS, CSP, X-Frame-Options, and Referrer-Policy in the response.
If they're missing, the `_headers` file is in the wrong location — it must be at
the **root** of the build output directory (i.e. next to `index.html`).

---

## Updating the site

Once everything above is wired up, the day-to-day flow is:

```powershell
# 1. Write or edit a post
notepad posts-source/some-new-post.md

# 2. (Posts only) build the HTML
./build.ps1

# 3. (Posts only) add a card to blog/index.html

# 4. Commit and push — Cloudflare auto-deploys
git add .
git commit -m "post: some new post"
git push
```

Edits to `index.html`, `about.html`, `scripts/index.html`, or `css/style.css`
don't need a build step — just edit, commit, push.

---

## Conventions / opinions baked in

- **Dark theme only** for now. Easier to maintain a single set of design tokens
  in `:root` than to implement a theme switcher I'll never test in light mode.
- **No client-side JavaScript** unless a specific page truly needs it.
- **No third-party fonts.** System font stack only — faster, no privacy
  considerations, and no FOUT.
- **No analytics by default.** Add Cloudflare Web Analytics later if you want
  privacy-respecting page-view counts (server-side, no cookies).
- **Markdown front matter is YAML-ish but parsed naively.** Keep it simple:
  `key: value` per line, comma-separated tags. Don't try to nest.

---

## Troubleshooting

**`build.ps1` fails with "ConvertFrom-Markdown is not recognized."**
You're on Windows PowerShell 5.1. Install PowerShell 7+ from
https://aka.ms/powershell and run `pwsh ./build.ps1`.

**Site loads but CSS is missing on a post page.**
Check that `<link rel="stylesheet" href="/css/style.css">` uses a leading slash.
Relative paths break when posts move between subdirectories.

**Cloudflare deploy succeeds but I see a 404.**
The build output directory in the Pages project settings probably doesn't match
where `index.html` lives. For this layout it should be `/` (repo root).

**CSP header is blocking something I added.**
Edit `_headers` and add the source you need. The default CSP is intentionally
strict; loosen one directive at a time.
