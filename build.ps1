<#
.SYNOPSIS
    Convert blog posts written in Markdown into static HTML pages.

.DESCRIPTION
    Reads every .md file in posts-source/, parses its YAML-style front matter
    (title, date, summary, tags), converts the body to HTML using the built-in
    ConvertFrom-Markdown cmdlet, and writes the result to blog/posts/<slug>.html
    wrapped in the site's standard header/footer template.

    Run from the repo root:  pwsh ./build.ps1
    Or just:                  ./build.ps1   (PowerShell 7+)

    Requires: PowerShell 7.0 or later (for ConvertFrom-Markdown).

.NOTES
    This script does NOT auto-update blog/index.html - add new posts to the
    listing manually. That's a deliberate choice: it keeps the build dumb and
    the listing fully under your control.
#>

[CmdletBinding()]
param(
    [string] $SourceDir = (Join-Path $PSScriptRoot 'posts-source'),
    [string] $OutputDir = (Join-Path $PSScriptRoot 'blog/posts')
)

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "PowerShell 7+ is required (you have $($PSVersionTable.PSVersion)). Install from https://aka.ms/powershell"
}

if (-not (Test-Path $SourceDir)) {
    throw "Source directory not found: $SourceDir"
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

function Parse-FrontMatter {
    param([string] $Raw)

    $meta = @{
        title   = '(untitled)'
        date    = (Get-Date -Format 'yyyy-MM-dd')
        summary = ''
        tags    = @()
    }
    $body = $Raw

    if ($Raw -match '(?s)^\s*---\s*\r?\n(.*?)\r?\n---\s*\r?\n(.*)$') {
        $front = $Matches[1]
        $body  = $Matches[2]
        foreach ($line in $front -split "`r?`n") {
            if ($line -match '^\s*([A-Za-z_]+)\s*:\s*(.+?)\s*$') {
                $key = $Matches[1].ToLower()
                $val = $Matches[2]
                if ($key -eq 'tags') {
                    $meta.tags = ($val -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                } else {
                    $meta[$key] = $val
                }
            }
        }
    }

    return @{ meta = $meta; body = $body }
}

function Get-Slug {
    param([string] $Path)
    return [System.IO.Path]::GetFileNameWithoutExtension($Path)
}

function Render-Tags {
    param([string[]] $Tags)
    if (-not $Tags -or $Tags.Count -eq 0) { return '' }
    ($Tags | ForEach-Object { "<span class=`"tag`">$_</span>" }) -join ' '
}

function Render-Page {
    param(
        [hashtable] $Meta,
        [string]    $BodyHtml
    )

    $title       = [System.Web.HttpUtility]::HtmlEncode($Meta.title)
    $description = [System.Web.HttpUtility]::HtmlEncode($Meta.summary)
    $date        = [System.Web.HttpUtility]::HtmlEncode($Meta.date)
    $tagsHtml    = Render-Tags -Tags $Meta.tags

    @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="$description">
    <title>$title - Bryce Maxheimer</title>
    <script>(function(){try{var t=localStorage.getItem('siteTheme');if(t)document.documentElement.setAttribute('data-theme',t);}catch(e){}})();</script>
    <link rel="stylesheet" href="/css/style.css">
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
</head>
<body>

<header class="site-header">
    <div class="container">
        <a href="/" class="brand"><span class="prompt">PS&gt;</span> brycemaxheimer</a>
        <nav class="nav">
            <a href="/about.html">About</a>
            <a href="/resume/">Resume</a>
            <a href="/certs/">Certs</a>
            <a href="/projects/">Projects</a>
            <a href="/lab/">Lab</a>
            <a href="/writeups/">Writeups</a>
            <a href="/kql/">KQL</a>
            <a href="/blog/" class="active">Blog</a>
            <a href="/customize/">Customize</a>
        </nav>
    </div>
</header>

<main class="container">

<article class="post">
    <h1>$title</h1>
    <div class="meta">$date &middot; $tagsHtml</div>

$BodyHtml

    <hr>
    <p style="color: var(--muted); font-size: 0.9rem">
        &larr; <a href="/blog/">Back to all posts</a>
    </p>
</article>

</main>

<footer class="site-footer">
    <div class="container">
        &copy; 2026 Bryce Maxheimer &middot;
        <a href="https://github.com/brycemaxheimer">GitHub</a> &middot;
        <a href="/about.html">Contact</a>
    </div>
</footer>

</body>
</html>
"@
}

# Needed for HtmlEncode in some PS environments
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# ----------------------------------------------------------------------
# Build loop
# ----------------------------------------------------------------------

$mdFiles = Get-ChildItem -Path $SourceDir -Filter '*.md' -File
if ($mdFiles.Count -eq 0) {
    Write-Host "No .md files in $SourceDir" -ForegroundColor Yellow
    return
}

Write-Host "Building $($mdFiles.Count) post(s)..." -ForegroundColor Cyan

foreach ($file in $mdFiles) {
    $raw    = Get-Content -Path $file.FullName -Raw
    $parsed = Parse-FrontMatter -Raw $raw

    $bodyHtml = (ConvertFrom-Markdown -InputObject $parsed.body).Html

    $page = Render-Page -Meta $parsed.meta -BodyHtml $bodyHtml

    $slug    = Get-Slug -Path $file.FullName
    $outPath = Join-Path $OutputDir "$slug.html"
    
    # The fix is here: completing the Set-Content command and closing the loop
    Set-Content -Path $outPath -Value $page
    Write-Host "  -> Built $slug.html" -ForegroundColor Green
}

Write-Host "Build complete!" -ForegroundColor Cyan
