<#
.SYNOPSIS
    Build the blog from Markdown sources.

.DESCRIPTION
    Reads every .md file in posts-source/, parses YAML-style front matter,
    converts the Markdown body to HTML via ConvertFrom-Markdown, and writes:

      - blog/posts/<slug>.html
      - blog/posts.json
      - blog/feed.xml

    Run from the repo root:
      powershell.exe -ExecutionPolicy Bypass -File .\build.ps1
      pwsh ./build.ps1

    PowerShell 7+ uses ConvertFrom-Markdown. Windows PowerShell 5.1 falls back
    to the light-weight internal renderer below.
#>

[CmdletBinding()]
param(
    [string] $SourceDir = '',
    [string] $OutputDir = '',
    [string] $SiteUrl   = 'https://brycemaxheimer.com'
)

$ErrorActionPreference = 'Stop'
$ScriptRoot = if ($PSScriptRoot) {
    $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    (Get-Location).Path
}

if (-not $SourceDir) {
    $SourceDir = Join-Path $ScriptRoot 'posts-source'
}

if (-not $OutputDir) {
    $OutputDir = Join-Path $ScriptRoot 'blog/posts'
}

if (-not (Test-Path $SourceDir)) {
    throw "Source directory not found: $SourceDir"
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$BlogJsonPath = Join-Path $ScriptRoot 'blog/posts.json'
$FeedXmlPath  = Join-Path $ScriptRoot 'blog/feed.xml'

function Escape-Html {
    param([string] $Text)
    [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Escape-Xml {
    param([string] $Text)
    [System.Security.SecurityElement]::Escape([string]$Text)
}

function Write-Utf8File {
    param(
        [string] $Path,
        [string] $Content
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Content)
    [System.IO.File]::WriteAllBytes($Path, $bytes)
}

function Parse-FrontMatter {
    param([string] $Raw)

    $meta = @{
        title     = '(untitled)'
        date      = (Get-Date -Format 'yyyy-MM-dd')
        summary   = ''
        tags      = @()
        published = $true
    }
    $body = $Raw

    if ($Raw -match '(?s)^\s*---\s*\r?\n(.*?)\r?\n---\s*\r?\n(.*)$') {
        $front = $Matches[1]
        $body  = $Matches[2]
        foreach ($line in $front -split "`r?`n") {
            if ($line -match '^\s*([A-Za-z_]+)\s*:\s*(.+?)\s*$') {
                $key = $Matches[1].ToLowerInvariant()
                $val = $Matches[2].Trim()
                if ($key -eq 'tags') {
                    $meta.tags = ($val -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                } elseif ($key -eq 'published') {
                    $meta.published = ($val -notmatch '^(false|0|no)$')
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
    [System.IO.Path]::GetFileNameWithoutExtension($Path)
}

function Get-WordCount {
    param([string] $Text)
    ([regex]::Matches([string]$Text, '\b[\p{L}\p{N}''-]+\b')).Count
}

function Get-ReadingTime {
    param([string] $Text)
    $words = Get-WordCount -Text $Text
    if ($words -le 0) { return 1 }
    [Math]::Max(1, [Math]::Ceiling($words / 200.0))
}

function Convert-InlineMarkdown {
    param([string] $Text)

    $working = Escape-Html $Text
    $codeSpans = @{}
    $working = [regex]::Replace($working, '`([^`]+)`', {
        param($m)
        $key = "__CODE_SPAN_$($codeSpans.Count)__"
        $codeSpans[$key] = '<code>{0}</code>' -f $m.Groups[1].Value
        $key
    })
    $working = [regex]::Replace($working, '\[([^\]]+)\]\(([^)]+)\)', '<a href="$2">$1</a>')
    $working = [regex]::Replace($working, '\*\*([^*]+)\*\*', '<strong>$1</strong>')
    $working = [regex]::Replace($working, '\*([^*]+)\*', '<em>$1</em>')
    foreach ($key in $codeSpans.Keys) {
        $working = $working.Replace($key, $codeSpans[$key])
    }
    return $working
}

function Convert-MarkdownFallback {
    param([string] $Markdown)

    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in (($Markdown -replace '(?s)<!--.*?-->', '') -split "`r?`n")) {
        [void]$lines.Add($line)
    }

    $html = New-Object System.Collections.Generic.List[string]
    $paragraph = New-Object System.Collections.Generic.List[string]
    $inCode = $false
    $codeLines = New-Object System.Collections.Generic.List[string]
    $listType = ''
    $listItems = New-Object System.Collections.Generic.List[string]
    $quoteLines = New-Object System.Collections.Generic.List[string]

    function Flush-Paragraph {
        if ($paragraph.Count -eq 0) { return }
        $joined = ($paragraph -join ' ').Trim()
        if ($joined) { [void]$html.Add('<p>{0}</p>' -f (Convert-InlineMarkdown $joined)) }
        $paragraph.Clear()
    }

    function Flush-List {
        if ($listItems.Count -eq 0) { return }
        $tag = if ($listType -eq 'ol') { 'ol' } else { 'ul' }
        [void]$html.Add("<$tag>")
        foreach ($item in $listItems) {
            [void]$html.Add('<li>{0}</li>' -f (Convert-InlineMarkdown $item))
        }
        [void]$html.Add("</$tag>")
        $listItems.Clear()
        Set-Variable -Name listType -Value '' -Scope 1
    }

    function Flush-Code {
        if (-not $inCode) { return }
        $codeHtml = Escape-Html ($codeLines -join "`n")
        [void]$html.Add("<pre><code>$codeHtml</code></pre>")
        $codeLines.Clear()
        Set-Variable -Name inCode -Value $false -Scope 1
    }

    function Flush-Quote {
        if ($quoteLines.Count -eq 0) { return }
        $joined = (($quoteLines | ForEach-Object { $_.Trim() }) -join ' ').Trim()
        [void]$html.Add('<blockquote><p>{0}</p></blockquote>' -f (Convert-InlineMarkdown $joined))
        $quoteLines.Clear()
    }

    foreach ($rawLine in $lines) {
        $line = $rawLine.TrimEnd()

        if ($line -match '^\s*```') {
            Flush-Paragraph
            Flush-List
            Flush-Quote
            if ($inCode) { Flush-Code } else { $inCode = $true }
            continue
        }

        if ($inCode) {
            [void]$codeLines.Add($rawLine)
            continue
        }

        if ([string]::IsNullOrWhiteSpace($line)) {
            Flush-Paragraph
            Flush-List
            Flush-Quote
            continue
        }

        if ($line -match '^\s*>\s?(.*)$') {
            Flush-Paragraph
            Flush-List
            [void]$quoteLines.Add($Matches[1])
            continue
        }
        Flush-Quote

        if ($line -match '^\s*#\s+(.*)$') {
            Flush-Paragraph
            Flush-List
            [void]$html.Add('<h1>{0}</h1>' -f (Convert-InlineMarkdown $Matches[1].Trim()))
            continue
        }

        if ($line -match '^\s*##\s+(.*)$') {
            Flush-Paragraph
            Flush-List
            [void]$html.Add('<h2>{0}</h2>' -f (Convert-InlineMarkdown $Matches[1].Trim()))
            continue
        }

        if ($line -match '^\s*###\s+(.*)$') {
            Flush-Paragraph
            Flush-List
            [void]$html.Add('<h3>{0}</h3>' -f (Convert-InlineMarkdown $Matches[1].Trim()))
            continue
        }

        if ($line -match '^\s*-\s+(.*)$') {
            Flush-Paragraph
            if ($listType -and $listType -ne 'ul') { Flush-List }
            $listType = 'ul'
            [void]$listItems.Add($Matches[1].Trim())
            continue
        }

        if ($line -match '^\s*\d+\.\s+(.*)$') {
            Flush-Paragraph
            if ($listType -and $listType -ne 'ol') { Flush-List }
            $listType = 'ol'
            [void]$listItems.Add($Matches[1].Trim())
            continue
        }

        if ($listType -and $listItems.Count -gt 0) {
            $lastIndex = $listItems.Count - 1
            $listItems[$lastIndex] = ('{0} {1}' -f $listItems[$lastIndex], $line.Trim()).Trim()
            continue
        }

        Flush-List
        [void]$paragraph.Add($line.Trim())
    }

    Flush-Paragraph
    Flush-List
    Flush-Quote
    if ($inCode) { Flush-Code }

    return ($html -join "`n")
}

function Convert-MarkdownBodyToHtml {
    param([string] $Markdown)

    if (Get-Command ConvertFrom-Markdown -ErrorAction SilentlyContinue) {
        return (ConvertFrom-Markdown -InputObject $Markdown).Html
    }
    return Convert-MarkdownFallback -Markdown $Markdown
}

function ConvertTo-BlogDate {
    param([string] $RawDate)
    try {
        $parsed = [DateTimeOffset]::Parse(
            $RawDate,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal
        )
        return $parsed.ToUniversalTime()
    } catch {
        return [DateTimeOffset]::UtcNow
    }
}

function Render-Tags {
    param([string[]] $Tags)
    if (-not $Tags -or $Tags.Count -eq 0) { return '' }
    ($Tags | ForEach-Object { '<span class="tag">{0}</span>' -f (Escape-Html $_) }) -join ' '
}

function Render-Page {
    param(
        [hashtable] $Meta,
        [string]    $BodyHtml,
        [string]    $Slug,
        [int]       $ReadingTimeMinutes,
        [bool]      $IsPublic = $true
    )

    $title       = Escape-Html $Meta.title
    $description = Escape-Html $Meta.summary
    $dateRaw     = Escape-Html $Meta.date
    $dateIso     = (ConvertTo-BlogDate -RawDate $Meta.date).ToString('o')
    $canonical   = "$SiteUrl/blog/posts/$Slug.html"
    $tagsHtml    = Render-Tags -Tags $Meta.tags
    $readingText = if ($ReadingTimeMinutes -eq 1) { '1 min read' } else { "$ReadingTimeMinutes min read" }
    $robotsMeta  = if ($IsPublic) { '' } else { "`n    <meta name=""robots"" content=""noindex, nofollow"">" }

@"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">$robotsMeta
    <meta name="description" content="$description"><link rel="canonical" href="$canonical">
<meta property="og:title" content="$title - Bryce Maxheimer">
<meta property="og:description" content="$description">
<meta property="og:type" content="article">
<meta property="og:url" content="$canonical">
<meta property="og:image" content="$SiteUrl/og/default.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:site_name" content="Bryce Maxheimer">
<meta property="article:published_time" content="$dateIso">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="$title - Bryce Maxheimer">
<meta name="twitter:description" content="$description">
<meta name="twitter:image" content="$SiteUrl/og/default.png">
    <title>$title - Bryce Maxheimer</title>
    <script>(function(){try{var t=localStorage.getItem('siteTheme');if(t)document.documentElement.setAttribute('data-theme',t);}catch(e){}})();</script>
    <link rel="stylesheet" href="/css/style.css">
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
</head>
<body>

<header class="site-header">
    <div class="container">
        <a href="/" class="brand">Bryce Maxheimer</a>
        <nav class="nav">
            <a href="/about.html">About</a>
            <a href="/resume/">Resume</a>
            <a href="/certs/">Certs</a>
        <span class="nav-dropdown">
            <a href="/lab/">Lab <span class="caret">&#9662;</span></a>
            <div class="nav-dropdown-menu">
                <div class="nested-dropdown">
                    <a href="#" class="nested-dropbtn">KQL Tools <span class="caret-right">&#9656;</span></a>
                    <div class="nested-dropdown-menu">
                        <a href="/kql/">KQL Playground</a>
                        <a href="/lab/practice/">KQL Practice</a>
                        <a href="/lab/kql-builder/">KQL Builder</a>
                        <a href="/lab/templates/">KQL Templates</a>
                    </div>
                </div>
                <a href="/lab/threat-feed/">Live Threat Feed</a>
            </div>
        </span>
            <a href="/blog/" class="active">Blog</a>
            <a href="/customize/">Customize</a>
        </nav>
    </div>
</header>

<main class="container">

<article class="post">
    <h1>$title</h1>
    <div class="meta">$dateRaw &middot; $readingText$(if ($tagsHtml) { " &middot; $tagsHtml" })</div>

$BodyHtml

    <hr>
    <p class="text-muted fs-sm">
        &larr; <a href="/blog/">Back to all posts</a>
    </p>
</article>

</main>

<footer class="site-footer">
    <div class="container">
        &copy; 2026 Bryce Maxheimer  &middot;
        <a href="https://github.com/brycemaxheimer">GitHub</a>  &middot;
        <a href="/about.html">Contact</a>
    </div>
</footer>

<script src="/js/motion.js" defer></script>
</body>
</html>
"@
}

function Render-Feed {
    param([object[]] $Posts)

    $items = foreach ($post in $Posts) {
        $link = "$SiteUrl/blog/posts/$($post.slug).html"
        $pubDate = $post.dateObject.ToString('r')
        $title = Escape-Xml $post.title
        $summary = Escape-Xml $post.summary
@"
    <item>
      <title>$title</title>
      <link>$link</link>
      <guid>$link</guid>
      <pubDate>$pubDate</pubDate>
      <description>$summary</description>
    </item>
"@
    }

@"
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Bryce Maxheimer Blog</title>
    <link>$SiteUrl/blog/</link>
    <description>Projects, writeups, and posts from Bryce Maxheimer.</description>
    <language>en-us</language>
    <lastBuildDate>$(Get-Date -Format 'r')</lastBuildDate>
$($items -join "`n")
  </channel>
</rss>
"@
}

$mdFiles = Get-ChildItem -Path $SourceDir -Filter '*.md' -File
if ($mdFiles.Count -eq 0) {
    Write-Host "No .md files in $SourceDir" -ForegroundColor Yellow
    return
}

$posts = foreach ($file in $mdFiles) {
    $raw = Get-Content -Path $file.FullName -Raw
    $parsed = Parse-FrontMatter -Raw $raw
    $slug = Get-Slug -Path $file.FullName
    $readingTime = Get-ReadingTime -Text $parsed.body
    $dateObject = ConvertTo-BlogDate -RawDate $parsed.meta.date
    $isPublic = ($parsed.meta.published.ToString().Trim().ToLowerInvariant() -notin @('false', '0', 'no'))
    [PSCustomObject]@{
        SourcePath   = $file.FullName
        Slug         = $slug
        Meta         = $parsed.meta
        BodyMarkdown = $parsed.body
        ReadingTime  = $readingTime
        DateObject   = $dateObject
        IsPublic     = $isPublic
    }
}

$posts = $posts | Sort-Object DateObject -Descending
$publicPosts = @($posts | Where-Object { $_.IsPublic })

Write-Host "Building $($posts.Count) post(s)..." -ForegroundColor Cyan

foreach ($post in $posts) {
    $bodyHtml = Convert-MarkdownBodyToHtml -Markdown $post.BodyMarkdown
    $page = Render-Page -Meta $post.Meta -BodyHtml $bodyHtml -Slug $post.Slug -ReadingTimeMinutes $post.ReadingTime -IsPublic $post.IsPublic
    $outPath = Join-Path $OutputDir "$($post.Slug).html"
    Write-Utf8File -Path $outPath -Content $page
    Write-Host "  -> Built blog/posts/$($post.Slug).html" -ForegroundColor Green
}

$manifest = [ordered]@{
    generatedAt = (Get-Date).ToString('o')
    count       = $publicPosts.Count
    posts       = @(
        foreach ($post in $publicPosts) {
            [ordered]@{
                title       = $post.Meta.title
                date        = $post.Meta.date
                summary     = $post.Meta.summary
                tags        = @($post.Meta.tags)
                slug        = $post.Slug
                readingTime = [int]$post.ReadingTime
                url         = "/blog/posts/$($post.Slug).html"
            }
        }
    )
}

$manifestJson = $manifest | ConvertTo-Json -Depth 6
Write-Utf8File -Path $BlogJsonPath -Content $manifestJson
Write-Host "  -> Built blog/posts.json" -ForegroundColor Green

$feedPosts = foreach ($post in $publicPosts) {
    [PSCustomObject]@{
        title      = $post.Meta.title
        summary    = $post.Meta.summary
        slug       = $post.Slug
        dateObject = $post.DateObject
    }
}
$feedXml = Render-Feed -Posts $feedPosts
Write-Utf8File -Path $FeedXmlPath -Content $feedXml
Write-Host "  -> Built blog/feed.xml" -ForegroundColor Green

Write-Host "Build complete!" -ForegroundColor Cyan
