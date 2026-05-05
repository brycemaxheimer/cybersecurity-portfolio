# OpenGraph share images

Drop `default.png` here (1200x630 PNG). Every page references it as
`og:image` / `twitter:image`.

The major link unfurlers (Twitter / X, LinkedIn, Slack, Discord, Facebook)
require a raster image at exactly 1200x630 for the `summary_large_image`
card; SVG isn't accepted. Until a real image is committed, shares will
fall back to no preview, which is the current behavior anyway.

## Quick recipes

- **Figma / Canva**: 1200x630 frame, dark background matching site theme
  (`--bg-0` is `#0e1216`), brand mark + tagline, export as PNG.
- **`magick` (one-liner)**: throw together a placeholder card from text:

  ```bash
  magick -size 1200x630 xc:'#0e1216' \
      -gravity center \
      -font Inter-SemiBold -pointsize 72 -fill '#46d09a' \
      -annotate 0,-40 'Bryce Maxheimer' \
      -font Inter-Regular -pointsize 36 -fill '#c9d1d9' \
      -annotate 0,40 'Cybersecurity portfolio' \
      og/default.png
  ```

## Per-page images (later)

Pages can override the default by editing their meta block in-place:

```html
<meta property="og:image" content="https://brycemaxheimer.com/og/kql-practice.png">
<meta name="twitter:image" content="https://brycemaxheimer.com/og/kql-practice.png">
```

High-traffic candidates: `/kql/practice/`, `/lab/threat-intel/demo.html`,
the blog post index, individual blog posts.

## Verify

After deploying with a real image:

- https://www.opengraph.xyz/  -- general OG validator
- https://cards-dev.twitter.com/validator  -- X / Twitter card preview
- https://developers.facebook.com/tools/debug/  -- Facebook + LinkedIn use the same scrape

`curl -s https://brycemaxheimer.com/lab/practice/ | grep -E 'og:|twitter:|canonical'`
shows the rendered tags from the command line.
