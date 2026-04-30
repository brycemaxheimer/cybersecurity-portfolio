---
title: Welcome to the lab
date: 2026-04-30
summary: Why I'm publishing in the open, how this site is built, and what's coming next.
tags: meta, soc
---

## Why publish in the open

Most of the cybersecurity work I do lives behind authentication walls — internal
runbooks, ticket comments, query libraries that are tied to a specific tenant.
That's fine for the day job, but it means the *general* lessons get buried with
the *specific* incidents.

This site is my attempt to fix that. I want a public-facing notebook for the
parts of the work that aren't sensitive: framework alignment, tooling patterns,
script writeups, and the occasional rabbit hole.

## How this site is built

Three deliberate constraints:

1. **No framework.** Plain HTML and CSS, hand-written. I wanted to actually
   *understand* every byte that ships, not delegate that to a build tool I don't
   read.
2. **Markdown for posts.** Authoring HTML for long-form content gets old fast.
   A small PowerShell build script (`build.ps1`) runs `ConvertFrom-Markdown`
   over `posts-source/*.md` and emits HTML files into `blog/posts/`.
3. **Hosted on Cloudflare Pages.** Free tier, automatic builds from a GitHub
   push, custom domain via Cloudflare DNS. The whole stack costs $0/month
   (excluding the domain registration).

The full source is on GitHub.

## What's coming next

Rough backlog, no committed schedule:

- A walkthrough of the `Invoke-KqlPS` lab harness — practicing KQL hunts against
  a local SQLite copy of common Sentinel tables.
- Notes on mapping the SOC Dashboard's threat-intel modules to MITRE ATT&CK data
  sources.
- A short post on running NIST CSF self-assessments out of an MS Access backend
  (yes, really — it's the right tool for some shops).

If a topic here is useful to you, the best feedback channel is the email on the
About page.

> **A note on scope.** Nothing on this site is offered as professional advice
> for your environment. It's a notebook of what's worked for *me* in the
> contexts I work in. Adopt selectively.
