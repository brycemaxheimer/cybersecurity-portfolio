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
