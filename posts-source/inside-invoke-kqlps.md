---
title: Inside Invoke-KqlPS
date: 2026-05-12
summary: Why I built a KQL interpreter in PowerShell, what subset it supports today, and how it anchors the rest of the lab.
tags: kql, powershell, tooling
published: false
---

## Why build a local KQL harness at all

The problem was simple: I wanted a place to practice hunting patterns against
realistic Sentinel-shaped data without needing a live tenant, ingest budget, or
demo workspace every time I wanted to test an idea.

That led to `Invoke-KqlPS.ps1`, a scoped Kusto Query Language interpreter in
pure PowerShell. It loads tables from a local SQLite database whose schema
mirrors the Microsoft Sentinel / Log Analytics table shapes I care about, keeps
rows in memory as PowerShell objects, and treats each tabular operator as a
function that takes a table and returns a new table. The pipe stays the mental
model all the way through.

The module was never meant to be "all of KQL." The useful target was the subset
that shows up constantly in daily SOC work: `where`, `project`, `extend`,
`summarize`, `distinct`, `union`, several join kinds, `parse with`, and
`mv-expand`, plus the scalar functions you reach for while cleaning data or
building pivots.

## What the current interpreter actually covers

The supported surface is intentionally honest and written down in the module
header. On the tabular side, the interpreter handles:

- `take`, `limit`, `top`
- `where`
- `project`, `project-keep`, `project-rename`, `project-away`
- `extend`
- `summarize ... by ...`
- `order by` / `sort by`
- `distinct`
- `union`
- `join kind=inner|leftouter|leftanti|innerunique`
- `parse with`
- `mv-expand`
- pass-through handling for `materialize`, `getschema`, and `render`

On the scalar side, it supports the functions I wanted available while teaching
or validating hunts: time helpers like `ago()` and `now()`, converters like
`tostring()` and `toint()`, string helpers like `startswith`, `contains`, and
`split`, and collection helpers like `make_set`, `make_list`, `array_length`,
and `array_index_of`.

Just as important, the out-of-scope list is explicit. `mv-apply`,
`evaluate bag_unpack`, `series_*`, parameterized user-defined functions, and
external tables are not quietly half-implemented. They raise a clear error so
the failure mode is "you hit an unsupported feature" instead of "you got a
plausible-looking but wrong result."

## The reproducibility trick that made the lab usable

One design detail matters more than it sounds: the module freezes the "current
time" anchor when the context is created.

That means `ago()` and `now()` are reproducible against the static sample data.
The browser lab and the PowerShell lab both depend on that idea. If the
reference clock drifted with the user's system clock, training queries would
keep getting weirder as the bundled data aged. Freezing the reference time
lets the dataset stay static while the exercises still behave like they're
running against a fresh window.

That small constraint is why the same query examples can be taught in the guide,
graded in the practice harness, and validated in the browser engine without
everyone getting different answers.

## Why SQLite sits underneath it

SQLite is the storage layer, not the query language. The companion
`Build-KqlLabDb.ps1` script stages CSV log samples into tables that match the
production-style schema, and `Import-KqlLabCsv.ps1` handles the type coercion.

That split matters:

- SQLite gives me a portable local store.
- PowerShell gives me a place to model KQL semantics directly.
- The sample tables keep the field names and data shapes familiar enough that a
  hunt can move from the lab into Sentinel or ADX with minimal translation.

The browser lab later ports the same mental model into JavaScript and WASM
SQLite, but the PowerShell version is the original reference implementation.

## Where this fits in the rest of the site

`Invoke-KqlPS` is not an isolated script. It is the anchor point for a bigger
chain:

- the local lab database builder
- the KQL guide and examples
- the browser playground
- the 30-question practice harness
- the validation matrix that keeps the browser port honest

That is the part I care about most. The goal was never just to write a parser.
It was to build a practice environment where the query, the data, the lesson,
and the grading path all line up.

If you want to poke at the browser side of the same idea, start with the
[KQL Playground](/kql/) and [KQL Practice](/lab/practice/). If you want the
PowerShell module inventory, the [Scripts page](/scripts/) is the map.
