---
title: MITRE Crosswalks in the Lab
date: 2026-05-11
summary: How the local ATT&CK explorer, CVE-to-technique mappings, and KQL tooling fit together in one offline-friendly workflow.
tags: mitre, attack, detection
published: true
---

## The problem I wanted to solve

I did not want ATT&CK living in my tooling as a poster on the wall.

The useful version of ATT&CK is the one that can sit next to the things an
analyst is already doing: checking whether a technique is relevant, seeing what
data sources it expects, comparing it with recent CVEs, and turning that into a
query or triage path without opening six tabs.

That is the job of the MITRE crosswalk pieces in this repo.

## The local explorer starts with the full STIX bundle

`MitreAttackExplorer.ps1` downloads the Enterprise ATT&CK STIX bundle,
parses it, and loads the useful pieces into the same SQLite database used by
the rest of the SOC Dashboard tooling.

The ingest path stores:

- tactics
- techniques and sub-techniques
- intrusion sets
- software
- mitigations
- relationships

The important design choice is that ATT&CK data is cached locally after the
first run. That keeps the tool fast, user-level, and workable in environments
where the interesting part of the day is analysis rather than waiting on a
remote dependency.

For a while there was a browser version of the explorer on this site too. It
shipped a slimmed static dataset so the public side stayed usable without a
backend. I ended up pulling it down - the local dashboard explorer is where
that work actually lives, and keeping two copies honest was more upkeep than
it was worth.

## CVE-to-ATT&CK mapping is intentionally a separate layer

The ATT&CK bundle alone answers "what is this technique?" It does not answer
"which current vulnerabilities line up with the behavior I care about?"

That is why `Update-CveAttackMap.ps1` exists as a separate import step. It reads
a CSV with `CveId` and `TechniqueId` columns, plus optional `Source`,
`Confidence`, and `Mapping` fields, then loads those rows into the database as a
first-class lookup table.

Separating the mapping layer from the ATT&CK ingest keeps a few good things
true:

1. Multiple mapping sources can coexist.
2. Analyst-curated mappings are not flattened into someone else's feed.
3. The explorer and the patching views can show confidence and provenance,
   instead of pretending every mapping is equally authoritative.

The script header even calls out the intended mapping sources: the Center for
Threat-Informed Defense mappings, NVD/CWE-derived bridges, and analyst-curated
entries from local investigations.

## Why this matters in practice

A local crosswalk turns three separate questions into one working loop:

- What technique is this adversary behavior pointing at?
- What data source should see it?
- Which current CVEs or products make that technique more urgent right now?

That is the connective tissue between the ATT&CK explorer, the CVE/KEV/EPSS
browser, and the KQL tooling.

If a technique shows up repeatedly in ATT&CK-oriented research, and the related
products are present in KEV with strong EPSS or ransomware linkage, that should
change the order in which I write detections, validate log coverage, or bug a
team about patching.

The repo already leans into that connection:

- the ATT&CK explorer keeps tactic / platform / relationship context close
- the CVE browser already ships KEV and EPSS together
- the KQL templates and practice surfaces provide a place to turn the framework
  view into an actual hunt

## Why keep it offline-friendly

One theme across this site is that the interesting part should survive without a
constant live dependency.

That is true for the KQL engine, and it is also true here. The ATT&CK bundle can
be cached. The mapping import can be run on demand. The browser explorer can
ship a trimmed JSON snapshot. That means the learning surface is still there
even when the network is not.

I like that constraint because it forces the tooling to stay honest. If the tool
only works when every external service is healthy, then the value is in the
integration. If the tool still works offline, the value is in the model.

## Where this goes next

The next useful step is not another page. It is tighter round-tripping:

- ATT&CK technique to starter KQL
- CVE view to mapped techniques
- templates tagged by ATT&CK technique
- practice questions that say what tactic they are really exercising

That is the direction I want the lab to keep moving: less taxonomy for its own
sake, more direct paths from framework language to an analyst doing the work.

If you want to poke at the live surfaces, start with the [Browser Lab](/lab/).
