"""Early signals: CVEs several researchers posted about that aren't in KEV or
the news yet. Pure code; no model text appears in this section."""

from __future__ import annotations

from collections import defaultdict

from .collect import Collection

# An account that posts about this many distinct CVEs in a day is a feed bot.
BOT_CVE_THRESHOLD = 15
# A post naming this many CVEs is a digest, not a signal.
DIGEST_CVE_THRESHOLD = 5


def find(col: Collection, min_authors: int, max_signals: int) -> list[dict]:
    social = [i for i in col.of_kind("social") if 0 < len(i.cves) < DIGEST_CVE_THRESHOLD]
    per_author: dict[str, set[str]] = defaultdict(set)
    for it in col.of_kind("social"):
        per_author[it.author.lower()].update(it.cves)
    bots = {a for a, cves in per_author.items() if len(cves) >= BOT_CVE_THRESHOLD}

    news_cves = {c for i in col.of_kind("news") for c in i.cves}
    advisory_cves = {c for i in col.of_kind("advisory") for c in i.cves}

    by_cve: dict[str, list] = defaultdict(list)
    for it in social:
        if it.author.lower() in bots:
            continue
        for c in it.cves:
            by_cve[c].append(it)

    out = []
    for cve, posts in by_cve.items():
        authors = {p.author.lower() for p in posts}
        if len(authors) < min_authors or cve in col.kev_catalog_cves or cve in news_cves:
            continue
        def engagement(p):
            e = p.extra
            return (e.get("likes", 0) + 2 * e.get("reposts", 0) + 2 * e.get("boosts", 0) + e.get("points", 0))
        top, seen = [], set()
        for p in sorted(posts, key=engagement, reverse=True):
            if p.author.lower() in seen:
                continue
            seen.add(p.author.lower())
            handle = p.author.split(":", 1)[-1].split("@")[0] or p.author
            top.append({"url": p.url, "platform": p.source, "account": f"@{handle}"[:60], "published": p.published})
            if len(top) == 5:
                break
        out.append(
            {
                "cve": cve,
                "authors": len(authors),
                "platforms": sorted({p.source for p in posts}),
                "posts": top,
                "first_seen": min(p.published for p in posts),
                "epss": col.epss.get(cve),
                "vendor_advisory": cve in advisory_cves,
            }
        )
    out.sort(key=lambda s: (-s["authors"], -(s["epss"] or {}).get("epss", 0)))
    return out[:max_signals]
