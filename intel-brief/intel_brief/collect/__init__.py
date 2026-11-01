"""Step 1: collect from free sources. Plain code, no model calls.

Each source fails on its own: an outage is logged in the run status and the
edition is built from whatever came back.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

from ..detections import sigma_repo
from ..models import Item
from . import epss, feeds, kev, nvd, social

log = logging.getLogger(__name__)


@dataclass
class Collection:
    items: list[Item] = field(default_factory=list)
    kev_catalog_cves: set[str] = field(default_factory=set)
    epss: dict[str, dict] = field(default_factory=dict)
    status: dict[str, str] = field(default_factory=dict)  # source -> "ok N" | "error ..."
    since: str = ""
    until: str = ""

    def by_id(self) -> dict[str, Item]:
        return {i.id: i for i in self.items}

    def of_kind(self, *kinds: str) -> list[Item]:
        return [i for i in self.items if i.kind in kinds]


def _run(status: dict, name: str, fn, *args) -> list[Item]:
    try:
        items = fn(*args)
        status[name] = f"ok {len(items)}"
        return items
    except Exception as e:
        log.warning("source %s failed: %s", name, e)
        status[name] = f"error {type(e).__name__}: {str(e)[:200]}"
        return []


MAX_LOOKBACK_HOURS = 72


def collect_all(
    run_date: date, settings: dict, sources: dict, published_kev: set[str], sigma_repo_dir,
    previous_until: datetime | None = None,
) -> Collection:
    """Window: the usual lookback, stretched back to where the previous edition's
    window ended (so a skipped day leaves no gap), but never more than 72 h."""
    cfg = settings["collect"]
    until = datetime.now(timezone.utc).replace(microsecond=0)
    since = until - timedelta(hours=cfg["lookback_hours"])
    if previous_until and previous_until < since:
        since = previous_until
    since = max(since, until - timedelta(hours=MAX_LOOKBACK_HOURS))
    col = Collection(since=since.isoformat(), until=until.isoformat())
    st = col.status

    try:
        catalog = kev.fetch_catalog()
        col.kev_catalog_cves = kev.catalog_cves(catalog)
        col.items += _run(st, "CISA KEV", kev.collect, run_date, catalog, published_kev)
    except Exception as e:
        st["CISA KEV"] = f"error {e}"

    col.items += _run(st, "NVD", nvd.collect, since, until)

    for n, feed in enumerate(sources.get("feed", []), 1):
        col.items += _run(
            st, feed["name"], feeds.collect_feed, feed, since, f"f{n}", cfg["item_text_chars"]
        )

    soc = sources.get("social", {})
    col.items += _run(st, "Bluesky", social.bluesky, soc["bluesky"], since, cfg["bluesky_max_pages"])
    col.items += _run(st, "Mastodon", social.mastodon, soc["mastodon"], since, cfg["mastodon_max_pages"])
    col.items += _run(st, "r/netsec", social.reddit, soc["reddit"], since)
    col.items += _run(st, "Hacker News", social.hackernews, soc["hackernews"], since)

    col.items += _run(st, "SigmaHQ new rules", sigma_repo.new_rules, sigma_repo_dir, since)

    cves = sorted({c for i in col.items for c in i.cves})
    try:
        col.epss = epss.scores(cves)
        st["EPSS"] = f"ok {len(col.epss)}"
    except Exception as e:
        st["EPSS"] = f"error {e}"

    # IDs must be unique: the models refer to items only by ID.
    ids = [i.id for i in col.items]
    assert len(ids) == len(set(ids)), "duplicate item IDs"
    return col
