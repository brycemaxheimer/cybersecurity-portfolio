"""Step 1: collect from free sources. Plain code, no model calls.

Each source fails on its own: an outage is logged in the run status and the
edition is built from whatever came back.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

from ..config import day_window
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


def _when(item: Item) -> datetime | None:
    try:
        dt = datetime.fromisoformat(item.published.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _clip(items: list[Item], since: datetime, until: datetime) -> list[Item]:
    """Keep only what was published inside the day the edition covers.

    The feed and social collectors search from a start time and take whatever
    is newer, so without this an edition built in the morning would carry that
    morning's posts alongside the day it is meant to report. KEV is exempt:
    its entries carry a date and no time, and kev.collect already selects the
    covered day.
    """
    kept = []
    for i in items:
        if i.kind == "kev":
            kept.append(i)
            continue
        when = _when(i)
        if when is None:
            log.warning("dropping %s %s: unreadable published %r", i.kind, i.id, i.published)
        elif since <= when < until:
            kept.append(i)
    return kept


def _run(status: dict, name: str, window: tuple[datetime, datetime], fn, *args) -> list[Item]:
    try:
        items = _clip(fn(*args), *window)
        status[name] = f"ok {len(items)}"
        return items
    except Exception as e:
        log.warning("source %s failed: %s", name, e)
        status[name] = f"error {type(e).__name__}: {str(e)[:200]}"
        return []


def collect_all(
    run_date: date, settings: dict, sources: dict, published_kev: set[str], sigma_repo_dir,
) -> Collection:
    """Window: the calendar day before run_date, in the site's own timezone.

    The edition published on a morning reports the whole of the day before and
    nothing else, the way a newspaper does. A story has then had a full day to
    be corroborated, corrected or dropped, instead of the page mixing an hour
    old report with one from two days ago.

    The window is derived from run_date alone, never from the clock, so the
    edition does not depend on when the job happens to run. Rebuilding a date
    later produces the same window, which is what makes a backfill honest.
    """
    cfg = settings["collect"]
    covers = run_date - timedelta(days=1)
    window = since, until = day_window(run_date, settings)
    col = Collection(since=since.isoformat(), until=until.isoformat())
    st = col.status

    try:
        catalog = kev.fetch_catalog()
        col.kev_catalog_cves = kev.catalog_cves(catalog)
        col.items += _run(st, "CISA KEV", window, kev.collect, covers, catalog, published_kev)
    except Exception as e:
        st["CISA KEV"] = f"error {e}"

    col.items += _run(st, "NVD", window, nvd.collect, since, until)

    for n, feed in enumerate(sources.get("feed", []), 1):
        col.items += _run(
            st, feed["name"], window, feeds.collect_feed, feed, since, f"f{n}", cfg["item_text_chars"]
        )

    soc = sources.get("social", {})
    col.items += _run(st, "Bluesky", window, social.bluesky, soc["bluesky"], since, cfg["bluesky_max_pages"])
    col.items += _run(st, "Mastodon", window, social.mastodon, soc["mastodon"], since, cfg["mastodon_max_pages"])
    col.items += _run(st, "r/netsec", window, social.reddit, soc["reddit"], since)
    col.items += _run(st, "Hacker News", window, social.hackernews, soc["hackernews"], since)

    col.items += _run(st, "SigmaHQ new rules", window, sigma_repo.new_rules, sigma_repo_dir, since)

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
