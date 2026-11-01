"""RSS / Atom feeds: news sites and vendor advisories."""

from __future__ import annotations

import calendar
import logging
from datetime import datetime, timezone

import feedparser

from ..http import get_bytes
from ..models import Item, find_cves
from ..safety import html_to_text, safe_url

log = logging.getLogger(__name__)


def entry_time(entry) -> datetime | None:
    for key in ("published_parsed", "updated_parsed"):
        t = entry.get(key)
        if t:
            return datetime.fromtimestamp(calendar.timegm(t), tz=timezone.utc)
    return None


def entry_text(entry) -> str:
    """Prefer full content when the feed carries it; fall back to summary."""
    content = entry.get("content") or []
    best = max((c.get("value", "") for c in content), key=len, default="")
    return best if len(best) > len(entry.get("summary", "")) else entry.get("summary", "")


def collect_feed(feed: dict, since: datetime, prefix: str, text_chars: int) -> list[Item]:
    raw = get_bytes(feed["url"], timeout=45, max_bytes=15_000_000)
    parsed = feedparser.parse(raw)
    allowed = set(feed.get("allowed_hosts", []))
    items = []
    for entry in parsed.entries:
        when = entry_time(entry)
        if when is None or when < since:
            continue
        url = safe_url(entry.get("link", ""), allowed)
        if not url:
            log.debug("dropped link from %s: %r", feed["name"], entry.get("link"))
            continue
        title = html_to_text(entry.get("title", ""), 300)
        text = html_to_text(entry_text(entry), text_chars)
        items.append(
            Item(
                id=f"{prefix}-{len(items) + 1}",
                kind=feed.get("kind", "news"),
                source=feed["name"],
                title=title,
                url=url,
                published=when.strftime("%Y-%m-%dT%H:%M:%SZ"),
                text=text,
                cves=find_cves(f"{title} {text}"),
                author=html_to_text(entry.get("author", ""), 80),
            )
        )
    return items
