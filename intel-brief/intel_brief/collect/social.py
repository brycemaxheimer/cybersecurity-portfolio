"""Researcher chatter: Bluesky, Mastodon (infosec.exchange), r/netsec, Hacker News.

X/Twitter is left out on purpose: its API is paid and scraping breaks its terms.
Only posts that mention a CVE are kept; they feed the early-signals section.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

import feedparser

from ..http import FetchError, get_bytes, get_json
from ..models import Item, find_cves
from ..safety import html_to_text, safe_url
from .feeds import entry_time

log = logging.getLogger(__name__)

_HANDLE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_RKEY = re.compile(r"^[A-Za-z0-9._~:-]{1,512}$")


def _iso(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def bluesky(cfg: dict, since: datetime, max_pages: int) -> list[Item]:
    items: list[Item] = []
    cursor = None
    for page in range(max_pages):
        params = {"q": cfg["query"], "sort": "latest", "limit": 100, "since": _fmt(since)}
        if cursor:
            params["cursor"] = cursor
        try:
            data = get_json(cfg["search_url"], params=params, timeout=30)
        except FetchError as e:
            # Unauthenticated search sometimes refuses deep pages (403); keep
            # what the earlier pages returned.
            if page == 0:
                raise
            log.info("bluesky stopped at page %d: %s", page + 1, str(e)[:120])
            break
        for post in data.get("posts", []):
            record = post.get("record", {})
            text = record.get("text", "")
            cves = find_cves(text)
            when = _iso(record.get("createdAt", ""))
            if not cves or not when or when < since:
                continue
            handle = post.get("author", {}).get("handle", "")
            rkey = post.get("uri", "").rsplit("/", 1)[-1]
            if not _HANDLE.match(handle) or not _RKEY.match(rkey):
                continue
            items.append(
                Item(
                    id=f"bsky-{len(items) + 1}",
                    kind="social",
                    source="Bluesky",
                    title=f"@{handle}",
                    url=f"https://bsky.app/profile/{handle}/post/{rkey}",
                    published=_fmt(when),
                    text=text[:600],
                    cves=cves,
                    author=f"bluesky:{handle}",
                    extra={"likes": post.get("likeCount", 0), "reposts": post.get("repostCount", 0)},
                )
            )
        cursor = data.get("cursor")
        if not cursor:
            break
    return items


def mastodon(cfg: dict, since: datetime, max_pages: int) -> list[Item]:
    instance = cfg["instance"]
    url = f"https://{instance}/api/v1/timelines/public"
    items: list[Item] = []
    max_id = None
    for _ in range(max_pages):
        params = {"local": "true", "limit": 40}
        if max_id:
            params["max_id"] = max_id
        page = get_json(url, params=params, timeout=30)
        if not page:
            break
        oldest = None
        for status in page:
            when = _iso(status.get("created_at", ""))
            oldest = when if oldest is None or (when and when < oldest) else oldest
            text = html_to_text(status.get("content", ""), 800)
            cves = find_cves(text)
            link = safe_url(status.get("url") or "", {instance})
            if not cves or not when or when < since or not link:
                continue
            acct = status.get("account", {}).get("acct", "")
            items.append(
                Item(
                    id=f"masto-{len(items) + 1}",
                    kind="social",
                    source="Mastodon",
                    title=f"@{acct}@{instance}" if "@" not in acct else f"@{acct}",
                    url=link,
                    published=_fmt(when),
                    text=text,
                    cves=cves,
                    author=f"mastodon:{acct}",
                    extra={"boosts": status.get("reblogs_count", 0)},
                )
            )
        max_id = page[-1].get("id")
        if oldest and oldest < since:
            break
    return items


def reddit(cfg: dict, since: datetime) -> list[Item]:
    parsed = feedparser.parse(get_bytes(cfg["feed_url"], timeout=30))
    items = []
    for entry in parsed.entries:
        when = entry_time(entry)
        link = safe_url(entry.get("link", ""), {"www.reddit.com"})
        title = html_to_text(entry.get("title", ""), 300)
        text = html_to_text(entry.get("summary", ""), 800)
        cves = find_cves(f"{title} {text}")
        if not when or when < since or not link or not cves:
            continue
        author = html_to_text(entry.get("author", ""), 60)
        items.append(
            Item(
                id=f"reddit-{len(items) + 1}",
                kind="social",
                source="r/netsec",
                title=title,
                url=link,
                published=_fmt(when),
                text=text,
                cves=cves,
                author=f"reddit:{author}",
            )
        )
    return items


def hackernews(cfg: dict, since: datetime) -> list[Item]:
    params = {
        "query": cfg["query"],
        # Without this Algolia fuzzy-matches "CVE" and the 200 hits are mostly noise.
        "typoTolerance": "false",
        "tags": "(story,comment)",
        "numericFilters": f"created_at_i>{int(since.timestamp())}",
        "hitsPerPage": 200,
    }
    data = get_json(cfg["search_url"], params=params, timeout=30)
    items = []
    for hit in data.get("hits", []):
        object_id = str(hit.get("objectID", ""))
        if not object_id.isdigit():
            continue
        title = hit.get("title") or hit.get("story_title") or ""
        text = html_to_text(hit.get("comment_text") or hit.get("story_text") or "", 800)
        cves = find_cves(f"{title} {text} {hit.get('url') or ''}")
        when = _iso(hit.get("created_at", ""))
        if not cves or not when:
            continue
        items.append(
            Item(
                id=f"hn-{len(items) + 1}",
                kind="social",
                source="Hacker News",
                title=html_to_text(title, 300) or "HN comment",
                url=f"https://news.ycombinator.com/item?id={object_id}",
                published=_fmt(when),
                text=text,
                cves=cves,
                author=f"hn:{hit.get('author', '')}",
                extra={"points": hit.get("points") or 0},
            )
        )
    return items
