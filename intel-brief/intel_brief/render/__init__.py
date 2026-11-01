"""Step 5: render the static site from data/editions/*.json.

Output (site/):
  index.html                       latest edition
  editions/<date>/index.html       each edition
  editions/<date>/edition.json     the edition's data
  archive/index.html               all editions
  feed.xml  (RSS 2.0)   feed.json  (JSON Feed 1.1)
  404.html, assets/, _headers

Jinja autoescaping is on for every template, and every href is re-checked
against the source allowlist here, so a hand-edited edition JSON can't add
links or markup either.
"""

from __future__ import annotations

import json
import shutil
from datetime import date, datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..config import EDITIONS_DIR, SITE_DIR, load_settings, load_sources
from ..safety import safe_url

HERE = Path(__file__).parent

HEADERS = """/*
  Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Strict-Transport-Security: max-age=31536000
  Cross-Origin-Opener-Policy: same-origin
"""

PLATFORM_LABEL = {
    "windows": "Windows", "m365_entra": "M365 / Entra", "edge_device": "Edge device",
    "linux_server": "Linux", "cloud_saas": "Cloud / SaaS", "web_app": "Web app",
    "mobile": "Mobile", "ics_ot": "ICS / OT", "other": "",
}
MODEL_NAMES = {
    "claude-haiku-5-5": "Claude Haiku 5.5",
    "claude-opus-5-5": "Claude Opus 5.5",
    "claude-sonnet-5-5": "Claude Sonnet 5.5",
}


def _date(s: str) -> date | None:
    try:
        return date.fromisoformat((s or "")[:10])
    except ValueError:
        return None


def longdate(s: str) -> str:
    d = _date(s)
    return f"{d.day} {d:%B %Y}" if d else (s or "")


def shortdate(s: str) -> str:
    d = _date(s)
    return f"{d.day} {d:%b}" if d else (s or "")


def weekday(s: str) -> str:
    d = _date(s)
    return f"{d:%A}" if d else ""


def utcshort(s: str) -> str:
    try:
        dt = datetime.fromisoformat((s or "").replace("Z", "+00:00"))
    except ValueError:
        return s or ""
    return f"{dt.day} {dt:%b %H:%M}"


def days_between(a: str, b: str) -> int | None:
    da, db = _date(a), _date(b)
    return (db - da).days if da and db else None


def domain(url: str) -> str:
    host = urlsplit(url or "").hostname or ""
    return host[4:] if host.startswith("www.") else host


def tier(story: dict) -> str:
    """crit = exploited or in KEV; high = PoC, reported exploitation or high
    EPSS/CVSS; watch = everything else. Drives dots, tags and the priority bar."""
    f, lab = story.get("factors", {}), story.get("labels", {})
    if f.get("in_kev") or lab.get("exploitation") == "confirmed_in_wild":
        return "crit"
    cves = story.get("cves", [])
    if (
        lab.get("exploitation") in ("reported", "public_poc")
        or any(c.get("poc") for c in cves)
        or (f.get("epss_max") or 0) >= 0.1
        or any((c.get("cvss") or 0) >= 9 for c in cves)
    ):
        return "high"
    return "watch"


def order_cves(cves: list[dict]) -> list[dict]:
    """Most urgent first: KEV with the nearest deadline, then KEV, then CVSS and EPSS."""
    return sorted(
        cves,
        key=lambda c: (
            not c.get("in_kev"),
            c.get("kev_due") or "9999-12-31",
            -(c.get("cvss") or 0),
            -(c.get("epss") or 0),
        ),
    )


def detection_tabs(det: dict) -> list[dict]:
    """Tabs for a story's detection panel, in display order."""
    tabs: list[dict] = []
    sig = (det or {}).get("sigma")
    if sig:
        tabs.append({"key": "sigma", "label": "Sigma", "code": sig["yaml"], "name": sig.get("title") or "Sigma rule", "validation": None})
        for key in ("kql", "spl", "elastic"):
            conv = (sig.get("conversions") or {}).get(key) or {}
            if conv.get("query"):
                label = {"kql": "Defender KQL", "spl": "Splunk SPL", "elastic": "Elastic"}[key]
                tabs.append({"key": key, "label": label, "code": conv["query"], "name": conv.get("label", label), "validation": conv.get("validation")})
    if det and (det.get("hunting_steps") or det.get("hunting_queries")):
        tabs.append({"key": "hunt", "label": "Hunting", "code": None, "name": "Hunting", "validation": None})
    keys = [t["key"] for t in tabs]
    default = "kql" if "kql" in keys else (keys[0] if keys else None)
    for t in tabs:
        t["checked"] = t["key"] == default
    return tabs


def _allowed_hosts() -> set[str]:
    hosts: set[str] = set()
    for feed in load_sources().get("feed", []):
        hosts.update(feed.get("allowed_hosts", []))
    return hosts


def _env() -> Environment:
    hosts = _allowed_hosts()
    env = Environment(
        loader=FileSystemLoader(HERE / "templates"),
        autoescape=select_autoescape(default=True, default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["href"] = lambda u: safe_url(u or "", hosts) or ""
    env.filters["paras"] = lambda t: [p.strip() for p in (t or "").split("\n\n") if p.strip()]
    env.filters["pct"] = lambda x: "" if x is None else (f"{100 * x:.1f}%" if x < 0.1 else f"{100 * x:.0f}%")
    env.filters.update(
        longdate=longdate, shortdate=shortdate, weekday=weekday, utcshort=utcshort,
        domain=domain, tier=tier, model_name=lambda m: MODEL_NAMES.get(m, m),
    )
    env.globals.update(PLATFORM_LABEL=PLATFORM_LABEL, detection_tabs=detection_tabs, days_between=days_between, order_cves=order_cves)
    return env


def load_editions() -> list[dict]:
    eds = []
    for p in sorted(EDITIONS_DIR.glob("*.json"), reverse=True):
        eds.append(json.loads(p.read_text(encoding="utf-8")))
    return eds


def _edition_url(base: str, date: str) -> str:
    return f"{base}/editions/{date}/"


def _summary_text(ed: dict, n: int = 10) -> str:
    lines = [f"{s['rank']}. {s['title']}" for s in ed.get("stories", [])[:n]]
    if ed.get("kev_new"):
        lines.append(f"New KEV entries: {', '.join(k['cve'] for k in ed['kev_new'])}")
    if ed.get("early_signals"):
        lines.append(f"Early signals: {', '.join(s['cve'] for s in ed['early_signals'])}")
    return "\n".join(lines)


def _rss(eds: list[dict], site: dict) -> bytes:
    base = site["base_url"].rstrip("/")
    rss = ET.Element("rss", version="2.0")
    ch = ET.SubElement(rss, "channel")
    ET.SubElement(ch, "title").text = site["title"]
    ET.SubElement(ch, "link").text = base + "/"
    ET.SubElement(ch, "description").text = "Daily AI-generated threat-intel brief: top stories, new KEV entries, early signals and detections."
    ET.SubElement(ch, "language").text = "en-us"
    for ed in eds:
        when = datetime.fromisoformat(ed["generated_at"].replace("Z", "+00:00"))
        it = ET.SubElement(ch, "item")
        ET.SubElement(it, "title").text = f"{site['title']}: {ed['date']}"
        ET.SubElement(it, "link").text = _edition_url(base, ed["date"])
        ET.SubElement(it, "guid", isPermaLink="true").text = _edition_url(base, ed["date"])
        ET.SubElement(it, "pubDate").text = format_datetime(when)
        ET.SubElement(it, "description").text = _summary_text(ed)
    return b'<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(rss, encoding="utf-8")


def _json_feed(eds: list[dict], site: dict) -> str:
    base = site["base_url"].rstrip("/")
    feed = {
        "version": "https://jsonfeed.org/version/1.1",
        "title": site["title"],
        "home_page_url": base + "/",
        "feed_url": base + "/feed.json",
        "description": "Daily AI-generated threat-intel brief.",
        "authors": [{"name": site["author"]}],
        "language": "en-US",
        "items": [
            {
                "id": _edition_url(base, ed["date"]),
                "url": _edition_url(base, ed["date"]),
                "title": f"{site['title']}: {ed['date']}",
                "content_text": _summary_text(ed),
                "date_published": ed["generated_at"],
                "_intel_brief": {
                    "data": f"{base}/editions/{ed['date']}/edition.json",
                    "stories": [
                        {"title": s["title"], "cves": [c["id"] for c in s["cves"]], "score": s["score"]}
                        for s in ed.get("stories", [])
                    ],
                },
            }
            for ed in eds
        ],
    }
    return json.dumps(feed, indent=1, ensure_ascii=False)


def render_site(out: Path = SITE_DIR) -> list[Path]:
    settings = load_settings()
    site = settings["site"]
    base = site["base_url"].rstrip("/")
    env = _env()
    eds = load_editions()
    written: list[Path] = []

    def write(rel: str, content: str | bytes) -> None:
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8", newline="\n")
        written.append(path)

    ctx = {"site": site, "base": base, "now": datetime.now(timezone.utc)}
    edition_tpl = env.get_template("edition.html")
    for i, ed in enumerate(eds):
        newer = eds[i - 1]["date"] if i > 0 else None
        older = eds[i + 1]["date"] if i + 1 < len(eds) else None
        page = edition_tpl.render(ed=ed, newer=newer, older=older, canonical=_edition_url(base, ed["date"]), root="../../", nav="", **ctx)
        write(f"editions/{ed['date']}/index.html", page)
        write(f"editions/{ed['date']}/edition.json", json.dumps(ed, indent=1, ensure_ascii=False))
    if eds:
        latest = eds[0]
        older = eds[1]["date"] if len(eds) > 1 else None
        write("index.html", edition_tpl.render(ed=latest, newer=None, older=older, canonical=_edition_url(base, latest["date"]), root="", nav="latest", **ctx))
    write("archive/index.html", env.get_template("archive.html").render(eds=eds, canonical=f"{base}/archive/", root="../", nav="archive", **ctx))
    write("methodology/index.html", env.get_template("methodology.html").render(canonical=f"{base}/methodology/", root="../", nav="method", **ctx))
    write("404.html", env.get_template("404.html").render(canonical=None, root="/", nav="", **ctx))
    feed_eds = eds[: settings["edition"]["feed_editions"]]
    write("feed.xml", _rss(feed_eds, site))
    write("feed.json", _json_feed(feed_eds, site))
    write("_headers", HEADERS)
    static = HERE / "static"
    for asset in static.rglob("*"):
        if asset.is_file():
            dest = out / "assets" / asset.relative_to(static)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(asset, dest)
            written.append(dest)
    return written
