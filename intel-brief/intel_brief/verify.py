"""Step 6: decide whether an edition may publish itself.

The daily workflow opens a pull request for every edition and merges it only if
the gates here pass. They stand in for the human skim that review mode relied
on, so they cover what a reader would have caught:

  shape      the edition and run records are complete and describe this date
  substance  enough stories, each carrying the write-up that was asked for
  honesty    no model refusal, no truncation from hitting the cost cap
  sources    the feeds the brief is built on actually answered
  inertness  nothing from an untrusted feed reached the page as markup, as an
             event handler, or as a link somewhere we never meant to send a
             reader

A FAIL holds the pull request for a person. A WARN publishes and is recorded in
the pull request body: a single dead feed or a coverage gap already in the past
cannot be fixed by waiting, and holding the edition over one would only widen
the gap it is reporting.

  python -m intel_brief verify --date 2026-11-05

Exit codes: 0 every gate passed, 1 at least one FAIL, 2 the edition could not
be read at all.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import date as _date_cls, datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
from typing import Iterator, NamedTuple
from urllib.parse import urlsplit

from .config import EDITIONS_DIR, RUNS_DIR, SITE_DIR, day_window, load_settings, load_sources
from .safety import BUILTIN_HOSTS, has_url

FAIL = "FAIL"
WARN = "WARN"

# Tags that would make the page do something. The renderer emits none of them:
# the edition page is plain markup, so any hit is content that escaped escaping.
_ACTIVE_TAG = re.compile(r"(?i)<\s*(script|iframe|object|embed|form|base|applet)\b")
# Inline handlers. Prose containing "onerror=" renders escaped, so this only
# matches a real attribute.
_HANDLER = re.compile(r"""(?i)\son[a-z]{3,}\s*=\s*["']""")
# Attribute values that execute or smuggle bytes.
_BAD_SCHEME = re.compile(
    r"""(?i)\b(?:href|src|action|formaction|srcdoc|xlink:href)\s*=\s*["']\s*"""
    r"""(javascript|data|vbscript|file):"""
)
_ATTR_URL = re.compile(r"""(?i)\b(?:href|src)\s*=\s*["']([^"']*)["']""")

class Finding(NamedTuple):
    level: str
    gate: str
    message: str

    def __str__(self) -> str:
        return f"{self.level} [{self.gate}] {self.message}"


class EditionMissing(Exception):
    """The edition or run record could not be read at all."""


def _load(path: Path, what: str) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise EditionMissing(f"{what}: {path.name}: {e}") from e


def _allowed_hosts() -> set[str]:
    """Hosts the renderer is willing to link to, plus our own."""
    hosts = set(BUILTIN_HOSTS)
    for feed in load_sources().get("feed", []):
        hosts.update(feed.get("allowed_hosts", []))
    base = urlsplit(load_settings()["site"]["base_url"]).hostname
    if base:
        hosts.add(base.lower())
    return hosts


def _parse_dt(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _check_shape(ed: dict, run: dict, date: str) -> list[Finding]:
    out = []
    if ed.get("schema") != 1:
        out.append(Finding(FAIL, "shape", f"edition schema is {ed.get('schema')!r}, expected 1"))
    if ed.get("date") != date:
        out.append(Finding(FAIL, "shape", f"edition is dated {ed.get('date')!r}, expected {date}"))
    if run.get("date") != date:
        out.append(Finding(FAIL, "shape", f"run record is dated {run.get('date')!r}, expected {date}"))
    for key in ("generated_at", "models", "window", "stories", "sources_status", "stats"):
        if key not in ed:
            out.append(Finding(FAIL, "shape", f"edition is missing {key!r}"))
    if run.get("dry_run"):
        out.append(Finding(FAIL, "shape", "run was a dry run: no model output in this edition"))
    return out


def _check_substance(ed: dict, cfg: dict) -> list[Finding]:
    out = []
    stories = ed.get("stories") or []
    if len(stories) < cfg["min_stories"]:
        out.append(Finding(
            FAIL, "substance",
            f"{len(stories)} stories, below the minimum of {cfg['min_stories']}"))

    missed = [s for s in stories if s.get("writeup_status") != "ok"]
    protected = [s for s in missed if (s.get("rank") or 0) <= cfg["protected_ranks"]]
    if protected:
        ranks = ", ".join(f"#{s.get('rank')} {s.get('title', '')[:60]}" for s in protected)
        out.append(Finding(FAIL, "substance", f"lead stories have no write-up: {ranks}"))
    elif len(missed) > cfg["max_failed_writeups"]:
        out.append(Finding(
            FAIL, "substance",
            f"{len(missed)} write-ups failed, more than the {cfg['max_failed_writeups']} allowed"))
    elif missed:
        out.append(Finding(
            WARN, "substance",
            f"{len(missed)} write-up(s) failed: "
            + ", ".join(f"#{s.get('rank')} ({s.get('writeup_status')})" for s in missed)))

    if ed.get("explainer_status") not in (None, "ok"):
        out.append(Finding(WARN, "substance", f"explainer status {ed['explainer_status']!r}"))
    if ed.get("stats", {}).get("kql_parser") != "available":
        out.append(Finding(
            WARN, "substance",
            "the KQL parser was unavailable, so published queries are unvalidated"))
    return out


def _check_honesty(ed: dict, run: dict) -> list[Finding]:
    out = []
    if run.get("budget_hit"):
        out.append(Finding(FAIL, "honesty", "the cost cap was hit: this edition is truncated"))

    cost = run.get("cost") or {}
    calls = cost.get("calls") or []
    refused = [c for c in calls if c.get("refusal_category")]
    for c in refused:
        out.append(Finding(
            FAIL, "honesty",
            f"{c.get('stage')} refused ({c['refusal_category']}): the model declined to "
            "process source content, so the page may misreport it"))

    cut = [c for c in calls if c.get("stop_reason") not in (None, "", "end_turn", "stop_sequence")]
    for c in cut:
        out.append(Finding(
            WARN, "honesty", f"{c.get('stage')} stopped on {c.get('stop_reason')!r}"))

    total, cap = cost.get("total_cost_usd"), cost.get("max_cost_usd")
    if isinstance(total, (int, float)) and isinstance(cap, (int, float)) and total > cap:
        out.append(Finding(FAIL, "honesty", f"spent ${total:.2f} against a ${cap:.2f} cap"))

    served = {c.get("served_by") for c in calls if c.get("served_by")}
    declared = {v for k, v in (ed.get("models") or {}).items() if k != "triage_method"}
    unexpected = served - declared
    if unexpected:
        out.append(Finding(
            WARN, "honesty",
            "served by a model the edition does not credit: " + ", ".join(sorted(unexpected))))
    return out


def _check_sources(ed: dict, cfg: dict) -> list[Finding]:
    out = []
    status = ed.get("sources_status") or {}
    if not status:
        return [Finding(FAIL, "sources", "no source status recorded")]

    bad = {k: v for k, v in status.items() if not str(v).startswith("ok")}
    for name in cfg["required_sources"]:
        if name not in status:
            out.append(Finding(FAIL, "sources", f"required source {name!r} did not run"))
        elif name in bad:
            out.append(Finding(FAIL, "sources", f"required source {name!r}: {bad[name]}"))

    ratio = len(bad) / len(status)
    if ratio > cfg["max_source_error_ratio"]:
        out.append(Finding(
            FAIL, "sources",
            f"{len(bad)} of {len(status)} sources errored ({ratio:.0%}), over the "
            f"{cfg['max_source_error_ratio']:.0%} limit"))
    elif bad:
        out.append(Finding(
            WARN, "sources", f"{len(bad)} source(s) errored: " + ", ".join(sorted(bad))))
    return out


def _check_coverage(ed: dict, date: str, settings: dict) -> list[Finding]:
    """An edition covers the calendar day before its own date, exactly.

    That window is derived from the date alone, so it is checkable rather than
    merely plausible: anything else means the page's account of what it read is
    wrong, whatever the stories say.
    """
    out = []
    window = ed.get("window") or {}
    since, until = _parse_dt(window.get("since", "")), _parse_dt(window.get("until", ""))
    if not since or not until:
        return [Finding(FAIL, "coverage", f"unreadable window {window!r}")]

    day = _date_cls.fromisoformat(date)
    covers = day - timedelta(days=1)
    want_since, want_until = day_window(day, settings)
    tz = ZoneInfo(settings["site"]["timezone"])
    if since != want_since or until != want_until:
        out.append(Finding(
            FAIL, "coverage",
            f"window is {since.isoformat()} to {until.isoformat()}; the {date} edition must "
            f"cover the whole of {covers.isoformat()}, which is {want_since.isoformat()} to "
            f"{want_until.isoformat()}"))

    previous = next((p.stem for p in sorted(EDITIONS_DIR.glob("*.json"), reverse=True)
                     if p.stem < date), None)
    if previous:
        try:
            missed = (day - _date_cls.fromisoformat(previous)).days - 1
        except ValueError:
            missed = 0
        if missed > 0:
            out.append(Finding(
                WARN, "coverage",
                f"no edition between {previous} and {date}: {missed} day(s) are reported by "
                "no edition, and nothing later will pick them up"))

    generated = _parse_dt(ed.get("generated_at", ""))
    if generated and generated.astimezone(tz).date() != day:
        out.append(Finding(
            WARN, "coverage",
            f"generated on {generated.astimezone(tz).date().isoformat()} local time, not {date}: "
            "a run that slips past local midnight dates its edition a day on"))
    return out


def _prose(ed: dict) -> Iterator[tuple[str, str]]:
    """Every string a model wrote that the page shows as prose, labelled.

    Only these pass through safety.clean_model_text, so only these should be
    free of URLs. The collector-gathered fields sitting beside them -- a story's
    `sources`, a Sigma rule's `yaml` and `references` -- carry real links by
    design and are deliberately not checked here; the page's own links are
    checked against the host allowlist in _check_page instead.
    """
    for s in ed.get("stories") or []:
        where = f"story #{s.get('rank')}"
        yield where, s.get("title") or ""
        wu = s.get("writeup") or {}
        for key in ("what_happened", "why_it_matters"):
            yield f"{where} {key}", wu.get(key) or ""
        for key in ("affected_versions", "fixed_versions", "recommended_actions"):
            for item in wu.get(key) or []:
                yield f"{where} {key}", item or ""
        det = s.get("detection") or {}
        for step in det.get("hunting_steps") or []:
            yield f"{where} hunting step", step or ""
        for q in det.get("hunting_queries") or []:
            yield f"{where} hunting query title", q.get("title") or ""
        yield f"{where} sigma title", (det.get("sigma") or {}).get("title") or ""

    ex = ed.get("explainer") or {}
    for key in ("concept", "dek", "why_today"):
        yield f"explainer {key}", ex.get(key) or ""
    for t in ex.get("takeaways") or []:
        yield "explainer takeaway", t or ""
    for part in ex.get("parts") or []:
        yield "explainer heading", part.get("heading") or ""
        for para in part.get("paragraphs") or []:
            yield "explainer paragraph", para or ""

    for g in ed.get("good_news") or []:
        yield "good news headline", g.get("headline") or ""
        yield "good news summary", g.get("summary") or ""


def _check_prose(ed: dict) -> list[Finding]:
    """Model text is published as plain text with URLs stripped. A raw URL here
    means a field reached the page without safety.clean_model_text."""
    out, seen = [], set()
    for where, text in _prose(ed):
        found = has_url(text)
        if found and where not in seen:
            seen.add(where)
            out.append(Finding(
                FAIL, "prose", f"{where} carries an unstripped URL: {found[:80]!r}"))
    return out


def _check_page(date: str, cfg: dict, hosts: set[str]) -> list[Finding]:
    out = []
    page = SITE_DIR / "editions" / date / "index.html"
    if not page.exists():
        return [Finding(FAIL, "page", f"{page.relative_to(SITE_DIR.parent)} was not rendered")]
    html = page.read_text(encoding="utf-8", errors="replace")
    if len(html) < cfg["min_page_bytes"]:
        out.append(Finding(
            FAIL, "page",
            f"the page is {len(html)} bytes, under the {cfg['min_page_bytes']} expected"))
    if date not in html:
        out.append(Finding(FAIL, "page", "the page does not mention its own date"))

    for pattern, what in ((_ACTIVE_TAG, "an active tag"),
                          (_HANDLER, "an inline event handler"),
                          (_BAD_SCHEME, "an executable URL scheme")):
        m = pattern.search(html)
        if m:
            out.append(Finding(
                FAIL, "page",
                f"the page contains {what}: {m.group(0)[:60]!r}. Untrusted content reached "
                "the page as markup"))

    off = sorted({u for u in _ATTR_URL.findall(html) if _host_not_allowed(u, hosts)})
    if off:
        out.append(Finding(
            FAIL, "page",
            f"{len(off)} link(s) point outside the allowlist: " + ", ".join(off[:5])))
    return out


def _host_not_allowed(url: str, hosts: set[str]) -> bool:
    url = url.strip()
    if url.startswith("//"):
        return True  # protocol-relative: inherits https but leaves the site
    if not url or url.startswith(("#", "/", "./", "../", "mailto:")):
        return False  # same-site or in-page
    parts = urlsplit(url)
    if not parts.scheme and not parts.netloc:
        return False  # a relative file
    if parts.scheme.lower() != "https":
        return True  # http://, protocol-relative //host, anything else
    host = (parts.hostname or "").lower().rstrip(".")
    return host not in hosts


def _check_feeds(date: str) -> list[Finding]:
    out = []
    xml_path, json_path = SITE_DIR / "feed.xml", SITE_DIR / "feed.json"
    try:
        ET.parse(xml_path)
    except (OSError, ET.ParseError) as e:
        out.append(Finding(FAIL, "feeds", f"feed.xml is unusable: {e}"))
    else:
        if date not in xml_path.read_text(encoding="utf-8"):
            out.append(Finding(FAIL, "feeds", f"feed.xml does not list the {date} edition"))
    try:
        feed = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        out.append(Finding(FAIL, "feeds", f"feed.json is unusable: {e}"))
    else:
        if not any(date in str(i.get("id", "")) + str(i.get("url", ""))
                   for i in feed.get("items", [])):
            out.append(Finding(FAIL, "feeds", f"feed.json does not list the {date} edition"))
    return out


def verify(date: str, settings: dict | None = None) -> list[Finding]:
    """Run every gate against the stored edition. Raises EditionMissing if the
    records cannot be read, which is a failure of its own kind."""
    settings = settings or load_settings()
    cfg = settings["verify"]
    ed = _load(EDITIONS_DIR / f"{date}.json", "edition")
    run = _load(RUNS_DIR / f"{date}.json", "run record")
    hosts = _allowed_hosts()
    return [
        *_check_shape(ed, run, date),
        *_check_substance(ed, cfg),
        *_check_honesty(ed, run),
        *_check_sources(ed, cfg),
        *_check_coverage(ed, date, settings),
        *_check_prose(ed),
        *_check_page(date, cfg, hosts),
        *_check_feeds(date),
    ]


def report(date: str, findings: list[Finding]) -> str:
    """Markdown for the pull request body."""
    fails = [f for f in findings if f.level == FAIL]
    warns = [f for f in findings if f.level == WARN]
    lines = []
    if fails:
        lines.append(f"**Held for review: {len(fails)} gate(s) failed.**\n")
        lines += [f"- **{f.gate}** — {f.message}" for f in fails]
        if warns:
            lines.append("")
    else:
        lines.append("**All gates passed.**" + (" Warnings below are recorded, not blocking.\n"
                                                if warns else "\n"))
    if warns:
        lines += [f"- _{f.gate}_ — {f.message}" for f in warns]
    return "\n".join(lines)
