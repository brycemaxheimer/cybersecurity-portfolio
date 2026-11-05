"""The gates that let an edition publish itself must fail a bad edition.

The daily workflow merges on a clean run of intel_brief.verify, so a gate that
quietly passes is a page published unread. Each test here degrades one thing
about an otherwise-publishable edition and asserts the matching gate fires.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from intel_brief import verify as V
from intel_brief.config import load_settings

DATE = "2026-11-05"
PREV = "2026-11-04"
FILLER = "Filler sentence to push the page past the minimum size. " * 600


def edition(**over):
    ed = {
        "schema": 1,
        "date": DATE,
        "generated_at": f"{DATE}T18:53:00Z",
        "generator": "intel-brief 0.1.0",
        "models": {"triage": "claude-haiku-5-5", "writeup": "claude-opus-5-5",
                   "triage_method": "model"},
        "window": {"since": f"{PREV}T18:47:00+00:00", "until": f"{DATE}T18:47:00+00:00"},
        "stats": {"items": {}, "stories_found": 9, "kql_parser": "available"},
        "sources_status": {"CISA KEV": "ok 1", "NVD": "ok 40",
                           "BleepingComputer": "ok 7", "SecurityWeek": "ok 2"},
        "kev_new": [],
        "early_signals": [],
        "more_stories": [],
        "explainer_status": "ok",
        "stories": [story(i) for i in (1, 2, 3, 4)],
        "good_news": [{"headline": "A botnet went down", "summary": "Good.",
                       "sources": [{"url": "https://krebsonsecurity.com/a/"}]}],
        "explainer": {"concept": "Token theft", "dek": "Why it matters.",
                      "why_today": "Because.", "takeaways": ["Rotate tokens."],
                      "parts": [{"heading": "How", "paragraphs": ["It happens."]}]},
    }
    ed.update(over)
    return ed


def story(rank, **over):
    s = {
        "id": f"story-{rank}", "rank": rank, "score": 90 - rank,
        "title": f"Story {rank}", "cves": [], "labels": [], "factors": [],
        "writeup_status": "ok",
        "sources": [{"title": "t", "url": "https://www.bleepingcomputer.com/news/x/",
                     "source": "BleepingComputer", "kind": "news"}],
        "writeup": {
            "what_happened": "Something happened.",
            "why_it_matters": "It matters.",
            "affected_versions": ["1.0"], "fixed_versions": ["1.1"],
            "recommended_actions": ["Patch."],
            "confidence": "high", "unsupported_cves": [],
            "model": "claude-opus-5-5",
        },
        "detection": {"type": "sigma", "notes": [], "hunting_steps": ["Look at logs."],
                      "hunting_queries": [{"title": "Suspicious logons", "kql": "Event | take 1"}],
                      "sigma": None},
    }
    s.update(over)
    return s


def run_record(**over):
    r = {
        "date": DATE, "started": f"{DATE}T18:47:07Z", "finished": f"{DATE}T18:53:14Z",
        "dry_run": False, "writeup_model": "claude-opus-5-5", "budget_hit": False,
        "cost": {
            "max_cost_usd": 2.0, "total_cost_usd": 0.56, "by_stage": {},
            "calls": [{"stage": "writeup:1", "model": "claude-opus-5-5",
                       "served_by": "claude-opus-5-5", "cost_usd": 0.07,
                       "stop_reason": "end_turn", "refusal_category": None}],
        },
    }
    r.update(over)
    return r


def page(date=DATE, body="", links=("https://www.bleepingcomputer.com/news/x/",)):
    anchors = "".join(f'<a href="{u}">src</a>' for u in links)
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<link rel="stylesheet" href="/assets/brief.css"><title>Brief {date}</title>'
            f"</head><body><h1>Daily Intel Brief</h1><p>Edition {date}</p>"
            f"{anchors}<p>{FILLER}</p>{body}</body></html>")


class GateCase(unittest.TestCase):
    """Lays a publishable edition into a temp tree, then lets tests spoil it."""

    def setUp(self):
        self.settings = load_settings()
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.eds, self.runs, self.site = root / "editions", root / "runs", root / "site"
        for d in (self.eds, self.runs, self.site / "editions" / DATE):
            d.mkdir(parents=True, exist_ok=True)
        for target, value in (("EDITIONS_DIR", self.eds), ("RUNS_DIR", self.runs),
                              ("SITE_DIR", self.site)):
            self.enterContext(mock.patch.object(V, target, value))
        self.write()

    def write(self, ed=None, run=None, html=None, feeds=True):
        (self.eds / f"{DATE}.json").write_text(json.dumps(ed or edition()), encoding="utf-8")
        (self.runs / f"{DATE}.json").write_text(json.dumps(run or run_record()), encoding="utf-8")
        (self.site / "editions" / DATE / "index.html").write_text(
            html if html is not None else page(), encoding="utf-8")
        item = f"https://intel.brycemaxheimer.com/editions/{DATE}/"
        (self.site / "feed.xml").write_text(
            '<?xml version="1.0"?><rss version="2.0"><channel><title>Brief</title>'
            f"<item><link>{item}</link></item></channel></rss>" if feeds
            else '<?xml version="1.0"?><rss version="2.0"><channel/></rss>',
            encoding="utf-8")
        (self.site / "feed.json").write_text(
            json.dumps({"version": "https://jsonfeed.org/version/1.1",
                        "items": [{"id": item, "url": item}] if feeds else []}),
            encoding="utf-8")

    def findings(self, **kw):
        self.write(**kw)
        return V.verify(DATE, self.settings)

    def assertGate(self, level, gate, **kw):
        hits = [f for f in self.findings(**kw) if f.level == level and f.gate == gate]
        self.assertTrue(hits, f"expected a {level} from {gate!r}, got: "
                              f"{[str(f) for f in self.findings(**kw)]}")
        return hits

    def assertClean(self, **kw):
        bad = [str(f) for f in self.findings(**kw)]
        self.assertEqual(bad, [], f"expected no findings, got: {bad}")


class CleanEditionTest(GateCase):
    def test_a_publishable_edition_passes(self):
        self.assertClean()

    def test_sigma_references_are_not_mistaken_for_uncleaned_prose(self):
        """A SigmaHQ rule's yaml and url carry real links by design."""
        s = story(1, detection={
            "type": "sigma", "notes": [], "hunting_steps": [], "hunting_queries": [],
            "sigma": {"origin": "sigmahq", "title": "Exploitation Indicators",
                      "url": "https://github.com/SigmaHQ/sigma/blob/master/rules/x.yml",
                      "yaml": "title: x\nreferences:\n    - https://example.vendor/advisory\n",
                      "check": {}, "conversions": []}})
        self.assertClean(ed=edition(stories=[s, story(2), story(3), story(4)]))


class ShapeTest(GateCase):
    def test_date_mismatch(self):
        self.assertGate(V.FAIL, "shape", ed=edition(date="2026-01-01"))

    def test_schema_bump(self):
        self.assertGate(V.FAIL, "shape", ed=edition(schema=2))

    def test_missing_key(self):
        ed = edition()
        del ed["window"]
        self.assertGate(V.FAIL, "shape", ed=ed)

    def test_dry_run_is_not_publishable(self):
        self.assertGate(V.FAIL, "shape", run=run_record(dry_run=True))

    def test_unreadable_edition_raises(self):
        (self.eds / f"{DATE}.json").write_text("{not json", encoding="utf-8")
        with self.assertRaises(V.EditionMissing):
            V.verify(DATE, self.settings)

    def test_absent_edition_raises(self):
        (self.eds / f"{DATE}.json").unlink()
        with self.assertRaises(V.EditionMissing):
            V.verify(DATE, self.settings)


class SubstanceTest(GateCase):
    def test_thin_edition(self):
        self.assertGate(V.FAIL, "substance", ed=edition(stories=[story(1)]))

    def test_lead_story_without_a_writeup_blocks(self):
        stories = [story(1, writeup_status="error"), story(2), story(3), story(4)]
        self.assertGate(V.FAIL, "substance", ed=edition(stories=stories))

    def test_one_miss_down_the_page_only_warns(self):
        stories = [story(1), story(2), story(3), story(4, writeup_status="error")]
        hits = self.assertGate(V.WARN, "substance", ed=edition(stories=stories))
        self.assertNotIn(V.FAIL, [f.level for f in self.findings(ed=edition(stories=stories))])
        self.assertIn("1 write-up", hits[0].message)

    def test_too_many_misses_block(self):
        stories = [story(1), story(2), story(3)] + [
            story(r, writeup_status="error") for r in (4, 5, 6)]
        self.assertGate(V.FAIL, "substance", ed=edition(stories=stories))

    def test_unvalidated_kql_warns(self):
        ed = edition()
        ed["stats"]["kql_parser"] = "missing"
        self.assertGate(V.WARN, "substance", ed=ed)


class HonestyTest(GateCase):
    def test_a_refusal_blocks(self):
        run = run_record()
        run["cost"]["calls"][0]["refusal_category"] = "harmful_content"
        self.assertGate(V.FAIL, "honesty", run=run)

    def test_budget_truncation_blocks(self):
        self.assertGate(V.FAIL, "honesty", run=run_record(budget_hit=True))

    def test_overspend_blocks(self):
        run = run_record()
        run["cost"]["total_cost_usd"] = 3.5
        self.assertGate(V.FAIL, "honesty", run=run)

    def test_truncated_call_warns(self):
        run = run_record()
        run["cost"]["calls"][0]["stop_reason"] = "max_tokens"
        self.assertGate(V.WARN, "honesty", run=run)

    def test_uncredited_model_warns(self):
        run = run_record()
        run["cost"]["calls"][0]["served_by"] = "claude-sonnet-5-5"
        self.assertGate(V.WARN, "honesty", run=run)


class SourceTest(GateCase):
    def test_required_source_down_blocks(self):
        ed = edition()
        ed["sources_status"]["NVD"] = "error FetchError: 503"
        self.assertGate(V.FAIL, "sources", ed=ed)

    def test_required_source_absent_blocks(self):
        ed = edition()
        del ed["sources_status"]["CISA KEV"]
        self.assertGate(V.FAIL, "sources", ed=ed)

    def test_widespread_errors_block(self):
        ed = edition(sources_status={"CISA KEV": "ok 1", "NVD": "ok 2",
                                     "BleepingComputer": "error 403",
                                     "SecurityWeek": "error 500"})
        self.assertGate(V.FAIL, "sources", ed=ed)

    def test_one_dead_feed_only_warns(self):
        ed = edition()
        ed["sources_status"]["SecurityWeek"] = "error 403 Forbidden"
        self.assertGate(V.WARN, "sources", ed=ed)


class CoverageTest(GateCase):
    def test_gap_since_the_last_edition_warns(self):
        (self.eds / f"{PREV}.json").write_text(
            json.dumps({"window": {"since": f"{PREV}T00:00:00+00:00",
                                   "until": f"{PREV}T06:00:00+00:00"}}), encoding="utf-8")
        hits = self.assertGate(V.WARN, "coverage")
        self.assertIn("no edition", hits[0].message)

    def test_no_gap_is_clean(self):
        (self.eds / f"{PREV}.json").write_text(
            json.dumps({"window": {"since": f"{PREV}T00:00:00+00:00",
                                   "until": f"{PREV}T18:47:00+00:00"}}), encoding="utf-8")
        self.assertClean()

    def test_backwards_window_blocks(self):
        ed = edition(window={"since": f"{DATE}T18:47:00+00:00",
                             "until": f"{PREV}T18:47:00+00:00"})
        self.assertGate(V.FAIL, "coverage", ed=ed)


class ProseTest(GateCase):
    def test_uncleaned_url_in_a_writeup_blocks(self):
        s = story(1)
        s["writeup"]["what_happened"] = "Log in at https://evil.example/phish to check."
        self.assertGate(V.FAIL, "prose", ed=edition(stories=[s, story(2), story(3), story(4)]))

    def test_uncleaned_url_in_good_news_blocks(self):
        ed = edition(good_news=[{"headline": "See www.evil.example/x", "summary": "x",
                                 "sources": []}])
        self.assertGate(V.FAIL, "prose", ed=ed)

    def test_uncleaned_url_in_the_explainer_blocks(self):
        ed = edition()
        ed["explainer"]["parts"][0]["paragraphs"] = ["Read https://evil.example/doc now."]
        self.assertGate(V.FAIL, "prose", ed=ed)


class PageTest(GateCase):
    def test_missing_page_blocks(self):
        self.write()
        (self.site / "editions" / DATE / "index.html").unlink()
        hits = [f for f in V.verify(DATE, self.settings)
                if f.level == V.FAIL and f.gate == "page"]
        self.assertTrue(hits)

    def test_stub_page_blocks(self):
        self.assertGate(V.FAIL, "page", html=f"<html><body>{DATE}</body></html>")

    def test_page_without_its_date_blocks(self):
        self.assertGate(V.FAIL, "page", html=page(date="1999-01-01").replace(DATE, "x"))

    def test_script_tag_blocks(self):
        self.assertGate(V.FAIL, "page", html=page(body="<script>alert(1)</script>"))

    def test_iframe_blocks(self):
        self.assertGate(V.FAIL, "page", html=page(body='<iframe src="https://x/"></iframe>'))

    def test_inline_handler_blocks(self):
        self.assertGate(V.FAIL, "page", html=page(body='<img src="x" onerror="alert(1)">'))

    def test_javascript_uri_blocks(self):
        self.assertGate(V.FAIL, "page", html=page(links=("javascript:alert(1)",)))

    def test_offsite_link_blocks(self):
        self.assertGate(V.FAIL, "page", html=page(links=("https://evil.example/x",)))

    def test_plain_http_link_blocks(self):
        self.assertGate(V.FAIL, "page",
                        html=page(links=("http://www.bleepingcomputer.com/x",)))

    def test_protocol_relative_link_blocks(self):
        self.assertGate(V.FAIL, "page", html=page(links=("//evil.example/x",)))

    def test_escaped_prose_is_not_a_handler(self):
        """The renderer escapes story text, so hostile prose is inert."""
        self.assertClean(html=page(body="<p>&lt;script&gt;alert(1)&lt;/script&gt; "
                                        "onerror=&quot;alert(1)&quot;</p>"))

    def test_in_page_and_relative_links_are_fine(self):
        self.assertClean(html=page(links=("#story-1", "/archive/", "../assets/x.css",
                                          "https://nvd.nist.gov/vuln/detail/CVE-2026-1")))


class FeedTest(GateCase):
    def test_feeds_without_the_edition_block(self):
        self.assertGate(V.FAIL, "feeds", feeds=False)

    def test_broken_feed_xml_blocks(self):
        self.write()
        (self.site / "feed.xml").write_text("<rss><channel>", encoding="utf-8")
        hits = [f for f in V.verify(DATE, self.settings)
                if f.level == V.FAIL and f.gate == "feeds"]
        self.assertTrue(hits)


class ReportTest(GateCase):
    def test_failures_lead_the_report(self):
        text = V.report(DATE, [V.Finding(V.FAIL, "page", "a script tag"),
                               V.Finding(V.WARN, "sources", "one feed down")])
        self.assertIn("Held for review", text)
        self.assertIn("a script tag", text)
        self.assertIn("one feed down", text)

    def test_clean_report_says_so(self):
        self.assertIn("All gates passed", V.report(DATE, []))


if __name__ == "__main__":
    unittest.main()
