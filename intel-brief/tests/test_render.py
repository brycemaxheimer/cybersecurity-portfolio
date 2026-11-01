"""The page must stay inert even if model text or edition JSON is hostile."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from intel_brief import render

XSS = '<script>alert(1)</script><img src=x onerror=alert(1)>'


def edition():
    return {
        "schema": 1, "date": "2026-10-31", "generated_at": "2026-10-31T11:30:00Z",
        "models": {"triage": "claude-haiku-5-5", "writeup": "claude-opus-5-5", "triage_method": "model"},
        "window": {"since": "2026-10-30T09:00:00+00:00", "until": "2026-10-31T11:00:00+00:00"},
        "stories": [{
            "id": "story-1", "rank": 1, "score": 80,
            "factors": {"in_kev": True, "epss_max": 0.5},
            "title": "Headline " + XSS,
            "labels": {"category": "vulnerability", "exploitation": "confirmed_in_wild", "prevalence": "ubiquitous", "platform": "windows", "vendor": XSS, "product": ""},
            "cves": [{"id": "CVE-2026-0001", "cvss": 9.8, "severity": "CRITICAL", "products": [], "epss": 0.5, "percentile": 0.99, "in_kev": True, "kev_due": "2026-11-21",
                      "poc": [{"url": "javascript:alert(1)", "name": "x", "stars": 1, "created": "2026-10-30"}], "sigmahq_rules": 0}],
            "writeup_status": "ok",
            "writeup": {"what_happened": XSS, "why_it_matters": "ok", "affected_versions": [XSS], "fixed_versions": [], "recommended_actions": [XSS], "confidence": "high"},
            "sources": [
                {"title": XSS, "url": "https://www.bleepingcomputer.com/news/a/", "source": "BleepingComputer", "kind": "news", "published": "2026-10-31T00:00:00Z"},
                {"title": "evil", "url": "https://evil.example/phish", "source": "x", "kind": "news", "published": ""},
            ],
            "detection": {"type": "behavioral", "sigma": None, "hunting_steps": [XSS],
                          "hunting_queries": [{"title": XSS, "kql": "DeviceProcessEvents | where FileName == '</code><script>alert(1)</script>'"}], "notes": []},
        }],
        "more_stories": [], "kev_new": [], "early_signals": [],
        "explainer": {"concept": "Concept " + XSS, "dek": XSS, "why_today": XSS, "related_story_ids": ["story-1"],
                      "parts": [{"heading": XSS, "paragraphs": [XSS]}], "takeaways": [XSS], "unsupported_cves": ["CVE-2021-0001"],
                      "model": "claude-opus-4-8"},
        "good_news": [{"headline": XSS, "summary": XSS, "kind": "takedown", "unsupported_cves": [],
                       "sources": [{"title": "t", "url": "https://evil.example/good", "source": XSS, "published": ""}]}],
        "sources_status": {"NVD": "ok 3"}, "stats": {"kql_parser": "not installed"},
    }


class RenderTest(unittest.TestCase):
    def test_escapes_and_drops_bad_links(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            eds = d / "editions"
            eds.mkdir()
            (eds / "2026-10-31.json").write_text(json.dumps(edition()), encoding="utf-8")
            with mock.patch.object(render, "EDITIONS_DIR", eds):
                render.render_site(d / "site")
            html = (d / "site" / "index.html").read_text(encoding="utf-8")
            self.assertNotIn("<script", html)
            self.assertNotIn("<img", html)
            self.assertNotIn("javascript:", html)
            self.assertNotIn("evil.example", html)
            self.assertIn("&lt;script&gt;", html)
            self.assertIn('href="https://www.bleepingcomputer.com/news/a/"', html)
            self.assertIn("AI-generated · untested", html)
            self.assertIn("AI-generated explainer by Claude Opus 4.8", html)
            self.assertIn("AI-generated summary by Claude Opus 5.5", html)
            self.assertEqual(render.model_name("claude-sonnet-4-6"), "Claude Sonnet 4.6")
            self.assertIn("mentions CVE-2021-0001, which no source in this edition names", html)
            self.assertIn('id="good-news"', html)
            feed = (d / "site" / "feed.xml").read_text(encoding="utf-8")
            self.assertNotIn("<script", feed)
            self.assertTrue((d / "site" / "_headers").read_text().count("Content-Security-Policy"))


class NoBreakTest(unittest.TestCase):
    def test_escapes_then_keeps_cve_ids_whole(self):
        out = str(render.nobreak_cves('<b>x</b> CVE-2026-111357 and cve-2026-1234'))
        self.assertEqual(out, '&lt;b&gt;x&lt;/b&gt; <span class="nowrap">CVE-2026-111357</span> and <span class="nowrap">cve-2026-1234</span>')


if __name__ == "__main__":
    unittest.main()
