import unittest

from intel_brief.models import find_cves
from intel_brief.safety import clean_model_text, html_to_text, safe_url


class SafeUrlTest(unittest.TestCase):
    def test_allows_https_on_allowed_host(self):
        self.assertEqual(
            safe_url("https://www.bleepingcomputer.com/news/x/", {"www.bleepingcomputer.com"}),
            "https://www.bleepingcomputer.com/news/x/",
        )

    def test_builtin_hosts(self):
        self.assertTrue(safe_url("https://nvd.nist.gov/vuln/detail/CVE-2026-1234"))

    def test_rejects_other_schemes_and_hosts(self):
        for bad in [
            "javascript:alert(1)",
            "http://www.bleepingcomputer.com/x",
            "data:text/html,<script>alert(1)</script>",
            "https://evil.example/x",
            "https://www.bleepingcomputer.com.evil.example/x",
            "https://user:pw@www.bleepingcomputer.com/x",
            "https://www.bleepingcomputer.com:8443/x",
            'https://www.bleepingcomputer.com/x"onmouseover="alert(1)',
            "//www.bleepingcomputer.com/x",
        ]:
            self.assertIsNone(safe_url(bad, {"www.bleepingcomputer.com"}), bad)

    def test_drops_fragment(self):
        self.assertEqual(safe_url("https://github.com/a/b#x"), "https://github.com/a/b")


class CleanTextTest(unittest.TestCase):
    def test_removes_urls(self):
        out = clean_model_text("Patch now: https://evil.example/login and www.evil.example/x")
        self.assertNotIn("evil", out)
        self.assertIn("[link removed]", out)

    def test_strips_control_and_bidi(self):
        self.assertEqual(clean_model_text("a‮b\x00c"), "abc")

    def test_caps_length(self):
        self.assertLessEqual(len(clean_model_text("x" * 5000, 100)), 100)


class HtmlToTextTest(unittest.TestCase):
    def test_drops_scripts_and_tags(self):
        out = html_to_text("<p>Hello <b>world</b></p><script>alert(1)</script>")
        self.assertEqual(out, "Hello world")


class CveTest(unittest.TestCase):
    def test_find(self):
        self.assertEqual(
            find_cves("cve-2026-1234, CVE-2026-1234 and CVE-2025-123456"),
            ["CVE-2026-1234", "CVE-2025-123456"],
        )


if __name__ == "__main__":
    unittest.main()
