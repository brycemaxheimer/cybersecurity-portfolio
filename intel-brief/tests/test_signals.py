import unittest

from intel_brief.collect import Collection
from intel_brief.models import Item
from intel_brief.signals import find


def post(n, author, cves, source="Bluesky"):
    return Item(id=f"p{n}", kind="social", source=source, title=f"@{author}", url=f"https://bsky.app/profile/{author}/post/{n}",
                published="2026-10-31T01:00:00Z", text="", cves=cves, author=f"bluesky:{author}")


class SignalsTest(unittest.TestCase):
    def test_threshold_and_exclusions(self):
        items = [post(1, "a", ["CVE-2026-0001"]), post(2, "b", ["CVE-2026-0001"]), post(3, "c", ["CVE-2026-0001"], "Mastodon"),
                 post(4, "a", ["CVE-2026-0002"]), post(5, "b", ["CVE-2026-0002"]), post(6, "c", ["CVE-2026-0002"]),
                 post(7, "a", ["CVE-2026-0003"]), post(8, "b", ["CVE-2026-0003"]), post(9, "c", ["CVE-2026-0003"]),
                 Item(id="n1", kind="news", source="X", title="t", url="https://x", published="", cves=["CVE-2026-0003"])]
        col = Collection(items=items, kev_catalog_cves={"CVE-2026-0002"})
        out = find(col, min_authors=3, max_signals=10)
        self.assertEqual([s["cve"] for s in out], ["CVE-2026-0001"])  # 0002 in KEV, 0003 in news
        self.assertEqual(out[0]["authors"], 3)

    def test_feed_bots_and_digests_ignored(self):
        bot_cves = [f"CVE-2026-{1000 + i}" for i in range(20)]
        items = [post(100 + i, "cvebot", [c]) for i, c in enumerate(bot_cves)]
        items += [post(1, "a", ["CVE-2026-1000"]), post(2, "b", ["CVE-2026-1000"])]
        items += [post(3, "c", ["CVE-2026-1000", "CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003", "CVE-2026-1004"])]
        out = find(Collection(items=items), min_authors=3, max_signals=10)
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
