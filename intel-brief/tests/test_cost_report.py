import json
import tempfile
import unittest
from pathlib import Path

from intel_brief.cost_report import edition_metrics, from_local, summarize


def story(status="ok", dtype="hunting_only", query_status=("pass",), sigma=None):
    return {"writeup_status": status,
            "detection": {"type": dtype, "sigma": sigma,
                          "hunting_queries": [{"title": "q", "kql": "T", "validation": {"status": s}} for s in query_status]}}


def record(date, state, cost, stories):
    return {"date": date, "pr": 1, "state": state, "cost": cost, "metrics": edition_metrics({"stories": stories})}


class CostReport(unittest.TestCase):
    def test_edition_metrics_counts_written_stories_and_passing_queries(self):
        m = edition_metrics({"stories": [story(), story(status="refused_or_failed", query_status=("fail",)),
                                         story(dtype="behavioral", query_status=("pass", "pass"), sigma={"title": "r"})]})
        self.assertEqual((m["stories"], m["stories_ok"], m["queries"], m["queries_pass"], m["sigma_rules"]), (3, 2, 4, 3, 1))
        self.assertEqual(m["detections"], {"hunting_only": 2, "behavioral": 1})

    def test_rejected_spend_counts_against_published_artifacts(self):
        recs = [record("2026-11-01", "published", 0.60, [story(), story()]),
                record("2026-11-02", "rejected", 0.40, [story()]),
                record("2026-11-03", "pending", 0.50, [story()])]
        s = summarize(recs)
        self.assertEqual(s["editions"], {"published": 1, "rejected": 1, "pending": 1})
        self.assertAlmostEqual(s["spend_usd"], 1.50)
        self.assertAlmostEqual(s["spend_by_state_usd"]["rejected"], 0.40)
        self.assertEqual(s["acceptance_rate"], 0.5)  # pending is not decided yet
        self.assertAlmostEqual(s["usd_per_published_edition"], 1.50)
        self.assertAlmostEqual(s["usd_per_published_story"], 0.75)
        self.assertAlmostEqual(s["usd_per_validated_query"], 0.75)

    def test_missing_run_log_is_reported_not_guessed(self):
        s = summarize([record("2026-11-01", "published", None, [story()]), record("2026-11-02", "published", 0.5, [story()])])
        self.assertEqual(s["cost_unknown"], ["2026-11-01"])
        self.assertAlmostEqual(s["spend_usd"], 0.5)

    def test_nothing_published_gives_no_per_artifact_cost(self):
        s = summarize([record("2026-11-02", "rejected", 0.4, [story()])])
        self.assertIsNone(s["usd_per_published_edition"])
        self.assertEqual(s["acceptance_rate"], 0.0)

    def test_local_mode_reads_data_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            (data / "editions").mkdir()
            (data / "runs").mkdir()
            (data / "editions" / "2026-11-01.json").write_text(json.dumps({"stories": [story()]}))
            (data / "runs" / "2026-11-01.json").write_text(json.dumps({"cost": {"total_cost_usd": 0.55}}))
            recs = from_local(data)
        self.assertEqual([(r["date"], r["state"], r["cost"]) for r in recs], [("2026-11-01", "published", 0.55)])


if __name__ == "__main__":
    unittest.main()
