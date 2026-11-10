"""Cost per accepted artifact for the intel brief.

Each daily run opens a PR titled "Intel brief: edition YYYY-MM-DD", and merging it publishes the edition
(automatic on passing gates since PR #15). A closed, unmerged PR is a rejected edition. Its run log never
reaches main, so this report reads every edition PR's run log and edition at the PR's head commit. The
spend on rejected editions then counts against the published ones.

Usage (from intel-brief/):
  python -m intel_brief.cost_report                  # every edition PR, read through gh
  python -m intel_brief.cost_report --json
  python -m intel_brief.cost_report --local data     # offline: each edition in data/ counts as published
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = "brycemaxheimer/cybersecurity-portfolio"
TITLE = re.compile(r"Intel brief: edition (\d{4}-\d{2}-\d{2})$")
STATE = {"MERGED": "published", "CLOSED": "rejected", "OPEN": "pending"}


def edition_metrics(edition: dict | None) -> dict:
    """What one edition produced: written stories, detections by type, hunting queries that passed the parser."""
    stories = (edition or {}).get("stories", [])
    queries = [q for s in stories for q in (s.get("detection") or {}).get("hunting_queries") or []]
    types: dict[str, int] = {}
    for s in stories:
        t = (s.get("detection") or {}).get("type", "none")
        types[t] = types.get(t, 0) + 1
    return {
        "stories": len(stories),
        "stories_ok": sum(s.get("writeup_status") == "ok" for s in stories),
        "detections": types,
        "sigma_rules": sum(bool((s.get("detection") or {}).get("sigma")) for s in stories),
        "queries": len(queries),
        "queries_pass": sum((q.get("validation") or {}).get("status") == "pass" for q in queries),
    }


def summarize(records: list[dict]) -> dict:
    """records: [{"date", "state" (published|rejected|pending), "cost" (USD or None), "metrics"}]."""
    known = [r for r in records if r["cost"] is not None]
    spend = round(sum(r["cost"] for r in known), 4)
    by_state = {s: [r for r in records if r["state"] == s] for s in ("published", "rejected", "pending")}
    published = by_state["published"]
    stories = sum(r["metrics"]["stories_ok"] for r in published)
    queries = sum(r["metrics"]["queries_pass"] for r in published)
    decided = len(published) + len(by_state["rejected"])
    per = lambda n: round(spend / n, 4) if n else None  # noqa: E731
    return {
        "editions": {s: len(v) for s, v in by_state.items()},
        "spend_usd": spend,
        "spend_by_state_usd": {s: round(sum(r["cost"] or 0 for r in v), 4) for s, v in by_state.items()},
        "cost_unknown": [r["date"] for r in records if r["cost"] is None],
        "acceptance_rate": round(len(published) / decided, 3) if decided else None,
        "published_stories": stories,
        "validated_queries": queries,
        "usd_per_published_edition": per(len(published)),
        "usd_per_published_story": per(stories),
        "usd_per_validated_query": per(queries),
    }


def _gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True, encoding="utf-8").stdout


def _raw(repo: str, path: str, ref: str) -> dict | None:
    try:
        return json.loads(_gh("api", "-H", "Accept: application/vnd.github.raw+json", f"repos/{repo}/contents/{path}?ref={ref}"))
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return None


def from_github(repo: str = REPO) -> list[dict]:
    prs = json.loads(_gh("pr", "list", "--repo", repo, "--state", "all", "--limit", "500",
                         "--search", "Intel brief: edition in:title", "--json", "number,state,title,headRefOid"))
    records = []
    for pr in prs:
        m = TITLE.search(pr["title"])
        if not m:
            continue
        date, ref = m.group(1), pr["headRefOid"]
        run = _raw(repo, f"intel-brief/data/runs/{date}.json", ref)
        edition = _raw(repo, f"intel-brief/data/editions/{date}.json", ref)
        records.append({"date": date, "pr": pr["number"], "state": STATE.get(pr["state"], "pending"),
                        "cost": (run or {}).get("cost", {}).get("total_cost_usd"), "metrics": edition_metrics(edition)})
    return sorted(records, key=lambda r: r["date"])


def from_local(data: Path) -> list[dict]:
    records = []
    for ed in sorted((data / "editions").glob("*.json")):
        run_path = data / "runs" / ed.name
        run = json.loads(run_path.read_text(encoding="utf-8")) if run_path.exists() else {}
        records.append({"date": ed.stem, "pr": None, "state": "published",
                        "cost": run.get("cost", {}).get("total_cost_usd"),
                        "metrics": edition_metrics(json.loads(ed.read_text(encoding="utf-8")))})
    return records


def markdown(records: list[dict], s: dict) -> str:
    usd = lambda v: "n/a" if v is None else f"${v:.2f}"  # noqa: E731
    lines = ["| Date | PR | State | Cost | Stories written | Queries passed |", "|---|---|---|---|---|---|"]
    for r in records:
        m = r["metrics"]
        lines.append(f"| {r['date']} | {('#' + str(r['pr'])) if r['pr'] else '-'} | {r['state']} | {usd(r['cost'])} "
                     f"| {m['stories_ok']}/{m['stories']} | {m['queries_pass']}/{m['queries']} |")
    e = s["editions"]
    rate = "n/a" if s["acceptance_rate"] is None else f"{s['acceptance_rate']:.0%}"
    lines += ["", f"Editions: {e['published']} published, {e['rejected']} rejected, {e['pending']} pending "
                  f"(acceptance {rate}). Spend {usd(s['spend_usd'])}, of which {usd(s['spend_by_state_usd']['rejected'])} "
                  f"bought rejected editions.",
              f"Per published edition {usd(s['usd_per_published_edition'])}; per published story "
              f"{usd(s['usd_per_published_story'])}; per validated query {usd(s['usd_per_validated_query'])}."]
    if s["cost_unknown"]:
        lines.append(f"No run log found for: {', '.join(s['cost_unknown'])} (left out of spend).")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=REPO)
    ap.add_argument("--local", type=Path, metavar="DATA_DIR", help="read data/ offline; every edition counts as published")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    records = from_local(args.local) if args.local else from_github(args.repo)
    summary = summarize(records)
    print(json.dumps({"editions": records, "summary": summary}, indent=1) if args.json else markdown(records, summary))
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
