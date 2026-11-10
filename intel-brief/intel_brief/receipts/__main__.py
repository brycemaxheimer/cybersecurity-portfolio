"""Issue receipts for published editions.

  python -m intel_brief.receipts                 # every edition, totals only
  python -m intel_brief.receipts --date 2026-11-10 --write
  python -m intel_brief.receipts --json

Needs a Kusto emulator (KUSTO_EMULATOR_URL, default http://localhost:8080).
--write stores the receipts in data/editions/<date>.json; re-render to show them.
"""

from __future__ import annotations

import argparse
import json
import sys

from ..config import EDITIONS_DIR
from . import run, summarize
from .engine import Engine


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m intel_brief.receipts")
    ap.add_argument("--date", action="append", help="edition date; repeatable; default every edition")
    ap.add_argument("--engine", help="Kusto engine URL")
    ap.add_argument("--wait", type=float, default=0, help="seconds to wait for the engine")
    ap.add_argument("--write", action="store_true", help="store receipts in the edition files")
    ap.add_argument("--json", action="store_true", help="print every receipt")
    args = ap.parse_args(argv)

    paths = [EDITIONS_DIR / f"{d}.json" for d in args.date] if args.date else sorted(EDITIONS_DIR.glob("*.json"))
    editions = {p: json.loads(p.read_text(encoding="utf-8")) for p in paths}
    detections = {f"{p.stem}|{s['id']}": s["detection"] for p, ed in editions.items()
                  for s in ed.get("stories", []) if s.get("detection")}
    status = run(detections, Engine(args.engine), wait=args.wait)
    if status["status"] != "ran":
        print(f"receipts {status['status']}: {status['reason']}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(detections, indent=1, default=str))
    else:
        print(f"{status['engine']}; baseline {status['baseline_events']} synthetic benign events; {len(editions)} editions")
        for k, v in summarize(detections).items():
            print(f"  {k:18} {v}")
    if args.write:
        for p, ed in editions.items():
            ed.setdefault("stats", {})["receipts"] = status
            p.write_text(json.dumps(ed, indent=1, ensure_ascii=False), encoding="utf-8")  # as pipeline.py writes it
    return 0


if __name__ == "__main__":
    sys.exit(main())
