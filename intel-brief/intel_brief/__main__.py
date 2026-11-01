"""CLI.

  python -m intel_brief run               collect, triage, write, detect, render
  python -m intel_brief run --dry-run     everything except model calls (free)
  python -m intel_brief render            re-render site/ from data/editions/
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .config import load_settings, load_sources


def main(argv: list[str] | None = None) -> int:
    settings = load_settings()
    p = argparse.ArgumentParser(prog="intel_brief")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="build today's edition")
    r.add_argument("--date", help="edition date, YYYY-MM-DD (default: today in the site timezone)")
    r.add_argument("--max-cost", type=float, default=settings["budget"]["max_cost_usd"], help="hard cap in USD for this run")
    r.add_argument("--writeup-model", default=settings["models"]["writeup"], choices=["claude-opus-5-5", "claude-sonnet-5-5"])
    r.add_argument("--top", type=int, default=settings["edition"]["top_stories"], help="number of stories to write up")
    r.add_argument("--dry-run", action="store_true", help="no model calls; fallback triage, no write-ups")
    r.add_argument("--from-cache", action="store_true", help="reuse .cache/runs/<date>/collection.json if present")
    r.add_argument("--lookback-hours", type=int, help="collection window (default from settings.toml; max 72)")
    r.add_argument("--no-render", action="store_true")

    sub.add_parser("render", help="render site/ from data/editions/")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    for noisy in ("httpx", "httpx2", "httpcore", "httpcore2", "urllib3", "anthropic"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    from .render import render_site

    if args.cmd == "render":
        n = len(render_site())
        print(f"rendered {n} files")
        return 0

    if args.date:
        run_date = date.fromisoformat(args.date)
    else:
        try:
            run_date = datetime.now(ZoneInfo(settings["site"]["timezone"])).date()
        except ZoneInfoNotFoundError:  # Windows without the tzdata package
            logging.warning("time zone data missing; using the UTC date (pass --date to override)")
            run_date = datetime.now(timezone.utc).date()

    from .pipeline import run

    if args.lookback_hours:
        settings["collect"]["lookback_hours"] = args.lookback_hours
    log = run(
        run_date,
        settings,
        load_sources(),
        max_cost=args.max_cost,
        writeup_model=args.writeup_model,
        top_n=args.top,
        dry_run=args.dry_run,
        from_cache=args.from_cache,
    )
    if not args.no_render:
        render_site()
    print(json.dumps({k: log["cost"][k] for k in ("total_cost_usd", "max_cost_usd", "by_stage", "tokens")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
