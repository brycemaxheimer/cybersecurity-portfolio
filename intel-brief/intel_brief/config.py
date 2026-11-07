"""Paths and settings loaded from config/*.toml."""

from __future__ import annotations

import tomllib
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
DATA_DIR = ROOT / "data"
EDITIONS_DIR = DATA_DIR / "editions"
RUNS_DIR = DATA_DIR / "runs"
SITE_DIR = ROOT / "site"
CACHE_DIR = ROOT / ".cache"
SIGMA_REPO_DIR = CACHE_DIR / "sigma"
KUSTO_DLL = CACHE_DIR / "kusto" / "Kusto.Language.dll"
KQL_SCHEMA = CONFIG_DIR / "kql_schema.json"


def load_settings() -> dict:
    with open(CONFIG_DIR / "settings.toml", "rb") as f:
        return tomllib.load(f)


def load_sources() -> dict:
    with open(CONFIG_DIR / "sources.toml", "rb") as f:
        return tomllib.load(f)


def day_window(run_date: date, settings: dict) -> tuple[datetime, datetime]:
    """What an edition dated run_date covers: the whole calendar day before it,
    in the site's timezone, as a half-open UTC span.

    Derived from the date and never from the clock, so when the job runs does
    not change what the edition contains, and rebuilding a date later gives the
    same window. The collector gathers by this and verify checks against it, so
    the two cannot drift apart.
    """
    tz = ZoneInfo(settings["site"]["timezone"])
    covers = run_date - timedelta(days=1)
    return (
        datetime.combine(covers, time.min, tz).astimezone(timezone.utc),
        datetime.combine(run_date, time.min, tz).astimezone(timezone.utc),
    )
