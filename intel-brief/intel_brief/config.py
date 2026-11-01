"""Paths and settings loaded from config/*.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path

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
