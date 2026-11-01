"""FIRST EPSS scores (probability of exploitation in the next 30 days)."""

from __future__ import annotations

from ..http import get_json

API = "https://api.first.org/data/v1/epss"


def scores(cves: list[str]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    unique = sorted(set(cves))
    for i in range(0, len(unique), 80):
        batch = unique[i : i + 80]
        data = get_json(API, params={"cve": ",".join(batch)}, timeout=30)
        for row in data.get("data", []):
            try:
                out[row["cve"].upper()] = {
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                }
            except (KeyError, ValueError):
                continue
    return out
