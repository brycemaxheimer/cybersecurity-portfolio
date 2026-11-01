"""NVD CVE API 2.0: recently published high and critical CVEs."""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime

from ..http import get_json
from ..models import Item

log = logging.getLogger(__name__)
API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _pause() -> None:
    # Public rate limit is 5 requests / 30 s, or 50 with an API key.
    time.sleep(0.7 if os.environ.get("NVD_API_KEY") else 6.5)


def _headers() -> dict:
    key = os.environ.get("NVD_API_KEY")
    return {"apiKey": key} if key else {}


def _nvd_time(dt: datetime) -> str:
    # requests encodes the "+" as %2B, which is what NVD expects.
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000") + "+00:00"


def _cvss(metrics: dict) -> tuple[float | None, str, str]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key, []):
            d = m.get("cvssData", {})
            if "baseScore" in d:
                return d["baseScore"], d.get("baseSeverity", ""), d.get("version", "")
    return None, "", ""


def _products(cve: dict) -> list[str]:
    out: dict[str, None] = {}
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 5 and m.get("vulnerable"):
                    out.setdefault(f"{parts[3]} {parts[4]}".replace("_", " "), None)
    return list(out)[:8]


def parse(vuln: dict) -> dict:
    cve = vuln.get("cve", {})
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    score, severity, version = _cvss(cve.get("metrics", {}))
    return {
        "id": cve.get("id", "").upper(),
        "published": cve.get("published", ""),
        "description": desc,
        "cvss": score,
        "severity": severity,
        "cvss_version": version,
        "products": _products(cve),
        "cwes": [
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")
        ][:4],
        "kev": bool(cve.get("cisaExploitAdd")),
    }


def collect(since: datetime, until: datetime) -> list[Item]:
    seen: dict[str, dict] = {}
    for sev in ("CRITICAL", "HIGH"):
        params = {
            "pubStartDate": _nvd_time(since),
            "pubEndDate": _nvd_time(until),
            "cvssV3Severity": sev,
            "resultsPerPage": 2000,
        }
        data = get_json(API, params=params, headers=_headers(), timeout=90)
        for v in data.get("vulnerabilities", []):
            p = parse(v)
            if p["id"]:
                seen.setdefault(p["id"], p)
        _pause()
    items = []
    for i, p in enumerate(seen.values(), 1):
        items.append(
            Item(
                id=f"nvd-{i}",
                kind="nvd",
                source="NVD",
                title=f"{p['id']} ({p['severity']} {p['cvss']})",
                url=f"https://nvd.nist.gov/vuln/detail/{p['id']}",
                published=p["published"] + ("Z" if not p["published"].endswith("Z") else ""),
                text=f"Products: {', '.join(p['products']) or 'unknown'}. {p['description']}",
                cves=[p["id"]],
                extra=p,
            )
        )
    return items


def lookup(cve_ids: list[str], limit: int = 12) -> dict[str, dict]:
    """Fetch NVD records for specific CVEs (early signals, story context)."""
    out = {}
    for cve in cve_ids[:limit]:
        try:
            data = get_json(API, params={"cveId": cve}, headers=_headers(), timeout=60)
            vulns = data.get("vulnerabilities", [])
            if vulns:
                out[cve] = parse(vulns[0])
        except Exception as e:
            log.warning("NVD lookup %s failed: %s", cve, e)
        _pause()
    return out
