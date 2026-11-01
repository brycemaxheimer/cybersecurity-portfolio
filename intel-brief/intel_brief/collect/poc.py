"""Public proof-of-concept repos, via nomi-sec/PoC-in-GitHub.

Links only. Nothing is cloned or hosted, and the page warns that PoC repos
are often fake or backdoored.
"""

from __future__ import annotations

import json
import logging
import re

from ..http import FetchError, get_bytes

log = logging.getLogger(__name__)

INDEX = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"
_REPO_URL = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")


def lookup(cves: list[str], per_cve: int = 3) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for cve in sorted(set(cves)):
        year = cve.split("-")[1]
        try:
            repos = json.loads(get_bytes(INDEX.format(year=year, cve=cve), timeout=20, retries=1))
        except FetchError:
            continue  # 404: no known PoC
        except Exception as e:  # bad JSON or network error: skip this CVE
            log.debug("PoC lookup %s: %s", cve, e)
            continue
        good = []
        for r in repos if isinstance(repos, list) else []:
            url = str(r.get("html_url", ""))
            if _REPO_URL.match(url):
                good.append(
                    {
                        "url": url,
                        "name": str(r.get("full_name", ""))[:120],
                        "stars": int(r.get("stargazers_count") or 0),
                        "created": str(r.get("created_at", ""))[:10],
                    }
                )
        if good:
            out[cve] = sorted(good, key=lambda r: -r["stars"])[:per_cve]
    return out
