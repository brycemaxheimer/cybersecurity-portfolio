"""CISA Known Exploited Vulnerabilities catalog."""

from __future__ import annotations

from datetime import date

from ..http import get_json
from ..models import Item

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # CISA's own mirror, used when the main site blocks the runner.
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]


def fetch_catalog() -> dict:
    last = None
    for url in KEV_URLS:
        try:
            return get_json(url, timeout=60)
        except Exception as e:  # try the mirror
            last = e
    raise RuntimeError(f"KEV unavailable: {last}")


def collect(covers: date, catalog: dict, already_published: set[str]) -> list[Item]:
    """Entries CISA added on the day this edition covers, that no earlier
    edition listed.

    Exactly that day, not a span: the edition reports one day and dateAdded is
    a date, so an entry belongs to the edition for the day after it was added.
    An entry CISA backdates after that day's edition has run is therefore never
    shown; widen this if that turns out to happen in practice.
    """
    items = []
    for v in catalog.get("vulnerabilities", []):
        cve = str(v.get("cveID", "")).upper()
        try:
            added = date.fromisoformat(v.get("dateAdded", ""))
        except ValueError:
            continue
        if added != covers or cve in already_published:
            continue
        items.append(
            Item(
                id=f"kev-{len(items) + 1}",
                kind="kev",
                source="CISA KEV",
                title=f"{cve}: {v.get('vulnerabilityName', '')}",
                url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                published=f"{added.isoformat()}T00:00:00Z",
                text=(
                    f"{v.get('vendorProject', '')} {v.get('product', '')}. "
                    f"{v.get('shortDescription', '')} Required action: {v.get('requiredAction', '')}"
                ),
                cves=[cve],
                extra={
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "name": v.get("vulnerabilityName", ""),
                    "date_added": v.get("dateAdded", ""),
                    "due_date": v.get("dueDate", ""),
                    "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                    "cwes": v.get("cwes", []),
                },
            )
        )
    return items


def catalog_cves(catalog: dict) -> set[str]:
    return {str(v.get("cveID", "")).upper() for v in catalog.get("vulnerabilities", [])}
