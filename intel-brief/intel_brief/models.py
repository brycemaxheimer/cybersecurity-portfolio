"""The collector's record type. Everything in an Item came from an outside
source, so all of it is untrusted: models read it, the renderer escapes it."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)


def find_cves(text: str) -> list[str]:
    """Return unique CVE IDs in order of first appearance, upper-cased."""
    seen: dict[str, None] = {}
    for m in CVE_RE.finditer(text or ""):
        seen.setdefault(f"CVE-{m.group(1)}-{m.group(2)}", None)
    return list(seen)


@dataclass
class Item:
    id: str  # short, unique within a run, e.g. "news-12"
    kind: str  # kev | nvd | advisory | news | social | sigma
    source: str  # display name, e.g. "BleepingComputer"
    title: str
    url: str  # already checked by safety.safe_url
    published: str  # ISO 8601, UTC
    text: str = ""  # plain-text excerpt for the models; never published
    cves: list[str] = field(default_factory=list)
    author: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Item":
        return cls(**d)
