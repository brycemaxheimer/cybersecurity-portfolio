"""Step 4: detections.

Order of preference per story:
1. An existing SigmaHQ rule tagged with the story's CVE (converted, not rewritten).
2. A Sigma rule Claude drafted (structured output) that passes `sigma check`.
3. Hunting steps and KQL hunting queries when there is no behavior to detect.

Every KQL query is then parsed with Microsoft's Kusto.Language. Anything
AI-generated is labelled "AI-generated, untested" on the page.
"""

from __future__ import annotations

import logging
import re

from ..safety import clean_model_text
from . import convert, kql_check, sigma_build
from .sigma_repo import BLOB, RuleIndex

log = logging.getLogger(__name__)

_HASH = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def _clean_query(q: str) -> str:
    q = "".join(ch for ch in q if ch in "\n\t" or ord(ch) >= 0x20)
    return q.strip()[:4000]


def unsupported_iocs(query: str, evidence: str) -> list[str]:
    """Hashes and IPs in a model-written query that no source item contains."""
    ev = evidence.lower()
    found = set(_HASH.findall(query)) | set(_IPV4.findall(query))
    benign = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}
    return sorted(x for x in found if x.lower() not in ev and x not in benign)


def build(story, writeup, rule_index: RuleIndex, references: list[str], evidence: str, date: str,
          llm=None, model: str = "", effort: str = "medium", retry: bool = True) -> dict:
    det: dict = {"type": writeup.detection_type if writeup else "none", "sigma": None,
                 "hunting_steps": [], "hunting_queries": [], "notes": []}

    existing = rule_index.rules_for(story.cves) if rule_index else []
    if existing:
        rel = existing[0]
        loaded = rule_index.read(rel)
        if loaded:
            text, rule = loaded
            det["sigma"] = {
                "origin": "sigmahq",
                "title": str(rule.get("title", ""))[:200],
                "url": BLOB + rel,
                "yaml": text,
                "check": {"status": "upstream", "messages": []},
                "conversions": convert.convert(text),
            }
            if len(existing) > 1:
                det["notes"].append(f"{len(existing)} SigmaHQ rules reference this CVE; showing the first.")

    if writeup and det["sigma"] is None and writeup.sigma_rule is not None:
        draft = writeup.sigma_rule
        for attempt in (1, 2):
            try:
                rule_yaml = sigma_build.to_yaml(draft, cves=story.cves, references=references, date=date)
                passed, messages = convert.sigma_check(rule_yaml)
            except sigma_build.DraftError as e:
                rule_yaml, passed, messages = None, False, [f"draft rejected: {e}"]
            if passed or attempt == 2 or not (retry and llm):
                break
            from ..writeup import fix_sigma  # local import: writeup imports this package's schema

            fixed = fix_sigma(draft, messages, llm, model, effort)
            if fixed is None:
                break
            draft = fixed
        if rule_yaml and passed:
            det["sigma"] = {
                "origin": "ai",
                "title": clean_model_text(draft.title, 100),
                "url": None,
                "yaml": rule_yaml,
                "check": {"status": "pass", "messages": messages[-5:]},
                "conversions": convert.convert(rule_yaml),
            }
        else:
            det["notes"].append("An AI-drafted Sigma rule failed validation and was dropped.")
            det["rejected_sigma"] = {"messages": messages[-10:]}

    if writeup:
        det["hunting_steps"] = [clean_model_text(s, 400) for s in writeup.hunting_steps][:6]
        for i, hq in enumerate(writeup.hunting_queries[:3], 1):
            q = _clean_query(hq.kql)
            bad = unsupported_iocs(q, evidence)
            if bad:
                det["notes"].append(f"Dropped a hunting query with indicators not found in any source: {', '.join(bad[:3])}")
                continue
            det["hunting_queries"].append({"title": clean_model_text(hq.title, 100), "kql": q})
    return det


def validate_all(detections: dict[str, dict]) -> str:
    """Parse every KQL query once, in a single pwsh run. Returns parser status."""
    queries: dict[str, str] = {}
    for sid, det in detections.items():
        sig = det.get("sigma") or {}
        kql = (sig.get("conversions") or {}).get("kql") or {}
        if kql.get("query"):
            queries[f"{sid}|sigma"] = kql["query"]
        for n, hq in enumerate(det.get("hunting_queries", [])):
            queries[f"{sid}|hunt{n}"] = hq["kql"]
    results = kql_check.validate(queries)
    for key, res in results.items():
        sid, which = key.split("|", 1)
        det = detections[sid]
        if which == "sigma":
            det["sigma"]["conversions"]["kql"]["validation"] = res
        else:
            det["hunting_queries"][int(which[4:])]["validation"] = res
    return "available" if kql_check.available() else "not installed"
