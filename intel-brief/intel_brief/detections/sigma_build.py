"""Turn a SigmaRuleDraft into Sigma YAML, rejecting anything malformed."""

from __future__ import annotations

import re
import uuid

import yaml

from ..safety import clean_model_text
from .schema import SigmaRuleDraft

_NS = uuid.UUID("5f1e2a4c-3b7d-4e8a-9c1f-6d2b8a0e4f17")  # fixed namespace for rule IDs
_NAME = re.compile(r"^(selection|filter)(_[a-z0-9]{1,30}){0,3}$")
_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9_.]{0,63}$")
_ATTACK = re.compile(r"^attack\.([a-z-]{3,40}|t\d{4}(\.\d{3})?|g\d{4}|s\d{4})$")
_SERVICE = re.compile(r"^[a-z0-9_-]{1,40}$")
_COND_TOKEN = re.compile(r"\(|\)|[A-Za-z0-9_*]+")
_COND_WORDS = {"and", "or", "not", "of", "them", "all", "1"}


class DraftError(ValueError):
    pass


def _check_condition(cond: str, names: set[str]) -> str:
    cond = " ".join(cond.split())
    if not cond or not re.fullmatch(r"[A-Za-z0-9_*() ]+", cond):
        raise DraftError(f"condition has unsupported characters: {cond!r}")
    depth = 0
    for tok in _COND_TOKEN.findall(cond):
        if tok == "(":
            depth += 1
        elif tok == ")":
            depth -= 1
            if depth < 0:
                raise DraftError("unbalanced parentheses in condition")
        elif tok in _COND_WORDS:
            continue
        elif "*" in tok:
            pattern = re.compile("^" + re.escape(tok).replace(r"\*", ".*") + "$")
            if not any(pattern.match(n) for n in names):
                raise DraftError(f"condition wildcard {tok!r} matches no selection")
        elif tok not in names:
            raise DraftError(f"condition refers to unknown selection {tok!r}")
    if depth:
        raise DraftError("unbalanced parentheses in condition")
    return cond


def to_yaml(draft: SigmaRuleDraft, *, cves: list[str], references: list[str], date: str) -> str:
    detection: dict = {}
    for sel in draft.selections:
        if not _NAME.match(sel.name) or sel.name in detection:
            raise DraftError(f"bad or duplicate selection name {sel.name!r}")
        if not sel.conditions:
            raise DraftError(f"selection {sel.name} is empty")
        body: dict = {}
        for c in sel.conditions:
            if not _FIELD.match(c.field):
                raise DraftError(f"bad field name {c.field!r}")
            values = [v for v in c.values if isinstance(v, str) and v.strip() and len(v) <= 500]
            if not values:
                raise DraftError(f"field {c.field} has no usable values")
            key = "|".join([c.field, *dict.fromkeys(c.modifiers)])
            if key in body:
                raise DraftError(f"duplicate key {key} in {sel.name}")
            body[key] = values if len(values) > 1 else values[0]
        detection[sel.name] = body
    detection["condition"] = _check_condition(draft.condition, set(detection))
    if not any(n.startswith("selection") for n in detection):
        raise DraftError("rule has no selection")

    logsource = {}
    if draft.logsource_product != "none":
        logsource["product"] = draft.logsource_product
    if draft.logsource_category != "none":
        logsource["category"] = draft.logsource_category
    if draft.logsource_service and _SERVICE.match(draft.logsource_service):
        logsource["service"] = draft.logsource_service
    if not logsource:
        raise DraftError("logsource is empty")

    title = clean_model_text(draft.title, 100)
    tags = [t.lower() for t in draft.attack_tags if _ATTACK.match(t.lower())]
    tags += [f"cve.{c[4:].lower()}" for c in cves]
    rule = {
        "title": title,
        "id": str(uuid.uuid5(_NS, f"{date}:{title}:{','.join(cves)}")),
        "status": "experimental",
        "description": clean_model_text(draft.description, 600) + " AI-generated, untested.",
        "references": references[:6],
        "author": "intel-brief (AI-generated, untested)",
        "date": date,
        "tags": list(dict.fromkeys(tags)),
        "logsource": logsource,
        "detection": detection,
        "falsepositives": [clean_model_text(f, 200) for f in draft.falsepositives][:5] or ["Unknown"],
        "level": draft.level,
    }
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=1000)
