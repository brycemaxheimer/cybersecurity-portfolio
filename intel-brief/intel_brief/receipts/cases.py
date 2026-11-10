"""Labelled test events for a Sigma rule, mapped to Defender XDR rows.

Events are built from the rule's own values: each selection satisfied, each
alternative value tried, each filter applied, letter case changed, and each
field broken in turn. The oracle, not the builder, decides whether an event
should match, so a badly built event costs a case but never a wrong label.

The Sigma-to-XDR column map is written from Microsoft's Defender XDR schema
reference, independently of pySigma's microsoft_xdr pipeline, so a mapping
mistake in the conversion surfaces as a disagreement.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .oracle import Rule, Unsupported, literal, split_key

_PROCESS = {
    "Image": "FolderPath",
    "OriginalFileName": "ProcessVersionInfoOriginalFileName",
    "CommandLine": "ProcessCommandLine",
    "ParentImage": "InitiatingProcessFolderPath",
    "ParentCommandLine": "InitiatingProcessCommandLine",
    "User": "AccountName",
    "IntegrityLevel": "ProcessIntegrityLevel",
    "Product": "ProcessVersionInfoProductName",
    "Description": "ProcessVersionInfoFileDescription",
    "Company": "ProcessVersionInfoCompanyName",
    "md5": "MD5",
    "sha1": "SHA1",
    "sha256": "SHA256",
    "ProcessId": "ProcessId",
    "ParentProcessId": "InitiatingProcessId",
}
_INITIATOR = {
    "Image": "InitiatingProcessFolderPath",
    "CommandLine": "InitiatingProcessCommandLine",
    "User": "InitiatingProcessAccountName",
}

# category -> (table, Sigma field -> column, columns every real row of that kind carries)
TABLES = {
    "process_creation": ("DeviceProcessEvents", _PROCESS, {"ActionType": "ProcessCreated"}),
    "network_connection": ("DeviceNetworkEvents", {
        **_INITIATOR,
        "DestinationIp": "RemoteIP",
        "DestinationPort": "RemotePort",
        "DestinationHostname": "RemoteUrl",
        "SourceIp": "LocalIP",
        "SourcePort": "LocalPort",
        "Protocol": "Protocol",
    }, {"ActionType": "ConnectionSuccess"}),
    "file_event": ("DeviceFileEvents", {**_INITIATOR, "TargetFilename": "FolderPath"}, {"ActionType": "FileCreated"}),
    "image_load": ("DeviceImageLoadEvents", {**_INITIATOR, "ImageLoaded": "FolderPath"}, {"ActionType": "ImageLoaded"}),
    "registry_set": ("DeviceRegistryEvents", {**_INITIATOR, "TargetObject": "RegistryKey", "Details": "RegistryValueData"},
                     {"ActionType": "RegistryValueSet"}),
}
PRODUCTS = {"windows", "linux", "macos"}
# A path column and the file-name column real telemetry fills from it.
NAME_OF = {"FolderPath": "FileName", "InitiatingProcessFolderPath": "InitiatingProcessFileName"}
BROKEN = "zz-unrelated"
NUMERIC = {"int", "long", "real", "decimal"}


@dataclass
class Case:
    name: str
    event: dict
    expected: bool


def target(rule: Rule) -> tuple[str, dict, dict]:
    if rule.product not in PRODUCTS or rule.category not in TABLES:
        raise Unsupported(f"no Defender XDR table for {rule.product or '?'}/{rule.category or '?'}")
    return TABLES[rule.category]


def regex_sample(pattern: str) -> str:
    """A string the regex matches, built by walking its parse tree."""
    try:
        from re import _parser as parser
    except ImportError:  # Python < 3.11
        import sre_parse as parser

    def walk(items) -> str:
        out = []
        for op, av in items:
            op = str(op)
            if op == "LITERAL":
                out.append(chr(av))
            elif op == "NOT_LITERAL":
                out.append("x" if chr(av) != "x" else "y")
            elif op == "ANY":
                out.append("x")
            elif op == "IN":
                out.append(walk_in(av))
            elif op in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                lo, _hi, sub = av
                out.append(walk(sub) * lo)
            elif op == "SUBPATTERN":
                out.append(walk(av[-1]))
            elif op == "ATOMIC_GROUP":
                out.append(walk(av))
            elif op == "BRANCH":
                out.append(walk(av[1][0]))
            elif op in ("AT", "ASSERT", "ASSERT_NOT"):
                continue
            elif op == "CATEGORY":
                out.append(category(av))
            else:
                raise Unsupported(f"regex feature {op}")
        return "".join(out)

    def walk_in(items) -> str:
        first_op, first_av = items[0]
        if str(first_op) == "NEGATE":
            return "x"
        if str(first_op) == "LITERAL":
            return chr(first_av)
        if str(first_op) == "RANGE":
            return chr(first_av[0])
        if str(first_op) == "CATEGORY":
            return category(first_av)
        raise Unsupported("regex character class")

    def category(cat) -> str:
        cat = str(cat)
        return "0" if "DIGIT" in cat and "NOT" not in cat else " " if "SPACE" in cat and "NOT" not in cat else "a"

    try:
        s = walk(parser.parse(pattern))
    except (re.error, IndexError, TypeError, ValueError) as e:
        raise Unsupported(f"regex {pattern[:40]!r}: {e}") from None
    if re.search(pattern, s) is None:
        raise Unsupported(f"no sample string for regex {pattern[:40]!r}")
    return s


def _plain(value) -> str:
    return str(value).lower() if isinstance(value, bool) else str(value) if isinstance(value, (int, float)) else literal(str(value))


def realize(constraints: list[tuple[list[str], object]], tail: bool = False):
    """One concrete field value meeting every (modifiers, value) constraint on a
    field: prefixes first, then contained parts, then suffixes. With `tail`,
    contained parts end the value, which tells overlapping values apart."""
    for mods, value in constraints:
        if value is None:
            return None
        if "cidr" in mods:
            net = ipaddress.ip_network(str(value), strict=False)
            return str(net.network_address + (1 if net.num_addresses > 1 else 0))
        if "re" in mods:
            return regex_sample(str(value))
    exact = [_plain(v) for mods, v in constraints if not {"contains", "startswith", "endswith"} & set(mods)]
    if exact:
        return exact[0]
    starts = "".join(_plain(v) for mods, v in constraints if "startswith" in mods)
    inner = " ".join(_plain(v) for mods, v in constraints if "contains" in mods)
    ends = "".join(_plain(v) for mods, v in constraints if "endswith" in mods)
    head = starts or ("/" if ends.startswith("/") else "C:\\" if ends.startswith("\\") else "")
    if tail and inner and not ends:
        return f"{head}zq {inner}"
    return f"{head}zq{f' {inner} zq' if inner else ''}{ends}"


def alternatives(selection) -> list[dict]:
    """Constraint sets ({field: [(modifiers, value)]}) that each satisfy the
    selection, one per alternative map and per alternative value, the first
    values of everything else kept."""
    items = selection if isinstance(selection, list) else [selection]
    frags = []
    for item in items:
        firsts, options = {}, []
        for key, values in item.items():
            field, mods = split_key(key)
            vals = values if isinstance(values, list) else [values]
            if "all" in mods:
                rest = [m for m in mods if m != "all"]
                firsts.setdefault(field, []).extend((rest, v) for v in vals)
                continue
            firsts.setdefault(field, []).append((mods, vals[0]))
            options += [(field, len(firsts[field]) - 1, (mods, v)) for v in vals[1:]]
        frags.append(firsts)
        for field, at, constraint in options:
            alt = {k: list(v) for k, v in firsts.items()}
            alt[field][at] = constraint
            frags.append(alt)
    return frags


def merge(*frags: dict) -> dict:
    out: dict = {}
    for frag in frags:
        for field, constraints in frag.items():
            out.setdefault(field, []).extend(constraints)
    return out


def events(constraints: dict, tail: bool = False) -> dict:
    return {field: realize(c, tail) for field, c in constraints.items()}


def _swapcase(v):
    return v.swapcase() if isinstance(v, str) else v


def build(rule: Rule, limit: int = 80) -> list[Case]:
    """Labelled events for one rule, de-duplicated, at most `limit`. The cases
    that probe structure (filters, broken fields) come before the per-value
    alternatives, so a long value list cannot crowd them out."""
    names = list(rule.selections)
    frags = {n: alternatives(rule.selections[n]) for n in names}
    positive = [n for n in names if not n.startswith("filter")]
    filters = [n for n in names if n.startswith("filter")]
    base_c = merge(*(frags[n][0] for n in positive))
    base = events(base_c)

    candidates = [("every selection", base), ("letter case changed", {k: _swapcase(v) for k, v in base.items()})]
    for n in filters:
        applied = events(merge(base_c, frags[n][0]))
        candidates += [(f"{n} applied", applied), (f"{n} applied, letter case changed", {k: _swapcase(v) for k, v in applied.items()})]
    candidates += [(f"{field} broken", {**base, field: BROKEN}) for field in base]
    candidates += [(f"{n} alone", events(frags[n][0])) for n in positive]
    for n in positive:
        others = merge(*(frags[m][0] for m in positive if m != n))
        for i, f in enumerate(frags[n], 1):
            if i > 1:
                candidates.append((f"{n} alternative {i}", events(merge(others, f))))
            candidates.append((f"{n} alternative {i}, contained text at the end", events(merge(others, f), tail=True)))

    cases, seen = [], set()
    for name, event in candidates:
        key = tuple(sorted((k, str(v)) for k, v in event.items()))
        if not event or key in seen:
            continue
        seen.add(key)
        cases.append(Case(name, event, rule.matches(event)))
    return cases[:limit]


def to_row(event: dict, columns: dict, types: dict[str, str], defaults: dict) -> dict | None:
    """Sigma event -> XDR row. None when a value cannot be expressed in its column's type."""
    row = dict(defaults)
    for field, value in event.items():
        if field not in columns:
            raise Unsupported(f"field {field} has no Defender XDR column")
        col = columns[field]
        if types.get(col) in NUMERIC and value is not None:
            if not re.fullmatch(r"-?\d+", str(value)):
                return None
            value = int(value)
        row[col] = value
        if col in NAME_OF and value is not None:
            row[NAME_OF[col]] = re.split(r"[\\/]", str(value))[-1]
    return row
