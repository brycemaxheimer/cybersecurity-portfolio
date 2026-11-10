"""An independent Sigma evaluator: the oracle that says whether an event should match.

It shares no code with pySigma, which produced the KQL under test, so a bug in
the conversion shows up as a disagreement instead of being repeated on both
sides. It covers what intel-brief's rules use: field selections with contains,
startswith, endswith, all, re and cidr; plain and wildcard values; null; lists
of maps; and conditions with and/or/not, parentheses, and "1 of" / "all of" a
name pattern or "them". Anything else raises Unsupported, and the rule is
reported as not tested.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re

MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "cidr"}


class Unsupported(Exception):
    """The rule uses Sigma the oracle does not implement."""


def wildcard_regex(value: str) -> str:
    """Sigma value -> regex source for the whole value. * and ? are wildcards;
    a backslash escapes *, ? and itself, and is literal before anything else."""
    out, i = [], 0
    while i < len(value):
        c = value[i]
        nxt = value[i + 1] if i + 1 < len(value) else ""
        if c == "\\" and nxt in ("*", "?", "\\"):
            out.append(re.escape(nxt))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return "".join(out)


def literal(value: str) -> str:
    """A concrete string the Sigma value matches: wildcards filled, escapes undone."""
    out, i = [], 0
    while i < len(value):
        c = value[i]
        nxt = value[i + 1] if i + 1 < len(value) else ""
        if c == "\\" and nxt in ("*", "?", "\\"):
            out.append(nxt)
            i += 2
            continue
        out.append("" if c == "*" else "x" if c == "?" else c)
        i += 1
    return "".join(out)


def split_key(key: str) -> tuple[str, list[str]]:
    field, *mods = key.split("|")
    unknown = [m for m in mods if m not in MODIFIERS]
    if unknown:
        raise Unsupported(f"modifier {unknown[0]} on {field}")
    return field, mods


def _one(actual, value, mods: list[str]) -> bool:
    if value is None:
        return actual is None or actual == ""
    if actual is None:
        return False
    s = str(actual)
    if "re" in mods:
        return re.search(str(value), s) is not None
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(s) in ipaddress.ip_network(str(value), strict=False)
        except ValueError:
            return False
    if isinstance(value, bool):
        value = str(value).lower()
    body = wildcard_regex(str(value))
    if "contains" in mods:
        body = f".*{body}.*"
    elif "startswith" in mods:
        body = f"{body}.*"
    elif "endswith" in mods:
        body = f".*{body}"
    return re.fullmatch(body, s, re.IGNORECASE | re.DOTALL) is not None


def field_matches(event: dict, key: str, values) -> bool:
    field, mods = split_key(key)
    values = values if isinstance(values, list) else [values]
    hits = (_one(event.get(field), v, mods) for v in values)
    return all(hits) if "all" in mods else any(hits)


def selection_matches(event: dict, selection) -> bool:
    if isinstance(selection, dict):
        return all(field_matches(event, k, v) for k, v in selection.items())
    if isinstance(selection, list) and all(isinstance(x, dict) for x in selection):
        return any(selection_matches(event, x) for x in selection)
    raise Unsupported("keyword selection")


_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokens(condition: str) -> list[str]:
    out, pos = [], 0
    condition = condition.strip()
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m:
            raise Unsupported(f"condition syntax near {condition[pos:pos + 12]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


class Condition:
    """Recursive-descent parse of a Sigma condition; precedence not > and > or."""

    def __init__(self, condition: str, names: list[str]):
        self.toks, self.i, self.names = _tokens(condition), 0, names
        self.tree = self._or()
        if self.i != len(self.toks):
            raise Unsupported(f"unexpected {self.toks[self.i]!r} in condition")

    def _peek(self):
        return self.toks[self.i].lower() if self.i < len(self.toks) else None

    def _take(self):
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def _or(self):
        node = self._and()
        while self._peek() == "or":
            self._take()
            node = ("or", node, self._and())
        return node

    def _and(self):
        node = self._not()
        while self._peek() == "and":
            self._take()
            node = ("and", node, self._not())
        return node

    def _not(self):
        if self._peek() == "not":
            self._take()
            return ("not", self._not())
        return self._atom()

    def _atom(self):
        tok = self._peek()
        if tok is None:
            raise Unsupported("condition ends early")
        if tok == "(":
            self._take()
            node = self._or()
            if self._peek() != ")":
                raise Unsupported("unbalanced parentheses")
            self._take()
            return node
        if tok in ("1", "any", "all") and self.i + 1 < len(self.toks) and self.toks[self.i + 1].lower() == "of":
            quant = "all" if self._take().lower() == "all" else "any"
            self._take()
            if self._peek() is None:
                raise Unsupported("'of' without a name")
            pattern = self._take()
            names = self.names if pattern.lower() == "them" else [n for n in self.names if fnmatch.fnmatchcase(n, pattern)]
            if not names:
                raise Unsupported(f"{pattern} names no selection")
            return (quant, names)
        name = self._take()
        if name not in self.names:
            raise Unsupported(f"unknown selection {name}")
        return ("name", name)

    def evaluate(self, results: dict[str, bool], node=None) -> bool:
        node = self.tree if node is None else node
        op = node[0]
        if op == "name":
            return results[node[1]]
        if op == "not":
            return not self.evaluate(results, node[1])
        if op == "and":
            return self.evaluate(results, node[1]) and self.evaluate(results, node[2])
        if op == "or":
            return self.evaluate(results, node[1]) or self.evaluate(results, node[2])
        if op == "any":
            return any(results[n] for n in node[1])
        return all(results[n] for n in node[1])


class Rule:
    """A parsed Sigma rule the oracle can evaluate. Raises Unsupported on construction."""

    def __init__(self, rule: dict):
        det = dict(rule.get("detection") or {})
        condition = det.pop("condition", None)
        det.pop("timeframe", None)
        if not isinstance(condition, str):
            raise Unsupported("condition must be one string")
        if "|" in condition:
            raise Unsupported("aggregation in condition")
        self.selections = det
        for sel in det.values():
            items = sel if isinstance(sel, list) else [sel]
            if not all(isinstance(x, dict) for x in items):
                raise Unsupported("keyword selection")
            for item in items:
                for key in item:
                    split_key(key)
        self.condition = Condition(condition, list(det))
        logsource = rule.get("logsource") or {}
        self.product = str(logsource.get("product") or "")
        self.category = str(logsource.get("category") or "")

    def matches(self, event: dict) -> bool:
        return self.condition.evaluate({n: selection_matches(event, s) for n, s in self.selections.items()})
