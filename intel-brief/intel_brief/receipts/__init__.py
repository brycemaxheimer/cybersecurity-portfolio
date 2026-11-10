"""Receipts: what each KQL query did when it ran on a real Kusto engine.

The Kusto parser says a query is well-formed. A receipt says what it does.
Every query goes to Microsoft's Kusto emulator:

- Every query, Sigma or hunting, runs on a synthetic benign baseline
  (baseline.py). Any row it returns there is a false positive.
- A Sigma rule's KQL conversion also runs on labelled cases built from the rule
  (cases.py). The oracle (oracle.py), not pySigma, labels each case, so a
  conversion that misses or over-matches shows up as a disagreement.

Neither is a test against real attack telemetry, and the labels say so. With no
engine reachable, nothing is attached and the page keeps "untested".
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone

import yaml

from ..config import KQL_SCHEMA
from . import baseline, cases
from .engine import Engine, EngineError, parse_columns
from .oracle import Rule, Unsupported


def _tables(query: str, schema: dict) -> list[str]:
    return [t for t in schema if re.search(rf"\b{t}\b", query)]


class Bench:
    """An engine loaded with the schema and the baseline, ready to issue receipts."""

    def __init__(self, engine: Engine, schema: dict[str, str], now: datetime):
        self.engine, self.schema, self.now = engine, schema, now
        self.columns = {t: parse_columns(c) for t, c in schema.items()}
        rows = baseline.build(now)
        engine.reset_tables(schema)
        for table, table_rows in rows.items():
            engine.ingest(table, self.columns[table], table_rows)
        self.counts = {t: len(rows.get(t, [])) for t in schema}

    def on_baseline(self, query: str) -> dict:
        tables = _tables(query, self.schema)
        try:
            hits = len(self.engine.query(query))
        except EngineError as e:
            return {"engine": "error", "message": str(e)}
        return {"engine": "ran", "baseline": {"events": sum(self.counts[t] for t in tables), "hits": hits, "tables": tables}}

    def on_cases(self, rule_yaml: str, query: str) -> dict:
        try:
            rule = Rule(yaml.safe_load(rule_yaml))
            table, mapping, defaults = cases.target(rule)
            built = cases.build(rule)
        except (Unsupported, yaml.YAMLError) as e:
            return {"status": "not_tested", "reason": str(e)}
        queried = query.lstrip().split("\n", 1)[0].split("|", 1)[0].strip()
        if queried != table:
            return {"status": "not_tested", "reason": f"the conversion reads {queried}; cases are built for {table}"}
        types = dict(self.columns[table])
        fixed = {**defaults, "Timestamp": self.now - timedelta(hours=1), "DeviceId": "dev-case", "DeviceName": "case-host.corp.example"}
        results, skipped = [], 0
        for case in built:
            try:
                row = cases.to_row(case.event, mapping, types, fixed)
            except Unsupported as e:
                return {"status": "not_tested", "reason": str(e)}
            if row is None:
                skipped += 1
                continue
            try:
                fired = self.engine.count_shadowed(query, table, self.columns[table], [row]) > 0
            except EngineError as e:
                return {"status": "error", "reason": str(e)}
            results.append((case, fired))
        pos = [f for c, f in results if c.expected]
        neg = [f for c, f in results if not c.expected]
        wrong = [{"case": c.name, "expected": c.expected, "fired": f} for c, f in results if f != c.expected]
        status = "fail" if wrong else "pass" if pos else "not_tested"
        out = {"status": status, "positive": len(pos), "positive_fired": sum(pos), "negative": len(neg),
               "negative_fired": sum(neg), "disagreements": wrong[:10], "skipped": skipped}
        if status == "not_tested":
            out["reason"] = "no case the rule matches could be built"
        return out

    def sigma(self, rule_yaml: str, query: str) -> dict:
        receipt = self.on_baseline(query)
        if receipt["engine"] == "ran":
            receipt["cases"] = self.on_cases(rule_yaml, query)
        return receipt


def run(detections: dict[str, dict], engine: Engine | None = None, now: datetime | None = None,
        wait: float | None = None) -> dict:
    """Attach a receipt to every KQL query in {story id: detection}. Returns the run status."""
    engine = engine or Engine()
    wait = float(os.environ.get("KUSTO_EMULATOR_WAIT", "0")) if wait is None else wait
    if not engine.ready(wait):
        return {"status": "not_run", "reason": f"no Kusto engine at {engine.url}"}
    schema = json.loads(KQL_SCHEMA.read_text(encoding="utf-8"))
    try:
        bench = Bench(engine, schema, now or datetime.now(timezone.utc))
        version = engine.mgmt(".show version")[0][0]
    except EngineError as e:
        return {"status": "error", "reason": str(e)}
    for det in detections.values():
        sig = det.get("sigma") or {}
        kql = (sig.get("conversions") or {}).get("kql") or {}
        if kql.get("query"):
            kql["receipt"] = bench.sigma(sig["yaml"], kql["query"])
        for hq in det.get("hunting_queries") or []:
            hq["receipt"] = bench.on_baseline(hq["kql"])
    return {"status": "ran", "engine": f"Kusto emulator {version}", "baseline_events": sum(bench.counts.values()),
            "baseline_seed": baseline.SEED}


def summarize(detections: dict[str, dict]) -> dict:
    """Totals over attached receipts, for logs and the CLI."""
    s = {"sigma_kql": 0, "sigma_pass": 0, "sigma_fail": 0, "sigma_not_tested": 0, "hunting": 0,
         "engine_errors": 0, "baseline_clean": 0, "baseline_hits": 0, "no_baseline_data": 0}
    for det in detections.values():
        kql = ((det.get("sigma") or {}).get("conversions") or {}).get("kql") or {}
        receipts = [(kql.get("receipt"), True)] if kql.get("receipt") else []
        receipts += [(hq.get("receipt"), False) for hq in det.get("hunting_queries") or [] if hq.get("receipt")]
        for r, is_sigma in receipts:
            s["sigma_kql" if is_sigma else "hunting"] += 1
            if r["engine"] != "ran":
                s["engine_errors"] += 1
                continue
            b = r["baseline"]
            s["no_baseline_data" if not b["events"] else "baseline_hits" if b["hits"] else "baseline_clean"] += 1
            if is_sigma:
                s[f"sigma_{r['cases']['status']}"] = s.get(f"sigma_{r['cases']['status']}", 0) + 1
    return s
