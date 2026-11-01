"""Convert Sigma YAML to Defender XDR KQL, Splunk SPL and Elastic with pySigma."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection

log = logging.getLogger(__name__)


def _targets():
    """(key, label, backend factory) tuples. Imported lazily so one broken
    backend package doesn't stop the others."""
    out = []
    try:
        from sigma.backends.kusto import KustoBackend
        from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

        out.append(("kql", "Defender XDR / Sentinel KQL", lambda: KustoBackend(processing_pipeline=microsoft_xdr_pipeline())))
    except ImportError as e:
        log.warning("kusto backend unavailable: %s", e)
    try:
        from sigma.backends.splunk import SplunkBackend
        from sigma.pipelines.splunk import splunk_windows_pipeline

        out.append(("spl", "Splunk SPL", lambda: SplunkBackend(processing_pipeline=splunk_windows_pipeline())))
    except ImportError as e:
        log.warning("splunk backend unavailable: %s", e)
    try:
        from sigma.backends.elasticsearch import LuceneBackend
        from sigma.pipelines.elasticsearch.windows import ecs_windows

        out.append(("elastic", "Elastic (Lucene, ECS)", lambda: LuceneBackend(processing_pipeline=ecs_windows())))
    except ImportError as e:
        log.warning("elasticsearch backend unavailable: %s", e)
    return out


def convert(rule_yaml: str) -> dict[str, dict]:
    """{target: {"label", "query" | None, "error" | None}}"""
    results: dict[str, dict] = {}
    for key, label, make in _targets():
        try:
            rules = SigmaCollection.from_yaml(rule_yaml)
            queries = make().convert(rules)
            query = "\n".join(str(q) for q in queries).strip()
            results[key] = {"label": label, "query": query or None, "error": None if query else "empty output"}
        except Exception as e:  # unsupported log source, field mapping, etc.
            results[key] = {"label": label, "query": None, "error": f"{type(e).__name__}: {e}"[:400]}
    return results


def _sigma_cli() -> list[str]:
    exe = Path(sys.executable).parent / ("sigma.exe" if os.name == "nt" else "sigma")
    return [str(exe)] if exe.exists() else ["sigma"]


def _rule_filename(rule_yaml: str) -> str:
    """SigmaHQ-style name (product_category_title.yml) so the filename
    validators judge the rule, not the temp file."""
    try:
        rule = yaml.safe_load(rule_yaml) or {}
    except yaml.YAMLError:
        rule = {}
    ls = rule.get("logsource") or {}
    parts = [str(ls.get("product", "")), str(ls.get("category") or ls.get("service") or ""), str(rule.get("title", "rule"))]
    slug = re.sub(r"[^a-z0-9]+", "_", "_".join(p for p in parts if p).lower()).strip("_")
    return (slug[:80] or "intel_brief_rule").ljust(12, "_") + ".yml"


def sigma_check(rule_yaml: str) -> tuple[bool, list[str]]:
    """Run `sigma check --fail-on-issues` on one rule. Returns (passed, messages).

    Without --fail-on-issues the CLI exits 0 even when validators report
    problems, so the exit code alone would pass bad rules."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / _rule_filename(rule_yaml)
        path.write_text(rule_yaml, encoding="utf-8")
        try:
            proc = subprocess.run(
                [*_sigma_cli(), "check", "--fail-on-error", "--fail-on-issues", str(path)],
                capture_output=True, text=True, timeout=120,
                env={**os.environ, "NO_COLOR": "1", "PYTHONIOENCODING": "utf-8"},
            )
        except (OSError, subprocess.SubprocessError) as e:
            return False, [f"sigma check could not run: {e}"]
    out = (proc.stdout + "\n" + proc.stderr).replace(str(path), "rule.yml")
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    return proc.returncode == 0, lines[-40:]
