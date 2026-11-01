"""Batch-validate KQL with Microsoft's Kusto.Language parser (through pwsh)."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..config import KQL_SCHEMA, KUSTO_DLL, ROOT

log = logging.getLogger(__name__)
SCRIPT = ROOT / "tools" / "validate_kql.ps1"


def available() -> bool:
    return KUSTO_DLL.exists() and KQL_SCHEMA.exists() and shutil.which("pwsh") is not None


def validate(queries: dict[str, str]) -> dict[str, dict]:
    """{id: query} -> {id: {"status": "pass"|"fail"|"not_run", "messages": [...]}}"""
    if not queries:
        return {}
    if not available():
        reason = "Kusto.Language parser not installed" if not KUSTO_DLL.exists() else "pwsh or schema missing"
        return {k: {"status": "not_run", "messages": [reason]} for k in queries}
    with tempfile.TemporaryDirectory() as d:
        inp = Path(d) / "queries.json"
        inp.write_text(json.dumps([{"id": k, "query": v} for k, v in queries.items()]), encoding="utf-8")
        proc = None
        try:
            proc = subprocess.run(
                ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
                 "-InputPath", str(inp), "-DllPath", str(KUSTO_DLL), "-SchemaPath", str(KQL_SCHEMA)],
                capture_output=True, text=True, timeout=300, encoding="utf-8",
            )
            rows = json.loads(proc.stdout or "[]")
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as e:
            log.warning("KQL validation failed to run: %s %s", e, (proc.stderr if proc else "")[:500])
            return {k: {"status": "not_run", "messages": [f"validator error: {type(e).__name__}"]} for k in queries}
    out = {}
    for row in rows:
        msgs = [f"{x['severity']} {x['code']}: {x['message']}" for x in row.get("diagnostics", [])]
        out[row["id"]] = {"status": "pass" if row.get("ok") else "fail", "messages": msgs[:10]}
    for k in queries:
        out.setdefault(k, {"status": "not_run", "messages": ["no result"]})
    return out
