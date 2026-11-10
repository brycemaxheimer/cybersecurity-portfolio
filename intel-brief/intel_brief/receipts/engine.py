"""Run KQL on a real Kusto engine: Microsoft's Kusto emulator, locally and in CI.

Standard library only. The emulator listens on localhost without auth; it is
started with ACCEPT_EULA=Y (see README) and never exposed further.
"""

from __future__ import annotations

import csv
import io
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DEFAULT_URL = "http://localhost:8080"
DB = "NetDefaultDB"


class EngineError(Exception):
    pass


def parse_columns(cols: str) -> list[tuple[str, str]]:
    """'(Timestamp:datetime, DeviceName:string)' -> [('Timestamp', 'datetime'), ...]"""
    out = []
    for part in cols.strip().strip("()").split(","):
        name, _, kind = part.strip().partition(":")
        out.append((name.strip(), kind.strip().lower() or "string"))
    return out


def _iso(value) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return str(value)


def literal(value, kind: str) -> str:
    """A typed KQL literal for a datatable row."""
    if value is None or (value == "" and kind != "string"):
        return '""' if kind == "string" else f"{kind}(null)"
    if kind == "string":
        s = str(value)
        if "\n" in s or "\r" in s:
            return json.dumps(s, ensure_ascii=False)
        return '@"' + s.replace('"', '""') + '"'
    if kind in ("long", "int"):
        return f"{kind}({int(value)})"
    if kind in ("real", "decimal"):
        return f"{kind}({float(value)})"
    if kind in ("bool", "boolean"):
        return "true" if str(value).lower() in ("true", "1") else "false"
    if kind == "datetime":
        return f"datetime({_iso(value)})"
    if kind == "dynamic":
        return f"dynamic({json.dumps(value)})"
    if kind in ("guid", "timespan"):
        return f"{kind}({value})"
    raise EngineError(f"no literal for type {kind}")


def _csv_value(value, kind: str) -> str:
    if value is None:
        return ""
    if kind == "datetime":
        return _iso(value)
    if kind == "dynamic":
        return json.dumps(value)
    if kind in ("bool", "boolean"):
        return "true" if str(value).lower() in ("true", "1") else "false"
    return str(value)


def datatable(columns: list[tuple[str, str]], rows: list[dict]) -> str:
    head = ", ".join(f"['{n}']:{k}" for n, k in columns)
    body = ",\n".join(", ".join(literal(r.get(n), k) for n, k in columns) for r in rows)
    return f"datatable({head})[\n{body}\n]"


class Engine:
    def __init__(self, url: str | None = None, db: str = DB, timeout: float = 60):
        self.url = (url or os.environ.get("KUSTO_EMULATOR_URL") or DEFAULT_URL).rstrip("/")
        self.db, self.timeout = db, timeout

    def _post(self, path: str, csl: str) -> dict:
        req = urllib.request.Request(
            self.url + path,
            data=json.dumps({"db": self.db, "csl": csl}).encode("utf-8"),
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace").strip()
            raise EngineError(text.splitlines()[0][:300] if text else f"HTTP {e.code}") from None
        except (urllib.error.URLError, OSError) as e:
            raise EngineError(f"engine unreachable at {self.url}: {e}") from None

    @staticmethod
    def _rows(resp: dict) -> list[list]:
        tables = resp.get("Tables") or []
        return tables[0]["Rows"] if tables else []

    def mgmt(self, csl: str) -> list[list]:
        return self._rows(self._post("/v1/rest/mgmt", csl))

    def query(self, csl: str) -> list[list]:
        return self._rows(self._post("/v1/rest/query", csl))

    def ready(self, wait: float = 0) -> bool:
        """True once the engine answers; polls for up to `wait` seconds."""
        deadline = time.monotonic() + wait
        while True:
            try:
                self.mgmt(".show version")
                return True
            except EngineError:
                if time.monotonic() >= deadline:
                    return False
                time.sleep(3)

    def reset_tables(self, schema: dict[str, str]) -> None:
        """Drop and recreate every schema table, empty."""
        lines = [f".drop table {t} ifexists" for t in schema] + [f".create table {t} {cols}" for t, cols in schema.items()]
        self.mgmt(".execute database script <|\n" + "\n".join(lines))

    def ingest(self, table: str, columns: list[tuple[str, str]], rows: list[dict]) -> None:
        if not rows:
            return
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        for r in rows:
            writer.writerow([_csv_value(r.get(n), k) for n, k in columns])
        self.mgmt(f".ingest inline into table {table} <|\n{buf.getvalue()}")

    def count_shadowed(self, query: str, table: str, columns: list[tuple[str, str]], rows: list[dict]) -> int:
        """Rows `query` returns when `table` holds only `rows`."""
        return len(self.query(f"let {table} = {datatable(columns, rows)};\n{query}"))
