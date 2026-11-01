"""Local shallow clone of SigmaHQ/sigma: new rules and a CVE -> rule index."""

from __future__ import annotations

import logging
import re
import subprocess
from datetime import datetime
from pathlib import Path

import yaml

from ..config import SIGMA_REPO_DIR
from ..models import Item, find_cves

log = logging.getLogger(__name__)

REPO_URL = "https://github.com/SigmaHQ/sigma.git"
RULE_DIRS = ("rules", "rules-emerging-threats", "rules-threat-hunting")
BLOB = "https://github.com/SigmaHQ/sigma/blob/master/"
_CVE_TAG = re.compile(r"^cve\.(\d{4})[-.](\d{4,7})$", re.IGNORECASE)

try:
    _Loader = yaml.CSafeLoader
except AttributeError:  # PyYAML built without libyaml
    _Loader = yaml.SafeLoader


def _git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True, timeout=600
    ).stdout


def ensure_repo(depth: int = 100) -> Path | None:
    """Clone (or refresh) the rules repo. Returns None if git fails.

    Uses --depth, not --shallow-since: the latter fails against GitHub with
    "error processing shallow info". SigmaHQ lands far fewer than 100 commits
    a day, so 100 covers the lookback window with room to spare."""
    try:
        if (SIGMA_REPO_DIR / ".git").exists():
            _git("fetch", "--quiet", f"--depth={depth}", "origin", "master", cwd=SIGMA_REPO_DIR)
            _git("checkout", "--quiet", "--detach", "FETCH_HEAD", cwd=SIGMA_REPO_DIR)
        else:
            SIGMA_REPO_DIR.parent.mkdir(parents=True, exist_ok=True)
            _git(
                "clone", "--quiet", "--single-branch", "--branch", "master",
                f"--depth={depth}", REPO_URL, str(SIGMA_REPO_DIR),
            )
        return SIGMA_REPO_DIR
    except (subprocess.SubprocessError, OSError) as e:
        log.warning("SigmaHQ repo unavailable: %s", e)
        return None


def load_rule(path: Path) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.load(f, Loader=_Loader)
        return doc if isinstance(doc, dict) and "detection" in doc else None
    except (OSError, yaml.YAMLError):
        return None


def rule_cves(rule: dict) -> list[str]:
    cves = []
    for tag in rule.get("tags") or []:
        m = _CVE_TAG.match(str(tag))
        if m:
            cves.append(f"CVE-{m.group(1)}-{m.group(2)}")
    text = f"{rule.get('title', '')} {rule.get('description', '')}"
    for c in find_cves(text):
        if c not in cves:
            cves.append(c)
    return cves


class RuleIndex:
    """CVE -> SigmaHQ rule files, built from the local clone."""

    def __init__(self, repo: Path | None):
        self.repo = repo
        self.by_cve: dict[str, list[str]] = {}
        if repo:
            self._build()

    def _build(self) -> None:
        for d in RULE_DIRS:
            for path in (self.repo / d).rglob("*.yml"):
                rule = load_rule(path)
                if not rule or rule.get("status") == "deprecated":
                    continue
                rel = path.relative_to(self.repo).as_posix()
                for cve in rule_cves(rule):
                    self.by_cve.setdefault(cve, []).append(rel)

    def rules_for(self, cves: list[str]) -> list[str]:
        out: list[str] = []
        for c in cves:
            for rel in self.by_cve.get(c, []):
                if rel not in out:
                    out.append(rel)
        return out

    def read(self, rel: str) -> tuple[str, dict] | None:
        path = (self.repo / rel).resolve()
        if self.repo.resolve() not in path.parents:
            return None
        rule = load_rule(path)
        return (path.read_text(encoding="utf-8"), rule) if rule else None


def new_rules(repo: Path | None, since: datetime) -> list[Item]:
    """Rules added to SigmaHQ since `since` (from git history)."""
    if not repo:
        return []
    try:
        out = _git(
            "log", f"--since={since.isoformat()}", "--diff-filter=A", "--name-only",
            "--pretty=format:@@%cI", "--", *RULE_DIRS, cwd=repo,
        )
    except subprocess.SubprocessError as e:
        log.warning("git log on SigmaHQ failed: %s", e)
        return []
    items: list[Item] = []
    when = ""
    seen: set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("@@"):
            when = line[2:]
            continue
        if not line.endswith(".yml") or line in seen:
            continue
        seen.add(line)
        rule = load_rule(repo / line)
        if not rule:
            continue
        logsource = rule.get("logsource") or {}
        items.append(
            Item(
                id=f"sigma-{len(items) + 1}",
                kind="sigma",
                source="SigmaHQ",
                title=str(rule.get("title", line))[:200],
                url=BLOB + line,
                published=when,
                text=str(rule.get("description", ""))[:600],
                cves=rule_cves(rule),
                extra={
                    "path": line,
                    "level": rule.get("level", ""),
                    "logsource": {k: str(v) for k, v in logsource.items() if k in ("product", "category", "service")},
                    "tags": [str(t) for t in rule.get("tags") or []][:12],
                },
            )
        )
    return items
