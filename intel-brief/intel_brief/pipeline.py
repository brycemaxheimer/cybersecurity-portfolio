"""Runs the five steps and writes data/editions/<date>.json and data/runs/<date>.json."""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, timezone

from . import __version__, detections, explainer, receipts, signals
from .collect import Collection, collect_all, nvd, poc
from .config import CACHE_DIR, EDITIONS_DIR, RUNS_DIR
from .detections import sigma_repo
from .llm import LLM, BudgetExceeded
from .models import Item, find_cves
from .safety import clean_model_text
from .triage import _chatter_items, triage
from .writeup import write_story

log = logging.getLogger(__name__)

SOURCE_ORDER = {"advisory": 0, "news": 1, "kev": 2, "nvd": 3, "sigma": 4}


def _previous_kev(run_date: date, keep: int = 5) -> set[str]:
    out: set[str] = set()
    for p in sorted(EDITIONS_DIR.glob("*.json"), reverse=True):
        if p.stem >= run_date.isoformat():
            continue
        try:
            out.update(k["cve"] for k in json.loads(p.read_text(encoding="utf-8")).get("kev_new", []))
        except (OSError, ValueError, KeyError):
            continue
        keep -= 1
        if keep == 0:
            break
    return out


def _recent_concepts(run_date: date, keep: int) -> list[str]:
    """Explainer topics from earlier editions, newest first, so they don't repeat."""
    out: list[str] = []
    for p in sorted(EDITIONS_DIR.glob("*.json"), reverse=True):
        if p.stem >= run_date.isoformat() or len(out) >= keep:
            continue
        try:
            concept = (json.loads(p.read_text(encoding="utf-8")).get("explainer") or {}).get("concept")
        except (OSError, ValueError):
            continue
        if concept:
            out.append(concept)
    return out


def without_good_news(more: list[dict], good_news: list[dict]) -> list[dict]:
    """Drop "Also on the radar" entries whose links already appear under Good news."""
    urls = {src["url"] for g in good_news for src in g["sources"]}
    return [m for m in more if not urls.intersection(src["url"] for src in m["sources"])]


def _cache_path(run_date: date):
    return CACHE_DIR / "runs" / run_date.isoformat() / "collection.json"


def _save_collection(col: Collection, run_date: date) -> None:
    path = _cache_path(run_date)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "items": [i.to_dict() for i in col.items],
                "kev_catalog_cves": sorted(col.kev_catalog_cves),
                "epss": col.epss,
                "status": col.status,
                "since": col.since,
                "until": col.until,
            }
        ),
        encoding="utf-8",
    )


def _load_collection(run_date: date) -> Collection | None:
    path = _cache_path(run_date)
    if not path.exists():
        return None
    d = json.loads(path.read_text(encoding="utf-8"))
    return Collection(
        items=[Item.from_dict(i) for i in d["items"]],
        kev_catalog_cves=set(d["kev_catalog_cves"]),
        epss=d["epss"],
        status=d["status"],
        since=d["since"],
        until=d["until"],
    )


def _cve_facts(cves, col, nvd_by_cve, kev_new, pocs, rule_index) -> list[dict]:
    out = []
    for c in cves:
        n = nvd_by_cve.get(c, {})
        e = col.epss.get(c, {})
        out.append(
            {
                "id": c,
                "cvss": n.get("cvss"),
                "severity": n.get("severity", ""),
                "products": n.get("products", [])[:5],
                "epss": e.get("epss"),
                "percentile": e.get("percentile"),
                "in_kev": c in col.kev_catalog_cves,
                "kev_due": kev_new.get(c, {}).get("due_date"),
                "poc": pocs.get(c, []),
                "sigmahq_rules": len(rule_index.rules_for([c])) if rule_index else 0,
            }
        )
    return out


def run(
    run_date: date,
    settings: dict,
    sources: dict,
    *,
    max_cost: float,
    writeup_model: str,
    top_n: int,
    dry_run: bool = False,
    from_cache: bool = False,
) -> dict:
    started = datetime.now(timezone.utc)
    repo = sigma_repo.ensure_repo()

    col = _load_collection(run_date) if from_cache else None
    if col is None:
        col = collect_all(run_date, settings, sources, _previous_kev(run_date), repo)
        _save_collection(col, run_date)
    log.info("collected %d items: %s", len(col.items), col.status)

    llm = LLM(max_cost, dry_run=dry_run)
    stories, triage_method = triage(col, llm, settings["models"]["triage"])
    picked = [s for s in stories if s.score >= settings["edition"]["min_score"]][:top_n]
    log.info("triage (%s): %d stories, %d picked", triage_method, len(stories), len(picked))

    items = {**col.by_id(), **{i.id: i for i in _chatter_items(col)}}
    rule_index = sigma_repo.RuleIndex(repo)
    nvd_by_cve = {i.cves[0]: i.extra for i in col.of_kind("nvd")}
    kev_new = {i.cves[0]: i.extra for i in col.of_kind("kev")}

    story_cves = list(dict.fromkeys(c for s in picked for c in s.cves[:4]))
    missing = [c for c in story_cves if c not in nvd_by_cve]
    signal_list = signals.find(col, settings["signals"]["min_authors"], settings["signals"]["max_signals"])
    missing += [s["cve"] for s in signal_list if s["cve"] not in nvd_by_cve]
    nvd_by_cve.update(nvd.lookup(list(dict.fromkeys(missing)), limit=20))
    pocs = poc.lookup(story_cves + [s["cve"] for s in signal_list])

    effort = settings["models"].get("writeup_effort", "medium")
    text_chars = settings["collect"]["item_text_chars"]
    out_stories, dets = [], {}
    budget_hit = dry_run
    for rank, s in enumerate(picked, 1):
        sid = f"story-{rank}"
        facts = _cve_facts(s.cves[:6], col, nvd_by_cve, kev_new, pocs, rule_index)
        enrich = {
            f["id"]: {
                "cvss": f["cvss"], "severity": f["severity"], "products": f["products"],
                "epss": f["epss"], "in_kev": f["in_kev"], "kev_due_date": f["kev_due"],
                "public_poc_exists": bool(f["poc"]), "existing_sigmahq_rule": f["sigmahq_rules"] > 0,
            }
            for f in facts
        }
        wu, status, wu_model = None, "skipped_budget" if budget_hit else "failed", writeup_model
        if not budget_hit:
            try:
                wu = write_story(s, items, col, enrich, llm, writeup_model, effort, text_chars)
                status = "ok" if wu else "refused_or_failed"
                wu_model = explainer.served_by(llm, writeup_model)
            except BudgetExceeded as e:
                log.warning("%s", e)
                budget_hit, status = True, "skipped_budget"
        if dry_run:
            status = "skipped_dry_run"

        members = [items[i] for i in s.item_ids if i in items and items[i].url]
        cited = set(wu.source_item_ids) if wu else set()
        members.sort(key=lambda it: (it.id not in cited, SOURCE_ORDER.get(it.kind, 9), it.published))
        srcs = [
            {"title": it.title[:200], "url": it.url, "source": it.source, "kind": it.kind, "published": it.published}
            for it in members[:8]
        ]
        evidence = "\n".join(f"{it.title}\n{it.text}" for it in members)
        try:
            det = detections.build(
                s, wu, rule_index, [x["url"] for x in srcs], evidence, run_date.isoformat(),
                llm=None if budget_hit else llm, model=writeup_model, effort=effort,
                retry=settings["detections"]["sigma_retry_on_fail"],
            )
        except BudgetExceeded as e:
            log.warning("%s", e)
            budget_hit = True
            det = detections.build(s, wu, rule_index, [x["url"] for x in srcs], evidence, run_date.isoformat())
        dets[sid] = det

        out_stories.append(
            {
                "id": sid,
                "rank": rank,
                "score": s.score,
                "factors": s.factors,
                "title": clean_model_text(wu.headline, 120) if wu else s.title,
                "labels": {
                    "category": s.category, "exploitation": s.exploitation, "prevalence": s.prevalence,
                    "platform": s.platform, "vendor": s.vendor, "product": s.product,
                },
                "cves": facts,
                "writeup_status": status,
                "writeup": None if not wu else {
                    "what_happened": clean_model_text(wu.what_happened, 1500),
                    "why_it_matters": clean_model_text(wu.why_it_matters, 1200),
                    "affected_versions": [clean_model_text(x, 200) for x in wu.affected_versions][:10],
                    "fixed_versions": [clean_model_text(x, 200) for x in wu.fixed_versions][:10],
                    "recommended_actions": [clean_model_text(x, 300) for x in wu.recommended_actions][:5],
                    "confidence": wu.confidence,
                    "model": wu_model,
                    # CVE IDs the model wrote that no source item contains: shown as a warning.
                    "unsupported_cves": [
                        c for c in find_cves(" ".join([wu.what_happened, wu.why_it_matters, *wu.affected_versions,
                                                       *wu.fixed_versions, *wu.recommended_actions]))
                        if c not in find_cves(evidence) and c not in s.cves
                    ],
                },
                "sources": srcs,
                "detection": det,
            }
        )

    kql_parser = detections.validate_all(dets)
    # Free: runs on the local Kusto emulator. Without one, pages keep "untested".
    receipt_status = receipts.run(dets)
    log.info("receipts: %s", receipt_status.get("reason") or receipts.summarize(dets))

    # Explainer and good news: one call, only after every story had its turn.
    ex_cfg = settings.get("explainer", {})
    ex, good_news, ex_status = None, [], "disabled"
    if ex_cfg.get("enabled", False):
        ex_status = "skipped_dry_run" if dry_run else "skipped_budget"
        if not budget_hit:
            try:
                ex, good_news = explainer.write(
                    out_stories, col, _recent_concepts(run_date, ex_cfg.get("history_editions", 30)),
                    llm, writeup_model, effort, ex_cfg,
                )
                ex_status = "ok" if ex or good_news else "refused_or_failed"
            except BudgetExceeded as e:
                log.warning("%s", e)

    edition = {
        "schema": 1,
        "date": run_date.isoformat(),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator": f"intel-brief {__version__}",
        "models": {"triage": settings["models"]["triage"], "writeup": writeup_model, "triage_method": triage_method},
        "window": {"since": col.since, "until": col.until},
        "stories": out_stories,
        "more_stories": without_good_news([
            {"title": s.title, "score": s.score, "cves": s.cves[:3],
             "sources": [{"title": items[i].title[:200], "url": items[i].url, "source": items[i].source}
                         for i in s.item_ids if i in items and items[i].url][:3]}
            for s in stories[len(picked):len(picked) + 15 + len(good_news)]
        ], good_news)[:15],
        "kev_new": [
            {
                "cve": i.cves[0], "vendor": i.extra["vendor"], "product": i.extra["product"],
                "name": i.extra["name"], "date_added": i.extra["date_added"], "due_date": i.extra["due_date"],
                "ransomware": i.extra["ransomware"], "url": i.url,
            }
            for i in col.of_kind("kev")
        ],
        "early_signals": [
            {**sig, "nvd": {k: nvd_by_cve.get(sig["cve"], {}).get(k) for k in ("cvss", "severity", "products", "description")},
             "poc": pocs.get(sig["cve"], [])}
            for sig in signal_list
        ],
        "explainer": ex,
        "good_news": good_news,
        "explainer_status": ex_status,
        "sources_status": col.status,
        "stats": {
            "items": {k: len(col.of_kind(k)) for k in ("news", "advisory", "kev", "nvd", "social", "sigma")},
            "stories_found": len(stories),
            "kql_parser": kql_parser,
            "receipts": receipt_status,
        },
    }
    for sig in edition["early_signals"]:
        desc = sig["nvd"].get("description") or ""
        sig["nvd"]["description"] = desc[:300] + ("…" if len(desc) > 300 else "")

    EDITIONS_DIR.mkdir(parents=True, exist_ok=True)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    (EDITIONS_DIR / f"{run_date.isoformat()}.json").write_text(
        json.dumps(edition, indent=1, ensure_ascii=False), encoding="utf-8"
    )
    run_log = {
        "date": run_date.isoformat(),
        "started": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "finished": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dry_run": dry_run,
        "writeup_model": writeup_model,
        "budget_hit": budget_hit and not dry_run,
        "cost": llm.summary(),
        "sources_status": col.status,
    }
    (RUNS_DIR / f"{run_date.isoformat()}.json").write_text(json.dumps(run_log, indent=1), encoding="utf-8")
    log.info("run cost $%.4f (cap $%.2f)", llm.spent, max_cost)
    return run_log
