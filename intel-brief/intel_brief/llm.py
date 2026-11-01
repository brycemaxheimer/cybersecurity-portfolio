"""Claude API wrapper: structured output only, hard cost cap, usage log.

Every call:
- sends no tools, so the model can't act on anything; it can only return JSON
  that matches a fixed Pydantic schema (structured outputs)
- puts the stable system prompt first with a cache breakpoint
- checks the budget against the worst case before it is sent
- logs tokens and cost, and returns None on a refusal or a truncated reply
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass

import anthropic
from pydantic import BaseModel, ValidationError

log = logging.getLogger(__name__)

# USD per million tokens: input, output, 5-minute cache write, cache read.
PRICES: dict[str, tuple[float, float, float, float]] = {
    "claude-opus-5-5": (4.00, 20.00, 5.00, 0.20),
    "claude-sonnet-5-5": (2.00, 10.00, 2.50, 0.20),
    "claude-haiku-5-5": (0.10, 0.50, 0.125, 0.01),
    # Where server-side fallback sends cyber-category refusals.
    "claude-opus-4-8": (5.00, 25.00, 6.25, 0.50),
    "claude-opus-5": (5.00, 25.00, 6.25, 0.50),
}
# Claude Haiku 5.5 bills prompts over 100K tokens at a higher rate.
HAIKU_LONG = (0.50, 2.50, 0.625, 0.05)
UNKNOWN = (10.00, 50.00, 12.50, 1.00)  # priced high so the cap stays safe
FALLBACK_MODEL_FOR_BUDGET = "claude-opus-4-8"
# Models that accept fallbacks: "default" (Haiku has no server-side fallback).
FALLBACK_CAPABLE = {"claude-opus-5-5", "claude-sonnet-5-5"}
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# A dedicated variable, passed explicitly. Never ANTHROPIC_API_KEY: a user-level
# ANTHROPIC_API_KEY would also switch Claude Code on this machine to API billing.
API_KEY_ENV = "INTEL_BRIEF_ANTHROPIC_API_KEY"
# Pinned so a stray ANTHROPIC_BASE_URL in the environment can't send the key elsewhere.
API_BASE_URL = "https://api.anthropic.com"


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class CallRecord:
    stage: str
    model: str
    served_by: str
    input_tokens: int
    cache_write_tokens: int
    cache_read_tokens: int
    output_tokens: int
    cost_usd: float
    stop_reason: str
    refusal_category: str | None
    request_id: str | None
    seconds: float
    note: str = ""


def price(model: str, prompt_tokens: int = 0) -> tuple[float, float, float, float]:
    if model == "claude-haiku-5-5" and prompt_tokens > 100_000:
        return HAIKU_LONG
    return PRICES.get(model, UNKNOWN)


def cost_of(model: str, usage) -> float:
    inp = getattr(usage, "input_tokens", 0) or 0
    cw = getattr(usage, "cache_creation_input_tokens", 0) or 0
    cr = getattr(usage, "cache_read_input_tokens", 0) or 0
    out = getattr(usage, "output_tokens", 0) or 0
    p_in, p_out, p_cw, p_cr = price(model, inp + cw + cr)
    return (inp * p_in + cw * p_cw + cr * p_cr + out * p_out) / 1_000_000


class LLM:
    def __init__(self, max_cost_usd: float, dry_run: bool = False):
        self.max_cost = max_cost_usd
        self.dry_run = dry_run
        self.calls: list[CallRecord] = []
        self.client = None
        if not dry_run:
            key = os.environ.get(API_KEY_ENV)
            if not key:
                raise SystemExit(f"{API_KEY_ENV} is not set (use --dry-run to build without model calls)")
            self.client = anthropic.Anthropic(api_key=key, base_url=API_BASE_URL, max_retries=3, timeout=600)

    @property
    def spent(self) -> float:
        return sum(c.cost_usd for c in self.calls)

    def worst_case(self, model: str, prompt_chars: int, max_tokens: int, fallbacks: bool) -> float:
        est_in = prompt_chars / 3.0 + 200  # generous: real text runs ~4 chars/token
        models = [model] + ([FALLBACK_MODEL_FOR_BUDGET] if fallbacks else [])
        p = [price(m, int(est_in)) for m in models]
        return (est_in * max(x[2] for x in p) + max_tokens * max(x[1] for x in p)) / 1_000_000

    def can_afford(self, model: str, prompt_chars: int, max_tokens: int, fallbacks: bool = True) -> bool:
        fb = fallbacks and model in FALLBACK_CAPABLE
        return self.spent + self.worst_case(model, prompt_chars, max_tokens, fb) <= self.max_cost

    def parse(
        self,
        *,
        stage: str,
        model: str,
        system: str,
        user: str,
        schema: type[BaseModel],
        max_tokens: int,
        effort: str | None = None,
    ) -> BaseModel | None:
        if self.dry_run:
            raise BudgetExceeded("dry run: no model calls")
        fallbacks = model in FALLBACK_CAPABLE
        worst = self.worst_case(model, len(system) + len(user), max_tokens, fallbacks)
        if self.spent + worst > self.max_cost:
            raise BudgetExceeded(
                f"{stage}: worst case ${worst:.3f} would pass the ${self.max_cost:.2f} cap "
                f"(spent ${self.spent:.3f})"
            )

        # messages.create with an explicit JSON schema rather than messages.parse:
        # parse() validates before we can look at stop_reason, so a refusal or a
        # truncated reply would raise without usage and the cost would go unlogged.
        output_config: dict = {
            "format": {"type": "json_schema", "schema": anthropic.transform_schema(schema.model_json_schema())}
        }
        if effort:
            output_config["effort"] = effort
        kwargs: dict = dict(
            model=model,
            max_tokens=max_tokens,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user}],
            output_config=output_config,
        )

        start = time.monotonic()
        if fallbacks:
            resp = self.client.beta.messages.create(betas=[FALLBACK_BETA], fallbacks="default", **kwargs)
        else:
            resp = self.client.messages.create(**kwargs)
        rec = self._record(stage, model, resp, time.monotonic() - start)

        if resp.stop_reason == "refusal":
            log.warning("%s: refused (%s)", stage, rec.refusal_category)
            return None
        if resp.stop_reason == "max_tokens":
            log.warning("%s: hit max_tokens=%d", stage, max_tokens)
            rec.note = "truncated at max_tokens"
            return None
        # Text after the last fallback block is the reply from the model that finished.
        parts: list[str] = []
        for block in resp.content:
            if block.type == "fallback":
                parts = []
            elif block.type == "text":
                parts.append(block.text)
        try:
            return schema.model_validate_json("".join(parts))
        except (ValidationError, json.JSONDecodeError, ValueError) as e:
            rec.note = f"schema validation failed: {e}"[:300]
            log.warning("%s: %s", stage, rec.note)
            return None

    def _record(self, stage, model, resp, seconds) -> CallRecord:
        u = resp.usage
        served = getattr(resp, "model", model) or model
        details = getattr(resp, "stop_details", None)
        rec = CallRecord(
            stage=stage,
            model=model,
            served_by=served,
            input_tokens=u.input_tokens or 0,
            cache_write_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0,
            cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
            output_tokens=u.output_tokens or 0,
            # Priced at whichever model served the turn. If a fallback ran,
            # the declined attempt's tokens may be billed too; the note flags it.
            cost_usd=round(cost_of(served, u), 6),
            stop_reason=resp.stop_reason or "",
            refusal_category=getattr(details, "category", None) if details else None,
            request_id=getattr(resp, "_request_id", None),
            seconds=round(seconds, 1),
            note="served by fallback model" if served != model else "",
        )
        self.calls.append(rec)
        log.info(
            "%-16s %-18s in=%-6d cw=%-6d cr=%-6d out=%-6d $%.4f  %s",
            stage, rec.served_by or model, rec.input_tokens, rec.cache_write_tokens,
            rec.cache_read_tokens, rec.output_tokens, rec.cost_usd, rec.stop_reason,
        )
        return rec

    def summary(self) -> dict:
        by_stage: dict[str, float] = {}
        for c in self.calls:
            by_stage[c.stage.split(":")[0]] = round(by_stage.get(c.stage.split(":")[0], 0) + c.cost_usd, 6)
        return {
            "max_cost_usd": self.max_cost,
            "total_cost_usd": round(self.spent, 4),
            "by_stage": by_stage,
            "calls": [asdict(c) for c in self.calls],
            "tokens": {
                k: sum(getattr(c, k) for c in self.calls)
                for k in ("input_tokens", "cache_write_tokens", "cache_read_tokens", "output_tokens")
            },
        }
