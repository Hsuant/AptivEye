"""Token cost tracker — monitors LLM usage across providers."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


# Approximate pricing per 1K tokens (USD) — update as pricing changes
PRICING: dict[str, dict[str, float]] = {
    "gpt-4o-mini":      {"input": 0.00015, "output": 0.00060},
    "gpt-4o":           {"input": 0.00250, "output": 0.01000},
    "gpt-4-turbo":      {"input": 0.01000, "output": 0.03000},
    "claude-haiku-4-5-20251001":  {"input": 0.00100, "output": 0.00500},
    "claude-sonnet-4-6":          {"input": 0.00300, "output": 0.01500},
    "claude-opus-4-8":            {"input": 0.01500, "output": 0.07500},
    # Local models are free
}


@dataclass
class UsageRecord:
    """A single LLM call's usage."""

    timestamp: float = field(default_factory=time.time)
    provider: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0


@dataclass
class CostTracker:
    """Tracks cumulative token usage and estimated cost.

    Thread-safe for use across workers.
    """

    records: list[UsageRecord] = field(default_factory=list)

    def record(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> UsageRecord:
        """Record a single LLM call and return the record."""
        cost = self._estimate_cost(model, input_tokens, output_tokens)
        record = UsageRecord(
            timestamp=time.time(),
            provider=provider,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost_usd=cost,
        )
        self.records.append(record)
        logger.debug(
            "LLM call: provider={} model={} in={} out={} cost=${:.6f}",
            provider,
            model,
            input_tokens,
            output_tokens,
            cost,
        )
        return record

    @property
    def total_input_tokens(self) -> int:
        return sum(r.input_tokens for r in self.records)

    @property
    def total_output_tokens(self) -> int:
        return sum(r.output_tokens for r in self.records)

    @property
    def total_cost_usd(self) -> float:
        return sum(r.estimated_cost_usd for r in self.records)

    def summary(self) -> dict:
        """Return a summary of all usage."""
        return {
            "calls": len(self.records),
            "input_tokens": self.total_input_tokens,
            "output_tokens": self.total_output_tokens,
            "total_tokens": self.total_input_tokens + self.total_output_tokens,
            "cost_usd": round(self.total_cost_usd, 6),
            "by_model": self._by_model(),
        }

    def _by_model(self) -> dict[str, dict]:
        by_model: dict[str, dict] = {}
        for r in self.records:
            if r.model not in by_model:
                by_model[r.model] = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
            by_model[r.model]["calls"] += 1
            by_model[r.model]["input_tokens"] += r.input_tokens
            by_model[r.model]["output_tokens"] += r.output_tokens
            by_model[r.model]["cost_usd"] += r.estimated_cost_usd
        return by_model

    @staticmethod
    def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost based on approximate per-token pricing."""
        pricing = PRICING.get(model)
        if pricing is None:
            # Unknown model — try prefix match
            for known, p in PRICING.items():
                if model.startswith(known):
                    pricing = p
                    break

        if pricing is None:
            return 0.0  # Unknown — assume free/local

        input_cost = (input_tokens / 1000) * pricing["input"]
        output_cost = (output_tokens / 1000) * pricing["output"]
        return input_cost + output_cost

    def reset(self) -> None:
        """Clear all records."""
        self.records.clear()
