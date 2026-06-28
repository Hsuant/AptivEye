"""Provider abstraction layer for LLM Gateway."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass(frozen=True)
class LLMResponse:
    """Normalized response from any LLM provider."""

    content: str
    model: str
    provider: str  # "openai" | "anthropic" | "local"
    input_tokens: int
    output_tokens: int
    finish_reason: str  # "stop" | "length" | "tool_call" | "error"
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    raw: Any = None  # Raw provider response for debugging


class BaseProvider(ABC):
    """Abstract base for LLM provider adapters."""

    @abstractmethod
    async def generate(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        """Send a chat completion request to the provider."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the provider is reachable and authenticated."""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique provider identifier."""
        ...
