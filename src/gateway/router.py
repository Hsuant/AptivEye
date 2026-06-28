"""LLM Gateway Router — routes tasks to the right model.

Supports:
- Model tier routing (light/standard/heavy)
- Provider selection (OpenAI / Anthropic / DeepSeek / Local)
- Cost tracking
- Rate limiting
- Sensitive-data-aware routing (auto → local)
"""

from __future__ import annotations

from typing import Any, Optional

from config.model_routing import ModelTier, get_routing_rule
from config.settings import get_settings
from src.gateway.cost_tracker import CostTracker
from src.gateway.providers import LLMResponse
from src.gateway.providers.anthropic import AnthropicProvider
from src.gateway.providers.deepseek import DeepSeekProvider
from src.gateway.providers.local import LocalProvider
from src.gateway.providers.openai import OpenAIProvider
from src.gateway.rate_limiter import RateLimiter
from src.utils.exceptions import (
    ModelUnavailableError,
    ProviderAuthError,
    RateLimitError,
    TokenLimitError,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


class LLMRouter:
    """Routes LLM requests to the appropriate provider and model.

    Usage::

        router = LLMRouter()
        response = await router.generate(
            messages=[{"role": "user", "content": "Analyze this..."}],
            task_type="vulnerability_analysis",
        )
    """

    def __init__(self) -> None:
        settings = get_settings().llm

        self._openai: OpenAIProvider | None = None
        self._anthropic: AnthropicProvider | None = None
        self._deepseek: DeepSeekProvider | None = None
        self._local: LocalProvider | None = None

        # Initialize available providers
        if settings.openai_api_key.get_secret_value():
            self._openai = OpenAIProvider()

        if settings.anthropic_api_key.get_secret_value():
            self._anthropic = AnthropicProvider()

        if settings.deepseek_api_key.get_secret_value():
            self._deepseek = DeepSeekProvider()

        if settings.local_model_enabled:
            self._local = LocalProvider()

        self._cost_tracker = CostTracker()
        self._rate_limiter = RateLimiter()

        self._model_map: dict[ModelTier, str] = {
            ModelTier.LIGHT: settings.light_model,
            ModelTier.STANDARD: settings.standard_model,
            ModelTier.HEAVY: settings.heavy_model,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def generate(
        self,
        messages: list[dict[str, Any]],
        *,
        task_type: str = "default",
        max_tokens: int | None = None,
        temperature: float = 0.0,
        tools: list[dict[str, Any]] | None = None,
        force_model: str | None = None,
        contains_sensitive_data: bool = False,
    ) -> LLMResponse:
        """Route a generation request to the right model.

        Args:
            messages: Chat messages (OpenAI format).
            task_type: Task type from the routing table.
            max_tokens: Override the default token limit.
            temperature: Sampling temperature (0 = deterministic).
            tools: Tool definitions for function calling.
            force_model: Bypass routing and use this specific model.
            contains_sensitive_data: If True, force route to local model.

        Returns:
            Normalized LLMResponse.
        """
        # Sensitive data MUST use local models
        if contains_sensitive_data:
            if self._local is None:
                raise ModelUnavailableError(
                    "Sensitive data detected but no local model is configured. "
                    "Set LOCAL_MODEL_ENABLED=true in .env."
                )
            return await self._call_local(
                messages, model=None, max_tokens=max_tokens or 4096,
                temperature=temperature, tools=tools,
            )

        # Determine model
        if force_model:
            model = force_model
        else:
            rule = get_routing_rule(task_type)
            model = self._model_map[rule.tier]
            if max_tokens is None:
                max_tokens = rule.max_tokens

        max_tokens = max_tokens or 4096

        # Rate limit
        wait = await self._rate_limiter.acquire()
        if wait > 0:
            logger.info("Rate limit — waiting {:.1f}s", wait)
            await self._import_asyncio_sleep(wait)

        # Route to provider based on model name
        provider = self._select_provider_for_model(model)
        return await self._call_provider(
            provider, messages, model=model, max_tokens=max_tokens,
            temperature=temperature, tools=tools,
        )

    async def health_check(self) -> dict[str, bool]:
        """Check health of all configured providers."""
        results: dict[str, bool] = {}
        if self._openai:
            results["openai"] = await self._openai.health_check()
        if self._anthropic:
            results["anthropic"] = await self._anthropic.health_check()
        if self._deepseek:
            results["deepseek"] = await self._deepseek.health_check()
        if self._local:
            results["local"] = await self._local.health_check()
        return results

    @property
    def cost_tracker(self) -> CostTracker:
        return self._cost_tracker

    def usage_summary(self) -> dict:
        return self._cost_tracker.summary()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _select_provider_for_model(self, model: str):
        """Pick the right provider for a model name."""
        model_lower = model.lower()
        if "claude" in model_lower:
            if self._anthropic is None:
                raise ProviderAuthError("ANTHROPIC_API_KEY is not set.")
            return self._anthropic
        if "gpt" in model_lower or "o1" in model_lower or "o3" in model_lower or "o4" in model_lower:
            if self._openai is None:
                raise ProviderAuthError("OPENAI_API_KEY is not set.")
            return self._openai
        if "deepseek" in model_lower:
            if self._deepseek is None:
                raise ProviderAuthError("DEEPSEEK_API_KEY is not set.")
            return self._deepseek
        # Default to OpenAI for unknown models
        if self._openai is not None:
            return self._openai
        if self._anthropic is not None:
            return self._anthropic
        raise ModelUnavailableError(f"No provider available for model: {model}")

    async def _call_provider(
        self,
        provider,
        messages,
        *,
        model: str,
        max_tokens: int,
        temperature: float,
        tools: list[dict[str, Any]] | None,
    ) -> LLMResponse:
        try:
            response = await provider.generate(
                messages=messages,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                tools=tools,
            )
        except Exception as exc:
            logger.error("Provider call failed: {} — {}", provider.provider_name, exc)
            raise LLMGatewayError(f"{provider.provider_name}: {exc}") from exc

        # Track cost
        self._cost_tracker.record(
            provider=response.provider,
            model=response.model,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        )
        return response

    async def _call_local(
        self,
        messages,
        *,
        model: str | None,
        max_tokens: int,
        temperature: float,
        tools: list[dict[str, Any]] | None,
    ) -> LLMResponse:
        assert self._local is not None
        response = await self._local.generate(
            messages=messages,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            tools=tools,
        )
        self._cost_tracker.record(
            provider=response.provider,
            model=response.model,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        )
        return response

    @staticmethod
    async def _import_asyncio_sleep(seconds: float) -> None:
        import asyncio
        await asyncio.sleep(seconds)


class LLMGatewayError(Exception):
    """Wrapper for errors during LLM gateway calls."""
