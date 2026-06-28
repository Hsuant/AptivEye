"""Anthropic (Claude) provider adapter."""

from __future__ import annotations

from typing import Any

from langchain_anthropic import ChatAnthropic

from config.settings import get_settings
from src.gateway.providers import BaseProvider, LLMResponse
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AnthropicProvider(BaseProvider):
    """Adapter for Anthropic Claude models."""

    def __init__(self) -> None:
        settings = get_settings().llm
        self._api_key = settings.anthropic_api_key.get_secret_value()
        self._healthy: bool | None = None

    @property
    def provider_name(self) -> str:
        return "anthropic"

    async def generate(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        """Send completion request via LangChain Anthropic client."""
        if not self._api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set.")

        llm = ChatAnthropic(
            model=model,
            api_key=self._api_key,
            max_tokens=max_tokens,
            temperature=temperature,
        )

        if tools:
            llm = llm.bind_tools(tools)

        try:
            response = await llm.ainvoke([{"role": m["role"], "content": m["content"]} for m in messages])  # type: ignore[arg-type]
        except Exception as exc:
            logger.error("Anthropic API call failed: {}", exc)
            raise

        usage = response.response_metadata.get("usage", {})
        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)

        tool_calls = []
        if hasattr(response, "tool_calls") and response.tool_calls:
            tool_calls = [
                {"id": tc.get("id", ""), "name": tc["name"], "arguments": tc["args"]}
                for tc in response.tool_calls
            ]

        content = response.content if hasattr(response, "content") else str(response)

        return LLMResponse(
            content=str(content) if content else "",
            model=model,
            provider="anthropic",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            finish_reason="tool_call" if tool_calls else "stop",
            tool_calls=tool_calls,
            raw=response,
        )

    async def health_check(self) -> bool:
        """Verify the API key works."""
        if not self._api_key:
            self._healthy = False
            return False

        try:
            await self.generate(
                messages=[{"role": "user", "content": "ping"}],
                model="claude-haiku-4-5-20251001",
                max_tokens=5,
            )
            self._healthy = True
            return True
        except Exception:
            self._healthy = False
            return False
