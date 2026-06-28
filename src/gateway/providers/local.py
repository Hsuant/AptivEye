"""Local model provider via Ollama."""

from __future__ import annotations

from typing import Any

from config.settings import get_settings
from src.gateway.providers import BaseProvider, LLMResponse
from src.utils.logger import get_logger

logger = get_logger(__name__)


class LocalProvider(BaseProvider):
    """Adapter for locally-hosted models via Ollama."""

    def __init__(self) -> None:
        settings = get_settings().llm
        self._base_url = settings.ollama_base_url
        self._model_name = settings.local_model_name
        self._enabled = settings.local_model_enabled
        self._healthy: bool | None = None

    @property
    def provider_name(self) -> str:
        return "local"

    async def generate(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        """Send completion request to Ollama.

        Uses httpx for minimal dependency footprint. Falls back gracefully
        if Ollama is not running.
        """
        import json

        import httpx

        model_name = model or self._model_name
        url = f"{self._base_url}/api/chat"

        payload: dict[str, Any] = {
            "model": model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        if tools:
            payload["tools"] = tools

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPError as exc:
            logger.error("Ollama API call failed: {}", exc)
            raise ConnectionError(f"Failed to reach Ollama at {self._base_url}: {exc}") from exc

        message = data.get("message", {})
        content = message.get("content", "")

        # Ollama doesn't give exact token counts — estimate
        estimated_input = sum(len(m.get("content", "")) // 4 for m in messages)
        estimated_output = len(content) // 4

        return LLMResponse(
            content=content,
            model=model_name,
            provider="local",
            input_tokens=estimated_input,
            output_tokens=estimated_output,
            finish_reason="stop",
            raw=data,
        )

    async def health_check(self) -> bool:
        """Check if Ollama is reachable."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self._base_url}/api/tags")
                response.raise_for_status()
            self._healthy = True
            return True
        except Exception:
            self._healthy = False
            return False
