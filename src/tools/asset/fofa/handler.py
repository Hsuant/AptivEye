"""FOFA tool handler — single MCP entry point for the FOFA sub-tool.

5 modes (pure data operations — no embedded LLM calls):
  - search:    FOFA asset search (field downgrade + dedup)
  - stats:     Statistical aggregation (top-N by country/port/protocol/etc.)
  - host:      Host profiling (IP/domain deep-dive: ports/products/certs/ASN/OS)
  - survival:  HTTP aliveness check on discovered URLs
  - icon_hash: Calculate FOFA icon_hash from favicon.ico for icon-based search

Design principle: this tool fetches data only. AI reasoning (query planning,
result summarization, risk analysis) happens at the agent layer via
src/agent/fofa_planner.py, which uses the agent's injected LLMRouter.
"""

from __future__ import annotations

import base64
from typing import Any

from src.tools.asset.fofa.client import FofaClient
from src.tools.asset.fofa.parser import (
    parse_host_response,
    parse_search_response,
    parse_stats_response,
)
from src.tools.asset.fofa.utils import IconHashCalculator
from src.tools.registry import ToolDefinition
from src.utils.logger import get_logger

logger = get_logger(__name__)


# ── Tool definition ──────────────────────────────────────────────────────

FOFA_TOOL_DEFINITION = ToolDefinition(
    name="fofa",
    description=(
        "Search FOFA (https://fofa.info) for internet-wide scan data. "
        "Five modes: "
        "search (资产查询: FOFA syntax → deduplicated IP/port/protocol/title/server/etc.), "
        "stats (统计聚合: top-N distribution by country/port/protocol/product/os/etc.), "
        "host (Host画像: IP/domain full profile with ports/products/certificates/ASN/OS), "
        "survival (存活检测: concurrent HTTP status check on discovered URLs), "
        "icon_hash (图标哈希: compute FOFA icon_hash from a target's favicon.ico). "
        "Requires FOFA_EMAIL + FOFA_API_KEY in .env. "
        "For AI-powered query planning, use the agent's built-in FOFA planning capability."
    ),
    parameters={
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["search", "stats", "host", "survival", "icon_hash"],
                "default": "search",
                "description": "search | stats | host | survival | icon_hash",
            },
            "query": {
                "type": "string",
                "description": (
                    "FOFA query syntax for search/stats mode, "
                    "IP/domain for host mode, "
                    "target URL for icon_hash mode, "
                    "unused for survival mode"
                ),
            },
            "size": {
                "type": "integer", "default": 100,
                "description": "Max results (search: max 10000, stats: top-N per field)",
            },
            "page": {
                "type": "integer", "default": 1,
                "description": "Page number (search mode)",
            },
            "fields": {
                "type": "string", "default": "",
                "description": (
                    "Custom return fields for search, or stats dimensions for stats. "
                    "Stats options: country,port,protocol,product,product_category,"
                    "domain,os,server,type,city,asn,org,icp"
                ),
            },
            "full": {
                "type": "boolean", "default": False,
                "description": "Include full-year historical data (enterprise only, search mode)",
            },
            "host": {
                "type": "string",
                "description": "Target IP/domain for host mode (overrides query if set)",
            },
            "urls": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of URLs for survival mode, e.g. ['http://1.2.3.4:80']",
            },
            "timeout": {
                "type": "number", "default": 5.0,
                "description": "Per-URL timeout in seconds (survival/icon_hash)",
            },
            "max_concurrent": {
                "type": "integer", "default": 20,
                "description": "Max concurrent checks (survival mode)",
            },
        },
        "required": [],
    },
    category="asset",
    risk_level=1,
)


# ── Unified handler ──────────────────────────────────────────────────────


async def handle_fofa(
    mode: str = "search",
    query: str = "",
    size: int = 100,
    page: int = 1,
    fields: str = "",
    full: bool = False,
    host: str = "",
    urls: list[str] | None = None,
    timeout: float = 5.0,
    max_concurrent: int = 20,
) -> dict[str, Any]:
    """Dispatch to the appropriate FOFA mode handler.

    All modes are pure data operations — no embedded LLM calls.
    For AI-powered query planning, use the agent's FofaQueryPlanner.

    Args:
        mode: search | stats | host | survival | icon_hash
        query: FOFA syntax (search/stats), IP/domain (host), URL (icon_hash)
        Other args are mode-specific — see the tool definition.

    Returns:
        Dict with mode-specific result structure.
    """
    # icon_hash mode doesn't need FOFA credentials
    if mode != "icon_hash":
        client = FofaClient()
        if not client.available:
            return {
                "error": "FOFA not configured. Set FOFA_EMAIL + FOFA_API_KEY in .env"
            }
    else:
        client = None

    if mode == "search":
        assert client is not None
        return await _search(client, query, size, page, fields, full)

    elif mode == "stats":
        assert client is not None
        return await _stats(client, query, fields)

    elif mode == "host":
        assert client is not None
        return await _host(client, host or query)

    elif mode == "survival":
        assert client is not None
        return await _survival(client, urls or [], timeout, max_concurrent)

    elif mode == "icon_hash":
        return await _icon_hash(query, timeout)

    return {"error": f"Unknown mode: {mode}"}


# ── Mode implementations ─────────────────────────────────────────────────


async def _search(
    client: FofaClient,
    query: str,
    size: int,
    page: int,
    fields: str,
    full: bool,
) -> dict[str, Any]:
    """FOFA asset search."""
    results, effective_fields = await client.search(
        query_str=query,
        page=page,
        fields=fields if fields else None,
        size=size,
        full=full,
    )
    if not results:
        qb64 = base64.b64encode(query.encode()).decode()
        return {
            "query": query, "source": "fofa",
            "total_results": 0, "hits": [],
            "query_url": f"{client.web_url}/result?qbase64={qb64}",
        }
    data: dict[str, Any] = {"results": results, "size": len(results)}
    result = parse_search_response(client, query, data, effective_fields)
    return result.model_dump()


async def _stats(
    client: FofaClient,
    query: str,
    fields: str,
) -> dict[str, Any]:
    """FOFA statistical aggregation."""
    stats_fields = fields if fields else "country,port,protocol,product"
    data = await client.stats_search(query_str=query, fields=stats_fields)
    return parse_stats_response(client, query, data, stats_fields)


async def _host(
    client: FofaClient,
    target: str,
) -> dict[str, Any]:
    """FOFA host profiling."""
    target = target.strip().strip("'").strip('"').strip()
    data = await client.host_search(target)
    return parse_host_response(client, target, data)


async def _survival(
    client: FofaClient,
    urls: list[str],
    timeout: float,
    max_concurrent: int,
) -> dict[str, Any]:
    """HTTP aliveness check."""
    results = await client.survival_check(
        urls, timeout=timeout, max_concurrent=max_concurrent,
    )
    alive = sum(1 for v in results.values() if isinstance(v, int) and v < 500)
    return {
        "total": len(urls), "alive": alive, "dead": len(urls) - alive,
        "results": {url: str(code) for url, code in results.items()},
    }


async def _icon_hash(
    target: str,
    timeout: float,
) -> dict[str, Any]:
    """Calculate FOFA icon_hash from favicon."""
    if not target:
        return {"error": "query parameter (target URL) is required for icon_hash mode"}

    icon_query = await IconHashCalculator.get_hash(target, timeout=timeout)
    if icon_query is None:
        return {
            "target": target,
            "icon_hash": None,
            "error": "Failed to compute icon hash — favicon not found or download failed",
        }

    return {
        "target": target,
        "icon_hash": icon_query,
        "fofa_query": icon_query,
    }


def register_fofa_tool(registry: Any) -> None:
    """Register the fofa tool into a ToolRegistry."""
    registry.register(FOFA_TOOL_DEFINITION, handle_fofa)
