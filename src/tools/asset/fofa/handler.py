"""FOFA tool handler — single MCP entry point with mode dispatch.

Exposes one 'fofa' tool with 4 modes:
  - search:   普通查询 (field downgrade + dedup)
  - stats:    统计聚合 (top-N distribution by fields)
  - host:     Host 画像 (IP/domain deep-dive profile)
  - survival: 存活检测 (HTTP status check on discovered URLs)
"""

from __future__ import annotations

from typing import Any

from src.tools.asset.fofa.client import FofaClient
from src.tools.asset.fofa.parser import (
    parse_host_response,
    parse_search_response,
    parse_stats_response,
)
from src.tools.registry import ToolDefinition


# ── Single tool definition ──────────────────────────────────────────────

FOFA_TOOL_DEFINITION = ToolDefinition(
    name="fofa",
    description=(
        "Search FOFA (https://fofa.info) for internet-wide scan data. "
        "Four modes: search (普通查询, field downgrade + dedup), "
        "stats (统计聚合, top-N by country/port/protocol/etc.), "
        "host (Host 画像, IP/domain full profile: ports/products/certs/ASN/OS), "
        "survival (存活检测, concurrent HTTP status check on URLs). "
        "Requires FOFA_EMAIL + FOFA_API_KEY in .env."
    ),
    parameters={
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["search", "stats", "host", "survival"],
                "default": "search",
                "description": "Query mode: search (普通查询) | stats (统计聚合) | host (Host画像) | survival (存活检测)",
            },
            "query": {
                "type": "string",
                "description": "FOFA query syntax for search/stats mode, or IP/domain for host mode, or unused for survival",
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
                "description": "Custom return fields (search) or stats dimensions (stats). Stats options: country,port,protocol,product,product_category,domain,os,server,type,city,asn,org,icp",
            },
            "full": {
                "type": "boolean", "default": False,
                "description": "Include full-year historical data (enterprise only, search mode)",
            },
            "host": {
                "type": "string",
                "description": "Target IP/domain for host mode",
            },
            "urls": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of URLs for survival mode, e.g. ['http://1.2.3.4:80']",
            },
            "timeout": {
                "type": "number", "default": 5.0,
                "description": "Per-URL timeout in seconds (survival mode)",
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


# ── Unified handler ─────────────────────────────────────────────────────


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
    """Dispatch FOFA query to the appropriate mode handler.

    Args:
        mode:   "search" | "stats" | "host" | "survival"
        query:  FOFA syntax (search/stats) or IP/domain (host)
        size:   Max results
        page:   Page number (search)
        fields: Custom fields (search) or stats dimensions (stats)
        full:   Full-year data flag (search)
        host:   Target for host mode (overrides query if set)
        urls:   URL list for survival mode
        timeout: Per-URL timeout (survival)
        max_concurrent: Concurrency limit (survival)

    Returns:
        Dict with mode-specific result structure.
    """
    client = FofaClient()
    if not client.available:
        return {"error": "FOFA not configured. Set FOFA_EMAIL + FOFA_API_KEY in .env"}

    # ── search mode ──
    if mode == "search":
        results, effective_fields = await client.search(
            query_str=query,
            page=page,
            fields=fields if fields else None,
            size=size,
            full=full,
        )
        if not results:
            import base64
            qb64 = base64.b64encode(query.encode()).decode()
            return {
                "query": query, "source": "fofa",
                "total_results": 0, "hits": [],
                "query_url": f"{client.web_url}/result?qbase64={qb64}",
            }
        data: dict[str, Any] = {"results": results, "size": len(results)}
        result = parse_search_response(client, query, data, effective_fields)
        return result.model_dump()

    # ── stats mode ──
    elif mode == "stats":
        stats_fields = fields if fields else "country,port,protocol,product"
        data = await client.stats_search(query_str=query, fields=stats_fields)
        return parse_stats_response(client, query, data, stats_fields)

    # ── host mode ──
    elif mode == "host":
        target = str(host or query).strip().strip("'").strip('"').strip()
        data = await client.host_search(target)
        return parse_host_response(client, target, data)

    # ── survival mode ──
    elif mode == "survival":
        url_list = urls or []
        results = await client.survival_check(
            url_list, timeout=timeout, max_concurrent=max_concurrent,
        )
        alive = sum(1 for v in results.values() if isinstance(v, int) and v < 500)
        return {
            "total": len(url_list),
            "alive": alive,
            "dead": len(url_list) - alive,
            "results": {url: str(code) for url, code in results.items()},
        }

    return {"error": f"Unknown mode: {mode}"}


def register_fofa_tool(registry: Any) -> None:
    """Register the single fofa tool into a ToolRegistry."""
    registry.register(FOFA_TOOL_DEFINITION, handle_fofa)
