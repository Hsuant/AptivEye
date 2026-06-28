"""零零信安 — security data aggregation platform.

Query 零零信安 (https://0zero.cn) for organization security intelligence.
"""

from __future__ import annotations

from typing import Any

import httpx

from config.settings import get_settings
from src.tools.asset.models import OrgIntelItem, OrgIntelResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


async def query_lingling(
    keyword: str,
    timeout: float = 15.0,
) -> OrgIntelResult:
    """Query 零零信安 security data platform for organization intelligence."""
    settings = get_settings().asset_api
    api_key = settings.lingling_api_key.get_secret_value()
    api_url = settings.lingling_api_url.rstrip("/")

    if not api_key:
        return OrgIntelResult(
            query=keyword,
            error="零零信安 API key not configured. Set LINGLING_API_KEY in .env",
        )

    items: list[OrgIntelItem] = []
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                f"{api_url}/api/search",
                params={"keyword": keyword, "token": api_key},
                headers={"User-Agent": "AptivEye/0.1"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("data", data.get("results", [])):
                    items.append(OrgIntelItem(
                        data_type=item.get("type", ""),
                        value=item.get("value", ""),
                        description=item.get("description", ""),
                        risk_level=item.get("risk", ""),
                        source=item.get("source", ""),
                        found_date=item.get("date", ""),
                    ))
    except Exception as exc:
        logger.error("零零信安 API error: {}", exc)
        return OrgIntelResult(query=keyword, error=str(exc))

    return OrgIntelResult(
        query=keyword,
        items=items,
        total_found=len(items),
        categories=list({i.data_type for i in items}),
        sources=list({i.source for i in items}),
    )
