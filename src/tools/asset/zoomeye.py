"""ZoomEye cyberspace mapping engine client.

ZoomEye (https://zoomeye.org) — KnownSec's cyberspace mapping engine.
Auth: API key → JWT access token.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from config.settings import get_settings
from src.tools.asset.models import NetworkSearchHit, NetworkSearchResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ZoomEyeClient:
    """ZoomEye API v2 client.

    Auth: API key in header (API-KEY).
    Docs: https://www.zoomeye.org/doc
    """

    def __init__(self, api_key: str = "", api_url: str = "") -> None:
        settings = get_settings().asset_api
        self._api_key = api_key or settings.zoomeye_api_key.get_secret_value()
        self._base_url = (api_url or settings.zoomeye_api_url).rstrip("/")
        self._web_url = settings.zoomeye_web_url.rstrip("/")
        self._configured = bool(self._api_key)
        self._access_token: Optional[str] = None

    @property
    def available(self) -> bool:
        return self._configured

    async def _login(self) -> bool:
        """Obtain ZoomEye JWT access token."""
        if self._access_token:
            return True
        if not self._configured:
            return False

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{self._base_url}/user/login",
                    json={"username": "", "password": self._api_key},
                )
                data = resp.json()
                if "access_token" in data:
                    self._access_token = data["access_token"]
                    return True
        except Exception as exc:
            logger.warning("ZoomEye login failed: {}", exc)
        return False

    async def search(
        self,
        query: str,
        *,
        search_type: str = "host",  # "host" or "web"
        page: int = 1,
        pagesize: int = 20,
        facets: str = "",
        timeout: float = 30.0,
    ) -> NetworkSearchResult:
        """Execute a ZoomEye search query."""
        if not self._configured:
            return NetworkSearchResult(
                query=query, source="zoomeye",
                error="ZoomEye API not configured. Set ZOOMEYE_API_KEY in .env",
            )

        if not await self._login():
            return NetworkSearchResult(query=query, source="zoomeye", error="ZoomEye login failed")

        url = f"{self._base_url}/{search_type}/search"
        headers = {
            "Authorization": f"JWT {self._access_token}",
            "API-KEY": self._api_key,
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(
                    url,
                    params={"query": query, "page": page, "pagesize": pagesize, "facets": facets},
                    headers=headers,
                )
                resp.raise_for_status()
                try:
                    data = resp.json()
                except Exception:
                    text = resp.text[:500]
                    logger.error("ZoomEye returned non-JSON: {}", text)
                    return NetworkSearchResult(
                        query=query, source="zoomeye",
                        error=f"ZoomEye returned non-JSON response (HTTP {resp.status_code}): {text}",
                    )
        except httpx.HTTPError as exc:
            logger.error("ZoomEye API error: {}", exc)
            return NetworkSearchResult(query=query, source="zoomeye", error=str(exc))

        matches = data.get("matches", [])
        hits: list[NetworkSearchHit] = []

        for m in matches:
            hits.append(NetworkSearchHit(
                ip=m.get("ip", ""),
                port=m.get("portinfo", {}).get("port", 0) if isinstance(m.get("portinfo"), dict) else 0,
                protocol=m.get("protocol", {}).get("application", "") if isinstance(m.get("protocol"), dict) else "",
                domain=", ".join(m.get("rdns", "").split(",")) if m.get("rdns") else "",
                title=m.get("title", ""),
                server=m.get("server", ""),
                banner=m.get("banner", "")[:500],
                country=m.get("geoinfo", {}).get("country", {}).get("names", {}).get("en", "") if isinstance(m.get("geoinfo"), dict) else "",
                city=m.get("geoinfo", {}).get("city", {}).get("names", {}).get("en", "") if isinstance(m.get("geoinfo"), dict) else "",
                org=m.get("geoinfo", {}).get("organization", "") if isinstance(m.get("geoinfo"), dict) else "",
                last_seen=m.get("timestamp", ""),
            ))

        logger.info("ZoomEye search '{}': {} results", query[:80], len(hits))

        return NetworkSearchResult(
            query=query,
            source="zoomeye",
            total_results=data.get("total", len(hits)),
            hits=hits,
            query_url=f"{self._web_url}/searchResult?q={query}",
        )
