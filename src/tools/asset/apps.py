"""移动APP discovery — iOS/Android app store search.

Discover mobile apps (iOS/Android) associated with an organization
via public app store APIs.
"""

from __future__ import annotations

import httpx

from config.settings import get_settings
from src.tools.asset.models import MobileApp
from src.utils.logger import get_logger

logger = get_logger(__name__)


async def discover_mobile_apps(
    keyword: str,
    timeout: float = 15.0,
) -> list[MobileApp]:
    """Discover mobile apps (iOS/Android) related to an organization.

    Strategy: iOS App Store search via iTunes public API (free, no auth).
    """
    settings = get_settings().asset_api
    apps: list[MobileApp] = []

    # iOS App Store search (free, no auth)
    try:
        url = settings.itunes_search_url
        params = {
            "term": keyword,
            "entity": "software",
            "limit": 25,
            "country": "CN",
        }
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, params=params)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("results", []):
                    developer = item.get("artistName", "")
                    if keyword.lower() in developer.lower() or keyword.lower() in item.get("trackName", "").lower():
                        apps.append(MobileApp(
                            app_name=item.get("trackName", ""),
                            platform="iOS",
                            package_id=item.get("bundleId", ""),
                            developer=developer,
                            version=item.get("version", ""),
                            store_url=item.get("trackViewUrl", ""),
                            description=(item.get("description", "") or "")[:300],
                        ))
        logger.info("iOS App Store: {} apps found for '{}'", len(apps), keyword)
    except Exception as exc:
        logger.debug("iOS app search for '{}' failed: {}", keyword, exc)

    return apps
