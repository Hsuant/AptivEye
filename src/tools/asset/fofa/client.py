"""FOFA API client — async HTTP client with retry, rate-limit handling.

Inspired by FofaMap v2.0 (by asaotomo / Hx0 Team):
  - 3-retry loop for 429 (rate-limit) and 45012 (business-layer throttle)
  - Auto field downgrade when premium fields not authorized (820001)
  - Search / Stats / Host / Login check endpoints
  - Base64 query encoding + HTTP Basic Auth
"""

from __future__ import annotations

import asyncio
import base64
from typing import Any

import httpx

from config.settings import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────

# Full field set (enterprise members)
FULL_FIELDS = (
    "host,ip,port,protocol,domain,title,server,banner,header,body,"
    "cert,icp,country,province,city,asn,org,os,"
    "lastupdatetime,product,product_category,version,"
    "js_name,js_version,icon_hash,cname,type,schema"
)

# Default fields for basic search
DEFAULT_FIELDS = (
    "ip,port,protocol,domain,title,server,banner,"
    "header,cert,icp,country,city,asn,org,os,"
    "lastupdatetime,product,version,icon_hash"
)

# Safe fallback fields (always authorized, even for free accounts)
SAFE_FIELDS = "host,ip,port,protocol,title,domain,country,city,server"

# Stats aggregation fields
STATS_FIELDS = (
    "country", "port", "protocol", "product", "product_category",
    "domain", "os", "server", "type", "city", "asn", "org", "icp",
)

# Max retries for transient errors
MAX_RETRIES = 3


# ── Client ────────────────────────────────────────────────────────────────


class FofaClient:
    """FOFA API v1 async client with intelligent retry and field downgrade.

    Usage::

        client = FofaClient()
        if await client.check_login():
            results, fields = await client.search('domain="example.com"')
            stats = await client.stats_search('app="nginx"', fields="country,port")
            host = await client.host_search("8.8.8.8")
    """

    def __init__(
        self,
        email: str = "",
        api_key: str = "",
        api_url: str = "",
    ) -> None:
        settings = get_settings().asset_api
        self._email = email or settings.fofa_email
        self._key = api_key or settings.fofa_api_key.get_secret_value()
        self._base_url = (api_url or settings.fofa_api_url).rstrip("/")
        self._web_url = settings.fofa_web_url.rstrip("/")
        self._configured = bool(self._email and self._key)
        self._user_info: dict[str, Any] | None = None

        self._headers = {
            "User-Agent": "AptivEye/0.1 (FOFA Client)",
        }
        self._client_args = {
            "http2": True,
            "verify": False,
            "timeout": httpx.Timeout(60.0, connect=15.0),
        }

    # ── Properties ──────────────────────────────────────────────────────

    @property
    def available(self) -> bool:
        return self._configured

    @property
    def user_info(self) -> dict[str, Any] | None:
        return self._user_info

    @property
    def web_url(self) -> str:
        return self._web_url

    # ── Auth ────────────────────────────────────────────────────────────

    async def check_login(self) -> dict[str, Any] | None:
        """Verify FOFA credentials and return user info.

        Returns dict with username, email, vip_level, etc., or None on failure.
        """
        if not self._configured:
            return None

        url = f"{self._base_url}/api/v1/info/my"
        params = {"email": self._email, "key": self._key}

        try:
            async with httpx.AsyncClient(**self._client_args) as client:  # type: ignore[arg-type]
                resp = await client.get(url, params=params, headers=self._headers)
                data = resp.json()
                if data.get("error"):
                    logger.error("FOFA login failed: {}", data.get("errmsg", "unknown"))
                    return None
                self._user_info = data
                logger.info("FOFA login OK — user={}, vip_level={}",
                            data.get("username"), data.get("vip_level"))
                return data
        except Exception as exc:
            logger.error("FOFA login error: {}", exc)
            return None

    # ── Search ──────────────────────────────────────────────────────────

    async def search(
        self,
        query_str: str,
        page: int = 1,
        fields: str | None = None,
        size: int | None = None,
        full: bool = False,
    ) -> tuple[list[list[Any]], str]:
        """Execute a FOFA search query with retry and auto field downgrade.

        Returns:
            (results, effective_fields) — results is a list of row-lists,
            effective_fields is the field string actually used (may differ
            from requested fields due to downgrade).
        """
        if not self._configured:
            return [], ""

        api_url = f"{self._base_url}/api/v1/search/all"
        qbase64 = base64.b64encode(query_str.encode("utf-8")).decode()

        current_fields = fields if fields else DEFAULT_FIELDS
        effective_fields = current_fields

        params: dict[str, Any] = {
            "email": self._email,
            "key": self._key,
            "qbase64": qbase64,
            "page": page,
            "size": min(size or 100, 10000),
            "fields": current_fields,
            "full": str(full).lower(),
        }

        async with httpx.AsyncClient(**self._client_args) as client:  # type: ignore[arg-type]
            for attempt in range(MAX_RETRIES):
                try:
                    if attempt == 0:
                        logger.info("FOFA search page {}: {}", page, query_str[:80])

                    resp = await client.get(api_url, params=params, headers=self._headers)

                    # — 429 Too Many Requests —
                    if resp.status_code == 429:
                        wait = 3 * (attempt + 1)
                        logger.warning("FOFA rate-limit (429), retry {}/{} after {}s",
                                       attempt + 1, MAX_RETRIES, wait)
                        await asyncio.sleep(wait)
                        continue

                    # — JSON parse —
                    try:
                        result = resp.json()
                    except Exception:
                        await asyncio.sleep(1)
                        continue

                    if result.get("error"):
                        errmsg = str(result.get("errmsg", ""))

                        # — 45012: business-layer throttle —
                        if "45012" in errmsg:
                            wait = 2 * (attempt + 1)
                            logger.warning("FOFA throttle (45012), retry {}/{} after {}s",
                                           attempt + 1, MAX_RETRIES, wait)
                            await asyncio.sleep(wait)
                            continue

                        # — 820001: permission denied for premium fields → downgrade —
                        if "820001" in errmsg or "权限" in errmsg:
                            if current_fields == SAFE_FIELDS:
                                logger.error("FOFA search failed even with safe fields: {}", errmsg)
                                return [], effective_fields

                            logger.warning("FOFA field permission denied, downgrading to safe fields")
                            params["fields"] = SAFE_FIELDS
                            effective_fields = SAFE_FIELDS
                            retry_resp = await client.get(api_url, params=params, headers=self._headers)
                            result = retry_resp.json()
                        else:
                            logger.error("FOFA search error: {}", errmsg)
                            return [], effective_fields

                    return result.get("results", []), effective_fields

                except Exception as exc:
                    logger.error("FOFA search exception (attempt {}): {}", attempt + 1, exc)
                    await asyncio.sleep(1)

        return [], effective_fields

    # ── Stats ───────────────────────────────────────────────────────────

    async def stats_search(
        self,
        query_str: str,
        fields: str = "country,port,protocol,product",
    ) -> dict[str, Any]:
        """Execute a FOFA statistical aggregation query.

        Returns the top-N distribution for each specified field.
        """
        if not self._configured:
            return {"error": "FOFA API not configured"}

        api_url = f"{self._base_url}/api/v1/search/stats"
        qbase64 = base64.b64encode(query_str.encode("utf-8")).decode()

        params: dict[str, Any] = {
            "email": self._email,
            "key": self._key,
            "qbase64": qbase64,
            "fields": fields,
            "size": 5,
        }

        async with httpx.AsyncClient(**self._client_args) as client:  # type: ignore[arg-type]
            try:
                resp = await client.get(api_url, params=params, headers=self._headers)
                return resp.json()
            except Exception as exc:
                logger.error("FOFA stats error: {}", exc)
                return {"error": str(exc)}

    # ── Host ────────────────────────────────────────────────────────────

    async def host_search(self, host: str) -> dict[str, Any]:
        """Execute a FOFA host aggregation query (IP/domain profiling).

        Returns detailed info: ports, products, certificates, ASN, OS, etc.
        With retry on rate-limit errors.
        """
        if not self._configured:
            return {"error": "FOFA API not configured"}

        api_url = f"{self._base_url}/api/v1/host/{host}"
        params: dict[str, Any] = {
            "email": self._email,
            "key": self._key,
            "detail": "true",
        }

        async with httpx.AsyncClient(**self._client_args) as client:  # type: ignore[arg-type]
            for attempt in range(MAX_RETRIES):
                try:
                    resp = await client.get(api_url, params=params, headers=self._headers)

                    if resp.status_code == 429:
                        await asyncio.sleep(3 * (attempt + 1))
                        continue

                    data = resp.json()
                    if data.get("error") and "45012" in str(data.get("errmsg", "")):
                        await asyncio.sleep(2 * (attempt + 1))
                        continue

                    return data
                except Exception as exc:
                    logger.error("FOFA host error (attempt {}): {}", attempt + 1, exc)
                    await asyncio.sleep(1)

        return {"error": "FOFA host query failed after retries"}

    # ── Survival check ─────────────────────────────────────────────────

    async def survival_check(
        self,
        urls: list[str],
        timeout: float = 5.0,
        max_concurrent: int = 20,
    ) -> dict[str, int | str]:
        """Check HTTP survival of target URLs with async concurrency.

        Args:
            urls: List of URLs to check (e.g. ['http://1.2.3.4:80', ...])
            timeout: Per-URL timeout in seconds
            max_concurrent: Maximum concurrent checks

        Returns:
            Dict mapping URL → HTTP status code (int) or "Failed" (str).
        """
        if not urls:
            return {}

        sem = asyncio.Semaphore(max_concurrent)
        results: dict[str, int | str] = {}

        async def check_one(url: str) -> None:
            async with sem:
                try:
                    async with httpx.AsyncClient(
                        timeout=httpx.Timeout(timeout),
                        follow_redirects=True,
                        verify=False,
                    ) as client:
                        resp = await client.get(url, headers={
                            "User-Agent": "Mozilla/5.0 (compatible; AptivEye/0.1)",
                        })
                        results[url] = resp.status_code
                except Exception:
                    results[url] = "Failed"

        tasks = [check_one(u) for u in urls if u]
        await asyncio.gather(*tasks)
        return results
