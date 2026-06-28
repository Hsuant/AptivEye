"""ICP备案查询 — MIIT filing database lookup.

Query domain ICP (Internet Content Provider) filing records from the
official MIIT (Ministry of Industry and Information Technology) API,
with automatic fallback to public ICP check services.
"""

from __future__ import annotations

from typing import Any

import httpx

from config.settings import get_settings
from src.tools.asset.models import ICPRecord, ICPResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


async def query_icp(
    keyword: str,
    *,
    search_type: str = "domain",  # domain / company
    timeout: float = 15.0,
) -> ICPResult:
    """Query ICP备案 records by domain or company name.

    Attempts multiple free API endpoints:
      1. Official MIIT API (if configured)
      2. Public ICP check services
    """
    settings = get_settings().asset_api
    api_key = settings.icp_api_key.get_secret_value()
    api_url = settings.icp_api_url

    records: list[ICPRecord] = []
    source = ""
    error = ""

    # Try official MIIT API
    if api_key and api_url:
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(
                    api_url,
                    params={"keyword": keyword, "type": search_type},
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    source = "miit_api"
                    for item in data.get("records", data.get("list", [])):
                        records.append(ICPRecord(
                            domain=item.get("domain", item.get("siteDomain", "")),
                            site_name=item.get("siteName", item.get("name", "")),
                            company_name=item.get("companyName", item.get("unitName", "")),
                            company_type=item.get("companyType", item.get("unitType", "")),
                            icp_number=item.get("icpNumber", item.get("icpNo", "")),
                            site_audit_date=item.get("auditDate", item.get("passDate", "")),
                            site_homepage=item.get("homepage", ""),
                            legal_person=item.get("legalPerson", ""),
                        ))
                    if records:
                        return ICPResult(
                            query=keyword, records=records,
                            total_found=len(records), source=source,
                        )
        except Exception as exc:
            error = f"MIIT API: {exc}"
            logger.warning("ICP API failed: {}", exc)

    # Try public ICP check (free, no API key required)
    try:
        icp_public_url = get_settings().asset_api.icp_public_url
        url = icp_public_url
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, params={"domain": keyword})
            if resp.status_code == 200:
                data = resp.json()
                if data.get("code") == 0 and data.get("data"):
                    source = "public_api"
                    item = data["data"]
                    records.append(ICPRecord(
                        domain=keyword,
                        site_name=item.get("siteName", ""),
                        company_name=item.get("companyName", ""),
                        company_type=item.get("companyType", ""),
                        icp_number=item.get("icpNo", ""),
                        site_audit_date=item.get("auditDate", ""),
                    ))
    except Exception:
        pass  # Public API may not be reachable

    if not records:
        error = error or "No ICP records found. Set ICP_API_KEY for official API access."

    return ICPResult(
        query=keyword, records=records,
        total_found=len(records), source=source, error=error,
    )
