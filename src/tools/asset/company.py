"""企业信息查询 — company registration & ownership lookup.

Query company information from 企查查 and 天眼查 with automatic source routing.
Also supports 零零信安 security data aggregation platform.
"""

from __future__ import annotations

from typing import Any

import httpx

from config.settings import get_settings
from src.tools.asset.models import CompanyInfo, CompanyResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


# ── 企查查 ────────────────────────────────────────────────────────────────


async def query_company_qichacha(
    keyword: str,
    timeout: float = 15.0,
) -> CompanyResult:
    """Query company information via 企查查 API."""
    settings = get_settings().asset_api
    api_key = settings.qichacha_api_key.get_secret_value()
    api_url = settings.qichacha_api_url.rstrip("/")

    if not api_key:
        return CompanyResult(
            query=keyword, source="qichacha",
            error="企查查 API key not configured. Set QICHACHA_API_KEY in .env",
        )

    companies: list[CompanyInfo] = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                f"{api_url}/CompanySearch/Search",
                params={"key": api_key, "searchKey": keyword},
                headers={"User-Agent": "AptivEye/0.1"},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("Status") == "200":
                    for item in data.get("Result", []):
                        companies.append(CompanyInfo(
                            company_name=item.get("CompanyName", item.get("Name", "")),
                            legal_person=item.get("OperName", item.get("LegalPerson", "")),
                            registered_capital=item.get("RegistCapi", item.get("RegCapital", "")),
                            established_date=item.get("StartDate", item.get("EstablishedDate", "")),
                            business_status=item.get("Status", ""),
                            unified_code=item.get("CreditCode", ""),
                            business_scope=item.get("Scope", "")[:500],
                            address=item.get("Address", ""),
                            email=item.get("Email", ""),
                            phone=item.get("Phone", ""),
                            website=item.get("Website", ""),
                            industry=item.get("Industry", ""),
                        ))
    except Exception as exc:
        logger.error("企查查 API error: {}", exc)
        return CompanyResult(query=keyword, source="qichacha", error=str(exc))

    return CompanyResult(
        query=keyword, source="qichacha",
        companies=companies, total_found=len(companies),
    )


# ── 天眼查 ────────────────────────────────────────────────────────────────


async def query_company_tianyancha(
    keyword: str,
    timeout: float = 15.0,
) -> CompanyResult:
    """Query company information via 天眼查 API."""
    settings = get_settings().asset_api
    api_key = settings.tianyancha_api_key.get_secret_value()
    api_url = settings.tianyancha_api_url.rstrip("/")

    if not api_key:
        return CompanyResult(
            query=keyword, source="tianyancha",
            error="天眼查 API key not configured. Set TIANYANCHA_API_KEY in .env",
        )

    companies: list[CompanyInfo] = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                f"{api_url}/search/v3",
                params={"keyword": keyword},
                headers={"Authorization": api_key},
            )
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("data", {}).get("companyList", []):
                    companies.append(CompanyInfo(
                        company_name=item.get("name", ""),
                        legal_person=item.get("legalPersonName", ""),
                        registered_capital=item.get("regCapital", ""),
                        established_date=item.get("estiblishTime", ""),
                        business_status=item.get("regStatus", ""),
                        unified_code=item.get("creditCode", ""),
                        business_scope=item.get("businessScope", "")[:500],
                        address=item.get("regLocation", ""),
                        email=item.get("email", ""),
                        phone=", ".join(item.get("phoneList", [])) if item.get("phoneList") else "",
                        industry=item.get("industry", ""),
                    ))
    except Exception as exc:
        logger.error("天眼查 API error: {}", exc)
        return CompanyResult(query=keyword, source="tianyancha", error=str(exc))

    return CompanyResult(
        query=keyword, source="tianyancha",
        companies=companies, total_found=len(companies),
    )


# ── Public API: Company lookup (auto-route) ───────────────────────────────


async def query_company(
    keyword: str,
    *,
    source: str = "auto",  # auto / qichacha / tianyancha
) -> CompanyResult:
    """Query company information with automatic source routing.

    Tries 天眼查 first (richer data), then 企查查.
    """
    results: list[CompanyInfo] = []
    errors: list[str] = []
    used_source = ""

    if source in ("auto", "tianyancha"):
        r = await query_company_tianyancha(keyword)
        if r.companies:
            results.extend(r.companies)
            used_source = "tianyancha"
        elif r.error:
            errors.append(r.error)

    if source in ("auto", "qichacha") and not results:
        r = await query_company_qichacha(keyword)
        if r.companies:
            results.extend(r.companies)
            used_source = used_source or "qichacha"
        elif r.error:
            errors.append(r.error)

    return CompanyResult(
        query=keyword,
        source=used_source,
        companies=results,
        total_found=len(results),
        error="; ".join(errors) if not results else "",
    )
