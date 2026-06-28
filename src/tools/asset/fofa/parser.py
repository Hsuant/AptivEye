"""FOFA response parsers — converts raw API responses to structured results.

Separates parsing logic from API client for clean separation of concerns
(as in FofaMap's architecture).
"""

from __future__ import annotations

import base64
from typing import Any

from src.tools.asset.fofa.client import FofaClient
from src.tools.asset.models import NetworkSearchHit, NetworkSearchResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


# ── Search response parser ───────────────────────────────────────────────


def parse_search_response(
    client: FofaClient,
    query: str,
    data: dict[str, Any],
    fields: str,
) -> NetworkSearchResult:
    """Parse FOFA search API response → NetworkSearchResult.

    Handles dedup by ip:port and extracts all known fields from row data.
    """
    if data.get("error"):
        return NetworkSearchResult(
            query=query, source="fofa",
            error=str(data.get("errmsg", data["error"])),
        )

    results = data.get("results", [])
    hits: list[NetworkSearchHit] = []
    field_names = fields.split(",")
    seen: set[str] = set()

    for row in results:
        hit_data: dict[str, Any] = {}
        for i, val in enumerate(row):
            if i < len(field_names):
                hit_data[field_names[i]] = (val or "")

        # Dedup by ip:port
        dedup_key = f"{hit_data.get('ip', '')}:{hit_data.get('port', '')}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        hits.append(NetworkSearchHit(
            ip=hit_data.get("ip", ""),
            port=int(hit_data.get("port", 0) or 0),
            protocol=hit_data.get("protocol", ""),
            domain=hit_data.get("domain", ""),
            title=hit_data.get("title", ""),
            server=hit_data.get("server", ""),
            banner=(hit_data.get("banner", "") or "")[:500],
            country=hit_data.get("country", ""),
            city=hit_data.get("city", ""),
            asn=hit_data.get("asn", ""),
            org=hit_data.get("org", ""),
            last_seen=hit_data.get("lastupdatetime", ""),
            url=_build_web_url(client, query),
        ))

    logger.info(
        "FOFA search '{}': {} hits ({} raw, {} deduped)",
        query[:80], len(hits), len(results), len(results) - len(hits),
    )

    return NetworkSearchResult(
        query=query,
        source="fofa",
        total_results=data.get("size", len(hits)),
        hits=hits,
        query_url=_build_web_url(client, query),
    )


# ── Stats response parser ───────────────────────────────────────────────


def parse_stats_response(
    client: FofaClient,
    query: str,
    data: dict[str, Any],
    fields: str,
) -> dict[str, Any]:
    """Parse FOFA stats API response → structured dict.

    Returns::

        {
            "query": "...",
            "total": 12345,
            "distinct": {"domain": 500, "ip": 800},
            "aggs": {"country": [{"name": "CN", "count": 3000}, ...], ...},
            "query_url": "...",
        }
    """
    if data.get("error"):
        return {"query": query, "error": str(data.get("errmsg", data["error"]))}

    field_list = [f.strip() for f in fields.split(",") if f.strip()]

    # Parse stats — FOFA returns either "stats" or "aggs" key
    aggs: dict[str, list[dict[str, Any]]] = {}
    raw_stats = data.get("stats", data.get("aggs", {}))

    for field in field_list:
        field_data = raw_stats.get(field, [])
        items: list[dict[str, Any]] = []
        for item in field_data:
            if isinstance(item, dict):
                items.append({
                    "name": item.get("name", ""),
                    "count": item.get("count", 0),
                    "regions": item.get("regions", []),
                })
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                items.append({"name": str(item[0]), "count": int(item[1])})
        if items:
            aggs[field] = items

    logger.info("FOFA stats '{}': fields={}, total={}",
                 query[:80], field_list, data.get("size", 0))

    return {
        "query": query,
        "total": data.get("size", 0),
        "distinct": data.get("distinct", {}),
        "aggs": aggs,
        "lastupdatetime": data.get("lastupdatetime", ""),
        "query_url": _build_web_url(client, query),
    }


# ── Host response parser ────────────────────────────────────────────────


def parse_host_response(
    client: FofaClient,
    target: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    """Parse FOFA host aggregation response → structured dict.

    Returns::

        {
            "target": "8.8.8.8",
            "ip": "8.8.8.8",
            "asn": 15169, "org": "Google", "country": "US", "os": "",
            "port_count": 5,
            "ports": [{"port": 53, "protocol": "dns", "products": [...], ...}],
            "certificates": [{"subject": "...", "issuer": "...", ...}],
            "products": ["Google Public DNS", ...],
            "query_url": "https://fofa.info/host/8.8.8.8",
        }
    """
    if data.get("error"):
        return {"target": target, "error": str(data.get("errmsg", data["error"]))}

    # Parse ports
    ports_list: list[dict[str, Any]] = []
    for p in data.get("ports", []):
        raw_products = p.get("products", [])
        products_list: list[str] = []
        if isinstance(raw_products, list):
            products_list = [
                prod.get("product", "") if isinstance(prod, dict) else str(prod)
                for prod in raw_products
            ]
        ports_list.append({
            "port": p.get("port", 0),
            "protocol": p.get("protocol", ""),
            "products": products_list,
            "banner": (p.get("banner", "") or "")[:300],
            "title": p.get("title", ""),
            "server": p.get("server", ""),
            "update_time": p.get("update_time", ""),
        })

    # Sort ports numerically
    ports_list.sort(key=lambda x: x["port"])

    # Parse certificates
    certs: list[dict[str, Any]] = []
    for c in data.get("certificates", data.get("certs", [])):
        certs.append({
            "subject": c.get("subject", ""),
            "issuer": c.get("issuer", c.get("issuer_org", "")),
            "not_before": c.get("not_before", ""),
            "not_after": c.get("not_after", ""),
            "dns_names": c.get("dns_names", c.get("domains", [])),
            "sha256": c.get("sha256", ""),
        })

    # Aggregate unique products across all ports
    all_products: list[str] = []
    for p in ports_list:
        for prod in p["products"]:
            if prod not in all_products:
                all_products.append(prod)

    logger.info("FOFA host '{}': {} ports, {} certs, {} products",
                 target, len(ports_list), len(certs), len(all_products))

    return {
        "target": target,
        "ip": data.get("ip", target),
        "asn": data.get("asn", ""),
        "org": data.get("org", ""),
        "country": data.get("country_name", data.get("country", "")),
        "country_code": data.get("country_code", ""),
        "os": data.get("os", ""),
        "is_ipv6": data.get("is_ipv6", False),
        "port_count": len(ports_list),
        "ports": ports_list,
        "certificates": certs,
        "products": all_products,
        "last_update": data.get("lastupdatetime", data.get("update_time", "")),
        "query_url": f"{client.web_url}/host/{target}",
    }


# ── Helpers ─────────────────────────────────────────────────────────────


def _build_web_url(client: FofaClient, query: str) -> str:
    """Build a FOFA web UI result URL for the given query."""
    qbase64 = base64.b64encode(query.encode()).decode()
    return f"{client.web_url}/result?qbase64={qbase64}"
