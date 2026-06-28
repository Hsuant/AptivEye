"""Asset Discovery MCP Server.

Exposes all asset discovery tools as individually callable MCP tools.
Each tool maps 1:1 to its source file.
"""

from __future__ import annotations

from typing import Any

from src.tools.asset.fingerprint import fingerprint_services
from src.tools.asset.models import AssetSummary, FingerprintResult, PortScanResult, SubdomainResult
from src.tools.asset.nmap import discover_ports
from src.tools.asset.subdomain import discover_subdomains
from src.tools.registry import ToolDefinition
from src.utils.logger import get_logger

logger = get_logger(__name__)

# =============================================================================
# Tool definitions
# =============================================================================

TOOL_DEFINITIONS: list[ToolDefinition] = [
    # ── Core ──
    ToolDefinition(
        name="subdomain",
        description=(
            "Discover subdomains of a target domain using multiple backends "
            "(DNS brute-force, crt.sh certificate transparency, OWASP Amass). "
            "Use this as the FIRST step in asset discovery for domain-based targets."
        ),
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain, e.g. 'example.com'"},
                "use_dns_brute": {"type": "boolean", "default": True},
                "use_crtsh": {"type": "boolean", "default": True},
                "use_amass": {"type": "boolean", "default": False},
                "wordlist": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["domain"],
        },
        category="asset",
        risk_level=1,
    ),
    ToolDefinition(
        name="nmap",
        description=(
            "Scan TCP ports on a target host. Supports nmap (SYN scan, service detection, "
            "NSE scripts) with automatic fallback to socket connect scan. "
            "Use presets: 'top10', 'top100', 'top1000', 'all', or '1-1000'."
        ),
        parameters={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target IP or hostname"},
                "ports": {"type": "string", "default": "top100", "description": "Port preset or range"},
                "service_detection": {"type": "boolean", "default": True},
                "timing": {"type": "integer", "default": 4, "minimum": 0, "maximum": 5},
                "timeout": {"type": "number", "default": 300},
            },
            "required": ["host"],
        },
        category="asset",
        risk_level=2,
    ),
    ToolDefinition(
        name="fingerprint",
        description=(
            "Fingerprint services on open ports. HTTP header analysis, "
            "technology stack detection, TLS certificate extraction, banner grabbing. "
            "Use AFTER nmap to identify software versions and configurations."
        ),
        parameters={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target IP or hostname"},
                "ports": {
                    "type": "array",
                    "items": {"type": "object", "properties": {
                        "port": {"type": "integer"}, "service": {"type": "string"}, "state": {"type": "string"},
                    }},
                    "description": "List of port info objects from a previous nmap result",
                },
            },
            "required": ["host", "ports"],
        },
        category="asset",
        risk_level=2,
    ),
    ToolDefinition(
        name="assets_full",
        description=(
            "Full asset discovery pipeline: subdomain → nmap → fingerprint. "
            "One-shot comprehensive discovery for domain targets."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain, e.g. 'example.com'"},
                "ports": {"type": "string", "default": "top100"},
                "max_hosts": {"type": "integer", "default": 5},
            },
            "required": ["target"],
        },
        category="asset",
        risk_level=3,
    ),

    # ── WHOIS ──
    ToolDefinition(
        name="whois",
        description=(
            "Query WHOIS registration data for a domain. Returns registrar, "
            "creation/expiration dates, name servers, registrant contacts, and emails."
        ),
        parameters={
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "Domain name, e.g. 'example.com'"}},
            "required": ["domain"],
        },
        category="asset",
        risk_level=1,
    ),

    # ── Network search (FOFA package: 1 tool, 4 modes) ──

    ToolDefinition(
        name="zoomeye",
        description=(
            "Search ZoomEye (https://zoomeye.org) for cyberspace mapping data. "
            "Find exposed IPs, ports, services, banners, and geolocation. "
            "Requires ZOOMEYE_API_KEY in .env."
        ),
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "ZoomEye search query, e.g. 'app:\"nginx\"'"},
                "search_type": {"type": "string", "enum": ["host", "web"], "default": "host"},
                "pagesize": {"type": "integer", "default": 20, "description": "Results per page (max 50)"},
            },
            "required": ["query"],
        },
        category="asset",
        risk_level=1,
    ),

    # ── ICP / Company ──
    ToolDefinition(
        name="icp",
        description=(
            "Query ICP备案 records from China's MIIT database. "
            "Returns domain, company name, ICP number, and audit dates."
        ),
        parameters={
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "Domain or company name to look up"},
                "search_type": {"type": "string", "enum": ["domain", "company"], "default": "domain"},
            },
            "required": ["keyword"],
        },
        category="asset",
        risk_level=1,
    ),
    ToolDefinition(
        name="company",
        description=(
            "Query company registration info from 企查查 and 天眼查. "
            "Returns legal person, registered capital, establishment date, business scope, "
            "address, and associated domains. Requires QICHACHA_API_KEY or TIANYANCHA_API_KEY."
        ),
        parameters={
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "Company name or unified social credit code"},
                "source": {"type": "string", "enum": ["auto", "qichacha", "tianyancha"], "default": "auto"},
            },
            "required": ["keyword"],
        },
        category="asset",
        risk_level=1,
    ),
    ToolDefinition(
        name="lingling",
        description=(
            "Query 零零信安 (https://0zero.cn) security data aggregation platform "
            "for organization security intelligence. Requires LINGLING_API_KEY in .env."
        ),
        parameters={
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "Organization name or domain"},
            },
            "required": ["keyword"],
        },
        category="asset",
        risk_level=1,
    ),

    # ── Digital assets ──
    ToolDefinition(
        name="wechat",
        description=(
            "Discover WeChat Official Accounts (微信公众号) and Mini Programs (微信小程序) "
            "associated with a target organization. No API key required."
        ),
        parameters={
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "Organization name or domain to search"},
            },
            "required": ["keyword"],
        },
        category="asset",
        risk_level=1,
    ),
    ToolDefinition(
        name="apps",
        description=(
            "Discover mobile apps (iOS/Android) associated with a target organization. "
            "Searches public app store APIs. No API key required."
        ),
        parameters={
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "Organization name to search"},
            },
            "required": ["keyword"],
        },
        category="asset",
        risk_level=1,
    ),
    ToolDefinition(
        name="emails",
        description=(
            "Discover email addresses associated with a domain. Uses Hunter.io API "
            "(requires HUNTER_API_KEY) and common organizational pattern guessing (free)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain, e.g. 'example.com'"},
            },
            "required": ["domain"],
        },
        category="asset",
        risk_level=1,
    ),
    ToolDefinition(
        name="digital_assets",
        description=(
            "Composite: discover WeChat accounts, Mini Programs, mobile apps, and emails "
            "all in one call. Use after basic discovery to build a complete digital footprint."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain or company name"},
                "target_type": {"type": "string", "enum": ["auto", "domain", "company"], "default": "auto"},
                "include_wechat": {"type": "boolean", "default": True},
                "include_miniprogram": {"type": "boolean", "default": True},
                "include_apps": {"type": "boolean", "default": True},
                "include_emails": {"type": "boolean", "default": True},
            },
            "required": ["target"],
        },
        category="asset",
        risk_level=1,
    ),

    # ── All-in-one ──
    ToolDefinition(
        name="all_assets",
        description=(
            "COMPREHENSIVE one-shot: subdomain + nmap + fingerprint + whois + fofa + zoomeye "
            "+ icp + company + digital_assets. Returns full ExtendedAssetSummary."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain or IP"},
                "ports": {"type": "string", "default": "top100"},
                "include_network_search": {"type": "boolean", "default": True},
                "include_whois": {"type": "boolean", "default": True},
                "include_icp": {"type": "boolean", "default": True},
                "include_company": {"type": "boolean", "default": True},
                "include_digital": {"type": "boolean", "default": True},
            },
            "required": ["target"],
        },
        category="asset",
        risk_level=3,
    ),
]

# =============================================================================
# Handlers
# =============================================================================


async def _handle_subdomain(
    domain: str, use_dns_brute: bool = True, use_crtsh: bool = True,
    use_amass: bool = False, wordlist: list[str] | None = None,
) -> dict[str, Any]:
    result: SubdomainResult = await discover_subdomains(
        domain=domain, use_dns_brute=use_dns_brute,
        use_crtsh=use_crtsh, use_amass=use_amass, wordlist=wordlist,
    )
    return result.model_dump()


async def _handle_nmap(
    host: str, ports: str = "top100",
    service_detection: bool = True, timing: int = 4, timeout: float = 300.0,
) -> dict[str, Any]:
    result: PortScanResult = await discover_ports(
        host=host, ports=ports, prefer_nmap=True,
        service_detection=service_detection, timing=timing, timeout=timeout,
    )
    return result.model_dump()


async def _handle_fingerprint(host: str, ports: list[dict[str, Any]]) -> dict[str, Any]:
    from src.tools.asset.models import PortInfo, PortState
    port_infos = []
    for p in ports:
        try:
            state = PortState(p.get("state", "open"))
        except ValueError:
            state = PortState.OPEN
        port_infos.append(PortInfo(port=p["port"], service=p.get("service", "unknown"), state=state))
    result: FingerprintResult = await fingerprint_services(host, port_infos)
    return result.model_dump()


async def _handle_assets_full(
    target: str, ports: str = "top100", max_hosts: int = 5,
) -> dict[str, Any]:
    from src.utils.validators import is_valid_ip

    subdomains: list[str] = []
    subdomain_result = None
    if not is_valid_ip(target):
        subdomain_result = await discover_subdomains(target, use_dns_brute=True, use_crtsh=True)
        subdomains = [sd.name for sd in subdomain_result.subdomains]

    hosts = subdomains[:max_hosts] if subdomains else [target]

    all_port_results: dict[str, PortScanResult] = {}
    for host in hosts:
        try:
            all_port_results[host] = await discover_ports(host, ports=ports, timeout=180.0)
        except Exception as exc:
            logger.warning("Port scan failed for {}: {}", host, exc)

    all_fingerprints: dict[str, FingerprintResult] = {}
    for host, scan_result in all_port_results.items():
        open_ports_list = [p for p in scan_result.ports if p.state.value == "open"]
        if open_ports_list:
            try:
                all_fingerprints[host] = await fingerprint_services(host, open_ports_list)
            except Exception as exc:
                logger.warning("Fingerprint failed for {}: {}", host, exc)

    live_hosts, open_ports_map, services_map = [], {}, {}
    for host, scan_result in all_port_results.items():
        open_list = [p.port for p in scan_result.ports if p.state.value == "open"]
        if open_list:
            live_hosts.append(host)
            open_ports_map[host] = sorted(open_list)
    for host, fp_result in all_fingerprints.items():
        services_map[host] = [fp.summary for fp in fp_result.fingerprints]

    summary = AssetSummary(
        target=target, subdomains=subdomains, live_hosts=live_hosts,
        open_ports=open_ports_map, services=services_map,
        total_subdomains=len(subdomains), total_live_hosts=len(live_hosts),
        total_open_ports=sum(len(v) for v in open_ports_map.values()),
    )
    return {
        "summary": summary.model_dump(),
        "subdomain_result": subdomain_result.model_dump() if subdomain_result else None,
        "markdown": summary.to_markdown(),
    }


async def _handle_whois(domain: str) -> dict[str, Any]:
    from src.tools.asset.whois import whois_lookup
    result = await whois_lookup(domain)
    return result.model_dump()


async def _handle_fofa(**kwargs: Any) -> dict[str, Any]:
    from src.tools.asset.fofa.handler import handle_fofa
    return await handle_fofa(**kwargs)


async def _handle_zoomeye(
    query: str, search_type: str = "host", pagesize: int = 20,
) -> dict[str, Any]:
    from src.tools.asset.zoomeye import ZoomEyeClient
    zoomeye = ZoomEyeClient()
    result = await zoomeye.search(query, search_type=search_type, pagesize=min(pagesize, 50))
    return result.model_dump()


async def _handle_icp(keyword: str, search_type: str = "domain") -> dict[str, Any]:
    from src.tools.asset.icp import query_icp
    result = await query_icp(keyword, search_type=search_type)
    return result.model_dump()


async def _handle_company(keyword: str, source: str = "auto") -> dict[str, Any]:
    from src.tools.asset.company import query_company
    result = await query_company(keyword, source=source)
    return result.model_dump()


async def _handle_lingling(keyword: str) -> dict[str, Any]:
    from src.tools.asset.lingling import query_lingling
    result = await query_lingling(keyword)
    return result.model_dump()


async def _handle_wechat(keyword: str) -> dict[str, Any]:
    from src.tools.asset.wechat import discover_mini_programs, discover_wechat_accounts
    accounts = await discover_wechat_accounts(keyword)
    mini_programs = await discover_mini_programs(keyword)
    return {
        "keyword": keyword,
        "wechat_accounts": [a.model_dump() for a in accounts],
        "mini_programs": [m.model_dump() for m in mini_programs],
    }


async def _handle_apps(keyword: str) -> dict[str, Any]:
    from src.tools.asset.apps import discover_mobile_apps
    apps = await discover_mobile_apps(keyword)
    return {"keyword": keyword, "apps": [a.model_dump() for a in apps]}


async def _handle_emails(domain: str) -> dict[str, Any]:
    from src.tools.asset.emails import discover_emails_hunter, discover_emails_pattern
    hunter = await discover_emails_hunter(domain)
    pattern = discover_emails_pattern(domain)
    return {
        "domain": domain,
        "emails": [e.model_dump() for e in hunter + pattern],
        "total": len(hunter) + len(pattern),
    }


async def _handle_digital_assets(
    target: str, target_type: str = "auto",
    include_wechat: bool = True, include_miniprogram: bool = True,
    include_apps: bool = True, include_emails: bool = True,
) -> dict[str, Any]:
    from src.tools.asset.digital_assets import discover_digital_assets
    result = await discover_digital_assets(
        target, target_type=target_type, include_wechat=include_wechat,
        include_miniprogram=include_miniprogram, include_apps=include_apps,
        include_emails=include_emails,
    )
    return result.model_dump()


async def _handle_all_assets(
    target: str, ports: str = "top100",
    include_network_search: bool = True, include_whois: bool = True,
    include_icp: bool = True, include_company: bool = True,
    include_digital: bool = True,
) -> dict[str, Any]:
    import asyncio as _asyncio
    from src.tools.asset.models import (
        CompanyResult, DigitalAssetResult, ExtendedAssetSummary,
        ICPResult, NetworkSearchResult, WhoisResult,
    )
    from src.utils.validators import is_valid_ip

    results: dict[str, Any] = {}
    errors: list[str] = []
    is_domain = not is_valid_ip(target)
    tasks: list[tuple[str, Any]] = []

    tasks.append(("core", _handle_assets_full(target, ports=ports)))
    if include_whois and is_domain:
        tasks.append(("whois", _handle_whois(target)))
    if include_network_search:
        tasks.append(("fofa", _handle_fofa(query=target)))
        tasks.append(("zoomeye", _handle_zoomeye(target)))
    if include_icp and is_domain:
        tasks.append(("icp", _handle_icp(target)))
    if include_company:
        tasks.append(("company", _handle_company(target)))
    if include_digital:
        tasks.append(("digital", _handle_digital_assets(target)))

    task_results = await _asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)
    for (name, _), tr in zip(tasks, task_results):
        if isinstance(tr, Exception):
            errors.append(f"{name}: {tr}")
        else:
            results[name] = tr

    core_data = results.get("core", {})
    core_summary = core_data.get("summary", {})
    summary = ExtendedAssetSummary(
        target=target, subdomains=core_summary.get("subdomains", []),
        live_hosts=core_summary.get("live_hosts", []),
        open_ports=core_summary.get("open_ports", {}),
        services=core_summary.get("services", {}),
        total_subdomains=core_summary.get("total_subdomains", 0),
        total_live_hosts=core_summary.get("total_live_hosts", 0),
        total_open_ports=core_summary.get("total_open_ports", 0),
    )
    if "whois" in results:
        summary.whois = WhoisResult(**results["whois"])
    if "icp" in results:
        summary.icp = ICPResult(**results["icp"])
    if "company" in results:
        summary.company = CompanyResult(**results["company"])
    if "digital" in results:
        summary.digital_assets = DigitalAssetResult(**results["digital"])
    for key in ("fofa", "zoomeye"):
        if key in results and not results[key].get("error"):
            summary.network_search.append(NetworkSearchResult(**results[key]))

    return {
        "summary": summary.model_dump(mode="json"),
        "markdown": summary.to_markdown(),
        "sources_used": list(results.keys()),
        "errors": errors,
    }


# =============================================================================
# Registration
# =============================================================================

HANDLERS: dict[str, Any] = {
    "subdomain":       _handle_subdomain,
    "nmap":            _handle_nmap,
    "fingerprint":     _handle_fingerprint,
    "assets_full":     _handle_assets_full,
    "whois":           _handle_whois,
    "fofa":            _handle_fofa,
    "zoomeye":         _handle_zoomeye,
    "icp":             _handle_icp,
    "company":         _handle_company,
    "lingling":        _handle_lingling,
    "wechat":          _handle_wechat,
    "apps":            _handle_apps,
    "emails":          _handle_emails,
    "digital_assets":  _handle_digital_assets,
    "all_assets":      _handle_all_assets,
}

# Extend with FOFA package tool definition
from src.tools.asset.fofa.handler import FOFA_TOOL_DEFINITION
TOOL_DEFINITIONS.append(FOFA_TOOL_DEFINITION)


def get_tools() -> list[tuple[ToolDefinition, Any]]:
    """Return (definition, handler) pairs for all asset discovery tools."""
    return [(td, HANDLERS[td.name]) for td in TOOL_DEFINITIONS]
