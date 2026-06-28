"""Asset Discovery MCP Server package.

Provides comprehensive asset discovery as independent MCP-compatible tools:

Phase 1 Core:
  - enumerate_subdomains: DNS/crtsh/Amass subdomain enumeration
  - scan_ports: nmap/socket port scanning
  - fingerprint_service: HTTP/TLS/banner service fingerprinting
  - discover_assets_full: Full pipeline: subdomains → ports → fingerprints

Phase 1 Extended:
  - whois_lookup: Domain WHOIS registration data
  - search_network_assets: FOFA + ZoomEye network space search
  - query_icp_record: ICP备案 (MIIT filing database)
  - query_company_info: 企查查/天眼查 company registration
  - discover_digital_assets: WeChat/MiniProgram/APP/Email discovery
  - discover_all_assets: COMPREHENSIVE one-shot asset discovery

Usage:
    from src.tools.asset import register_all
    from src.tools.registry import get_registry

    registry = get_registry()
    register_all(registry)
    # Now the agent can discover and call all 10 asset discovery tools.
"""

# Models — core
from src.tools.asset.models import (
    AssetSummary,
    ExtendedAssetSummary,
    FingerprintResult,
    PortInfo,
    PortScanResult,
    PortState,
    ServiceFingerprint,
    Subdomain,
    SubdomainResult,
    SubdomainSource,
)
# Models — extended
from src.tools.asset.models import (
    WhoisContact,
    WhoisResult,
    NetworkSearchHit,
    NetworkSearchResult,
    ICPRecord,
    ICPResult,
    CompanyInfo,
    CompanyResult,
    WeChatAccount,
    MiniProgram,
    MobileApp,
    EmailInfo,
    DigitalAssetResult,
    OrgIntelItem,
    OrgIntelResult,
)

from src.tools.asset.server import get_tools, HANDLERS, TOOL_DEFINITIONS
from src.tools.registry import ToolRegistry
from src.utils.logger import get_logger

logger = get_logger(__name__)

__all__ = [
    # Core models
    "AssetSummary", "ExtendedAssetSummary", "FingerprintResult",
    "PortInfo", "PortScanResult", "PortState", "ServiceFingerprint",
    "Subdomain", "SubdomainResult", "SubdomainSource",
    # Extended models
    "WhoisContact", "WhoisResult",
    "NetworkSearchHit", "NetworkSearchResult",
    "ICPRecord", "ICPResult",
    "CompanyInfo", "CompanyResult",
    "WeChatAccount", "MiniProgram", "MobileApp", "EmailInfo",
    "DigitalAssetResult",
    "OrgIntelItem", "OrgIntelResult",
    # Server
    "TOOL_DEFINITIONS", "HANDLERS", "get_tools", "register_all",
]


def register_all(registry: ToolRegistry) -> int:
    """Register all 15 asset discovery tools into a ToolRegistry.

    Returns the number of tools registered.
    """
    count = 0
    for definition, handler in get_tools():
        registry.register(definition, handler)
        count += 1
    logger.info("Registered {} asset discovery tools", count)
    return count
