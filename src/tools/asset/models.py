"""Pydantic models for asset discovery results.

All asset discovery tools return structured data using these models,
enabling type-safe consumption by the agent and downstream tools.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# =============================================================================
# Subdomain
# =============================================================================

class SubdomainSource(str, Enum):
    """Source of the subdomain discovery."""
    DNS_BRUTE = "dns_brute"
    CRT_SH = "crt_sh"
    AMASS = "amass"
    DNS_RESOLVE = "dns_resolve"


class Subdomain(BaseModel):
    """A discovered subdomain with its metadata."""

    name: str = Field(..., description="Full subdomain name, e.g. mail.example.com")
    source: SubdomainSource = Field(..., description="Discovery method")
    ip_addresses: list[str] = Field(default_factory=list, description="Resolved IP addresses")
    is_wildcard: bool = Field(default=False, description="True if this resolves to a wildcard IP")
    cnames: list[str] = Field(default_factory=list, description="CNAME chain if any")
    first_seen: Optional[str] = Field(default=None, description="First seen timestamp (from crt.sh)")

    @field_validator("name")
    @classmethod
    def _lowercase(cls, v: str) -> str:
        return v.lower().strip().rstrip(".")


class SubdomainResult(BaseModel):
    """Aggregated result of a subdomain enumeration task."""

    domain: str = Field(..., description="The target domain")
    subdomains: list[Subdomain] = Field(default_factory=list)
    total_found: int = Field(default=0)
    sources_used: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    duration_seconds: float = Field(default=0.0)
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# =============================================================================
# Port
# =============================================================================

class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


class PortInfo(BaseModel):
    """Information about a scanned port."""

    port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(default="tcp")
    state: PortState = Field(default=PortState.CLOSED)
    service: str = Field(default="unknown", description="Service name, e.g. http, ssh")
    product: str = Field(default="", description="Product name, e.g. Apache httpd")
    version: str = Field(default="", description="Version string, e.g. 2.4.41")
    extrainfo: str = Field(default="", description="Extra info from service detection")
    cpe: str = Field(default="", description="CPE identifier if available")
    banner: str = Field(default="", description="Service banner grabbed")


class PortScanResult(BaseModel):
    """Result of a port scan on a single host."""

    host: str = Field(..., description="Target host IP or hostname")
    ports: list[PortInfo] = Field(default_factory=list)
    total_scanned: int = Field(default=0)
    open_ports: list[int] = Field(default_factory=list)
    scan_method: str = Field(default="", description="nmap / socket")
    scan_duration_seconds: float = Field(default=0.0)
    os_detection: str = Field(default="", description="OS detection guess")
    errors: list[str] = Field(default_factory=list)
    raw_command: str = Field(default="", description="The exact command executed")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# =============================================================================
# Fingerprint
# =============================================================================

class ServiceFingerprint(BaseModel):
    """Detailed fingerprint of a network service."""

    host: str
    port: int
    protocol: str = "tcp"
    service_name: str = "unknown"
    # HTTP specific
    http_headers: dict[str, str] = Field(default_factory=dict)
    http_title: str = ""
    http_status_code: int = 0
    http_server: str = ""
    http_technologies: list[str] = Field(default_factory=list)  # e.g. ["jQuery", "Bootstrap"]
    # TLS specific
    tls_subject: str = ""
    tls_issuer: str = ""
    tls_not_before: str = ""
    tls_not_after: str = ""
    tls_san: list[str] = Field(default_factory=list)  # Subject Alternative Names
    tls_version: str = ""
    # Generic
    banner: str = ""
    raw_response: str = ""  # Truncated first response for analysis

    @property
    def summary(self) -> str:
        """One-line summary for agent consumption."""
        parts = [f"{self.host}:{self.port}"]
        parts.append(self.service_name)
        if self.http_server:
            parts.append(f"({self.http_server})")
        if self.http_title:
            parts.append(f"[{self.http_title[:50]}]")
        if self.tls_subject:
            parts.append(f"TLS:{self.tls_subject[:40]}")
        return " ".join(parts)


class FingerprintResult(BaseModel):
    """Aggregated fingerprint results for a target."""

    host: str
    fingerprints: list[ServiceFingerprint] = Field(default_factory=list)
    total_services: int = 0
    errors: list[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# =============================================================================
# Asset (aggregated)
# =============================================================================

class AssetSummary(BaseModel):
    """Aggregated asset summary for a target — the end product of asset discovery."""

    target: str = Field(..., description="The original scan target")
    subdomains: list[str] = Field(default_factory=list)
    live_hosts: list[str] = Field(default_factory=list)
    open_ports: dict[str, list[int]] = Field(default_factory=dict)  # host -> [ports]
    services: dict[str, list[str]] = Field(default_factory=dict)    # host -> [service summaries]
    total_subdomains: int = 0
    total_live_hosts: int = 0
    total_open_ports: int = 0
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_markdown(self) -> str:
        """Render as a Markdown summary for agent consumption."""
        lines = [
            f"# Asset Discovery Summary: {self.target}",
            "",
            f"**Scan Time:** {self.timestamp}",
            "",
            f"## Subdomains ({self.total_subdomains})",
        ]
        for sd in self.subdomains[:50]:
            lines.append(f"- {sd}")
        if self.total_subdomains > 50:
            lines.append(f"  ... and {self.total_subdomains - 50} more")

        lines += ["", f"## Live Hosts ({self.total_live_hosts})"]
        for host in self.live_hosts:
            ports = self.open_ports.get(host, [])
            services = self.services.get(host, [])
            lines.append(f"- **{host}** — {len(ports)} open ports")
            for svc in services[:10]:
                lines.append(f"  - {svc}")

        lines += ["", f"**Total Open Ports:** {self.total_open_ports}"]
        return "\n".join(lines)


# =============================================================================
# Whois — domain registration information
# =============================================================================

class WhoisContact(BaseModel):
    """Contact information extracted from WHOIS record."""
    name: str = ""
    organization: str = ""
    email: str = ""
    phone: str = ""
    country: str = ""


class WhoisResult(BaseModel):
    """WHOIS lookup result for a domain."""

    domain: str = Field(..., description="Queried domain name")
    registrar: str = Field(default="", description="Domain registrar")
    creation_date: str = Field(default="", description="Domain creation date")
    expiration_date: str = Field(default="", description="Domain expiration date")
    updated_date: str = Field(default="", description="Last update date")
    name_servers: list[str] = Field(default_factory=list)
    status: list[str] = Field(default_factory=list)
    registrant: WhoisContact = Field(default_factory=WhoisContact)
    admin: WhoisContact = Field(default_factory=WhoisContact)
    tech: WhoisContact = Field(default_factory=WhoisContact)
    raw_text: str = Field(default="", description="Raw WHOIS response (truncated)")
    emails: list[str] = Field(default_factory=list, description="All emails found in WHOIS")
    error: str = Field(default="", description="Error message if lookup failed")


# =============================================================================
# Network Search — FOFA / ZoomEye results
# =============================================================================

class NetworkSearchHit(BaseModel):
    """A single hit from FOFA or ZoomEye."""

    ip: str = ""
    port: int = 0
    protocol: str = ""
    domain: str = ""
    title: str = ""
    server: str = ""
    banner: str = ""
    country: str = ""
    city: str = ""
    asn: str = ""
    org: str = Field(default="", description="Organization/ISP name")
    last_seen: str = ""
    url: str = ""


class NetworkSearchResult(BaseModel):
    """Aggregated result from FOFA/ZoomEye search."""

    query: str = Field(..., description="The search query")
    source: str = Field(default="", description="fofa / zoomeye")
    total_results: int = 0
    hits: list[NetworkSearchHit] = Field(default_factory=list)
    error: str = ""
    query_url: str = ""


# =============================================================================
# ICP备案
# =============================================================================

class ICPRecord(BaseModel):
    """A single ICP备案 record."""

    domain: str = Field(..., description="备案域名")
    site_name: str = Field(default="", description="网站名称")
    company_name: str = Field(default="", description="主办单位名称")
    company_type: str = Field(default="", description="主办单位性质（企业/个人/政府）")
    icp_number: str = Field(default="", description="ICP备案号，如 京ICP备XXXXXXXX号")
    site_audit_date: str = Field(default="", description="审核通过日期")
    site_homepage: str = Field(default="", description="网站首页URL")
    legal_person: str = Field(default="", description="法定代表人")


class ICPResult(BaseModel):
    """ICP备案查询结果."""

    query: str = Field(..., description="查询关键词（域名/公司名）")
    records: list[ICPRecord] = Field(default_factory=list)
    total_found: int = 0
    source: str = Field(default="", description="API source used")
    error: str = ""


# =============================================================================
# Company / Organization — 企查查/天眼查
# =============================================================================

class CompanyInfo(BaseModel):
    """Company information from 企查查/天眼查."""

    company_name: str = Field(..., description="公司名称")
    legal_person: str = Field(default="", description="法定代表人")
    registered_capital: str = Field(default="", description="注册资本")
    established_date: str = Field(default="", description="成立日期")
    business_status: str = Field(default="", description="经营状态（存续/注销等）")
    unified_code: str = Field(default="", description="统一社会信用代码")
    business_scope: str = Field(default="", description="经营范围")
    address: str = Field(default="", description="注册地址")
    email: str = Field(default="", description="企业邮箱")
    phone: str = Field(default="", description="联系电话")
    website: str = Field(default="", description="企业官网")
    industry: str = Field(default="", description="行业分类")
    shareholders: list[dict[str, str]] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list, description="关联域名")


class CompanyResult(BaseModel):
    """公司查询结果."""

    query: str = Field(..., description="查询关键词")
    source: str = Field(default="", description="qichacha / tianyancha")
    companies: list[CompanyInfo] = Field(default_factory=list)
    total_found: int = 0
    error: str = ""


# =============================================================================
# Digital Assets — 微信公众号/小程序/APP/邮箱
# =============================================================================

class WeChatAccount(BaseModel):
    """微信公众号信息."""

    account_name: str = Field(..., description="公众号名称")
    account_id: str = Field(default="", description="公众号ID/微信号")
    description: str = Field(default="", description="公众号简介")
    company_verified: str = Field(default="", description="认证主体（企业名称）")
    service_type: str = Field(default="", description="订阅号/服务号/企业号")
    followers_estimate: str = Field(default="", description="预估粉丝数")


class MiniProgram(BaseModel):
    """微信小程序信息."""

    app_name: str = Field(..., description="小程序名称")
    app_id: str = Field(default="", description="小程序AppID")
    description: str = Field(default="", description="小程序简介")
    company: str = Field(default="", description="所属企业")
    category: str = Field(default="", description="小程序类目")


class MobileApp(BaseModel):
    """移动APP信息."""

    app_name: str = Field(..., description="APP名称")
    platform: str = Field(default="", description="iOS / Android")
    package_id: str = Field(default="", description="包名/Bundle ID")
    developer: str = Field(default="", description="开发者/公司")
    version: str = Field(default="", description="最新版本")
    store_url: str = Field(default="", description="应用商店URL")
    description: str = Field(default="", description="应用描述")


class EmailInfo(BaseModel):
    """邮箱发现信息."""

    email: str = Field(..., description="邮箱地址")
    source: str = Field(default="", description="来源（domain/hunter/whois）")
    first_name: str = Field(default="")
    last_name: str = Field(default="")
    position: str = Field(default="", description="职位")
    confidence: int = Field(default=0, description="可信度 0-100")


class DigitalAssetResult(BaseModel):
    """综合数字资产发现结果."""

    query: str = Field(..., description="查询目标（域名/公司名）")
    wechat_accounts: list[WeChatAccount] = Field(default_factory=list)
    mini_programs: list[MiniProgram] = Field(default_factory=list)
    mobile_apps: list[MobileApp] = Field(default_factory=list)
    emails: list[EmailInfo] = Field(default_factory=list)
    total_found: int = 0
    sources_used: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# =============================================================================
# Organization Intelligence — 零零信安 聚合
# =============================================================================

class OrgIntelItem(BaseModel):
    """Single intelligence item from 零零信安 or aggregation."""

    data_type: str = Field(default="", description="domain/ip/email/leak/vuln/social")
    value: str = Field(default="", description="The discovered value")
    description: str = Field(default="")
    risk_level: str = Field(default="", description="high/medium/low")
    source: str = Field(default="")
    found_date: str = Field(default="")


class OrgIntelResult(BaseModel):
    """组织情报聚合结果."""

    query: str = Field(..., description="查询目标")
    items: list[OrgIntelItem] = Field(default_factory=list)
    total_found: int = 0
    categories: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    error: str = ""


# =============================================================================
# Extended AssetSummary
# =============================================================================

class ExtendedAssetSummary(AssetSummary):
    """Extended asset summary including WHOIS, ICP, digital assets."""

    whois: WhoisResult | None = Field(default=None, description="WHOIS lookup result")
    icp: ICPResult | None = Field(default=None, description="ICP备案信息")
    company: CompanyResult | None = Field(default=None, description="企业信息")
    digital_assets: DigitalAssetResult | None = Field(default=None, description="数字资产")
    network_search: list[NetworkSearchResult] = Field(default_factory=list)
    org_intel: OrgIntelResult | None = Field(default=None, description="组织情报")

    def to_markdown(self) -> str:
        lines = [super().to_markdown(), ""]

        if self.whois and self.whois.domain:
            lines += [
                f"## WHOIS: {self.whois.domain}",
                f"- **Registrar:** {self.whois.registrar}",
                f"- **Created:** {self.whois.creation_date}",
                f"- **Expires:** {self.whois.expiration_date}",
                f"- **Name Servers:** {', '.join(self.whois.name_servers[:5])}",
                f"- **Emails Found:** {', '.join(self.whois.emails[:5]) or 'None'}",
                "",
            ]

        if self.icp and self.icp.records:
            lines.append(f"## ICP备案 ({len(self.icp.records)} records)")
            for r in self.icp.records[:5]:
                lines.append(f"- **{r.domain}** — {r.company_name} ({r.icp_number})")
            lines.append("")

        if self.company and self.company.companies:
            lines.append(f"## 企业信息 ({len(self.company.companies)} results)")
            for c in self.company.companies[:5]:
                lines.append(f"- **{c.company_name}** — 法人:{c.legal_person}, 成立:{c.established_date}")
                if c.domains:
                    lines.append(f"  关联域名: {', '.join(c.domains[:10])}")
            lines.append("")

        if self.digital_assets:
            da = self.digital_assets
            if da.wechat_accounts:
                lines.append(f"## 微信公众号 ({len(da.wechat_accounts)})")
                for w in da.wechat_accounts:
                    lines.append(f"- **{w.account_name}** ({w.account_id}) — {w.company_verified}")
                lines.append("")
            if da.mini_programs:
                lines.append(f"## 微信小程序 ({len(da.mini_programs)})")
                for m in da.mini_programs:
                    lines.append(f"- **{m.app_name}** — {m.company}")
                lines.append("")
            if da.mobile_apps:
                lines.append(f"## 移动APP ({len(da.mobile_apps)})")
                for a in da.mobile_apps:
                    lines.append(f"- **{a.app_name}** ({a.platform}) — {a.developer}")
                lines.append("")
            if da.emails:
                lines.append(f"## 关联邮箱 ({len(da.emails)})")
                for e in da.emails[:20]:
                    lines.append(f"- {e.email} (source: {e.source}, confidence: {e.confidence}%)")
                lines.append("")

        return "\n".join(lines)
