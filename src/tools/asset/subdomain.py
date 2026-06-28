"""Subdomain enumeration — DNS brute-force, crt.sh, Amass integration.

Provides multiple discovery backends with graceful degradation:
  - DNS brute-force: always available (built-in wordlist + dnspython)
  - crt.sh API: no auth, certificate transparency log mining
  - Amass: comprehensive but requires external binary

Each backend is independently usable and returns typed Subdomain objects.
"""

from __future__ import annotations

import asyncio
import random
import re
import socket
import time
from typing import Optional

import httpx

from src.tools.asset.models import Subdomain, SubdomainResult, SubdomainSource
from src.utils.logger import get_logger

logger = get_logger(__name__)

# ── Built-in DNS wordlist (top ~80 common subdomains) ─────────────────────
BUILT_IN_WORDLIST: list[str] = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "dev", "staging",
    "admin", "portal", "cdn", "mobile", "media", "test", "beta", "git",
    "docs", "support", "apps", "auth", "db", "demo", "download", "dns",
    "email", "forum", "help", "imap", "intranet", "jenkins", "jira",
    "login", "mysql", "news", "ns", "pop", "pop3", "proxy", "sandbox",
    "sip", "sql", "ssh", "status", "store", "uat", "upload", "video",
    "wiki", "www2", "crm", "dashboard", "monitor", "node", "svn",
    "travis", "vps", "web", "wpad", "chat", "ldap", "kibana", "grafana",
    "prometheus", "consul", "nomad", "vault", "backup", "storage",
    "assets", "static", "files", "cloud",
]

# ── DNS resolver helpers ──────────────────────────────────────────────────


def _resolve_dns(domain: str, rdtype: str = "A", timeout: float = 3.0) -> list[str]:
    """Resolve a DNS query, returning results or empty list."""
    try:
        import dns.resolver

        answers = dns.resolver.resolve(domain, rdtype, lifetime=timeout)
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.resolver.Timeout, dns.exception.DNSException):
        return []
    except ImportError:
        # dnspython not available — fall back to system resolver
        try:
            info = socket.getaddrinfo(domain, None, socket.AF_INET)
            return list({addr[4][0] for addr in info})
        except (socket.gaierror, OSError):
            return []


def _has_wildcard(domain: str) -> tuple[bool, list[str]]:
    """Detect if a domain uses wildcard DNS by resolving a random subdomain."""
    rand_sub = f"{random.randint(100000, 999999)}.{domain}"
    ips = _resolve_dns(rand_sub, "A")
    return (len(ips) > 0, ips)


# ── Backend: DNS brute-force ──────────────────────────────────────────────


async def enumerate_subdomains_dns(
    domain: str,
    wordlist: list[str] | None = None,
    concurrency: int = 20,
    timeout: float = 5.0,
) -> list[Subdomain]:
    """Enumerate subdomains via DNS brute-force using a wordlist.

    Uses asyncio for concurrent DNS resolution. Falls back to socket
    if dnspython is not installed.

    Args:
        domain: Target domain, e.g. "example.com".
        wordlist: Custom wordlist. Uses built-in if not provided.
        concurrency: Max concurrent DNS queries.
        timeout: Per-query timeout in seconds.

    Returns:
        List of Subdomain objects that resolved successfully.
    """
    words = wordlist or BUILT_IN_WORDLIST
    wildcard_flag, wildcard_ips = _has_wildcard(domain)

    semaphore = asyncio.Semaphore(concurrency)
    found: list[Subdomain] = []

    async def _check(sub: str) -> None:
        async with semaphore:
            fqdn = f"{sub}.{domain}"
            loop = asyncio.get_event_loop()
            ips = await loop.run_in_executor(None, _resolve_dns, fqdn, "A", timeout)
            if ips:
                is_wc = wildcard_flag and set(ips) == set(wildcard_ips)
                found.append(Subdomain(
                    name=fqdn,
                    source=SubdomainSource.DNS_BRUTE,
                    ip_addresses=ips,
                    is_wildcard=is_wc,
                ))

    tasks = [_check(w) for w in words]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Deduplicate by name
    seen: set[str] = set()
    unique: list[Subdomain] = []
    for sd in found:
        if sd.name not in seen:
            seen.add(sd.name)
            unique.append(sd)

    logger.info("DNS brute-force: {} subdomains found for {}", len(unique), domain)
    return unique


# ── Backend: crt.sh certificate transparency ──────────────────────────────


async def enumerate_subdomains_crtsh(
    domain: str,
    timeout: float = 15.0,
) -> list[Subdomain]:
    """Query crt.sh for certificate transparency log entries.

    crt.sh is a free, public CT log search — no API key required.
    Returns subdomain names extracted from SSL/TLS certificate CN/SAN fields.
    """
    from config.settings import get_settings
    api_url = get_settings().asset_api.crtsh_api_url.rstrip("/")
    url = f"{api_url}/?q=%25.{domain}&output=json"
    headers = {"User-Agent": "AptivEye/0.1"}

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            entries = response.json()
    except httpx.HTTPError as exc:
        logger.warning("crt.sh query failed for {}: {}", domain, exc)
        return []
    except ValueError:
        logger.warning("crt.sh returned non-JSON for {}", domain)
        return []

    # Extract unique names from name_value fields
    names: set[str] = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in re.split(r"[\n\r]+", name_value):
            name = name.strip().lower().rstrip(".")
            # Filter: must contain the target domain, not be a wildcard cert
            if name and domain in name and not name.startswith("*."):
                names.add(name)

    subdomains: list[Subdomain] = []
    first_seen: dict[str, str] = {}
    for entry in entries:
        nv = entry.get("name_value", "")
        entry_time = entry.get("entry_timestamp", "")
        for name in re.split(r"[\n\r]+", nv):
            name = name.strip().lower().rstrip(".")
            if name and domain in name and not name.startswith("*."):
                if name not in first_seen or (entry_time and entry_time < first_seen.get(name, "")):
                    first_seen[name] = entry_time

    # Resolve IPs for discovered subdomains (concurrently)
    semaphore = asyncio.Semaphore(10)

    async def _resolve(name: str) -> Subdomain:
        async with semaphore:
            loop = asyncio.get_event_loop()
            ips = await loop.run_in_executor(None, _resolve_dns, name, "A", 3.0)
            return Subdomain(
                name=name,
                source=SubdomainSource.CRT_SH,
                ip_addresses=ips,
                first_seen=first_seen.get(name),
            )

    tasks = [_resolve(n) for n in names]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    subdomains = [r for r in results if isinstance(r, Subdomain)]

    logger.info("crt.sh: {} subdomains found for {}", len(subdomains), domain)
    return subdomains


# ── Backend: Amass (external binary) ──────────────────────────────────────


async def enumerate_subdomains_amass(
    domain: str,
    amass_bin: str = "amass",
    timeout: float = 120.0,
    passive: bool = True,
) -> list[Subdomain]:
    """Run OWASP Amass for comprehensive subdomain enumeration.

    Requires `amass` to be installed and on PATH.
    Falls back gracefully if not available.

    Args:
        domain: Target domain.
        amass_bin: Path to amass binary.
        timeout: Max execution time in seconds.
        passive: If True, use passive mode (no direct scanning).
    """
    # Check if amass is available
    try:
        proc = await asyncio.create_subprocess_exec(
            amass_bin, "-version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=5.0)
        if proc.returncode != 0:
            logger.info("Amass not available — skipping")
            return []
    except (FileNotFoundError, asyncio.TimeoutError, OSError):
        logger.info("Amass binary '{}' not found — skipping", amass_bin)
        return []

    # Build command
    cmd = [amass_bin, "enum", "-d", domain, "-json", "subdomains.json"]
    if passive:
        cmd.append("-passive")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("Amass timed out after {}s for {}", timeout, domain)
        return []
    except FileNotFoundError:
        return []

    # Parse amass output — each line is a subdomain name
    subdomains: list[Subdomain] = []
    for line in stdout.decode(errors="replace").splitlines():
        name = line.strip().lower().rstrip(".")
        if name and domain in name:
            subdomains.append(Subdomain(
                name=name,
                source=SubdomainSource.AMASS,
            ))

    logger.info("Amass: {} subdomains found for {}", len(subdomains), domain)
    return subdomains


# ── Main entry point ──────────────────────────────────────────────────────


async def discover_subdomains(
    domain: str,
    *,
    use_dns_brute: bool = True,
    use_crtsh: bool = True,
    use_amass: bool = False,
    wordlist: list[str] | None = None,
    dns_concurrency: int = 20,
) -> SubdomainResult:
    """Run all enabled subdomain enumeration backends and merge results.

    This is the primary entry point called by the MCP Server tool handler.

    Args:
        domain: Target domain name.
        use_dns_brute: Enable DNS brute-force with wordlist.
        use_crtsh: Enable crt.sh certificate transparency lookup.
        use_amass: Enable OWASP Amass (requires installed binary).
        wordlist: Custom wordlist for DNS brute-force.
        dns_concurrency: Max concurrent DNS queries.

    Returns:
        SubdomainResult with deduplicated, merged results from all backends.
    """
    start = time.monotonic()
    errors: list[str] = []
    sources_used: list[str] = []
    all_subdomains: dict[str, Subdomain] = {}

    tasks = []
    if use_dns_brute:
        sources_used.append("dns_brute")
        tasks.append(("dns", enumerate_subdomains_dns(domain, wordlist, dns_concurrency)))
    if use_crtsh:
        sources_used.append("crt_sh")
        tasks.append(("crtsh", enumerate_subdomains_crtsh(domain)))
    if use_amass:
        sources_used.append("amass")
        tasks.append(("amass", enumerate_subdomains_amass(domain)))

    # Run all backends concurrently
    results = await asyncio.gather(
        *[t[1] for t in tasks],
        return_exceptions=True,
    )

    for (backend_name, _), result in zip(tasks, results):
        if isinstance(result, Exception):
            errors.append(f"{backend_name}: {result}")
            logger.warning("Subdomain backend {} failed: {}", backend_name, result)
        elif isinstance(result, list):
            for sd in result:
                if sd.name not in all_subdomains:
                    all_subdomains[sd.name] = sd
                else:
                    # Merge IP addresses from multiple sources
                    existing = all_subdomains[sd.name]
                    existing_ips = set(existing.ip_addresses)
                    for ip in sd.ip_addresses:
                        if ip not in existing_ips:
                            existing.ip_addresses.append(ip)
                    # Keep the earliest first_seen
                    if sd.first_seen and (not existing.first_seen or sd.first_seen < existing.first_seen):
                        existing.first_seen = sd.first_seen

    merged = list(all_subdomains.values())
    merged.sort(key=lambda s: s.name)

    duration = time.monotonic() - start
    logger.info(
        "Subdomain discovery complete: {} subdomains from {} sources in {:.1f}s",
        len(merged), sources_used, duration,
    )

    return SubdomainResult(
        domain=domain,
        subdomains=merged,
        total_found=len(merged),
        sources_used=sources_used,
        errors=errors,
        duration_seconds=round(duration, 2),
    )
