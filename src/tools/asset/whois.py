"""WHOIS lookup — domain registration intelligence.

Two backends:
  - python-whois: Full-featured WHOIS client (preferred)
  - socket: Raw WHOIS protocol via TCP/43 (fallback, zero-dependency)

Extracts: registrar, creation/expiry dates, name servers, contact emails,
registrant organization — all critical for asset attribution.
"""

from __future__ import annotations

import re
import socket
import time
from datetime import datetime

from src.tools.asset.models import WhoisContact, WhoisResult
from src.utils.logger import get_logger

logger = get_logger(__name__)

# WHOIS servers for common TLDs (fallback when python-whois unavailable)
WHOIS_SERVERS: dict[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "cn": "whois.cnnic.cn",
    "com.cn": "whois.cnnic.cn",
    "net.cn": "whois.cnnic.cn",
    "org.cn": "whois.cnnic.cn",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "ai": "whois.nic.ai",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "xyz": "whois.nic.xyz",
    "info": "whois.afilias.net",
    "biz": "whois.nic.biz",
    "top": "whois.nic.top",
    "tech": "whois.nic.tech",
    "cloud": "whois.nic.cloud",
}


def _parse_whois_raw(raw: str) -> dict:
    """Parse key WHOIS fields from raw text using regex patterns."""
    data: dict = {
        "registrar": "", "creation_date": "", "expiration_date": "",
        "updated_date": "", "name_servers": [], "status": [],
        "emails": [],
        "registrant": {"name": "", "organization": "", "email": "", "phone": "", "country": ""},
        "admin": {"name": "", "organization": "", "email": "", "phone": "", "country": ""},
        "tech": {"name": "", "organization": "", "email": "", "phone": "", "country": ""},
    }

    patterns = {
        "registrar": [
            r"Registrar:\s*(.+)",
            r"Sponsoring Registrar:\s*(.+)",
        ],
        "creation_date": [
            r"Creation Date:\s*(.+)",
            r"Created on:\s*(.+)",
            r"Registration Time:\s*(.+)",
        ],
        "expiration_date": [
            r"Registry Expiry Date:\s*(.+)",
            r"Expiry Date:\s*(.+)",
            r"Expiration Date:\s*(.+)",
            r"Expires on:\s*(.+)",
        ],
        "updated_date": [
            r"Updated Date:\s*(.+)",
            r"Last Updated on:\s*(.+)",
        ],
    }

    for field, field_patterns in patterns.items():
        for pat in field_patterns:
            m = re.search(pat, raw, re.IGNORECASE)
            if m:
                data[field] = m.group(1).strip()
                break

    # Name servers
    data["name_servers"] = re.findall(r"Name Server:\s*(.+)", raw, re.IGNORECASE)

    # Status
    data["status"] = re.findall(r"Status:\s*(.+)", raw, re.IGNORECASE)

    # Emails
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    data["emails"] = list(set(re.findall(email_pattern, raw)))

    # Contact fields
    contact_maps = {
        "registrant": "Registrant",
        "admin": "Admin",
        "tech": "Tech",
    }
    for contact_key, prefix in contact_maps.items():
        for field in ["name", "organization", "email", "phone", "country"]:
            pat = rf"{prefix}\s+{field.replace('_', ' ')}:\s*(.+)" if field != "country" else rf"{prefix}\s+Country:\s*(.+)"
            m = re.search(pat, raw, re.IGNORECASE)
            if m:
                data[contact_key][field] = m.group(1).strip()
            # Try alternate format: "Registrant Email:"
            pat2 = rf"{prefix}\s+{field.replace('_', ' ').title()}:\s*(.+)"
            m = re.search(pat2, raw, re.IGNORECASE)
            if m and not data[contact_key].get(field, ""):
                data[contact_key][field] = m.group(1).strip()

    return data


# ── Backend: python-whois ─────────────────────────────────────────────────


async def whois_lookup_python_whois(domain: str) -> WhoisResult:
    """Use the python-whois library for full-featured WHOIS lookup."""
    import whois as whois_lib

    loop = __import__("asyncio").get_event_loop()

    def _lookup():
        return whois_lib.whois(domain)

    try:
        w = await loop.run_in_executor(None, _lookup)
    except Exception as exc:
        logger.warning("python-whois failed for {}: {}", domain, exc)
        return WhoisResult(domain=domain, error=str(exc))

    # Extract data
    creation = ""
    expiration = ""
    updated = ""
    if w.creation_date:
        creation = str(w.creation_date)
    if w.expiration_date:
        expiration = str(w.expiration_date)
    if w.updated_date:
        updated = str(w.updated_date)

    # Collect all emails from raw text
    raw_text = w.text if w.text else ""
    emails = list(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", raw_text)))

    return WhoisResult(
        domain=domain,
        registrar=w.registrar or "",
        creation_date=creation,
        expiration_date=expiration,
        updated_date=updated,
        name_servers=w.name_servers or [],
        status=[str(s) for s in (w.status or [])],
        registrant=WhoisContact(
            name=w.name or "",
            organization=w.org or "",
            email=w.emails[0] if w.emails else "",
            country=w.country or "",
        ),
        raw_text=raw_text[:2000],
        emails=emails,
    )


# ── Backend: Raw socket WHOIS ─────────────────────────────────────────────


async def whois_lookup_raw(domain: str, timeout: float = 10.0) -> WhoisResult:
    """Raw WHOIS lookup via TCP port 43 — zero external dependencies."""
    # Determine the TLD
    parts = domain.lower().rstrip(".").split(".")
    tld = parts[-1]
    # Handle second-level TLDs like com.cn
    if len(parts) >= 2 and parts[-2] in ("com", "net", "org", "gov", "edu"):
        tld = f"{parts[-2]}.{parts[-1]}"

    whois_server = WHOIS_SERVERS.get(tld, "whois.iana.org")
    query_domain = domain if tld not in ("com.cn", "net.cn", "org.cn") else domain

    loop = __import__("asyncio").get_event_loop()

    def _raw_query():
        sock = socket.create_connection((whois_server, 43), timeout=timeout)
        try:
            sock.sendall(f"{query_domain}\r\n".encode())
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data.decode(errors="replace")
        finally:
            sock.close()

    try:
        raw_text = await loop.run_in_executor(None, _raw_query)
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        logger.warning("Raw WHOIS failed for {}: {}", domain, exc)
        return WhoisResult(domain=domain, error=str(exc))

    parsed = _parse_whois_raw(raw_text)

    return WhoisResult(
        domain=domain,
        registrar=parsed["registrar"],
        creation_date=parsed["creation_date"],
        expiration_date=parsed["expiration_date"],
        updated_date=parsed["updated_date"],
        name_servers=parsed["name_servers"],
        status=parsed["status"],
        registrant=WhoisContact(**parsed["registrant"]),
        admin=WhoisContact(**parsed["admin"]),
        tech=WhoisContact(**parsed["tech"]),
        raw_text=raw_text[:2000],
        emails=parsed["emails"],
    )


# ── Public API ────────────────────────────────────────────────────────────


async def whois_lookup(domain: str) -> WhoisResult:
    """Perform WHOIS lookup with automatic backend selection.

    Tries python-whois first (richer parsing), falls back to raw socket.
    """
    domain = domain.lower().strip().rstrip(".")

    # Try python-whois first
    try:
        return await whois_lookup_python_whois(domain)
    except ImportError:
        logger.info("python-whois not installed — using raw WHOIS socket")
    except Exception as exc:
        logger.warning("python-whois error: {} — falling back to raw WHOIS", exc)

    # Fall back to raw socket
    return await whois_lookup_raw(domain)
