"""关联邮箱 discovery — Hunter.io API + domain pattern guessing.

Discover email addresses associated with an organization via
Hunter.io API (requires key) and common organizational patterns (free).
"""

from __future__ import annotations

import httpx

from config.settings import get_settings
from src.tools.asset.models import EmailInfo
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Common email patterns for organizational domains
EMAIL_PATTERNS: list[str] = [
    "admin", "webmaster", "hostmaster", "postmaster", "info", "contact",
    "support", "sales", "marketing", "hr", "jobs", "security", "abuse",
    "noc", "dns", "tech", "it", "help", "service", "press", "media",
    "pr", "legal", "finance", "office", "mail", "root",
]


async def discover_emails_hunter(
    domain: str,
    timeout: float = 15.0,
) -> list[EmailInfo]:
    """Discover email addresses via Hunter.io API."""
    settings = get_settings().asset_api
    api_key = settings.hunter_api_key.get_secret_value()
    api_url = settings.hunter_api_url.rstrip("/")

    if not api_key:
        return []

    emails: list[EmailInfo] = []

    try:
        url = f"{api_url}/domain-search"
        params = {"domain": domain, "api_key": api_key, "limit": 100}
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, params=params)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("data", {}).get("emails", []):
                    emails.append(EmailInfo(
                        email=item.get("value", ""),
                        source="hunter",
                        first_name=item.get("first_name", ""),
                        last_name=item.get("last_name", ""),
                        position=item.get("position", ""),
                        confidence=item.get("confidence", 0),
                    ))
    except Exception as exc:
        logger.debug("Hunter.io API for '{}' failed: {}", domain, exc)

    return emails


def discover_emails_pattern(
    domain: str,
) -> list[EmailInfo]:
    """Generate common organizational email patterns for a domain.

    Always available — no API key required.
    Note: These are GUESSES based on common patterns, not verified addresses.
    """
    emails: list[EmailInfo] = []
    domain = domain.lower().strip().rstrip(".")

    for prefix in EMAIL_PATTERNS:
        emails.append(EmailInfo(
            email=f"{prefix}@{domain}",
            source="pattern",
            confidence=10,
        ))

    return emails
