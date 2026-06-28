"""General-purpose validators used across the codebase."""

from __future__ import annotations

import ipaddress
import re
from typing import Any


def is_valid_ip(target: str) -> bool:
    """Check if target is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_valid_cidr(target: str) -> bool:
    """Check if target is a valid CIDR range."""
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def is_valid_domain(target: str) -> bool:
    """Check if target looks like a valid domain name."""
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(domain_pattern.match(target))


def is_valid_url(target: str) -> bool:
    """Check if target is a valid HTTP(S) URL."""
    url_pattern = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
    return bool(url_pattern.match(target))


def validate_target(target: str) -> str:
    """Validate a scan target and return a normalized string.

    Returns the target unchanged if valid; raises ValueError otherwise.
    """
    if is_valid_ip(target) or is_valid_cidr(target) or is_valid_domain(target):
        return target
    raise ValueError(f"Invalid target: {target!r}")


def truncate_str(value: str, max_length: int = 1000, *, suffix: str = "...[truncated]") -> str:
    """Truncate a string to max_length, adding a suffix if truncated."""
    if len(value) <= max_length:
        return value
    return value[: max_length - len(suffix)] + suffix


def sanitize_filename(name: str) -> str:
    """Replace characters unsafe for filenames."""
    return re.sub(r"[^\w\-.]", "_", name)


def deep_redact(data: Any, keys: set[str] | None = None) -> Any:
    """Recursively redact sensitive keys from a dict/list structure.

    Args:
        data: The data structure to redact.
        keys: Set of key names to redact. Defaults to common sensitive keys.

    Returns:
        A new data structure with sensitive values replaced by "[REDACTED]".
    """
    if keys is None:
        keys = {
            "api_key", "apikey", "secret", "password", "passwd", "token",
            "authorization", "auth", "credential", "private_key",
        }

    if isinstance(data, dict):
        return {
            k: "[REDACTED]" if k.lower() in keys else deep_redact(v, keys)
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [deep_redact(item, keys) for item in data]
    return data
