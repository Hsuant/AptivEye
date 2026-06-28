"""Configuration module for AptivEye.

Uses pydantic-settings for type-safe configuration loaded from
environment variables and .env files.
"""

from config.settings import Settings, get_settings

__all__ = ["Settings", "get_settings"]
