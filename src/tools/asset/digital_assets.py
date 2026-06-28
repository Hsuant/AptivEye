"""Digital asset discovery — composite tool.

Orchestrates WeChat, MiniProgram, Mobile App, and Email discovery
into a single DigitalAssetResult. Each sub-module can also be used independently.
"""

from __future__ import annotations

import asyncio

from src.tools.asset.apps import discover_mobile_apps
from src.tools.asset.emails import discover_emails_hunter, discover_emails_pattern
from src.tools.asset.models import DigitalAssetResult
from src.tools.asset.wechat import discover_mini_programs, discover_wechat_accounts
from src.utils.logger import get_logger

logger = get_logger(__name__)


async def discover_digital_assets(
    target: str,
    *,
    target_type: str = "auto",
    include_emails: bool = True,
    include_wechat: bool = True,
    include_miniprogram: bool = True,
    include_apps: bool = True,
) -> DigitalAssetResult:
    """Discover digital assets associated with a target.

    Args:
        target: Domain name or company name.
        target_type: Type of target for optimized search.
        include_emails: Enable email discovery.
        include_wechat: Enable WeChat account discovery.
        include_miniprogram: Enable mini-program discovery.
        include_apps: Enable mobile app discovery.
    """
    result = DigitalAssetResult(query=target)

    tasks = []
    task_names = []

    if include_wechat:
        tasks.append(discover_wechat_accounts(target))
        task_names.append("wechat")
    if include_miniprogram:
        tasks.append(discover_mini_programs(target))
        task_names.append("miniprogram")
    if include_apps:
        tasks.append(discover_mobile_apps(target))
        task_names.append("apps")
    if include_emails:
        tasks.append(discover_emails_hunter(target))
        task_names.append("emails_hunter")

    if tasks:
        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        for name, r in zip(task_names, gathered):
            if isinstance(r, Exception):
                logger.warning("{} discovery failed: {}", name, r)
            elif name == "wechat":
                result.wechat_accounts = r
            elif name == "miniprogram":
                result.mini_programs = r
            elif name == "apps":
                result.mobile_apps = r
            elif name == "emails_hunter":
                result.emails = r

    # Always include pattern-based emails (free, no API key)
    if include_emails:
        result.emails.extend(discover_emails_pattern(target))

    return result
