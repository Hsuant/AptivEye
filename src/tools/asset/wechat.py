"""微信公众号 & 微信小程序 discovery.

Discover WeChat Official Accounts and Mini Programs associated
with an organization via public search endpoints.
"""

from __future__ import annotations

import re

import httpx

from config.settings import get_settings
from src.tools.asset.models import MiniProgram, WeChatAccount
from src.utils.logger import get_logger

logger = get_logger(__name__)


async def discover_wechat_accounts(
    keyword: str,
    timeout: float = 15.0,
) -> list[WeChatAccount]:
    """Discover WeChat Official Accounts related to an organization."""
    settings = get_settings().asset_api
    accounts: list[WeChatAccount] = []

    try:
        url = settings.weixin_search_url
        params = {"type": 1, "query": keyword, "ie": "utf8"}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code == 200:
                text = resp.text
                name_matches = re.findall(
                    r'<a[^>]*uigs="account_name_[^"]*"[^>]*>(.*?)</a>',
                    text, re.DOTALL,
                )
                id_matches = re.findall(
                    r'微信号[：:]\s*([a-zA-Z0-9_-]+)',
                    text,
                )
                for i, name in enumerate(name_matches[:20]):
                    name = re.sub(r"<[^>]+>", "", name).strip()
                    if name and keyword.lower() in name.lower():
                        account_id = id_matches[i] if i < len(id_matches) else ""
                        accounts.append(WeChatAccount(
                            account_name=name,
                            account_id=account_id,
                            description="",
                        ))

        if accounts:
            logger.info("WeChat search: {} accounts found for '{}'", len(accounts), keyword)
    except Exception as exc:
        logger.debug("WeChat discovery for '{}' failed: {}", keyword, exc)

    return accounts


async def discover_mini_programs(
    keyword: str,
    timeout: float = 15.0,
) -> list[MiniProgram]:
    """Discover WeChat Mini Programs related to an organization."""
    settings = get_settings().asset_api
    mini_programs: list[MiniProgram] = []

    try:
        url = settings.miniprogram_search_url
        params = {"keyword": keyword}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code == 200:
                text = resp.text
                app_matches = re.findall(
                    r'data-appid="([^"]+)".*?data-name="([^"]+)"',
                    text,
                )
                for app_id, app_name in app_matches[:20]:
                    if app_name:
                        mini_programs.append(MiniProgram(
                            app_name=app_name.strip(),
                            app_id=app_id.strip(),
                            company=keyword,
                        ))

        logger.info("MiniProgram search: {} found for '{}'", len(mini_programs), keyword)
    except Exception as exc:
        logger.debug("MiniProgram discovery for '{}' failed: {}", keyword, exc)

    return mini_programs
