"""FOFA AI Query Planner — agent-level FOFA intelligence.

Integrates FOFA domain expertise into the agent's planning and reasoning
pipeline. Uses the agent's injected LLMRouter (NOT its own) so that all
LLM calls go through the same gateway, cost tracker, and rate limiter.

Capabilities:
  - query_planning: Natural language → structured FOFA query plan
  - reflect_and_retry: Generate broader queries when results are empty
  - summarize_assets: Identify tech stacks + recommend scanning params
  - analyze_host_risk: Risk assessment for a single IP/domain
  - analyze_stat_trends: Global situational awareness from stats data

Usage (from agent nodes)::

    from src.agent.planner import FofaQueryPlanner

    planner = FofaQueryPlanner(llm_router)
    plan = await planner.plan_query(
        user_intent="find nginx servers in China",
        vip_level=2,
    )
    # → {"action": "fofa_search", "queries": [...], "fields": "...", ...}
"""

from __future__ import annotations

import json
import re
from typing import Any

from src.utils.logger import get_logger

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Prompt templates (inline — these ARE the domain expertise)
# ═══════════════════════════════════════════════════════════════════════════

_STRATEGIC_PLANNING_PROMPT = """你是一个精通 FOFA 搜索引擎的安全专家。请根据用户需求，精准选择 API 接口并生成参数。

### 🕹️ 智能路由 (Action Routing) - 必须从以下 5 个动作中选择:
1. **fofa_search**: [资产清单] 用户想获取具体的 IP/URL 列表时使用。(默认)
2. **host_query**: [单体画像] 用户提供了具体的单个 IP，想看它的详细标签、端口、产品。
3. **stat_query**: [统计聚合] 用户想看数据的分布、排名、趋势 (Top 5)。
4. **icon_query**: [图标逆向] 用户提供 URL，想搜同类图标资产。
5. **bat_query**: [批量文件] 用户提到了本地文件路径。

### 🔓 核心原则:
1. Search Query: 全员可用 `body=`, `icon_hash=` 等高级语法。
2. Fields: 严格受等级限制，越权会报错。
3. 组合拳: 使用 `||` 和 `&&` 聚合特征 (如 `app="Redis" && country="CN"`).

### 📊 统计聚合专用规则 (Stat Rules):
仅当 action="stat_query" 时有效。支持的字段: protocol, domain, port, title, os, server, country, asn, org, asset_type, fid, icp

### 📚 字段权限表 (Fields Permission Guide):
当前用户等级: **{vip_level} ({level_name})**

**【Level 0+ 全员可用】** ip, port, protocol, host, domain, title, server, os, header, banner, icp, jarm, country, region, city, asn, org, cert, cert.domain, cert.issuer.org, cert.subject.cn, tls.ja3s, tls.version
**【Level 11+ 个人版及以上】** header_hash, banner_hash, banner_fid
**【Level 12+ 专业版及以上】** product, product_category, cname, lastupdatetime
**【Level 13+ 商业版及以上】** body, icon_hash, fid, product.version, cert.is_valid
**【Level 5 企业版V2】** 包含所有权限 + icon, structinfo

### 🧠 决策逻辑:
1. Action: 判定动作。2. Target: host_query/icon/bat 的目标。3. Queries: 生成 FOFA 查询语句 (1-5条)。
4. Fields: 根据等级选择字段。5. 大胆使用 body=, app=, icon_hash= 等语法。

### 📝 返回格式 (JSON Only):
{{"action": "fofa_search|host_query|stat_query|icon_query|bat_query", "target": "具体目标或null", "queries": ["查询语句"], "fields": "逗号分隔的字段列表", "run_nuclei": true/false}}
"""

_REFLECTION_PROMPT = """你是一个FOFA高级搜索专家。

【现状】用户想要查询："{user_intent}"
但是，你生成的以下查询语句全部返回了 0 条数据（失败）：
{failed_queries_json}

【反思与修正】请分析失败原因并生成 3 条新的、更宽泛的修正查询语句。

【修正策略】
1. 保守修正：去掉最可能出错的 1 个条件，保留核心指纹。
2. 模糊匹配：使用 body= 或 title= 替换 host=，扩大搜索范围。
3. 极度宽泛：仅保留最核心关键词 + country="CN"。
4. 域名猜想：尝试 .cn 或 .com 替代 .edu.cn。

【权限限制】用户等级 Level {vip_level}。确保字段不越权。

请仅返回 JSON：{{"correction_reason": "简短分析", "new_queries": ["query1", "query2", "query3"]}}
"""

_SUMMARY_PROMPT = """你是一个精通漏洞挖掘的安全专家。用户最初需求：'{user_intent}'。
资产样本如下：{preview_json}

【决策逻辑】
1. 技术栈识别: 分析 Title/Server/Header/Port → Spring/ThinkPHP/WebLogic/Exchange
2. 意图对齐: 特定漏洞→对应 tags；大范围普查→-as -severity critical,high
3. 参数调优: 目标少→-bs 25 -rl 150；目标多→-tags cves,misconfig

【输出格式 (JSON Only)】
{{"summary": "Markdown格式的资产画像总结", "nuclei_args": "命令行参数字符串"}}
"""

_HOST_RISK_PROMPT = """你是一名高级渗透测试工程师。请根据以下 FOFA Host 聚合数据，生成【单体资产风险画像】。

用户意图: {user_intent}
资产概要: {context_json}

请输出 Markdown 报告:
1. 🛡️ 暴露面分析: 高危端口 (3389, 445, 22, 数据库端口等)
2. ⚠️ 风险研判: 识别产品推测可能漏洞
3. 🎯 攻击路径推演: 优先攻击入口
4. 📝 综合评分: 高/中/低 + 一句话总结
"""

_STAT_TRENDS_PROMPT = """你是一名网络空间测绘数据分析师。请根据 FOFA 统计聚合数据，生成【全球态势分析小结】。

查询语句: {query}
用户意图: {user_intent}
统计数据(Top5): {context_json}

请输出 Markdown:
1. 📊 分布特征: 地域集中性、端口分布规律
2. 🔍 异常洞察: 非标准端口、异常 Title
3. 🌍 宏观影响: 全球普及度和潜在影响面
4. 💡 结论: 一句话总结态势
"""


# ═══════════════════════════════════════════════════════════════════════════
# FofaQueryPlanner
# ═══════════════════════════════════════════════════════════════════════════


class FofaQueryPlanner:
    """Agent-level FOFA AI capabilities using the injected LLMRouter.

    This is NOT a tool — it's an agent component that the Supervisor
    or Worker can use directly. All LLM calls go through the agent's
    shared LLMRouter, ensuring unified cost tracking and rate limiting.

    Usage::

        from src.gateway.router import LLMRouter
        from src.agent.planner import FofaQueryPlanner

        llm = LLMRouter()
        planner = FofaQueryPlanner(llm)
        plan = await planner.plan_query("find exposed Redis in US")
    """

    # VIP level display names
    _LEVEL_NAMES = {
        0: "注册用户", 1: "普通会员", 2: "高级会员(专业版)",
        5: "企业版V2", 11: "个人版", 12: "专业版", 13: "商业版",
    }

    def __init__(self, llm_router: Any) -> None:
        """Initialize with the agent's LLMRouter (dependency injection).

        Args:
            llm_router: The agent's LLMRouter instance (NOT created here).
        """
        self._llm = llm_router

    # ── Core: Strategic Query Planning ─────────────────────────────────

    async def plan_query(
        self,
        user_intent: str,
        vip_level: int = 0,
    ) -> dict[str, Any] | None:
        """Convert natural language into a FOFA query plan.

        The LLM chooses the appropriate action and generates optimized
        FOFA query syntax with VIP-level-aware field selection.

        Args:
            user_intent: Natural language description of what to find.
            vip_level: FOFA account VIP level (0=free, 2=professional, etc.).

        Returns:
            {"action": "...", "target": "...", "queries": [...], "fields": "...", "run_nuclei": bool}
            or None on failure.
        """
        level_name = self._LEVEL_NAMES.get(vip_level, f"Level {vip_level}")
        system_prompt = _STRATEGIC_PLANNING_PROMPT.format(
            vip_level=vip_level, level_name=level_name
        )

        logger.info("FOFA query planning: intent='{}', vip={}", user_intent[:80], vip_level)

        raw = await self._call(system_prompt, user_intent, temperature=0.2)

        if not raw:
            return None

        try:
            return json.loads(re.sub(r"```json\s*|\s*```", "", raw).strip())
        except json.JSONDecodeError:
            logger.error("Failed to parse FOFA plan JSON")
            return None

    # ── Self-Reflection: Retry on empty results ────────────────────────

    async def reflect_and_retry(
        self,
        user_intent: str,
        failed_queries: list[str],
        vip_level: int = 0,
    ) -> list[str]:
        """Generate broader fallback queries when all previous queries fail.

        Args:
            user_intent: Original user request.
            failed_queries: Query strings that returned 0 results.
            vip_level: FOFA account VIP level.

        Returns:
            List of new, broader query strings (up to 3), or empty list.
        """
        if not failed_queries:
            return []

        prompt = _REFLECTION_PROMPT.format(
            user_intent=user_intent,
            failed_queries_json=json.dumps(failed_queries, ensure_ascii=False),
            vip_level=vip_level,
        )

        logger.info("FOFA reflection: {} failed queries", len(failed_queries))

        raw = await self._call(prompt, "Generate corrected queries.", temperature=0.4)

        if not raw:
            return []

        try:
            data = json.loads(re.sub(r"```json\s*|\s*```", "", raw).strip())
            reason = data.get("correction_reason", "unknown")
            new_qs = data.get("new_queries", [])
            logger.info("FOFA reflection: {} → {} new queries", reason, len(new_qs))
            return new_qs
        except (json.JSONDecodeError, TypeError):
            return []

    # ── Asset Summarization ────────────────────────────────────────────

    async def summarize_assets(
        self,
        results: list[Any],
        user_intent: str,
        max_samples: int = 30,
    ) -> tuple[str | None, str | None]:
        """Generate asset fingerprinting summary + Nuclei scanning args.

        Args:
            results: Raw FOFA search results (list of rows).
            user_intent: Original user request for context.
            max_samples: Max result samples to send to LLM.

        Returns:
            (summary_markdown, nuclei_args) — either may be None.
        """
        if not results:
            return None, None

        preview = [str(r)[:100] for r in results[:max_samples]]
        prompt = _SUMMARY_PROMPT.format(
            user_intent=user_intent,
            preview_json=json.dumps(preview, ensure_ascii=False),
        )

        logger.info("FOFA summarization: {} results", len(results))

        raw = await self._call(prompt, "Summarize assets.", temperature=0.3)

        if not raw:
            return None, None

        try:
            data = json.loads(re.sub(r"```json\s*|\s*```", "", raw).strip())
            return data.get("summary"), data.get("nuclei_args")
        except (json.JSONDecodeError, TypeError):
            return None, None

    # ── Host Risk Analysis ─────────────────────────────────────────────

    async def analyze_host_risk(
        self,
        host_data: dict[str, Any],
        user_intent: str = "",
    ) -> str | None:
        """Generate AI risk assessment for a single IP/domain.

        Args:
            host_data: FOFA host aggregation response.
            user_intent: Optional context.

        Returns:
            Markdown risk report, or None.
        """
        context = {
            "ip": host_data.get("ip"),
            "org": host_data.get("org"),
            "ports": [p.get("port") for p in host_data.get("ports", [])],
            "products": [
                p.get("products") for p in host_data.get("ports", []) if p.get("products")
            ],
            "update_time": host_data.get("update_time"),
        }

        prompt = _HOST_RISK_PROMPT.format(
            user_intent=user_intent or "资产审计",
            context_json=json.dumps(context, ensure_ascii=False),
        )

        logger.info("FOFA host risk: {}", host_data.get("ip", "unknown"))

        report = await self._call(prompt, "Analyze host risk.", temperature=0.3)

        if report:
            # Append raw data appendix
            report += _build_host_appendix(host_data)
        return report

    # ── Statistical Trend Analysis ─────────────────────────────────────

    async def analyze_stat_trends(
        self,
        stat_data: dict[str, Any],
        query: str,
        user_intent: str = "",
    ) -> str | None:
        """Generate global situational awareness from FOFA stats.

        Args:
            stat_data: FOFA stats aggregation response.
            query: Original FOFA query string.
            user_intent: Optional context.

        Returns:
            Markdown trend report, or None.
        """
        context_aggs = {}
        for k, v in stat_data.get("aggs", {}).items():
            context_aggs[k] = v[:5] if isinstance(v, list) else v

        prompt = _STAT_TRENDS_PROMPT.format(
            query=query,
            user_intent=user_intent or "行业分析",
            context_json=json.dumps(context_aggs, ensure_ascii=False),
        )

        logger.info("FOFA stat trends: query='{}'", query[:60])

        report = await self._call(prompt, "Analyze trends.", temperature=0.3)

        if report:
            report += _build_stat_appendix(stat_data, query)
        return report

    # ── Internal: LLM call via injected router ─────────────────────────

    async def _call(
        self,
        system_prompt: str,
        user_content: str,
        temperature: float = 0.2,
    ) -> str | None:
        """Route an LLM call through the agent's LLMRouter."""
        try:
            response = await self._llm.generate(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                task_type="fofa_query_planning",
                temperature=temperature,
            )
            return response.content if response else None
        except Exception as exc:
            logger.error("FOFA planner LLM call failed: {}", exc)
            return None


# ═══════════════════════════════════════════════════════════════════════════
# Appendix builders
# ═══════════════════════════════════════════════════════════════════════════


def _build_host_appendix(host_data: dict[str, Any]) -> str:
    """Raw data appendix for host risk reports."""
    a = "\n\n---\n### 📎 附录：原始资产数据快照 (Host Data)\n"
    a += f"**IP**: `{host_data.get('ip', 'N/A')}` | **ASN**: `{host_data.get('asn', 'N/A')} {host_data.get('org', '')}`\n\n"
    a += "| Port | Protocol | Product | Update Time |\n| :---: | :---: | :--- | :--- |\n"
    for p in sorted(host_data.get("ports", []), key=lambda x: x.get("port", 0)):
        prods = [pr.get("product", "") for pr in p.get("products", [])]
        prod_str = ", ".join(prods[:3]) + ("..." if len(prods) > 3 else "")
        a += f"| {p.get('port')} | {p.get('protocol')} | {prod_str} | {p.get('update_time', '').split(' ')[0] if p.get('update_time') else ''} |\n"
    return a


def _build_stat_appendix(stat_data: dict[str, Any], query: str) -> str:
    """Raw data appendix for statistical trend reports."""
    a = "\n\n---\n### 📎 附录：统计数据快照 (Statistical Data)\n"
    a += f"**Query**: `{query}` | **Total**: `{stat_data.get('size', 0)}`\n"

    distinct = stat_data.get("distinct", {})
    if distinct:
        a += "\n#### 唯一性计数\n"
        for k, v in distinct.items():
            a += f"- **{k}**: {v}\n"

    for field, items in stat_data.get("aggs", {}).items():
        if not items:
            continue
        a += f"\n#### Top {field.upper()}\n| Rank | Name | Count | Top Regions |\n| :---: | :--- | :---: | :--- |\n"
        for i, item in enumerate(items, start=1):
            name = str(item.get("name", "")).replace("|", "\\|")
            count = item.get("count", 0)
            regions = item.get("regions", [])
            rs = ", ".join([f"{r['name']}({r['count']})" for r in regions[:3]])
            a += f"| {i} | {name} | {count} | {rs} |\n"
    return a
