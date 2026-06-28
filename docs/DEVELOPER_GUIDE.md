# AptivEye — 开发手册 v1.0

> **版本**: v1.0 | **日期**: 2026-06-27
> **覆盖**: Phase 0 (基础骨架) + Phase 1 (资产测绘核心 + 扩展)
> **测试**: 157 单元测试, 100% 通过 | **代码**: 6,412 行 Python

---

## 目录

1. [项目概况](#一项目概况)
2. [工具功能总览](#二工具功能总览)
3. [架构分层速览](#三架构分层速览)
4. [如何添加新工具](#四如何添加新工具)
5. [如何单独调用工具](#五如何单独调用工具)
6. [如何自定义与扩展](#六如何自定义与扩展)
7. [附录：关键文件索引](#七附录关键文件索引)

---

## 一、项目概况

```
AptivEye/
├── src/
│   ├── agent/          (1,076 行)    L4 编排与决策层 — LangGraph Supervisor + Worker
│   ├── security/       (1,278 行)    🔒 安全贯穿层 — Scope → PolicyEngine → Sanitizer
│   ├── tools/
│   │   ├── registry.py (296 行)      L3 MCP 工具注册中心
│   │   └── asset/      (3,810 行)    L3 资产测绘工具族 (11 文件)
│   ├── gateway/        (558 行)      L1 LLM 网关 + 成本追踪 + 模型路由
│   ├── memory/         (272 行)      L2 ChromaDB 向量存储 + 会话记忆
│   ├── sandbox/        (112 行)      L1 Docker 沙箱 (Phase 5)
│   ├── utils/          (228 行)      异常层次 + loguru 日志 + 校验
│   └── cli.py          (352 行)      L5 typer + rich CLI (4 命令)
├── config/
│   ├── settings.py                    Pydantic 配置 (含 15 个外部 API 端点，Key + URL 均可配)
│   ├── model_routing.py               LLM 三级路由表 (Light/Standard/Heavy)
│   └── prompts/
│       └── asset_discovery.yaml       Supervisor + Worker Prompt 模板
└── tests/unit/         (9 文件)       157 单元测试
```

---

## 二、工具功能总览

### 2.1 Phase 0 — 基础工具 (2 个)

| # | 工具名 | 类别 | 功能 | 实现 |
|---|--------|------|------|------|
| 1 | `echo` | general | Agent 流水线连通性测试，回显输入 | lambda 函数 |
| 2 | `system_info` | general | 获取 Python 版本、平台、当前工作目录 | lambda 函数 |

### 2.2 Phase 1 Core — 资产测绘核心 (4 个)

| # | 工具名 | 风险 | 功能 | 数据源/后端 | API Key 需求 |
|---|--------|------|------|------------|-------------|
| 3 | `enumerate_subdomains` | 1 | 子域名枚举 | DNS brute-force (内置 80 词表) → crt.sh CT 日志 → OWASP Amass | 无 (Amass 可选) |
| 4 | `scan_ports` | 2 | TCP 端口扫描 | nmap (-sS/-sV/-O/NSE) → socket connect() 纯 Python 降级 | 无 (nmap 可选) |
| 5 | `fingerprint_service` | 2 | 服务指纹识别 | HTTP 头分析 + 14 种技术栈检测 + TLS 证书提取 + Banner 抓取 | 无 |
| 6 | `discover_assets_full` | 3 | 一键资产测绘 | 串联子域名→端口→指纹 全流程，输出 AssetSummary + Markdown | 无 |

### 2.3 Phase 1 Extended — 扩展资产测绘 (6 个)

| # | 工具名 | 风险 | 功能 | 数据源 | API Key |
|---|--------|------|------|--------|---------|
| 7 | `whois_lookup` | 1 | **域名 Whois** — 注册商、创建/过期日、NS、邮箱、联系人 | python-whois → TCP:43 raw WHOIS | 无 |
| 8 | `search_network_assets` | 1 | **网络空间搜索** — FOFA + ZoomEye 发现暴露 IP/端口/服务/banner/SSL/ASN | FOFA API + ZoomEye API | 是 |
| 9 | `query_icp_record` | 1 | **ICP 备案查询** — 域名备案号、主办单位、审核日期 | MIIT API → 公共 ICP API 降级 | 否 |
| 10 | `query_company_info` | 1 | **企业信息查询** — 法人、注册资本、成立日期、经营范围、关联域名 | 天眼查 API → 企查查 API | 是 |
| 11 | `discover_digital_assets` | 1 | **数字资产发现** — 微信公众号、微信小程序、iOS/Android APP、关联邮箱 | 搜狗微信 + iTunes + Hunter.io | 部分 |
| 12 | `discover_all_assets` | 3 | **全资产一键测绘** — 并发执行上述全部工具，返回 ExtendedAssetSummary + Markdown | 全部上述 | 无 |

### 2.4 工具降级策略

所有工具设计为 **零配置可用**：

```
nmap  ──(not installed)──→  socket connect() scan  ──(timeout)──→  返回部分 + errors
Amass ──(not installed)──→  crt.sh API            ──(offline)──→  DNS brute-force
python-whois ──(not installed)──→ TCP:43 raw WHOIS ──(failed)──→ 返回 error 字段
FOFA ──(no API key)──→ 返回 "FOFA not configured" error
天眼查 ──(no API key)──→  企查查 ──(no API key)──→ 返回 "not configured"
Hunter.io ──(no API key)──→ 本地 pattern 邮箱生成 (admin@, webmaster@...)
```

---

## 三、架构分层速览

### 3.1 六层架构 (5+1)

```
L5 CLI       ← typer + rich, 4 命令 (run/tools/status/health)
L4 Agent     ← LangGraph Supervisor → Worker(ReAct) → Aggregate → Fallback
L3 Tools     ← MCP ToolRegistry: 12 tools, 2 categories
L2 Memory    ← ChromaDB vector store + SessionMemory (sliding window)
L1 Gateway   ← LLM Router (3 tiers, 3 providers) + Sandbox (Phase 5)
──────────────────────────────────────────────────────────────
🔒 Security  ← Scope → PolicyEngine(5-stage) → Sanitizer(6 rules)
               → LoopDetector → HITL → Audit(JSONL) → PromptGuard
```

### 3.2 工具调用全流程（每次调用自动执行）

```
Agent 调用 scan_ports(host="192.168.1.5", ports="top100")
  │
  ├─ [L4] LoopDetector.check()          ← SHA256 指纹去重, 同参数×3 → 中断
  ├─ [L4] SecurityPolicyEngine.validate() ← 5 阶段校验链:
  │     1. Scope 过期? → DENIED
  │     2. 目标在授权范围内? → DENIED
  │     3. 操作类型允许? → DENIED
  │     4. 参数含注入? → DENIED (InjectionDetected)
  │     5. 风险评分 ≥ 阈值? → ESCALATED (HITL 审批)
  ├─ [L4] HITL 断点: risk_level ≥ 7 → 暂停等人工确认 (5min 超时自动拒)
  ├─ [L3] ToolRegistry.call()          ← 执行 handler (同步/异步自动适配)
  ├─ [L3] OutputSanitizer.sanitize()   ← 6 条净化规则 (脱敏/截断/注入模式标记)
  ├─ [L2] SessionMemory.add_tool_result() ← 写入会话记忆
  └─ [🔒] AuditLogger.log_tool_call()    ← JSONL 文件追加审计记录
```

### 3.3 Agent 状态图

```
[START] → supervisor ─[plan不为空]──→ worker ─[还有task]──→ worker
              │                           │                    │
              └─[plan为空]──→ END         └─[全部完成]──→ aggregate → END
                                          └─[超错误阈值]──→ fallback → END
```

---

## 四、如何添加新工具

### 4.1 方式一：直接注册（适合单工具，最快 1 分钟）

在 `src/cli.py` 的 `_setup_tools()` 函数中添加 3 步：

**第 1 步：写 handler**

```python
# 异步 handler（推荐 — 不阻塞 Agent 循环）
async def my_new_tool(target: str, option: int = 1) -> dict:
    """工具的实现逻辑。"""
    import httpx
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"https://api.example.com/{target}")
    return {"status": "ok", "data": resp.json()}

# 同步 handler（简单场景）
def my_sync_tool(message: str) -> dict:
    return {"echo": message}
```

**第 2 步：创建 ToolDefinition**

```python
from src.tools.registry import ToolDefinition

my_tool_def = ToolDefinition(
    name="my_new_tool",                 # Agent 通过此名称调用
    description=(                       # LLM 据此决定何时调用 — 务必写清楚触发场景
        "Search target on Example API. Returns structured data about X. "
        "Use this when you need to discover Y for a domain target."
    ),
    parameters={                        # JSON Schema — LLM 据此生成参数
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target domain or IP to search",
            },
            "option": {
                "type": "integer",
                "description": "Option value (default: 1)",
                "default": 1,
            },
        },
        "required": ["target"],         # 必填参数
    },
    category="asset",                   # asset / vuln / pentest / code_audit / cve / assess
    risk_level=2,                       # 0-10, ≥7 自动触发 HITL 审批
    requires_approval=False,            # True → 每次调用都暂停等人工确认
)
```

**第 3 步：注册**

```python
# 在 _setup_tools() 中添加:
registry.register(my_tool_def, handler=my_new_tool)
```

### 4.2 方式二：MCP Server 模式（适合工具族，推荐）

按 `src/tools/asset/` 的结构创建新包：

```
src/tools/vuln/                    ← 新建包
├── __init__.py                     ← register_all(registry) 入口
├── server.py                       ← TOOL_DEFINITIONS + HANDLERS
├── nuclei.py                       ← Nuclei 扫描引擎封装
├── weak_pass.py                    ← 弱口令检测
└── custom_poc.py                   ← 自定义 POC 执行
```

**`server.py` 模板**（关键骨架）：

```python
"""Vulnerability Scanning MCP Server."""

from src.tools.registry import ToolDefinition

TOOL_DEFINITIONS: list[ToolDefinition] = [
    ToolDefinition(
        name="scan_vulnerabilities",
        description="Scan target for known vulnerabilities using Nuclei templates.",
        parameters={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target IP/hostname"},
                "severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                },
            },
            "required": ["host"],
        },
        category="vuln",
        risk_level=4,
    ),
    # ... 更多工具 ...
]

async def _handle_scan_vulnerabilities(host: str, severity: str = "high") -> dict:
    from src.tools.vuln.nuclei import run_nuclei_scan
    result = await run_nuclei_scan(host, severity)
    return result.model_dump()

HANDLERS = {
    "scan_vulnerabilities": _handle_scan_vulnerabilities,
}

def get_tools():
    return [(td, HANDLERS[td.name]) for td in TOOL_DEFINITIONS]
```

**`__init__.py` 模板**：

```python
from src.tools.registry import ToolRegistry
from src.tools.vuln.server import get_tools
from src.utils.logger import get_logger

logger = get_logger(__name__)

def register_all(registry: ToolRegistry) -> int:
    count = 0
    for definition, handler in get_tools():
        registry.register(definition, handler)
        count += 1
    logger.info(f"Registered {count} vulnerability scanning tools")
    return count
```

**在 `cli.py` 中集成**：

```python
from src.tools.vuln import register_all as register_vuln_tools

def _setup_tools():
    ...
    register_vuln_tools(registry)    # ← 新增这一行
```

### 4.3 ToolDefinition 完整字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | `str` | ✅ | 全局唯一标识。Agent 的 function call 名称。 |
| `description` | `str` | ✅ | LLM 判断**何时调用**此工具的唯一依据。必须写清楚："这个工具做什么"和"什么场景下使用"。 |
| `parameters` | `dict` | ✅ | JSON Schema 格式参数定义。LLM 据此生成调用参数。 |
| `category` | `str` | ❌ | 工具分类。Agent 通过 `registry.list_tools(category="vuln")` 按场景过滤。预定义: `asset`, `vuln`, `pentest`, `code_audit`, `cve`, `assess`。 |
| `risk_level` | `int` (0-10) | ❌ | 安全策略引擎的风险评分输入。≥7 自动触发 HITL 审批。 |
| `requires_approval` | `bool` | ❌ | 强制每次调用都暂停等人工确认，无论 risk_level。 |

---

## 五、如何单独调用工具

所有工具均可脱离 Agent 框架独立调用——在 Python 脚本、Jupyter Notebook 或交互式 Shell 中直接使用。

### 5.1 通过 ToolRegistry 调用（标准方式）

```python
import asyncio
from src.tools.registry import ToolRegistry, ToolDefinition

# 初始化注册中心
registry = ToolRegistry()

# 注册一个快速测试工具
registry.register(
    ToolDefinition(
        name="hello",
        description="Say hello",
        parameters={"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
        category="general",
    ),
    handler=lambda name, **kw: {"greeting": f"Hello, {name}!"},
)

# 调用
result = asyncio.run(registry.call("hello", name="World"))
print(result)  # {"greeting": "Hello, World!"}

# 同步调用
result = registry.call_sync("hello", name="Sync")
```

### 5.2 直接调用工具模块（零依赖方式）

不经过 Registry，直接 import 工具函数：

#### 子域名枚举

```python
import asyncio
from src.tools.asset.subdomain import discover_subdomains

result = asyncio.run(discover_subdomains(
    domain="example.com",
    use_dns_brute=True,    # DNS brute-force (内置 80 词表)
    use_crtsh=True,        # crt.sh 证书透明度日志
    use_amass=False,       # OWASP Amass (需安装)
))
print(f"Found {result.total_found} subdomains from {result.sources_used}")
for sd in result.subdomains[:5]:
    print(f"  {sd.name} → {sd.ip_addresses} (source: {sd.source.value})")
```

#### 端口扫描

```python
import asyncio
from src.tools.asset.port_scan import discover_ports

result = asyncio.run(discover_ports(
    host="127.0.0.1",
    ports="top10",           # top10 / top100 / top1000 / all / "1-1000"
    prefer_nmap=True,        # 优先用 nmap, 不可用时自动降级 socket
    service_detection=True,  # -sV 版本检测
))
print(f"Scan method: {result.scan_method}")
print(f"Open ports: {result.open_ports}")
for port in result.ports:
    if port.state.value == "open":
        print(f"  {port.port}/{port.protocol} {port.service} {port.product} {port.version}")
```

#### 服务指纹识别

```python
import asyncio
from src.tools.asset.fingerprint import fingerprint_services
from src.tools.asset.models import PortInfo, PortState

open_ports = [
    PortInfo(port=80, state=PortState.OPEN, service="http"),
    PortInfo(port=443, state=PortState.OPEN, service="https"),
    PortInfo(port=3306, state=PortState.OPEN, service="mysql"),
]
result = asyncio.run(fingerprint_services("127.0.0.1", open_ports))
for fp in result.fingerprints:
    print(fp.summary)
    print(f"  Server: {fp.http_server}, Title: {fp.http_title}")
    print(f"  Technologies: {fp.http_technologies}")
    print(f"  TLS Subject: {fp.tls_subject}")
```

#### WHOIS 查询

```python
import asyncio
from src.tools.asset.whois import whois_lookup

result = asyncio.run(whois_lookup("example.com"))
print(f"Registrar: {result.registrar}")
print(f"Created: {result.creation_date}")
print(f"Expires: {result.expiration_date}")
print(f"Name Servers: {result.name_servers}")
print(f"Emails found: {result.emails}")
print(f"Registrant: {result.registrant.organization}")
```

#### FOFA / ZoomEye 搜索

```python
import asyncio
from src.tools.asset.network_search import search_network

results = asyncio.run(search_network(
    query='domain="example.com"',
    target_type="domain",
    source="auto",         # auto / fofa / zoomeye
    max_results=50,
))
for r in results:
    print(f"Source: {r.source}, Total: {r.total_results}")
    for hit in r.hits[:5]:
        print(f"  {hit.ip}:{hit.port} - {hit.server} - {hit.title} - {hit.org}")
```

#### ICP 备案查询

```python
import asyncio
from src.tools.asset.org_intel import query_icp

result = asyncio.run(query_icp("example.cn", search_type="domain"))
for r in result.records:
    print(f"Domain: {r.domain}")
    print(f"Company: {r.company_name}")
    print(f"ICP No: {r.icp_number}")
    print(f"Audit Date: {r.site_audit_date}")
```

#### 企业信息查询

```python
import asyncio
from src.tools.asset.org_intel import query_company

result = asyncio.run(query_company("腾讯科技", source="auto"))
for c in result.companies:
    print(f"Company: {c.company_name}")
    print(f"Legal Person: {c.legal_person}")
    print(f"Capital: {c.registered_capital}")
    print(f"Established: {c.established_date}")
    print(f"Domains: {c.domains}")
```

#### 数字资产发现（微信/小程序/APP/邮箱）

```python
import asyncio
from src.tools.asset.digital_assets import discover_digital_assets

result = asyncio.run(discover_digital_assets(
    target="tencent.com",
    include_wechat=True,
    include_miniprogram=True,
    include_apps=True,
    include_emails=True,
))
print(f"WeChat Accounts: {len(result.wechat_accounts)}")
for w in result.wechat_accounts:
    print(f"  {w.account_name} ({w.account_id}) — {w.company_verified}")

print(f"Mini Programs: {len(result.mini_programs)}")
for m in result.mini_programs:
    print(f"  {m.app_name} — {m.company}")

print(f"Mobile Apps: {len(result.mobile_apps)}")
for a in result.mobile_apps:
    print(f"  {a.app_name} ({a.platform}) — {a.developer}")

print(f"Emails: {len(result.emails)}")
for e in result.emails[:10]:
    print(f"  {e.email} (source: {e.source}, confidence: {e.confidence}%)")
```

### 5.3 通过 CLI 调用

```bash
# 查看所有工具
aptiveye tools

# 查看系统状态
aptiveye status

# 检查 LLM 连通性
aptiveye health

# 运行评估任务
aptiveye run "全面测绘 example.com" -t example.com -i passive --no-approval -o report.md
```

---

## 六、如何自定义与扩展

### 6.1 配置 API Key 与端点 URL

所有外部 API 支持独立配置 Key **和** URL。编辑 `.env` 文件（从 `.env.example` 复制）：

```bash
# ── FOFA 网络空间搜索引擎 ──
FOFA_EMAIL=your_email@example.com
FOFA_API_KEY=your_fofa_api_key
FOFA_API_URL=https://fofa.info/api/v1          # 可改为自建镜像/代理
FOFA_WEB_URL=https://fofa.info                  # Web 结果页地址

# ── ZoomEye 网络空间搜索引擎 ──
ZOOMEYE_API_KEY=your_zoomeye_key
ZOOMEYE_API_URL=https://api.zoomeye.org
ZOOMEYE_WEB_URL=https://www.zoomeye.org

# ── ICP 备案查询 ──
ICP_API_KEY=your_icp_key
ICP_API_URL=https://api.beian.miit.gov.cn       # MIIT 官方 API
ICP_PUBLIC_URL=https://api.devopsclub.cn/api/icpquery  # 公共降级 API

# ── 企查查 ──
QICHACHA_API_KEY=your_qichacha_key
QICHACHA_API_URL=https://api.qichacha.com

# ── 天眼查 ──
TIANYANCHA_API_KEY=your_tianyancha_key
TIANYANCHA_API_URL=https://api.tianyancha.com

# ── 零零信安 ──
LINGLING_API_KEY=your_lingling_key
LINGLING_API_URL=https://api.0zero.cn

# ── Hunter.io (邮箱发现) ──
HUNTER_API_KEY=your_hunter_key
HUNTER_API_URL=https://api.hunter.io/v2

# ── crt.sh (证书透明度日志, 免费无需认证) ──
CRTSH_API_URL=https://crt.sh

# ── 搜狗微信搜索 ──
WEIXIN_SEARCH_URL=https://weixin.sogou.com/weixin

# ── 微信小程序搜索 ──
MINIPROGRAM_SEARCH_URL=https://mp.weixin.qq.com/wxamp/search

# ── iTunes App Store ──
ITUNES_SEARCH_URL=https://itunes.apple.com/search
```

**使用场景**：

| 场景 | 配置示例 |
|------|----------|
| 自建 API 代理/镜像 | `FOFA_API_URL=https://fofa-mirror.internal.company.com/api/v1` |
| 企业 API 网关统一鉴权 | `QICHACHA_API_URL=https://api-gateway.company.com/qichacha` |
| 离线环境本地数据副本 | `CRTSH_API_URL=http://ct-log-replica.local:8080` |
| 切换到兼容 API 供应商 | `ICP_API_URL=https://new-icp-vendor.com/api/v2` |

**添加新的 API Key/URL 只需三步**：

1. 在 `config/settings.py` 的 `AssetAPISettings` 类添加 `Field(default=..., alias="...")`
2. 在 `.env.example` 添加占位符
3. 在工具代码中通过 `get_settings().asset_api.xxx` 读取（Key 用 `.get_secret_value()`，URL 直接用字符串）

### 6.2 自定义子域名词表

```python
from src.tools.asset.subdomain import discover_subdomains

# 使用自定义词表
my_wordlist = [
    "api", "dev", "staging", "admin", "portal",
    "vpn", "cloud", "cdn", "monitor", "grafana",
    "jenkins", "gitlab", "k8s", "swagger", "console",
]

result = asyncio.run(discover_subdomains(
    "example.com",
    use_dns_brute=True,
    wordlist=my_wordlist,
    dns_concurrency=30,  # 并发数, 默认20
))
```

### 6.3 自定义端口扫描范围

```python
from src.tools.asset.port_scan import discover_ports

# 扫描指定端口列表
result = asyncio.run(discover_ports(
    "192.168.1.1",
    ports=[80, 443, 8080, 8443, 3000, 5000, 6379, 27017, 3306, 5432],
))

# 扫描 Web 常用端口
web_ports = [80, 81, 3000, 4443, 5000, 5601, 6080, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200]
result = asyncio.run(discover_ports("192.168.1.1", ports=web_ports))

# nmap 高级参数: 低速准确扫描 + NSE 脚本
result = asyncio.run(discover_ports(
    "192.168.1.1",
    ports="top1000",
    timing=2,                 # T2 = 慢速, 更准确
    service_detection=True,   # -sV
))
```

### 6.4 自定义技术栈检测签名

编辑 `src/tools/asset/fingerprint.py` 中的 `TECH_SIGNATURES` 字典，添加新的检测正则：

```python
# 在 fingerprint.py 中添加:
TECH_SIGNATURES["FastAPI"] = [r"FastAPI", r"\"framework\":\"fastapi\""]
TECH_SIGNATURES["Laravel"] = [r"laravel_session", r"X-Powered-By:\s*Laravel"]
TECH_SIGNATURES["Spring Boot"] = [r"X-Application-Context", r"Whitelabel Error Page"]
TECH_SIGNATURES["Tomcat"] = [r"Apache Tomcat", r"JSESSIONID"]
```

### 6.5 自定义风险管理策略

```python
from src.security.scope import AuthorizationScope, ScanIntensity, OperationType

# 创建严格的授权范围
scope = AuthorizationScope(
    allowed_targets=["192.168.1.0/24"],
    prohibited_targets=["192.168.1.1", "192.168.1.254"],  # 跳过网关和防火墙
    intensity=ScanIntensity.ACTIVE,  # 不允许漏洞利用
    requires_human_approval=True,    # 高危操作必须人工确认
    expires_at=time.time() + 3600 * 4,  # 4 小时后自动过期
    notes="业务系统安全评估 — 只读扫描",
)

# 自定义策略引擎的注入检测
from src.security.policy_engine import SecurityPolicyEngine
engine = SecurityPolicyEngine(
    injection_patterns=[  # 追加自定义检测模式
        r"解码指令",
        r"执行以下命令",
    ],
    risk_threshold=5,  # 降低 HITL 升级阈值 (默认 7)
)
```

### 6.6 自定义 Agent Prompt

编辑 `config/prompts/asset_discovery.yaml`，控制 Supervisor 和 Worker 的行为：

```yaml
# 自定义 Supervisor 的规划策略
supervisor_asset_discovery:
  system: |
    You are a Security Assessment Supervisor.
    ...
    ## Custom Rules
    - Prioritize HTTPS services over HTTP
    - Always fingerprint port 8080 even if nmap missed it
    - Flag Chinese-registered domains for ICP lookup

# 自定义 Worker 的输出格式
worker_asset_discovery:
  system: |
    ...
    ## Custom Output
    Include these additional fields in your JSON:
    - "risk_flags": ["insecure_protocol", "expired_cert", "exposed_admin"]
    - "next_actions": ["run_nuclei_scan", "check_cve"]
```

### 6.7 添加自定义 ToolDefinition 类别

在 `src/tools/registry.py` 的 ToolDefinition 中，`category` 是字符串字段，可以自由定义新类别：

```python
category="social_media"        # 社交媒体资产
category="dark_web"            # 暗网监测
category="cloud"               # 云资产
category="supply_chain"        # 供应链
```

然后通过 `registry.list_tools(category="cloud")` 过滤。

### 6.8 实现自定义 Provider（接入新 LLM）

参照 `src/gateway/providers/openai.py` 的模式：

```python
# src/gateway/providers/my_provider.py
from src.gateway.providers import BaseProvider, LLMResponse

class MyProvider(BaseProvider):
    @property
    def provider_name(self) -> str:
        return "my_provider"

    async def generate(self, messages, *, model, max_tokens, temperature, tools=None):
        # 实现你的 API 调用
        ...
        return LLMResponse(content="...", model=model, provider="my_provider", ...)

    async def health_check(self) -> bool:
        ...
```

然后在 `src/gateway/router.py` 的 `LLMRouter._select_provider_for_model()` 中添加路由。

---

## 七、附录：关键文件索引

### 核心源文件

| 文件 | 关键类/函数 | 用途 |
|------|-----------|------|
| [src/tools/registry.py](src/tools/registry.py) | `ToolRegistry`, `ToolDefinition` | MCP 工具注册与发现中心 |
| [src/tools/asset/server.py](src/tools/asset/server.py) | `TOOL_DEFINITIONS`, `HANDLERS`, `get_tools()` | 10 个资产工具的定义与 handler |
| [src/tools/asset/subdomain.py](src/tools/asset/subdomain.py) | `discover_subdomains()` | 子域名枚举入口 |
| [src/tools/asset/port_scan.py](src/tools/asset/port_scan.py) | `discover_ports()`, `_parse_nmap_xml()` | 端口扫描入口 + nmap XML 解析 |
| [src/tools/asset/fingerprint.py](src/tools/asset/fingerprint.py) | `fingerprint_services()`, `fingerprint_http()`, `fingerprint_tls()` | 服务指纹识别 |
| [src/tools/asset/whois.py](src/tools/asset/whois.py) | `whois_lookup()`, `_parse_whois_raw()` | WHOIS 查询 + 原始解析 |
| [src/tools/asset/network_search.py](src/tools/asset/network_search.py) | `FofaClient`, `ZoomEyeClient`, `search_network()` | FOFA + ZoomEye API |
| [src/tools/asset/org_intel.py](src/tools/asset/org_intel.py) | `query_icp()`, `query_company()` | ICP备案 + 企业查询 |
| [src/tools/asset/digital_assets.py](src/tools/asset/digital_assets.py) | `discover_digital_assets()` | 微信/小程序/APP/邮箱 |
| [src/tools/asset/models.py](src/tools/asset/models.py) | 27 个 Pydantic 模型 | 所有资产数据结构 |
| [src/agent/__init__.py](src/agent/__init__.py) | `AgentRunner` | Agent 运行入口 |
| [src/security/policy_engine.py](src/security/policy_engine.py) | `SecurityPolicyEngine.validate()` | 5 阶段安全校验 |
| [src/security/sanitizer.py](src/security/sanitizer.py) | `OutputSanitizer.sanitize()` | 工具输出净化 |
| [src/gateway/router.py](src/gateway/router.py) | `LLMRouter.generate()` | LLM 网关 + 模型路由 |
| [config/settings.py](config/settings.py) | `Settings`, `AssetAPISettings` | 全局配置 |
| [config/model_routing.py](config/model_routing.py) | `ROUTING_TABLE`, `ModelTier` | LLM 路由规则 |

### 测试文件

| 文件 | 覆盖模块 | 测试数 |
|------|----------|--------|
| [tests/unit/test_asset_models.py](tests/unit/test_asset_models.py) | models.py — Subdomain, PortInfo, Fingerprint, Summary | 14 |
| [tests/unit/test_asset_tools.py](tests/unit/test_asset_tools.py) | port_scan.py + server.py — nmap XML, 工具注册, Schema | 24 |
| [tests/unit/test_asset_extended.py](tests/unit/test_asset_extended.py) | models + server — Whois, ICP, Company, Digital, Whois Parser | 35 |
| [tests/unit/test_scope.py](tests/unit/test_scope.py) | scope.py — IP/CIDR/域名匹配, 强度层级 | 15 |
| [tests/unit/test_policy_engine.py](tests/unit/test_policy_engine.py) | policy_engine.py — 5 阶段校验链 | 13 |
| [tests/unit/test_sanitizer.py](tests/unit/test_sanitizer.py) | sanitizer.py — 注入检测, URL脱敏, 截断 | 15 |
| [tests/unit/test_loop_detector.py](tests/unit/test_loop_detector.py) | loop_detector.py — 指纹去重, 滑动窗口 | 10 |
| [tests/unit/test_registry.py](tests/unit/test_registry.py) | registry.py — CRUD, 调用, LLM格式 | 16 |
| [tests/unit/test_validators.py](tests/unit/test_validators.py) | validators.py — IP/URL/域名校验, 脱敏 | 20 |

---

> **维护**: 本文档随项目演进而更新。新工具添加后，请在第二章更新工具表。
>
> **下一步**: Phase 2 — 漏洞扫描与 CVE 匹配 (Week 7-10)
