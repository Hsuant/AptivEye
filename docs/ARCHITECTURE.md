# AptivEye — 网络安全AI Agent 技术架构设计与开发规划

> **版本**: v2.0 | **日期**: 2026-06-27 | **状态**: 设计阶段

---

## 目录

1. [设计原则](#一设计原则)
2. [整体架构](#二整体架构)
3. [核心设计模式](#三核心设计模式)
4. [关键技术决策](#四关键技术决策)
5. [安全设计](#五安全设计)
6. [项目目录结构](#六项目目录结构)
7. [开发计划](#七开发计划)
8. [评估体系](#八评估体系)
9. [风险矩阵](#九风险矩阵)
10. [附录](#十附录)

---

## 一、设计原则

| 原则 | 说明 | 设计体现 |
|------|------|----------|
| **安全第一 (Security-by-Design)** | Agent自身安全与目标安全同等重要 | 每层内建安全护栏，而非事后加固 |
| **工具标准化 (Protocol-First)** | 所有工具通过标准协议接入，与Agent框架解耦 | MCP协议作为L3的唯一工具接入标准 |
| **可量化 (Measurable)** | 每个能力有明确的评估基准 | 每Phase附带Benchmark子阶段 |
| **失败安全 (Fail-Safe)** | 任何组件失败不会导致级联风险 | 分层降级策略 + 全局超时 + 死循环检测 |
| **最小权限 (Least Privilege)** | 每个工具调用携带scope，策略引擎前置校验 | L4安全策略引擎 |
| **渐进增强 (Progressive Enhancement)** | MVP可用 → 增量完善 → 生产就绪 | 六阶段开发 + 每阶段后评估 |
| **成本可控 (Cost-Aware)** | LLM调用按任务复杂度路由到适用模型 | 模型路由策略 |

---

## 二、整体架构

### 2.1 六层架构（改进版）

在原五层基础上，将安全护栏提升为独立贯穿层，形成 **5+1 架构**：

```
                              ┌──────────────────────────────┐
                              │     Security Cross-Cutting    │
                              │  策略引擎 · 审计追踪 · 净化器  │
                              │  HITL断点 · 注入防护 · 降级   │
                              └──────────────────────────────┘
                                    ↓ 贯穿各层 ↓
┌─────────────────────────────────────────────────────────────────┐
│                      L5: 应用与交互层                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ CLI (rich)│  │ Web API  │  │ 报告生成  │  │ 实时监控面板  │   │
│  │          │  │ (FastAPI)│  │ (MD/JSON │  │ (可观测性)    │   │
│  │          │  │          │  │  /HTML)  │  │              │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                      L4: 编排与决策层                            │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │              Hierarchical ReAct Engine                     │ │
│  │  ┌─────────────┐  ┌──────────────────────────────────┐   │ │
│  │  │ Supervisor   │  │  Worker Agents (per Sub-Task)    │   │ │
│  │  │ Node         │──│  ┌────────┐ ┌────────┐ ┌──────┐ │   │ │
│  │  │ (任务分解/    │  │  │Worker 1│ │Worker 2│ │...N  │ │   │ │
│  │  │  结果聚合)    │  │  │ReAct   │ │ReAct   │ │ReAct │ │   │ │
│  │  └─────────────┘  │  └────────┘ └────────┘ └──────┘ │   │ │
│  │                    └──────────────────────────────────┘   │ │
│  └───────────────────────────────────────────────────────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐    │
│  │安全策略   │ │HITL      │ │循环检测   │ │降级管理器     │    │
│  │引擎       │ │断点管理   │ │器         │ │(Fallback)    │    │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│                      L3: 工具与能力层                            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                 MCP 协议层 (唯一工具接入标准)              │   │
│  ├──────────┬──────────┬──────────┬──────────┬────────────┤   │
│  │资产测绘   │漏洞扫描   │渗透测试   │代码审计   │CVE匹配     │   │
│  │MCP Server│MCP Server│MCP Server│MCP Server│MCP Server  │   │
│  │·子域名    │·Nuclei   │·信息收集  │·Semgrep  │·NVD检索    │   │
│  │·端口扫描  │·弱口令   │·漏洞利用  │·Bandit   │·CVSS计算   │   │
│  │·指纹识别  │·自定义POC│·权限提升  │·LLM分析  │·关联匹配   │   │
│  └──────────┴──────────┴──────────┴──────────┴────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 工具输出净化器 │ 工具审计日志 │ 工具注册中心               │  │
│  └──────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                      L2: 知识与记忆层                            │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐  │
│  │向量数据库   │ │会话记忆     │ │CVE知识库    │ │经验库       │  │
│  │(Chroma/    │ │(短期/长期)  │ │(向量化+     │ │(历史任务    │  │
│  │ Qdrant)   │ │            │ │ 结构化索引) │ │ 模式复用)   │  │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                      L1: 基础设施层                              │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐  │
│  │LLM Gateway  │ │沙箱环境     │ │日志与监控   │ │配置管理     │  │
│  │(模型路由/   │ │(Docker隔离) │ │(Loguru/    │ │(Pydantic   │  │
│  │ 速率限制/   │ │            │ │ OpenTel)   │ │ Settings)  │  │
│  │ 成本追踪)   │ │            │ │            │ │            │  │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 各层职责定义

#### L1: 基础设施层

| 组件 | 职责 | 关键约束 |
|------|------|----------|
| LLM Gateway | 多模型接入、模型路由、速率限制、Token成本追踪 | 支持OpenAI/Claude/本地模型热切换 |
| 沙箱环境 | Docker容器隔离，Agent生成的代码在此执行 | 无网络出站（默认），只读挂载必要文件 |
| 日志与监控 | 结构化日志、分布式追踪、告警 | 所有工具调用必须记录完整审计日志 |
| 配置管理 | 环境变量、模型密钥、沙箱参数管理 | 密钥不入Git，通过`.env`或Secret Manager |

#### L2: 知识与记忆层

| 组件 | 职责 | 存储策略 |
|------|------|----------|
| 向量数据库 | CVE知识库、工具手册、历史任务嵌入 | Chroma（开发）→ Qdrant（生产），支持过滤索引 |
| 会话记忆 | 短期（当前任务上下文）、长期（跨任务经验） | 短期：内存LRU；长期：向量库持久化 |
| CVE知识库 | NVD数据 + Exploit-DB + 内部POC | 每周自动增量更新，离线可用 |
| 经验库 | 历史成功/失败模式，用于后续任务优化 | 任务完成后异步写入，不阻塞主流程 |

#### L3: 工具与能力层

**核心原则：MCP协议是L3的唯一工具接入标准。**

所有安全工具（无论第三方还是自研）必须封装为MCP Server。Agent通过MCP Client动态发现和调用工具，与上层框架解耦。

```
工具调用全流程：
Agent决策(调用X工具)
  → L4安全策略引擎(校验scope/权限)
    → MCP Client(构造标准请求)
      → MCP Server X(执行工具逻辑)
        → 工具输出净化器(去注入/截断/脱敏)
          → 审计日志(记录调用参数/结果/耗时)
            → 返回LLM上下文
```

#### L4: 编排与决策层

**Hierarchical ReAct（分层推理-行动循环）**：

```
                    ┌─────────────────┐
                    │  Supervisor Node │ (高层决策，不直接调工具)
                    │  "扫描目标X"     │
                    └────────┬────────┘
                             │ 分解为子任务
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │ Worker 1 │  │ Worker 2 │  │ Worker N │
        │"资产测绘" │  │"漏洞扫描" │  │"CVE匹配"  │
        │ReAct循环  │  │ReAct循环  │  │ReAct循环  │
        └──────────┘  └──────────┘  └──────────┘
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    ┌─────────────────┐
                    │  Supervisor Node │ (汇总Worker结果)
                    │  "生成综合报告"   │
                    └─────────────────┘
```

**L4安全组件**：

| 组件 | 触发时机 | 行为 |
|------|----------|------|
| 安全策略引擎 | 每个工具调用前 | 校验scope → 检查IP白名单 → 验证操作类型权限 → 通过/拒绝/升级审批 |
| HITL断点管理 | 高风险操作识别 | 漏洞利用/系统命令执行/数据外传 → 暂停 → 推送人工确认 |
| 循环检测器 | 每次工具调用后 | 检测(同工具+同参数)×N → 强制中断 + 降级处理 |
| 降级管理器 | LLM错误/工具超时/异常 | 重试(换模型) → 跳过 → 人工介入，按策略链递减 |

#### L5: 应用与交互层

- **CLI**: 基于`rich`的终端交互，支持实时流式输出和彩色渲染
- **Web API**: FastAPI，供外部系统集成
- **报告生成**: Markdown（人读）+ JSON（机器读）+ HTML（可视化）
- **实时监控面板**: 基于OpenTelemetry的追踪可视化

#### 安全贯穿层（Security Cross-Cutting）

不独立成层，但贯穿L1-L5：

| 能力 | 覆盖层级 | 实现 |
|------|----------|------|
| 工具输出净化 | L3→L4 | 去除注入载体（可执行代码/URL/base64） |
| 审计追踪 | L3/L4/L5 | 每个工具调用+Agent决策的完整链 |
| 提示词注入防护 | L3/L4 | 输入清洗 + 分隔符标记 + 角色边界强化 |
| 数据脱敏 | L2/L5 | 敏感信息不入向量库，报告可配置脱敏 |

---

## 三、核心设计模式

### 3.1 Hierarchical ReAct（分层推理-行动）

**与Flat ReAct的对比**：

| 维度 | Flat ReAct | Hierarchical ReAct（本方案） |
|------|------------|------------------------------|
| 上下文窗口 | 线性膨胀 | Supervisor只看摘要，Worker上下文隔离 |
| 任务聚焦 | 易跳转，丢失专注 | 每个Worker专注单一子任务 |
| 并行能力 | 不支持 | 多个Worker可并行（如同时扫描多IP） |
| Token消耗 | 高（全量历史） | 低（Supervisor精简上下文） |
| 调试难度 | 低（线性轨迹） | 中（需追踪Supervisor和Worker两层） |

**Supervisor Prompt模板（精简版）**：

```
你是一个安全任务调度器。你的职责是：
1. 分析用户的安全扫描目标
2. 将目标分解为独立的子任务
3. 将每个子任务分配给专用的Worker Agent
4. 汇总Worker的结果，生成最终报告

你**不直接调用工具**。你只做任务分解和结果聚合。

当前目标: {target}
允许的操作范围: {scope}
已知上下文: {context_summary}

请输出JSON格式的子任务列表:
[{"id": "1", "type": "asset_discovery", "target": "...", "priority": "high"}, ...]
```

### 3.2 MCP-First 工具架构

**为什么MCP必须在Phase 0/1而不是Phase 6**：

1. **解耦Agent框架与工具实现**：工具可被任何MCP兼容的Agent调用，不锁定LangChain
2. **动态工具发现**：新增工具无需修改Agent代码，MCP Server启动即自动注册
3. **标准化安全审计**：所有工具调用走统一MCP协议，审计日志格式一致
4. **社区生态复用**：社区MCP Server可直接集成（如GitHub MCP Server用于代码审计）

**MCP Server实现规范**：

```python
# 每个安全工具封装为独立MCP Server
# 示例: Asset Discovery MCP Server

from mcp.server import Server, Tool
from mcp.types import ToolDefinition

server = Server("asset-discovery")

@server.tool()
async def enumerate_subdomains(
    domain: str,
    scope_id: str,  # 权限scope，由L4策略引擎校验
) -> list[str]:
    """
    子域名枚举工具。
    scope_id: 授权范围标识符，必须与授权记录匹配。
    """
    # 1. scope校验（由MCP Server自检 + L4策略引擎双重校验）
    # 2. 执行枚举
    # 3. 输出净化
    # 4. 审计日志
    pass

@server.tool()
async def scan_ports(
    target: str,
    ports: str = "1-1000",
    scope_id: str = None,
) -> dict:
    """端口扫描工具。scope_id必填。"""
    pass
```

### 3.3 模型路由策略

```
                 ┌─────────────────────────┐
                 │      LLM Gateway        │
                 │   (L1 基础设施层)        │
                 └───────────┬─────────────┘
                             │
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │ 轻量任务路由  │ │ 标准任务路由  │ │ 重任务路由    │
    │ (低成本模型)  │ │ (平衡模型)    │ │ (最强模型)    │
    ├──────────────┤ ├──────────────┤ ├──────────────┤
    │·工具结果解析  │ │·漏洞分析      │ │·代码安全审计  │
    │·JSON格式化    │ │·常规报告生成  │ │·复杂漏洞利用  │
    │·简单分类      │ │·CVE匹配推理   │ │·对抗性分析    │
    │·状态总结      │ │·资产分析      │ │·零日研判      │
    ├──────────────┤ ├──────────────┤ ├──────────────┤
    │gpt-4o-mini   │ │claude-sonnet  │ │claude-opus    │
    │claude-haiku  │ │gpt-4o         │ │gpt-4-turbo    │
    │本地:llama-8b │ │               │ │               │
    └──────────────┘ └──────────────┘ └──────────────┘
```

**路由规则定义**：

```python
MODEL_ROUTING = {
    "tool_result_parsing": {"tier": "light", "max_tokens": 2000},
    "json_formatting": {"tier": "light", "max_tokens": 1000},
    "vulnerability_analysis": {"tier": "standard", "max_tokens": 8000},
    "cve_matching": {"tier": "standard", "max_tokens": 4000},
    "code_security_audit": {"tier": "heavy", "max_tokens": 16000},
    "zero_day_analysis": {"tier": "heavy", "max_tokens": 32000},
    "report_generation": {"tier": "standard", "max_tokens": 8000},
    "supervisor_planning": {"tier": "standard", "max_tokens": 4000},
}

# 敏感数据自动路由到本地模型
def route_model(task_type: str, contains_sensitive_data: bool) -> ModelConfig:
    if contains_sensitive_data:
        return LOCAL_MODEL_CONFIG  # llama-3.1-70b 或类似
    return MODEL_REGISTRY[MODEL_ROUTING[task_type]["tier"]]
```

---

## 四、关键技术决策

| 决策点 | 选型 | 排名 | 决策理由 |
|--------|------|------|----------|
| Agent框架 | **LangGraph** (主) + **CrewAI** (多Agent协作补充) | 1st/2nd | LangGraph状态图适合安全流程编排；CrewAI的角色分工适合多Agent协作场景 |
| LLM网关 | 自研**LLM Gateway**（LiteLLM备选） | 1st | 需要模型路由+成本追踪+敏感数据分流，通用网关不满足 |
| 工具协议 | **MCP** (Model Context Protocol) | **唯一标准** | 从第一个工具起即用MCP封装；作为架构基石而非可选项 |
| 向量数据库 | **Chroma**（开发/小规模）→ **Qdrant**（生产/大规模） | - | Chroma零配置快速启动；Qdrant过滤索引+量化压缩适合10w+级别 |
| 沙箱环境 | **Docker** + **gVisor**（生产增强） | - | Docker基础隔离；敏感操作使用gVisor额外内核级隔离 |
| 开发语言 | **Python 3.12+** | - | Agent生态最成熟；类型注解强制使用 |
| Web框架 | **FastAPI** + **WebSocket** | - | 异步支持好，适合流式Agent输出 |
| CLI框架 | **rich** + **typer** | - | rich提供专业终端渲染，typer提供类型安全CLI |
| 配置管理 | **pydantic-settings** + **HashiCorp Vault**（生产） | - | 开发用.env（15个API端点Key+URL均可配）；生产密钥用Vault |
| 可观测性 | **Loguru** + **OpenTelemetry** + **LangSmith**（可选） | - | 结构化日志+分布式追踪+Agent专用调试 |

---

## 五、安全设计

### 5.1 Agent威胁模型（STRIDE分析）

| 威胁类型 | 攻击向量 | 风险等级 | 缓解措施 |
|----------|----------|----------|----------|
| **Spoofing** | 恶意MCP Server冒充合法工具 | 🔴 高 | MCP Server签名验证，注册白名单 |
| **Tampering** | 工具输出被中间人篡改 | 🔴 高 | 输出净化器 + 完整性校验 |
| **Repudiation** | Agent操作无法追溯到责任方 | 🟡 中 | 完整审计日志链，不可篡改 |
| **Information Disclosure** | 扫描结果泄露到公共LLM | 🔴 高 | 敏感数据路由到本地模型，数据脱敏 |
| **Denial of Service** | Agent死循环耗尽资源 | 🟡 中 | 循环检测器 + 全局超时 + 资源配额 |
| **Elevation of Privilege** | Agent越权执行未授权操作 | 🔴 高 | L4策略引擎 + Scope校验 + HITL |
| **Prompt Injection** (额外) | 扫描目标网页/文件包含恶意prompt | 🔴 高 | 输出净化 + 角色边界强化 + 不可信内容隔离 |

### 5.2 安全策略引擎

```python
# L4 安全策略引擎核心接口

class SecurityPolicyEngine:
    """
    所有工具调用必须通过此引擎的前置校验。
    校验发生在MCP Client构造请求之前。
    """

    async def validate_tool_call(
        self,
        tool_name: str,
        params: dict,
        scope: AuthorizationScope,  # 任务授权范围
        session: SessionContext,
    ) -> ValidationResult:
        """
        校验链（按顺序，任一失败即拒绝）：
        1. Scope校验: 目标IP/域名是否在授权范围内
        2. 操作校验: 操作类型是否在允许列表中
        3. 速率校验: 是否超过频率限制
        4. 注入检测: 参数是否包含注入载荷
        5. 风险评估: 风险评分是否超过阈值 → HITL升级
        """
        ...

class AuthorizationScope(BaseModel):
    """任务授权范围，每个任务启动时必须定义"""
    allowed_targets: list[str]        # 允许的目标IP/域名/CIDR
    allowed_operations: list[str]     # 允许的操作类型
    prohibited_targets: list[str]     # 明确禁止的目标
    max_scan_intensity: str           # "passive" | "active" | "intrusive"
    requires_human_approval: bool     # 是否需要人工审批
    expires_at: datetime              # 授权过期时间
```

### 5.3 工具输出净化器

```python
class OutputSanitizer:
    """
    所有工具输出在进入LLM上下文前必须通过此净化器。
    核心目标: 防止间接提示词注入。
    """

    async def sanitize(self, tool_output: str) -> SanitizedOutput:
        """
        净化规则：
        1. 移除或转义 markdown 代码块标记
        2. 检测并标记可疑的 prompt 注入模式
        3. 截断超长输出（默认保留头尾，中间截断）
        4. URL脱敏（替换为 [URL_REDACTED]）
        5. base64编码内容检测和移除
        6. 可执行命令模式检测
        """
        ...

class SanitizedOutput(BaseModel):
    content: str               # 净化后的内容
    truncated: bool            # 是否被截断
    suspicious_patterns: list  # 检测到的可疑模式
    original_length: int       # 原始长度
```

### 5.4 Human-in-the-Loop (HITL) 断点

```
高风险操作触发条件:
  - 漏洞利用执行 (exploit_* 类工具)
  - 对生产环境的写入操作
  - 系统命令执行 (shell/exec 类工具)
  - 数据外传操作
  - 策略引擎风险评分 > 阈值

断点流程:
  Agent → 策略引擎(评分) → [高风险] → HITL断点
    → 推送审批请求(含上下文摘要) → 等待人工决策
      → 批准: 继续执行，记录审批者
      → 拒绝: 跳过该操作，记录原因
      → 超时(5min): 自动拒绝，降级处理
```

### 5.5 循环检测器

```python
class LoopDetector:
    """
    检测Agent是否陷入无效循环。
    触发条件：同一工具+相同参数连续调用超过 N 次（默认3次）。
    """

    def __init__(self, max_repeats: int = 3, window_size: int = 10):
        self.call_history: deque = deque(maxlen=window_size)

    def check(self, tool_name: str, params: dict) -> LoopDetection:
        """
        检测逻辑：
        1. 计算 (tool_name, canonical_params_hash) 的指纹
        2. 在滑动窗口中查找相同指纹
        3. 连续重复次数 >= max_repeats → 触发
        """
        ...

    # 触发后行为:
    # 1. 向Supervisor注入强提示："你已连续3次调用{tool}，请改变策略"
    # 2. 如仍无变化 → 强制中断当前Worker
    # 3. Supervisor降级：跳过该子任务或升级人工
```

---

## 六、项目目录结构

```
AptivEye/
├── pyproject.toml                    # 项目配置与依赖
├── .env.example                      # 环境变量模板
├── CLAUDE.md                         # Claude Code 项目文档
├── README.md
│
├── config/
│   ├── __init__.py
│   ├── settings.py                   # pydantic-settings 配置类
│   ├── model_routing.py              # 模型路由规则
│   └── prompts/                      # Prompt 模板（版本管理）
│       ├── supervisor.yaml
│       ├── asset_discovery.yaml
│       ├── vulnerability_scan.yaml
│       ├── code_audit.yaml
│       └── report_generation.yaml
│
├── src/
│   ├── __init__.py
│   │
│   ├── gateway/                      # L1: LLM Gateway
│   │   ├── __init__.py
│   │   ├── router.py                 # 模型路由（tier-based）
│   │   ├── providers/                # 多提供商适配
│   │   │   ├── openai.py
│   │   │   ├── anthropic.py
│   │   │   └── local.py
│   │   ├── cost_tracker.py           # Token成本追踪
│   │   └── rate_limiter.py
│   │
│   ├── agent/                        # L4: 编排与决策
│   │   ├── __init__.py
│   │   ├── supervisor.py             # Supervisor Node
│   │   ├── worker.py                 # Worker Agent (ReAct)
│   │   ├── state.py                  # LangGraph 状态定义
│   │   ├── graph.py                  # 状态图组装
│   │   ├── router.py                 # 任务路由（Supervisor→Worker）
│   │   └── fallback.py               # 降级策略
│   │
│   ├── security/                     # 安全贯穿层
│   │   ├── __init__.py
│   │   ├── policy_engine.py          # 安全策略引擎
│   │   ├── scope.py                  # 授权范围定义与校验
│   │   ├── sanitizer.py              # 工具输出净化器
│   │   ├── loop_detector.py          # 死循环检测
│   │   ├── hitl.py                   # 人机协作断点管理
│   │   ├── audit.py                  # 审计日志
│   │   └── prompt_guard.py           # 提示词注入防护
│   │
│   ├── tools/                        # L3: MCP工具封装
│   │   ├── __init__.py
│   │   ├── registry.py               # MCP Client & 工具注册中心
│   │   ├── asset/                    # 资产测绘 MCP Server
│   │   │   ├── server.py
│   │   │   ├── subdomain.py
│   │   │   ├── port_scan.py
│   │   │   └── fingerprint.py
│   │   ├── vuln/                     # 漏洞扫描 MCP Server
│   │   │   ├── server.py
│   │   │   ├── nuclei.py
│   │   │   ├── weak_pass.py
│   │   │   └── custom_poc.py
│   │   ├── pentest/                  # 渗透测试 MCP Server
│   │   │   ├── server.py
│   │   │   ├── recon.py
│   │   │   └── exploit.py
│   │   ├── code_audit/               # 代码审计 MCP Server
│   │   │   ├── server.py
│   │   │   ├── semgrep.py
│   │   │   ├── bandit.py
│   │   │   └── llm_analyzer.py
│   │   ├── cve/                      # CVE MCP Server
│   │   │   ├── server.py
│   │   │   ├── fetcher.py
│   │   │   ├── matcher.py
│   │   │   └── cvss.py
│   │   └── assess/                   # 评估修复 MCP Server
│   │       ├── server.py
│   │       ├── prioritizer.py
│   │       └── remediate.py
│   │
│   ├── memory/                       # L2: 知识与记忆
│   │   ├── __init__.py
│   │   ├── vector_store.py           # Chroma/Qdrant 统一接口
│   │   ├── session_memory.py         # 短期记忆（当前任务）
│   │   ├── long_term_memory.py       # 长期记忆（跨任务经验）
│   │   ├── cve_knowledge.py          # CVE知识库管理
│   │   └── embeddings.py             # Embedding生成
│   │
│   ├── sandbox/                      # L1: 沙箱执行环境
│   │   ├── __init__.py
│   │   ├── docker_manager.py         # Docker容器生命周期
│   │   ├── executor.py               # 代码/命令安全执行
│   │   └── policies/                 # 沙箱策略（网络/文件/权限）
│   │       ├── default.yaml
│   │       ├── restricted.yaml       # 无网络出站
│   │       └── read_only.yaml        # 只读文件系统
│   │
│   ├── report/                       # L5: 报告生成
│   │   ├── __init__.py
│   │   ├── generator.py              # 报告生成引擎
│   │   ├── templates/                # Jinja2模板
│   │   │   ├── report.md.j2
│   │   │   ├── report.json.j2
│   │   │   └── report.html.j2
│   │   └── exporter.py               # 多格式导出
│   │
│   └── utils/                        # 通用工具
│       ├── __init__.py
│       ├── logger.py                 # loguru 配置
│       ├── telemetry.py              # OpenTelemetry 集成
│       ├── exceptions.py             # 自定义异常体系
│       └── validators.py             # 通用数据校验
│
├── tests/
│   ├── unit/                         # 单元测试（从Phase 0开始）
│   │   ├── test_policy_engine.py
│   │   ├── test_sanitizer.py
│   │   ├── test_loop_detector.py
│   │   ├── test_cvss.py
│   │   └── ...
│   ├── integration/                  # 集成测试
│   │   ├── test_mcp_servers.py
│   │   ├── test_agent_loop.py
│   │   └── ...
│   ├── e2e/                          # 端到端测试（靶机验证）
│   │   ├── test_metasploitable.py
│   │   ├── test_dvwa.py
│   │   └── ...
│   └── fixtures/                     # 测试固定数据
│       ├── sample_nmap_output.xml
│       ├── sample_cve_data.json
│       └── ...
│
├── benchmarks/                       # 评估基准
│   ├── targets/                      # 基准测试目标定义
│   │   ├── metasploitable.yaml
│   │   └── dvwa.yaml
│   ├── metrics/                      # 指标定义
│   │   ├── accuracy.py               # TPR/FPR/FNR
│   │   ├── cost.py                   # Token成本
│   │   └── time.py                   # 时间效率
│   └── reports/                      # 基准测试报告存档
│
├── scripts/                          # 运维脚本
│   ├── bootstrap_db.py               # 初始化CVE数据库
│   ├── update_cve.py                 # 增量更新CVE
│   └── run_benchmark.py              # 运行基准测试
│
├── data/                             # 数据目录
│   ├── cve/                          # CVE原始数据
│   ├── vector_store/                 # 向量数据库持久化
│   ├── reports/                      # 生成的报告
│   └── audit/                        # 审计日志
│
└── docs/
    ├── ARCHITECTURE.md               # 本文档
    ├── THREAT_MODEL.md               # Agent威胁模型
    ├── API.md                        # API文档
    ├── MCP_SERVERS.md                # MCP Server开发指南
    └── DEPLOYMENT.md                 # 部署指南
```

---

## 七、开发计划

### 总体规划：6阶段 + 6评估，总计16周

```
Phase 0 ──→ Phase 1 ──→ Phase 2 ──→ Phase 3 ──→ Phase 4 ──→ Phase 5
  │  E0       │  E1       │  E2       │  E3       │  E4       │  E5
  ▼          ▼          ▼          ▼          ▼          ▼
基础可用   资产测绘   漏洞扫描   代码审计   评估报告   生产就绪
```

### Phase 0: 基础框架与安全护栏（Week 1-3）

**目标**: 可运行的项目骨架 + MCP基础设施 + 安全护栏就位

| # | 任务 | 产出 | 优先级 |
|---|------|------|--------|
| 0.1 | 项目初始化：`pyproject.toml`、依赖、目录结构 | 可安装项目包 | P0 |
| 0.2 | 配置管理：`pydantic-settings` + `.env` + 分层配置 | 配置系统 | P0 |
| 0.3 | LLM Gateway：模型路由 + OpenAI适配 + 成本追踪 | 多模型调用能力 | P0 |
| 0.4 | 日志与可观测性：`loguru` + `opentelemetry` 骨架 | 结构化日志+追踪 | P0 |
| 0.5 | **MCP基础设施**：MCP Client + 工具注册中心 + 首个示例MCP Server | MCP协议集成 | P0 |
| 0.6 | **安全策略引擎**：Scope定义 + 策略校验框架 + 审计日志 | 安全校验链 | P0 |
| 0.7 | **工具输出净化器**：注入检测 + 截断 + URL脱敏 | 净化器 | P1 |
| 0.8 | 基础Agent循环：Supervisor Node + 单Worker ReAct最小实现 | Agent骨架 | P0 |
| 0.9 | **循环检测器** + **HITL断点框架** | 安全防护 | P1 |
| **E0** | 基准：Agent可执行"echo"类任务，LLM路由正常，策略引擎阻断非法调用 | 基础可用验证 | P1 |

### Phase 1: 资产测绘能力（Week 4-6）

**目标**: Agent能自动化完成子域名枚举 + 端口扫描 + 服务指纹识别

| # | 任务 | 产出 | 优先级 |
|---|------|------|--------|
| 1.1 | 资产测绘 MCP Server: 子域名枚举（Amass封装） | `tools/asset/server.py` | P0 |
| 1.2 | 资产测绘 MCP Server: 端口扫描（nmap封装 + NSE脚本） | 端口扫描工具 | P0 |
| 1.3 | 资产测绘 MCP Server: 服务指纹识别 | 指纹识别工具 | P0 |
| 1.4 | 资产测绘 Prompt模板优化 + System Prompt | `config/prompts/asset_discovery.yaml` | P0 |
| 1.5 | Worker Agent 集成资产测绘工具链 | Agent可执行完整资产测绘 | P0 |
| 1.6 | 资产测绘结果的结构化存储（→ L2向量库） | 结果持久化 | P1 |
| **E1** | 基准：对Metasploitable执行资产测绘，对比手动结果，计算发现率 | 资产测绘准确度 | P0 |

### Phase 2: 漏洞扫描与CVE匹配（Week 7-10）

**目标**: 自动漏洞扫描 + CVE数据库检索 + RAG增强分析

| # | 任务 | 产出 | 优先级 |
|---|------|------|--------|
| 2.1 | CVE数据管道：NVD下载 → 清洗 → Embedding → 入库 | CVE知识库 | P0 |
| 2.2 | CVE MCP Server: 向量检索 + 结构化过滤 + CVSS计算 | CVE匹配引擎 | P0 |
| 2.3 | 漏洞扫描 MCP Server: Nuclei封装 + 自定义POC框架 | 漏洞扫描工具 | P0 |
| 2.4 | 弱口令检测 MCP Server | 弱口令检测 | P0 |
| 2.5 | RAG检索增强：漏洞扫描结果 → CVE知识库 → LLM分析 | 智能漏洞分析 | P0 |
| 2.6 | 向量数据库迁移准备（Chroma → Qdrant接口抽象） | 可扩展向量存储 | P1 |
| 2.7 | CVE增量更新脚本 + 定时任务 | CVE数据保鲜 | P1 |
| **E2** | 基准：对已知漏洞靶机扫描，计算TPR/FPR/FNR | 漏洞扫描准确度 | P0 |

### Phase 3: 代码审计能力（Week 11-13）

**目标**: 静态代码扫描 + LLM上下文分析 + 修复建议

| # | 任务 | 产出 | 优先级 |
|---|------|------|--------|
| 3.1 | 代码审计 MCP Server: Semgrep + Bandit封装 | 静态扫描工具 | P0 |
| 3.2 | 代码审计 MCP Server: LLM驱动的上下文感知分析 | 深度代码分析 | P0 |
| 3.3 | 代码审计 MCP Server: 修复建议生成（+代码diff） | 自动修复建议 | P0 |
| 3.4 | Git仓库集成（本地 + 远程） | 批量审计能力 | P1 |
| 3.5 | 代码审计 Prompt模板优化 | `config/prompts/code_audit.yaml` | P0 |
| **E3** | 基准：对已知漏洞代码库（OWASP Benchmark / Juliet Test Suite）审计 | 代码审计准确度 | P0 |

### Phase 4: 评估修复与报告闭环（Week 14-15）

**目标**: 完整"扫描→评估→优先级→修复→报告"闭环

| # | 任务 | 产出 | 优先级 |
|---|------|------|--------|
| 4.1 | 评估 MCP Server: 漏洞优先级排序（基于CVSS+可利用性+资产价值） | 风险评估引擎 | P0 |
| 4.2 | 评估 MCP Server: 修复方案生成（分短期/中期/长期） | 修复方案 | P0 |
| 4.3 | 报告引擎: Markdown/JSON/HTML多格式输出 | 报告生成 | P0 |
| 4.4 | Supervisor集成：多Worker结果聚合 → 综合报告 | 闭环流程 | P0 |
| 4.5 | 证据收集：每个漏洞发现关联工具输出证据 | 审计追踪 | P1 |
| **E4** | 基准：端到端扫描完整流程，评估从输入到报告的Token成本和耗时 | 效率基线 | P0 |

### Phase 5: 安全加固与生产就绪（Week 16-18）

**目标**: Agent自身安全 + CLI工具 + 测试 + 文档

| # | 任务 | 产出 | 优先级 |
|---|------|------|--------|
| 5.1 | Docker沙箱完整实现（多策略：默认/限制/只读） | `sandbox/` | P0 |
| 5.2 | HITL完整集成：WebSocket推送审批 + 超时处理 | 人工审批流程 | P0 |
| 5.3 | 提示词注入防护完善（分隔符强化 + 不可信内容隔离） | `security/prompt_guard.py` | P0 |
| 5.4 | LangSmith集成（可选，用于Agent调试追踪） | 可观测性增强 | P1 |
| 5.5 | CLI交互界面（rich + typer）：实时流式输出 + 彩色渲染 | 命令行工具 | P0 |
| 5.6 | Web API（FastAPI + WebSocket）：RESTful + 流式 | API服务 | P2 |
| 5.7 | 测试补齐：单元测试 > 70% + 集成测试 + E2E（靶机） | 测试套件 | P0 |
| 5.8 | 文档：部署指南 + MCP Server开发指南 + 用户手册 | `docs/` | P0 |
| **E5** | 最终评估：所有评估基准汇总，误报/漏报率达标，成本模型验证 | 生产就绪报告 | P0 |

### Phase 6: 持续增强（∞）

| # | 任务 | 优先级 |
|---|------|--------|
| 6.1 | 多模型支持完善（Claude全系列、本地llama/qwen） | P0 |
| 6.2 | 渗透测试辅助能力（信息收集→漏洞利用→权限提升→横向移动） | P0 |
| 6.3 | 多Agent角色协作（侦察Agent + 漏洞Agent + 审计Agent并行） | P1 |
| 6.4 | 任务持久化与恢复（中断后从断点继续） | P1 |
| 6.5 | Web可视化面板（实时Agent状态 + 资产地图 + 漏洞仪表盘） | P2 |
| 6.6 | 社区MCP Server集成（GitHub、Shodan、VirusTotal等） | P2 |
| 6.7 | 自适应扫描策略（基于初始探测结果动态调整扫描深度） | P3 |

---

## 八、评估体系

### 8.1 评估基准总览

| 评估 | 关联Phase | 测试目标 | 核心指标 | 达标线 |
|------|-----------|----------|----------|--------|
| E0 | Phase 0 | 框架可用性 | Agent可执行基础循环，LLM路由正确 | 100%基础任务通过 |
| E1 | Phase 1 | 资产测绘准确度 | 子域名发现率、端口开放检测准确率、服务识别准确率 | 发现率 > 90% |
| E2 | Phase 2 | 漏洞扫描准确度 | TPR、FPR、FNR（以Metasploitable已知漏洞为基准） | TPR > 85%, FPR < 15% |
| E3 | Phase 3 | 代码审计准确度 | 与OWASP Benchmark基线对比 | TPR > 80%, FPR < 20% |
| E4 | Phase 4 | 效率与成本 | 端到端Token成本、扫描耗时 | 单靶机扫描 < 50K tokens |
| E5 | Phase 5 | 安全性自检 | 注入防护通过率、审计链完整性 | 100%注入样本被拦截 |

### 8.2 基准测试靶机

```
靶机矩阵:
├── Metasploitable 2/3    → 漏洞扫描 + 渗透测试基准
├── DVWA                  → Web应用漏洞基准
├── VulHub 精选镜像        → CVE关联验证基准
├── OWASP Benchmark       → 代码审计基准 (SAST)
├── Juliet Test Suite     → 代码审计基准 (CWEs覆盖率)
└── 自建干净靶机            → FPR基准 (不应报告任何漏洞)
```

### 8.3 成本模型

```
单次扫描任务Token预算 = Supervisor规划 + Σ(Worker执行) + 报告生成

预估（单IP全量扫描）:
  Supervisor:             ~2,000 tokens (规划 + 聚合)
  Worker-资产测绘:        ~8,000 tokens (子域名+端口+指纹)
  Worker-漏洞扫描:        ~15,000 tokens (Nuclei结果 + LLM分析)
  Worker-CVE匹配:         ~10,000 tokens (RAG检索 + 匹配推理)
  Worker-报告生成:        ~5,000 tokens
  总计:                   ~40,000 tokens ≈ $0.30-1.00 (视模型)

成本优化：
  - 轻量任务路由到mini模型，节省 ~40%
  - Worker结果缓存（相同指纹目标复用分析），节省 ~25%
  - 本地模型处理常规任务，节省 ~60%
```

---

## 九、风险矩阵

| # | 风险 | 可能性 | 影响 | 缓解策略 | 检测手段 |
|----|------|--------|------|----------|----------|
| R1 | LLM幻觉导致误报 | 高 | 高 | 工具输出作为事实锚点，LLM仅做分析和建议；每条漏洞必须有工具证据支撑 | E2基准测试FPR监测 |
| R2 | Agent执行危险命令 | 中 | 高 | 沙箱隔离 + 策略引擎 + HITL断点 + 审计日志 | E5注入防护测试 |
| R3 | 间接提示词注入 | 中 | 高 | 工具输出净化器 + 角色边界强化 + 不可信内容隔离 | 注入测试套件 |
| R4 | 敏感数据泄露到公共LLM | 中 | 高 | 敏感数据自动路由本地模型 + 数据脱敏 + 审计 | 数据流审计 |
| R5 | 工具执行超时/资源耗尽 | 高 | 中 | 全局超时控制 + 资源配额 + 死循环检测器 | 资源监控告警 |
| R6 | CVE数据库更新滞后 | 低 | 中 | 自动增量更新 + 在线API兜底 + 最后更新日期透明度 | 更新脚本监控 |
| R7 | LLM API故障不可用 | 中 | 高 | 多模型冗余 + 本地模型兜底 + 降级策略链 | 健康检查 + 自动切换 |
| R8 | 上下文窗口溢出 | 中 | 中 | Hierarchical ReAct隔离Worker上下文 + 截断策略 + 摘要压缩 | Token计数监控 |
| R9 | MCP Server进程崩溃 | 中 | 中 | 进程守护 + 自动重启 + 优雅降级（跳过该工具） | 心跳检测 |
| R10 | LangGraph API破坏性变更 | 低 | 中 | 锁定主版本 + MCP解耦工具层（换框架只影响L4） | CI依赖检查 |

---

## 十、附录

### A. 关键技术版本锁定

| 组件 | 版本 | 约束 |
|------|------|------|
| Python | ≥3.12 | 强制类型注解 |
| LangChain | ≥0.3.0 | 锁定主版本 |
| LangGraph | ≥0.2.0 | 锁定主版本 |
| MCP Protocol | ≥2024-11-05 | 随规范更新 |
| Chroma | ≥0.5.0 | - |
| Qdrant | ≥1.9.0 | 生产迁移 |
| Docker Engine | ≥24.0 | 沙箱依赖 |
| Pydantic | ≥2.0 | Settings + Validation |

### B. Prompt工程规范

1. **所有Prompt模板存放在`config/prompts/`，使用YAML格式**
2. **每个Prompt模板有版本号，变更需记录CHANGELOG**
3. **System Prompt中明确角色边界**：
   ```
   ## 角色定义
   你是一个安全扫描Worker。你的职责是执行指定的扫描任务。
   
   ## 不可逾越的边界
   - 你只能在scope授权的目标上操作
   - 你不能修改系统配置
   - 你不能将扫描结果发送到外部
   
   ## 输出格式
   所有分析结果必须以JSON格式输出，包含evidence字段引用工具输出。
   ```
4. **不可信内容必须用`<untrusted_content>...</untrusted_content>`标签包裹**

### C. 错误处理规范

```
异常层次结构:
AptivEyeError (基类)
├── ConfigurationError        # 配置错误
├── LLMGatewayError           # LLM网关错误
│   ├── RateLimitError        # 速率限制
│   ├── TokenLimitError       # Token超限
│   └── ModelUnavailableError # 模型不可用
├── ToolExecutionError        # 工具执行错误
│   ├── ToolTimeoutError      # 工具超时
│   └── ToolOutputError       # 工具输出异常
├── SecurityPolicyError       # 安全策略违反
│   ├── ScopeViolationError   # 超出授权范围
│   └── InjectionDetectedError # 检测到注入
├── SandboxError              # 沙箱错误
└── AgentLoopError            # Agent循环异常
    └── InfiniteLoopDetectedError  # 检测到死循环
```

### D. 审计日志格式

```json
{
  "event_id": "evt_20260627_001",
  "timestamp": "2026-06-27T10:30:00Z",
  "session_id": "sess_abc123",
  "scope_id": "scope_xyz789",
  "agent_node": "supervisor | worker:<id>",
  "event_type": "tool_call | llm_decision | hitl_approval | policy_violation",
  "detail": {
    "tool_name": "nmap_scan",
    "params": {"target": "192.168.1.1", "ports": "1-1000"},
    "decision": "approved | denied | escalated",
    "risk_score": 3,
    "duration_ms": 4500,
    "token_used": 1200
  },
  "trace_id": "trace_for_opentelemetry"
}
```

---

> **文档维护**: 本架构文档随项目演进持续更新。重大架构变更需经过技术评审并更新本文档。
>
> **实施状态**:
> - ✅ **Phase 0 完成** (2026-06-27): 项目骨架、六层架构、7安全组件、LLM Gateway、LangGraph Agent、CLI
> - ✅ **Phase 1 完成** (2026-06-27): 10资产测绘工具（子域名/端口/指纹/WHOIS/FOFA/ZoomEye/ICP/企查查/天眼查/微信/APP/邮箱），15个API端点全可配
>
> **最后更新**: 2026-06-27 | **下一次计划评审**: Phase 2 启动前
