"""Planner Module — standalone task planning and execution for the agent system.

Provides a ``Planner`` class that encapsulates all planning, execution, and
aggregation logic. Usable both inside the LangGraph graph (via supervisor_node)
and standalone for direct task execution.

Supports three execution modes:

* **In-graph planning**: ``planner.plan(task)`` called from supervisor_node.
* **整体执行 (batch)**: ``planner.execute_all(task)`` — plan → execute all → aggregate.
* **单个执行 (single)**: ``planner.execute_one(plan, task_id)`` (retry a sub-task) or
  ``planner.execute_single(task)`` (plan+execute an atomic task).

All LLM calls route through the injected ``LLMRouter`` — the Planner does
not create its own LLM connections.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from src.security.audit import AuditEvent, AuditEventType, AuditLogger
from src.security.loop_detector import LoopDetector
from src.security.policy_engine import SecurityPolicyEngine
from src.security.sanitizer import OutputSanitizer
from src.security.scope import AuthorizationScope
from src.tools.registry import ToolRegistry
from src.utils.logger import get_logger
from src.utils.parsing import parse_json_response

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Exception
# ═══════════════════════════════════════════════════════════════════════════


class PlannerError(Exception):
    """Raised when planning or execution fails irrecoverably."""


# ═══════════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════════


class SubTask(BaseModel):
    """A single sub-task within an execution plan."""

    id: str = Field(..., description="Unique task identifier, e.g. 'task_1'")
    title: str = Field(..., description="Human-readable task name")
    description: str = Field(..., description="Detailed description of what to execute")
    tool_category: str = Field(default="general", description="Tool category filter for the worker")
    priority: str = Field(default="medium", description="high | medium | low")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain dict (backward compatible with AgentState['plan'])."""
        return self.model_dump()


class Plan(BaseModel):
    """A complete execution plan produced by the Planner."""

    rationale: str = Field(..., description="Why the planner chose this decomposition")
    sub_tasks: list[SubTask] = Field(..., description="Ordered list of sub-tasks")

    def to_state_dict(self) -> dict[str, Any]:
        """Convert to the shape AgentState expects."""
        return {
            "plan": [st.to_dict() for st in self.sub_tasks],
            "plan_rationale": self.rationale,
        }


@dataclass
class WorkerDependencies:
    """Dependencies needed by the Planner to execute sub-tasks.

    Only required for standalone execution modes (execute_all, execute_one,
    execute_single). Not required for in-graph planning via plan().
    """

    registry: ToolRegistry
    policy_engine: SecurityPolicyEngine
    sanitizer: OutputSanitizer
    loop_detector: LoopDetector


# ═══════════════════════════════════════════════════════════════════════════
# Prompt Templates
# ═══════════════════════════════════════════════════════════════════════════

_PLANNER_SYSTEM_PROMPT = """You are a Security Assessment Supervisor Agent.

Your role is to:
1. Analyze the user's security assessment request
2. Decompose it into concrete, executable sub-tasks
3. Each sub-task must be specific and use available tools
4. Output a structured JSON plan

You do NOT execute tools directly. You plan and delegate.

## Available Tool Categories
{tool_categories}

## Output Format
Respond ONLY with valid JSON in this exact structure:
{{
  "rationale": "Brief explanation of your planning strategy",
  "sub_tasks": [
    {{
      "id": "task_1",
      "title": "Human-readable task name",
      "description": "Detailed description of what to do",
      "tool_category": "asset|vuln|code_audit|cve|assess",
      "priority": "high|medium|low"
    }}
  ]
}}

## Rules
- Each sub-task should represent ONE logical unit of work
- Order tasks by dependency (asset discovery before vulnerability scanning)
- Maximum 5 sub-tasks per plan
- Be specific about targets and expected outputs
"""

_PLANNER_SINGLE_TASK_PROMPT = """You are a Security Assessment Agent. The user has a single, atomic task.

Convert the user's request into exactly ONE sub-task. Do NOT decompose further.

## Available Tool Categories
{tool_categories}

## Output Format
Respond ONLY with valid JSON:
{{
  "rationale": "Brief explanation",
  "sub_tasks": [
    {{
      "id": "task_1",
      "title": "Human-readable task name",
      "description": "Detailed description of what to do",
      "tool_category": "asset|vuln|code_audit|cve|assess|general",
      "priority": "high|medium|low"
    }}
  ]
}}

## Rule
- Produce EXACTLY ONE sub-task. Do not decompose further.
"""

_PLANNER_AGGREGATION_PROMPT = """You are a Security Assessment Supervisor.

You have received results from multiple worker agents. Your task is to
synthesize these results into a coherent summary.

## Original Task
{task}

## Worker Results
{worker_results}

## Instructions
Provide a comprehensive summary that:
1. Lists all findings, organized by severity
2. Identifies relationships between findings
3. Recommends next steps
4. Notes any gaps or incomplete areas

Format your response in clear Markdown.
"""


# ═══════════════════════════════════════════════════════════════════════════
# Planner
# ═══════════════════════════════════════════════════════════════════════════


class Planner:
    """Standalone task planner for the AptivEye agent system.

    Supports three usage modes::

        # 1. In-graph planning (used inside supervisor_node)
        plan = await planner.plan("Scan example.com for open ports")

        # 2. 整体执行 — plan, execute all, aggregate in one call
        result = await planner.execute_all("Scan example.com for open ports")

        # 3a. 单个执行 — execute a specific sub-task from an existing plan
        result = await planner.execute_one(plan, "task_2")

        # 3b. 单个执行 — plan + execute a single atomic task
        result = await planner.execute_single("Check port 443 on example.com")

    Args:
        llm: The agent's LLMRouter instance (dependency injection).
        worker_deps: WorkerDependencies bundle. Required ONLY for execute_*
            methods. Can be omitted when the Planner is used only for plan()
            inside the LangGraph graph.
    """

    def __init__(
        self,
        llm: Any,  # LLMRouter — avoid circular import with string annotation
        *,
        worker_deps: WorkerDependencies | None = None,
    ) -> None:
        self._llm = llm
        self._worker_deps = worker_deps

    # ── Core: Plan only (used inside LangGraph supervisor node) ─────────

    async def plan(self, task: str) -> Plan:
        """Decompose a high-level task into an ordered Plan of SubTasks.

        Used by the LangGraph supervisor node to produce the execution plan.
        Does NOT require worker_deps.

        Args:
            task: The user's natural-language security assessment request.

        Returns:
            A ``Plan`` with rationale and ordered list of ``SubTask`` objects.

        Raises:
            PlannerError: If the LLM call fails and no fallback can be produced.
        """
        logger.info("Planner.plan() for task: {}", task[:100])

        # Build planning prompt
        categories = self._get_categories()
        system_prompt = _PLANNER_SYSTEM_PROMPT.format(tool_categories=categories)

        plan_messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Plan the following security assessment task:\n\n{task}"},
        ]

        try:
            response = await self._llm.generate(
                messages=plan_messages,
                task_type="supervisor_planning",
                temperature=0.0,
            )
        except Exception as exc:
            logger.error("LLM call failed in plan(): {}", exc)
            return self._fallback_plan(task, f"LLM error: {exc}")

        # Parse the structured response
        plan_data = parse_json_response(response.content)

        rationale = plan_data.get("rationale", "No rationale provided")
        raw_sub_tasks = plan_data.get("sub_tasks", [])

        # If LLM didn't produce structured tasks, create a default
        if not raw_sub_tasks:
            logger.warning("Planner produced no sub-tasks — using fallback plan")
            return self._fallback_plan(task, "LLM did not produce structured output")

        # Convert to Pydantic models with validation
        sub_tasks: list[SubTask] = []
        for st_data in raw_sub_tasks:
            try:
                # Ensure required fields exist
                if "id" not in st_data:
                    st_data["id"] = f"task_{uuid.uuid4().hex[:8]}"
                sub_tasks.append(SubTask(**st_data))
            except Exception as exc:
                logger.warning("Skipping invalid sub-task: {} — {}", st_data, exc)
                continue

        if not sub_tasks:
            return self._fallback_plan(task, "All sub-tasks failed validation")

        logger.info("Planner produced plan: {} sub-tasks — {}", len(sub_tasks), rationale[:80])
        return Plan(rationale=rationale, sub_tasks=sub_tasks)

    # ── 整体执行: Plan + Execute All + Aggregate ────────────────────────

    async def execute_all(
        self,
        task: str,
        *,
        scope: AuthorizationScope | None = None,
        audit: AuditLogger | None = None,
        max_iterations_per_task: int = 10,
    ) -> dict[str, Any]:
        """Plan a task, execute all sub-tasks sequentially, aggregate results.

        This is a complete end-to-end run — **整体执行**.

        Args:
            task: The high-level task description.
            scope: Authorization boundaries (optional).
            audit: Audit logger. A transient one is created if omitted.
            max_iterations_per_task: ReAct loop iteration limit per sub-task.

        Returns:
            Dict with keys: ``plan``, ``worker_results``, ``final_report``, ``status``.

        Raises:
            PlannerError: If ``worker_deps`` was not provided at init.
        """
        if self._worker_deps is None:
            raise PlannerError(
                "WorkerDependencies required for execute_all(). "
                "Provide worker_deps when constructing the Planner."
            )

        if audit is None:
            audit = AuditLogger(session_id=f"planner_{uuid.uuid4().hex[:8]}")

        # Phase 1: Plan
        plan = await self.plan(task)
        audit.log(AuditEvent(
            event_type=AuditEventType.SESSION_START,
            detail={
                "task": task,
                "sub_tasks": len(plan.sub_tasks),
                "rationale": plan.rationale,
            },
        ))

        # Phase 2: Execute each sub-task sequentially
        worker_results: dict[str, Any] = {}
        overall_status = "completed"

        for i, sub_task in enumerate(plan.sub_tasks):
            logger.info("Executing sub-task [{}/{}]: {}", i + 1, len(plan.sub_tasks), sub_task.title)

            result = await self._execute_sub_task(
                sub_task,
                scope=scope,
                audit=audit,
                max_iterations=max_iterations_per_task,
            )

            worker_results[sub_task.id] = {
                "title": sub_task.title,
                "status": result.get("status", "unknown"),
                "findings": result.get("findings", []),
                "tools_used": result.get("tools_used", []),
                "summary": result.get("summary", ""),
            }

            if result.get("status") == "failed":
                overall_status = "partial"
                logger.warning("Sub-task '{}' failed — continuing", sub_task.id)

        # Phase 3: Aggregate
        try:
            final_report = await self.aggregate(task, worker_results)
        except Exception as exc:
            logger.error("Aggregation failed: {}", exc)
            final_report = (
                f"## Report Generation Failed\n\n"
                f"**Error:** {exc}\n\n"
                f"## Raw Results\n\n"
                f"```json\n{json.dumps(worker_results, indent=2, ensure_ascii=False)}\n```"
            )
            overall_status = "partial"

        audit.log(AuditEvent(
            event_type=AuditEventType.SESSION_END,
            detail={
                "status": overall_status,
                "results_count": len(worker_results),
            },
        ))

        return {
            "plan": plan,
            "worker_results": worker_results,
            "final_report": final_report,
            "status": overall_status,
        }

    # ── 单个执行 Mode A: Execute a specific sub-task from an existing plan

    async def execute_one(
        self,
        plan: Plan,
        task_id: str,
        *,
        scope: AuthorizationScope | None = None,
        audit: AuditLogger | None = None,
        max_iterations: int = 10,
    ) -> dict[str, Any]:
        """Execute a single sub-task from an already-planned Plan.

        Useful for retrying a failed task or debugging a specific step.

        Args:
            plan: The full plan (must contain a sub-task with ``task_id``).
            task_id: The ID of the sub-task to execute.
            scope: Authorization boundaries (optional).
            audit: Audit logger.
            max_iterations: ReAct loop iteration limit.

        Returns:
            Dict with keys: ``task_id``, ``result``, ``status``.

        Raises:
            PlannerError: If worker_deps is missing.
            ValueError: If ``task_id`` is not found in ``plan.sub_tasks``.
        """
        if self._worker_deps is None:
            raise PlannerError(
                "WorkerDependencies required for execute_one(). "
                "Provide worker_deps when constructing the Planner."
            )

        # Find the sub-task
        sub_task = next((st for st in plan.sub_tasks if st.id == task_id), None)
        if sub_task is None:
            raise ValueError(
                f"Sub-task '{task_id}' not found in plan. "
                f"Available: {[st.id for st in plan.sub_tasks]}"
            )

        if audit is None:
            audit = AuditLogger(session_id=f"planner_one_{uuid.uuid4().hex[:8]}")

        logger.info("Planner.execute_one() task_id={}, title={}", task_id, sub_task.title)

        result = await self._execute_sub_task(
            sub_task,
            scope=scope,
            audit=audit,
            max_iterations=max_iterations,
        )

        return {
            "task_id": task_id,
            "result": result,
            "status": result.get("status", "unknown"),
        }

    # ── 单个执行 Mode B: Plan + Execute a single atomic task ────────────

    async def execute_single(
        self,
        task: str,
        *,
        scope: AuthorizationScope | None = None,
        audit: AuditLogger | None = None,
        max_iterations: int = 10,
    ) -> dict[str, Any]:
        """Plan and execute a single atomic task (lightweight one-off).

        Internally calls a single-task-biased plan, then executes the one
        resulting sub-task. Use for quick, focused operations where full
        decomposition is unnecessary.

        Args:
            task: The atomic task to execute.
            scope: Authorization boundaries (optional).
            audit: Audit logger.
            max_iterations: ReAct loop iteration limit.

        Returns:
            Dict with keys: ``task_id``, ``result``, ``status``, ``plan``.

        Raises:
            PlannerError: If worker_deps is missing.
        """
        if self._worker_deps is None:
            raise PlannerError(
                "WorkerDependencies required for execute_single(). "
                "Provide worker_deps when constructing the Planner."
            )

        if audit is None:
            audit = AuditLogger(session_id=f"planner_single_{uuid.uuid4().hex[:8]}")

        logger.info("Planner.execute_single() for task: {}", task[:100])

        # Phase 1: Single-task-biased planning
        categories = self._get_categories()
        system_prompt = _PLANNER_SINGLE_TASK_PROMPT.format(tool_categories=categories)

        plan_messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Execute this single task:\n\n{task}"},
        ]

        try:
            response = await self._llm.generate(
                messages=plan_messages,
                task_type="supervisor_planning",
                temperature=0.0,
            )
            plan_data = parse_json_response(response.content)
        except Exception as exc:
            logger.error("LLM call failed in execute_single(): {}", exc)
            plan_data = {}

        sub_tasks_raw = plan_data.get("sub_tasks", [])
        if sub_tasks_raw:
            try:
                st_data = sub_tasks_raw[0]
                if "id" not in st_data:
                    st_data["id"] = f"task_{uuid.uuid4().hex[:8]}"
                sub_task = SubTask(**st_data)
                rationale = plan_data.get("rationale", "Single-task execution")
            except Exception:
                sub_task = self._create_default_sub_task(task)
                rationale = "Fallback single-task plan"
        else:
            sub_task = self._create_default_sub_task(task)
            rationale = "Fallback single-task plan (LLM produced no sub-tasks)"

        plan = Plan(rationale=rationale, sub_tasks=[sub_task])

        # Phase 2: Execute
        result = await self._execute_sub_task(
            sub_task,
            scope=scope,
            audit=audit,
            max_iterations=max_iterations,
        )

        return {
            "task_id": sub_task.id,
            "result": result,
            "status": result.get("status", "unknown"),
            "plan": plan,
        }

    # ── Aggregation ────────────────────────────────────────────────────

    async def aggregate(
        self,
        task: str,
        worker_results: dict[str, Any],
    ) -> str:
        """Synthesize worker results into a final Markdown report.

        Args:
            task: Original user request for context.
            worker_results: Dict keyed by task_id with per-worker output.

        Returns:
            Markdown-formatted final report string.
        """
        logger.info("Planner.aggregate() — {} result sets", len(worker_results))

        results_str = json.dumps(worker_results, indent=2, ensure_ascii=False)
        prompt = _PLANNER_AGGREGATION_PROMPT.format(
            task=task,
            worker_results=results_str,
        )

        try:
            response = await self._llm.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="report_generation",
                temperature=0.0,
            )
            return response.content
        except Exception as exc:
            logger.error("Aggregation LLM call failed: {}", exc)
            raise

    # ── Internal Helpers ───────────────────────────────────────────────

    async def _execute_sub_task(
        self,
        sub_task: SubTask,
        *,
        scope: AuthorizationScope | None,
        audit: AuditLogger,
        max_iterations: int,
    ) -> dict[str, Any]:
        """Execute a single SubTask via the ReAct loop.

        Uses the extracted ``run_react_loop`` function from worker.py.
        Import is deferred to avoid circular dependency at module level.
        """
        # Deferred import to avoid circular dependency
        from src.agent.worker import run_react_loop  # noqa: PLC0415

        assert self._worker_deps is not None  # checked by callers

        result = await run_react_loop(
            sub_task=sub_task.to_dict(),
            llm=self._llm,
            registry=self._worker_deps.registry,
            policy_engine=self._worker_deps.policy_engine,
            sanitizer=self._worker_deps.sanitizer,
            loop_detector=self._worker_deps.loop_detector,
            audit=audit,
            scope=scope,
            max_iterations=max_iterations,
        )

        return result

    def _get_categories(self) -> str:
        """Get available tool categories formatted for prompt injection."""
        if self._worker_deps is not None:
            categories = self._worker_deps.registry.get_categories()
        else:
            categories = []
        return "\n".join(f"- {c}" for c in categories) if categories else "- general"

    @staticmethod
    def _create_default_sub_task(task: str) -> SubTask:
        """Create a fallback single SubTask when planning fails."""
        return SubTask(
            id=f"task_{uuid.uuid4().hex[:8]}",
            title="Execute Assessment",
            description=task,
            tool_category="general",
            priority="high",
        )

    def _fallback_plan(self, task: str, reason: str) -> Plan:
        """Create a fallback single-task Plan with a given reason."""
        sub_task = self._create_default_sub_task(task)
        logger.info("Fallback plan created: reason={}", reason)
        return Plan(
            rationale=f"Fallback plan: {reason}",
            sub_tasks=[sub_task],
        )
