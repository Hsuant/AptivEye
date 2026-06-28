"""Supervisor Node — thin LangGraph adapter that delegates to Planner.

The Supervisor is the "orchestrator" of the agent system. It delegates all
intelligence (planning, aggregation) to the :class:`Planner` and acts as a
thin adapter between the LangGraph state graph and the Planner's API.
"""

from __future__ import annotations

import json
from typing import Any

from src.agent.planner import Planner
from src.agent.state import AgentState
from src.gateway.router import LLMRouter
from src.tools.registry import ToolRegistry
from src.utils.logger import get_logger

logger = get_logger(__name__)


async def supervisor_node(
    state: AgentState,
    llm: LLMRouter,
    registry: ToolRegistry,
    *,
    planner: Planner | None = None,
) -> dict[str, Any]:
    """Supervisor LangGraph node — delegates to :class:`Planner`.

    - On first call (status='planning'): calls ``planner.plan(task)``.
    - On aggregation (status='aggregating'): calls ``planner.aggregate(task, results)``.

    Args:
        state: Current LangGraph agent state.
        llm: LLM router for model calls.
        registry: Tool registry (used to create a Planner if none provided).
        planner: Pre-created Planner instance. Created on-demand if omitted.

    Returns:
        State update dict with plan, status, final_report, etc.
    """
    status = state.get("status", "planning")

    if planner is None:
        planner = Planner(llm)

    if status == "aggregating":
        return await _handle_aggregation(state, planner)

    return await _handle_planning(state, planner)


# ═══════════════════════════════════════════════════════════════════════════
# Internal helpers
# ═══════════════════════════════════════════════════════════════════════════


async def _handle_planning(
    state: AgentState,
    planner: Planner,
) -> dict[str, Any]:
    """Delegate task decomposition to the Planner."""
    task = state.get("task", "")
    logger.info("Supervisor planning for task: {}", task[:100])

    try:
        plan = await planner.plan(task)
        return {
            **plan.to_state_dict(),
            "current_task_index": 0,
            "worker_results": {},
            "status": "executing",
            "error_count": 0,
            "iteration_count": 0,
        }
    except Exception as exc:
        logger.error("Supervisor planning failed: {}", exc)
        # Fallback: single-task plan
        fallback = Planner._create_default_sub_task(task)
        return {
            "plan": [fallback.to_dict()],
            "plan_rationale": f"Fallback plan due to planning error: {exc}",
            "current_task_index": 0,
            "worker_results": {},
            "status": "executing",
            "error_count": 0,
            "iteration_count": 0,
        }


async def _handle_aggregation(
    state: AgentState,
    planner: Planner,
) -> dict[str, Any]:
    """Delegate result aggregation to the Planner."""
    task = state.get("task", "")
    worker_results = state.get("worker_results", {})

    logger.info("Supervisor aggregating {} worker results", len(worker_results))

    try:
        report = await planner.aggregate(task, worker_results)
    except Exception as exc:
        logger.error("Aggregation failed: {}", exc)
        results_str = json.dumps(worker_results, indent=2, ensure_ascii=False)
        report = (
            f"## Report Generation Failed\n\n"
            f"**Error:** {exc}\n\n"
            f"## Raw Results\n\n"
            f"```json\n{results_str}\n```"
        )

    return {
        "final_report": report,
        "status": "completed",
    }
