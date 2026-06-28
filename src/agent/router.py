"""Agent graph router — determines the next node to execute.

The router is the decision-making hub of the state graph.
It examines the current state and decides whether to:
  - Continue planning
  - Execute the next worker
  - Aggregate results
  - Trigger fallback on errors
  - End the run
"""

from __future__ import annotations

from src.agent.state import AgentState
from src.utils.logger import get_logger

logger = get_logger(__name__)


# Valid next node destinations
NEXT_PLAN = "supervisor"
NEXT_WORKER = "worker"
NEXT_AGGREGATE = "aggregate"
NEXT_FALLBACK = "fallback"
NEXT_END = "__end__"


def route_after_supervisor(state: AgentState) -> str:
    """After the supervisor plans, decide: execute workers or end.

    If no plan was produced (or plan is empty), end.
    If there are errors, check threshold.
    Otherwise, start worker execution.
    """
    plan = state.get("plan", [])
    status = state.get("status", "")

    if status == "error":
        error_count = state.get("error_count", 0)
        max_errors = state.get("max_errors", 3)
        if error_count >= max_errors:
            logger.warning("Error threshold reached ({}/{}), triggering fallback", error_count, max_errors)
            return NEXT_FALLBACK
        return NEXT_END

    if not plan:
        logger.info("No plan produced — ending")
        return NEXT_END

    # Start executing the first task
    state["current_task_index"] = 0
    state["status"] = "executing"
    return NEXT_WORKER


def route_after_worker(state: AgentState) -> str:
    """After a worker completes, decide: next task, aggregate, or handle error.

    Returns:
        NEXT_WORKER if more tasks remain.
        NEXT_AGGREGATE if all tasks are done.
        NEXT_FALLBACK on repeated errors.
    """
    status = state.get("status", "")
    error_count = state.get("error_count", 0)

    if status == "error":
        max_errors = state.get("max_errors", 3)
        if error_count >= max_errors:
            return NEXT_FALLBACK
        # Retry: stay on the same worker
        return NEXT_WORKER

    # Move to next task
    plan = state.get("plan", [])
    current_index = state.get("current_task_index", 0)
    next_index = current_index + 1

    if next_index >= len(plan):
        # All tasks done
        logger.info("All {} sub-tasks complete — aggregating", len(plan))
        return NEXT_AGGREGATE

    # More tasks to execute
    state["current_task_index"] = next_index
    return NEXT_WORKER


def route_after_fallback(state: AgentState) -> str:
    """After fallback handling, decide whether to end or retry."""
    return NEXT_END


def should_continue(state: AgentState) -> str:
    """Generic routing based on status field."""
    status = state.get("status", "")
    mapping: dict[str, str] = {
        "planning": NEXT_PLAN,
        "executing": NEXT_WORKER,
        "aggregating": NEXT_AGGREGATE,
        "completed": NEXT_END,
        "error": NEXT_FALLBACK,
    }
    return mapping.get(status, NEXT_END)
