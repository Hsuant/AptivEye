"""Agent state definitions for LangGraph.

Defines the central state object that flows through the agent graph.
Uses LangGraph's TypedDict-based state with annotation-driven reducers.
"""

from __future__ import annotations

from typing import Annotated, Any, Optional, TypedDict

from langgraph.graph.message import add_messages

from src.security.scope import AuthorizationScope


class AgentState(TypedDict, total=False):
    """Central state object flowing through the LangGraph agent graph.

    Fields with Annotated reducers are merged (not overwritten) across updates.
    """

    # --- Messages (auto-merged via add_messages reducer) ---
    messages: Annotated[list[Any], add_messages]

    # --- Task definition ---
    task: str                                    # Original user request
    scope: Optional[AuthorizationScope]          # Authorization boundaries

    # --- Supervisor planning ---
    plan: list[dict[str, Any]]                   # Decomposed sub-tasks
    plan_rationale: str                          # Why the supervisor chose this plan

    # --- Worker execution ---
    current_task_index: int                      # Which sub-task is being executed
    worker_results: dict[str, Any]               # Accumulated results keyed by task_id
    worker_context: dict[str, Any]               # Per-worker context

    # --- Control flow ---
    status: str                                  # "planning" | "executing" | "aggregating" | "completed" | "error"
    error_count: int                             # Consecutive error counter
    max_errors: int                              # Max errors before fallback
    iteration_count: int                         # Total ReAct iterations

    # --- Identifiers ---
    session_id: str                              # Session identifier

    # --- Output ---
    final_report: str                            # Final aggregated report
