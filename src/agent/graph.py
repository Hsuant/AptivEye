"""Agent state graph — assembles the LangGraph StateGraph.

This is the main entry point for building the agent's execution graph.
The graph defines:
  - Nodes: supervisor, worker, aggregate, fallback
  - Edges: control flow between nodes
  - Conditional routing: decisions based on state
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from src.agent.fallback import fallback_node
from src.agent.planner import Planner
from src.agent.router import (
    route_after_supervisor,
    route_after_worker,
    route_after_fallback,
)
from src.agent.state import AgentState
from src.agent.supervisor import supervisor_node
from src.agent.worker import worker_node
from src.gateway.router import LLMRouter
from src.security.audit import AuditLogger
from src.security.loop_detector import LoopDetector
from src.security.policy_engine import SecurityPolicyEngine
from src.security.sanitizer import OutputSanitizer
from src.tools.registry import ToolRegistry
from src.utils.logger import get_logger

logger = get_logger(__name__)


def build_agent_graph(
    llm: LLMRouter,
    registry: ToolRegistry,
    policy_engine: SecurityPolicyEngine,
    sanitizer: OutputSanitizer,
    loop_detector: LoopDetector,
    audit: AuditLogger,
    *,
    planner: Planner | None = None,
) -> StateGraph:
    """Build and return a compiled LangGraph StateGraph for the agent.

    Graph structure::

        [START] → supervisor → [route]
                      │
                    worker → [route]
                      │
                  aggregate → [END]
                      │
                  fallback → [END]

    Args:
        llm: LLM router for model calls.
        registry: Tool registry for tool discovery and invocation.
        policy_engine: Security policy validation.
        sanitizer: Tool output sanitizer.
        loop_detector: Infinite loop detection.
        audit: Audit logger.
        planner: Pre-created Planner instance. Created on-demand if omitted.

    Returns:
        A compiled LangGraph StateGraph ready for invocation.
    """
    # Create Planner if not provided (in-graph use only needs plan/aggregate)
    if planner is None:
        planner = Planner(llm)

    # Create the graph with our state schema
    graph = StateGraph(AgentState)

    # --- Node factories ---
    # We use closures to inject dependencies into nodes

    async def _supervisor(state: AgentState) -> dict:
        return await supervisor_node(state, llm, registry, planner=planner)

    async def _worker(state: AgentState) -> dict:
        return await worker_node(
            state, llm, registry, policy_engine, sanitizer, loop_detector, audit,
        )

    async def _aggregate(state: AgentState) -> dict:
        # The supervisor handles aggregation when status == "aggregating"
        state["status"] = "aggregating"
        return await supervisor_node(state, llm, registry, planner=planner)

    async def _fallback(state: AgentState) -> dict:
        return await fallback_node(state)

    # --- Add nodes ---
    graph.add_node("supervisor", _supervisor)
    graph.add_node("worker", _worker)
    graph.add_node("aggregate", _aggregate)
    graph.add_node("fallback", _fallback)

    # --- Add edges ---
    # Entry point
    graph.set_entry_point("supervisor")

    # Conditional routing after supervisor
    graph.add_conditional_edges(
        "supervisor",
        route_after_supervisor,
        {
            "worker": "worker",
            "fallback": "fallback",
            "__end__": END,
        },
    )

    # Conditional routing after worker
    graph.add_conditional_edges(
        "worker",
        route_after_worker,
        {
            "worker": "worker",
            "aggregate": "aggregate",
            "fallback": "fallback",
        },
    )

    # After aggregate → end
    graph.add_edge("aggregate", END)

    # After fallback → end
    graph.add_edge("fallback", END)

    # Compile
    compiled = graph.compile()

    logger.info("Agent graph compiled successfully")

    return compiled
