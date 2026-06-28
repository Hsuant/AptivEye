"""L4 Orchestration & Decision layer — Hierarchical ReAct Agent Engine.

Exports:
  - build_agent_graph: assembles the LangGraph state graph
  - AgentState: central state type
  - AgentRunner: convenience wrapper for running the agent
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from langgraph.graph import StateGraph

from src.agent.graph import build_agent_graph
from src.agent.state import AgentState
from src.gateway.router import LLMRouter
from src.security.audit import AuditEventType, AuditLogger
from src.security.loop_detector import LoopDetector
from src.security.policy_engine import SecurityPolicyEngine
from src.security.sanitizer import OutputSanitizer
from src.security.scope import AuthorizationScope
from src.tools.registry import ToolRegistry
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AgentRunner:
    """Convenience wrapper for running the agent graph.

    Handles initialization, session management, and cleanup.

    Usage::

        runner = AgentRunner(llm_router, tool_registry)
        result = await runner.run(
            task="Scan 192.168.1.0/24 for open ports and vulnerabilities",
            scope=AuthorizationScope(
                allowed_targets=["192.168.1.0/24"],
                intensity=ScanIntensity.ACTIVE,
            ),
        )
        print(result["final_report"])
    """

    def __init__(
        self,
        llm: LLMRouter,
        registry: ToolRegistry,
        *,
        policy_engine: SecurityPolicyEngine | None = None,
        sanitizer: OutputSanitizer | None = None,
        loop_detector: LoopDetector | None = None,
    ) -> None:
        self._llm = llm
        self._registry = registry

        # Create default security components if not provided
        self._policy_engine = policy_engine or SecurityPolicyEngine()
        self._sanitizer = sanitizer or OutputSanitizer()
        self._loop_detector = loop_detector or LoopDetector()

        # Graph is built lazily because audit logger needs a session
        self._graph: StateGraph | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def run(
        self,
        task: str,
        *,
        scope: AuthorizationScope | None = None,
        session_id: str | None = None,
        max_errors: int = 3,
    ) -> dict[str, Any]:
        """Run the agent to completion.

        Args:
            task: The security assessment task description.
            scope: Authorization boundaries. If None, a permissive scope is used.
            session_id: Session identifier (auto-generated if omitted).
            max_errors: Maximum errors before fallback.

        Returns:
            Final state dict with 'final_report', 'worker_results', etc.
        """
        session_id = session_id or f"sess_{uuid.uuid4().hex[:12]}"
        audit = AuditLogger(session_id=session_id)

        if scope is None:
            scope = AuthorizationScope(
                requires_human_approval=False,
                notes="Default permissive scope — restrict in production",
            )

        # Log session start
        audit.log(AuditEventType.SESSION_START, detail={
            "task": task,
            "scope": scope.to_dict(),
            "tools_available": self._registry.tool_count,
        })

        # Build graph with this session's audit logger
        graph = build_agent_graph(
            llm=self._llm,
            registry=self._registry,
            policy_engine=self._policy_engine,
            sanitizer=self._sanitizer,
            loop_detector=self._loop_detector,
            audit=audit,
        )

        # Prepare initial state
        initial_state: AgentState = {
            "messages": [],
            "task": task,
            "scope": scope,
            "plan": [],
            "plan_rationale": "",
            "current_task_index": 0,
            "worker_results": {},
            "worker_context": {},
            "status": "planning",
            "error_count": 0,
            "max_errors": max_errors,
            "iteration_count": 0,
            "session_id": session_id,
            "final_report": "",
        }

        logger.info("Starting agent run — session={}, task={}", session_id, task[:100])

        try:
            # Run the graph until completion
            final_state = await graph.ainvoke(initial_state)
        except Exception as exc:
            logger.error("Agent graph execution failed: {}", exc)
            audit.log_error("graph_execution_failed", str(exc))
            final_state = {
                **initial_state,
                "final_report": f"# Agent Execution Failed\n\n**Error:** {exc}\n\nCheck audit log for details.",
                "status": "completed",
            }

        # Log session end
        audit.log(AuditEventType.SESSION_END, detail={
            "status": final_state.get("status"),
            "iteration_count": final_state.get("iteration_count", 0),
            "results_count": len(final_state.get("worker_results", {})),
            "audit_events": audit.count(),
        })

        logger.info(
            "Agent run complete — status={}, iterations={}, results={}",
            final_state.get("status"),
            final_state.get("iteration_count", 0),
            len(final_state.get("worker_results", {})),
        )

        # Include audit summary in the result
        final_state["audit_summary"] = audit.summary()
        final_state["llm_usage"] = self._llm.usage_summary()

        return dict(final_state)

    async def run_simple(self, task: str) -> str:
        """Run a simple task and return just the final report string.

        Convenience method for CLI usage.
        """
        result = await self.run(task)
        return result.get("final_report", "No report generated.")


from src.agent.fofa_planner import FofaQueryPlanner

__all__ = ["AgentRunner", "AgentState", "build_agent_graph", "FofaQueryPlanner"]
