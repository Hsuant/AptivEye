"""Fallback strategies for agent error recovery.

When the agent encounters unrecoverable errors:
  1. Gracefully degrade functionality
  2. Preserve partial results
  3. Log detailed diagnostics
  4. Return a structured error report
"""

from __future__ import annotations

from typing import Any

from src.agent.state import AgentState
from src.utils.logger import get_logger

logger = get_logger(__name__)


async def fallback_node(state: AgentState) -> dict[str, Any]:
    """Fallback LangGraph node — handles unrecoverable errors.

    Triggered when:
      - Error count exceeds max_errors threshold
      - Infinite loop detected and cannot be resolved
      - Critical tool failure

    Returns:
        State update with partial results and error report.
    """
    worker_results = state.get("worker_results", {})
    error_count = state.get("error_count", 0)
    plan = state.get("plan", [])
    task = state.get("task", "")

    logger.warning(
        "Fallback triggered: {} errors, {} tasks attempted, {} results collected",
        error_count,
        len(plan),
        len(worker_results),
    )

    # Build a fallback report preserving partial results
    completed_tasks = [
        {"title": r.get("title", "Unknown"), "summary": r.get("summary", "No summary")}
        for r in worker_results.values()
        if r.get("status") != "failed"
    ]

    failed_tasks = [
        t.get("title", "Unknown")
        for i, t in enumerate(plan)
        if t.get("id", f"task_{i}") not in worker_results
    ]

    report_lines = [
        "# Assessment Report (Partial — Errors Encountered)",
        "",
        f"**Original Task:** {task}",
        "",
        f"**Status:** Completed with errors ({len(completed_tasks)} tasks succeeded, {len(failed_tasks)} failed)",
        "",
        "## Completed Tasks",
    ]

    for ct in completed_tasks:
        report_lines.append(f"- **{ct['title']}**: {ct['summary'][:200]}")

    if failed_tasks:
        report_lines.append("")
        report_lines.append("## Failed Tasks")
        for ft in failed_tasks:
            report_lines.append(f"- {ft}")

    report_lines.append("")
    report_lines.append("## Error Summary")
    report_lines.append(f"Total errors encountered: {error_count}")
    report_lines.append("")
    report_lines.append("> ℹ️  The agent encountered errors it could not recover from. ")
    report_lines.append("> Review the audit log for detailed diagnostics and retry with adjusted parameters.")

    report = "\n".join(report_lines)

    logger.info("Fallback report generated ({} chars)", len(report))

    return {
        "final_report": report,
        "status": "completed",
    }
