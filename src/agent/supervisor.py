"""Supervisor Node — decomposes the user's task into sub-tasks.

The Supervisor is the "orchestrator" of the agent system. It:
  1. Analyzes the user's security assessment request
  2. Decomposes it into discrete sub-tasks
  3. Assigns priorities and expected tools to each sub-task
  4. Aggregates worker results into a final report

In Phase 0, the Supervisor uses a simplified planning approach.
Phase 2+ introduces LLM-driven intelligent planning.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from config.model_routing import get_routing_rule
from src.agent.state import AgentState
from src.gateway.router import LLMRouter
from src.security.prompt_guard import PromptGuard
from src.tools.registry import ToolRegistry
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Supervisor system prompt
SUPERVISOR_SYSTEM_PROMPT = """You are a Security Assessment Supervisor Agent.

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


SUPERVISOR_AGGREGATION_PROMPT = """You are a Security Assessment Supervisor.

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


async def supervisor_node(
    state: AgentState,
    llm: LLMRouter,
    registry: ToolRegistry,
) -> dict[str, Any]:
    """Supervisor LangGraph node.

    Analyzes the task and produces a plan of sub-tasks.
    If all sub-tasks are complete, aggregates results into a final report.
    """
    status = state.get("status", "planning")

    if status == "aggregating":
        return await _aggregate(state, llm)

    # --- Planning phase ---
    task = state.get("task", "")
    messages = state.get("messages", [])

    logger.info("Supervisor planning for task: {}", task[:100])

    # Build the planning prompt
    categories = registry.get_categories()
    categories_str = "\n".join(f"- {c}" for c in categories) if categories else "- general"

    system_prompt = SUPERVISOR_SYSTEM_PROMPT.format(tool_categories=categories_str)

    plan_messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Plan the following security assessment task:\n\n{task}"},
    ]

    try:
        response = await llm.generate(
            messages=plan_messages,
            task_type="supervisor_planning",
            temperature=0.0,
        )

        # Parse JSON from the response
        plan_data = _parse_json_response(response.content)

        rationale = plan_data.get("rationale", "No rationale provided")
        sub_tasks = plan_data.get("sub_tasks", [])

        # If LLM didn't produce structured tasks, create a simple default
        if not sub_tasks:
            logger.warning("Supervisor produced no sub-tasks — using default plan")
            sub_tasks = [_default_sub_task(task)]
            rationale = "Default single-task plan (LLM did not produce structured output)"

        logger.info("Supervisor plan: {} sub-tasks — {}", len(sub_tasks), rationale[:80])

        return {
            "plan": sub_tasks,
            "plan_rationale": rationale,
            "current_task_index": 0,
            "worker_results": {},
            "status": "executing",
            "error_count": 0,
            "iteration_count": 0,
        }

    except Exception as exc:
        logger.error("Supervisor planning failed: {}", exc)
        # Fall back to a simple single-task plan
        sub_tasks = [_default_sub_task(task)]
        return {
            "plan": sub_tasks,
            "plan_rationale": f"Fallback plan due to planning error: {exc}",
            "current_task_index": 0,
            "worker_results": {},
            "status": "executing",
            "error_count": 0,
            "iteration_count": 0,
        }


async def _aggregate(state: AgentState, llm: LLMRouter) -> dict[str, Any]:
    """Aggregate worker results into a final report."""
    task = state.get("task", "")
    worker_results = state.get("worker_results", {})

    logger.info("Supervisor aggregating {} worker results", len(worker_results))

    # Format worker results for the prompt
    results_str = json.dumps(worker_results, indent=2, ensure_ascii=False)

    prompt = SUPERVISOR_AGGREGATION_PROMPT.format(
        task=task,
        worker_results=results_str,
    )

    try:
        response = await llm.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="report_generation",
            temperature=0.0,
        )
        report = response.content
    except Exception as exc:
        logger.error("Aggregation failed: {}", exc)
        report = f"## Report Generation Failed\n\nError: {exc}\n\n## Raw Results\n\n```json\n{results_str}\n```"

    return {
        "final_report": report,
        "status": "completed",
    }


def _parse_json_response(content: str) -> dict[str, Any]:
    """Parse JSON from LLM response, handling markdown code blocks."""
    # Try direct parse first
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Try extracting from markdown code blocks
    import re
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", content)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Try to find JSON-like structure with braces
    match = re.search(r"\{[\s\S]*\}", content)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    # Give up
    logger.warning("Failed to parse JSON from response: {}...", content[:200])
    return {}


def _default_sub_task(task: str) -> dict[str, Any]:
    """Create a default single sub-task when planning fails."""
    return {
        "id": f"task_{uuid.uuid4().hex[:8]}",
        "title": "Execute Assessment",
        "description": task,
        "tool_category": "general",
        "priority": "high",
    }
