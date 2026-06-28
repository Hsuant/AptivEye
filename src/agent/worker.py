"""Worker Node — executes a single sub-task using the ReAct pattern.

Each Worker is an independent ReAct loop:
  1. Think: Analyze the sub-task and current state
  2. Act: Decide which tool to call (or ask for help)
  3. Observe: Process tool output
  4. Repeat until done or max iterations

Workers are stateless across sub-tasks (context is scoped per task).
"""

from __future__ import annotations

import json
import time
from typing import Any

from src.agent.state import AgentState
from src.gateway.router import LLMRouter
from src.security.audit import AuditEventType, AuditLogger
from src.security.loop_detector import LoopDetector
from src.security.policy_engine import SecurityPolicyEngine
from src.security.sanitizer import OutputSanitizer
from src.tools.registry import ToolRegistry
from src.utils.logger import get_logger

logger = get_logger(__name__)

WORKER_SYSTEM_PROMPT = """You are a Security Assessment Worker Agent.

## Your Task
Execute the assigned sub-task using available tools. Follow the ReAct pattern:
1. THINK about what you need to do
2. ACT by calling the appropriate tool
3. OBSERVE the tool output
4. DECIDE whether to continue or report results

## Available Tools
You can call tools using function calls. Each tool has a description and parameters.

## Rules
- Execute tools ONE at a time
- Read tool outputs carefully before deciding next steps
- If a tool fails, try an alternative approach
- Report your findings clearly when the task is complete
- Do NOT make up results — only report what tools actually returned
- You operate within a defined AuthorizationScope — stay within bounds

## Output When Done
When you have completed the task, output a JSON summary:
{{
  "status": "completed" | "partial" | "failed",
  "findings": ["finding 1", "finding 2", ...],
  "tools_used": ["tool_a", "tool_b", ...],
  "summary": "Concise summary of what was accomplished and discovered"
}}
"""


async def worker_node(
    state: AgentState,
    llm: LLMRouter,
    registry: ToolRegistry,
    policy_engine: SecurityPolicyEngine,
    sanitizer: OutputSanitizer,
    loop_detector: LoopDetector,
    audit: AuditLogger,
) -> dict[str, Any]:
    """Worker LangGraph node — executes a single sub-task via ReAct loop.

    Returns updated state fields after completing (or failing) the sub-task.
    """
    plan = state.get("plan", [])
    current_index = state.get("current_task_index", 0)

    if current_index >= len(plan):
        logger.error("Worker called with invalid task index {} (plan has {})", current_index, len(plan))
        return {"status": "error", "error_count": state.get("error_count", 0) + 1}

    sub_task = plan[current_index]
    task_id = sub_task.get("id", f"task_{current_index}")
    task_title = sub_task.get("title", "Unknown Task")
    task_desc = sub_task.get("description", "")
    scope = state.get("scope")

    logger.info("Worker starting task [{}/{}]: {}", current_index + 1, len(plan), task_title)

    # Get tool definitions for the LLM
    tool_category = sub_task.get("tool_category")
    tools_for_llm = registry.get_tool_definitions_for_llm(category=tool_category)

    # Build messages for the worker
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": WORKER_SYSTEM_PROMPT},
        {"role": "user", "content": f"## Task: {task_title}\n\n{task_desc}\n\nExecute this task step by step. Call tools as needed. Report your findings when done."},
    ]

    max_iterations = 10
    tools_used: list[str] = []
    findings: list[str] = []
    final_summary = ""

    # --- ReAct Loop ---
    for iteration in range(max_iterations):
        # Check for loops
        logger.debug("Worker iteration {}/{} for task '{}'", iteration + 1, max_iterations, task_id)

        # Call LLM
        try:
            response = await llm.generate(
                messages=messages,
                task_type="vulnerability_analysis",
                temperature=0.0,
                tools=tools_for_llm if tools_for_llm else None,
            )
        except Exception as exc:
            logger.error("LLM call failed in worker: {}", exc)
            audit.log_error("worker_llm_error", str(exc), {"task_id": task_id, "iteration": iteration})
            continue

        # Add assistant message
        messages.append({"role": "assistant", "content": response.content})

        # Check if the LLM wants to call a tool
        if response.tool_calls:
            for tool_call in response.tool_calls:
                tool_name = tool_call.get("name", "")
                tool_args = tool_call.get("arguments", {})

                if isinstance(tool_args, str):
                    try:
                        tool_args = json.loads(tool_args)
                    except json.JSONDecodeError:
                        tool_args = {}

                logger.info("Worker wants to call: {} with args: {}", tool_name, tool_args)

                # --- Security checks ---
                # Check for loops
                loop_result = loop_detector.check(tool_name, tool_args)
                if loop_result.is_looping:
                    logger.warning("Loop detected in worker: {}", loop_result.message)
                    audit.log(AuditEventType.LOOP_DETECTED, detail={
                        "task_id": task_id,
                        "tool_name": tool_name,
                        "repeat_count": loop_result.repeat_count,
                    })
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.get("id", ""),
                        "content": f"ERROR: {loop_result.message} You MUST change your approach.",
                    })
                    continue

                # Policy engine validation
                if scope:
                    validation = policy_engine.validate(tool_name, tool_args, scope)
                    audit.log_policy_decision(
                        tool_name,
                        validation.decision.value,
                        validation.reason,
                        scope_id=scope.scope_id,
                        risk_score=validation.risk_score,
                    )
                    if validation.decision.value == "denied":
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.get("id", ""),
                            "content": f"ERROR: Tool call denied by security policy. Reason: {validation.reason}",
                        })
                        continue

                # --- Execute tool ---
                start_time = time.monotonic()
                try:
                    result = await registry.call(tool_name, **tool_args)
                    tools_used.append(tool_name)
                except KeyError:
                    result = f"Error: Tool '{tool_name}' is not available. Available tools: {[t['function']['name'] for t in tools_for_llm]}"
                except Exception as exc:
                    result = f"Error executing tool '{tool_name}': {exc}"
                    logger.error("Tool execution failed: {}", exc)
                    audit.log_error("tool_execution_error", str(exc), {"tool_name": tool_name, "task_id": task_id})

                duration_ms = (time.monotonic() - start_time) * 1000

                # Sanitize tool output
                result_str = json.dumps(result, ensure_ascii=False, default=str) if not isinstance(result, str) else result
                sanitized = sanitizer.sanitize(result_str)

                # Audit log
                audit.log_tool_call(
                    tool_name=tool_name,
                    params=tool_args,
                    scope_id=scope.scope_id if scope else "",
                    decision="approved",
                    risk_score=0,
                    duration_ms=duration_ms,
                )

                # Add tool result to messages
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.get("id", ""),
                    "content": sanitized.content,
                })

        else:
            # No tool call — check if the worker is reporting completion
            content = response.content

            # Try to parse completion JSON
            try:
                parsed = _parse_json_response(content)
                if parsed.get("status"):
                    findings = parsed.get("findings", [])
                    final_summary = parsed.get("summary", content)
                    logger.info("Worker completed task '{}': status={}, findings={}", task_id, parsed["status"], len(findings))
                    break
            except Exception:
                pass

            # If no JSON but the message looks like a final answer, treat it as completion
            if _looks_like_completion(content, iteration, max_iterations):
                final_summary = content
                logger.info("Worker completed task '{}' with text summary", task_id)
                break

            # Otherwise, prompt the worker to take action
            messages.append({
                "role": "user",
                "content": "Please take the next action: call a tool to gather information, or output your final JSON summary if you have enough data to complete the task.",
            })
    else:
        # Max iterations reached
        logger.warning("Worker reached max iterations ({}) for task '{}'", max_iterations, task_id)
        final_summary = f"Task reached maximum iterations ({max_iterations}) without explicit completion."

    # --- Store results ---
    worker_results = dict(state.get("worker_results", {}))
    worker_results[task_id] = {
        "title": task_title,
        "status": "completed" if findings or final_summary else "incomplete",
        "findings": findings,
        "tools_used": list(set(tools_used)),
        "summary": final_summary,
    }

    iteration_count = state.get("iteration_count", 0) + iteration + 1

    return {
        "worker_results": worker_results,
        "status": "executing",
        "error_count": 0,
        "iteration_count": iteration_count,
    }


def _parse_json_response(content: str) -> dict[str, Any]:
    """Parse JSON from LLM response."""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    import re
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", content)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    match = re.search(r"\{[\s\S]*\}", content)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return {}


def _looks_like_completion(content: str, iteration: int, max_iterations: int) -> bool:
    """Heuristic: does this response look like a final answer?"""
    completion_keywords = [
        "task complete", "task is complete", "completed successfully",
        "final summary", "in conclusion", "here is my report",
        "### summary", "## summary", "## findings",
    ]
    content_lower = content.lower()
    return any(kw in content_lower for kw in completion_keywords)
