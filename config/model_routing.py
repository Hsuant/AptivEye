"""Model routing rules — maps task types to model tiers.

The LLM Gateway uses this configuration to select the right model
for each task, balancing capability with cost.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ModelTier(str, Enum):
    """Model capability tiers for cost-aware routing."""

    LIGHT = "light"       # Cheap, fast — for parsing, classification, formatting
    STANDARD = "standard" # Balanced — for analysis, matching, reporting
    HEAVY = "heavy"       # Most capable — for code audit, zero-day analysis


@dataclass(frozen=True)
class RoutingRule:
    """A single routing rule mapping a task type to a model tier."""

    task_type: str
    tier: ModelTier
    max_tokens: int
    description: str = ""


# ---------------------------------------------------------------------------
# Routing table
# ---------------------------------------------------------------------------
ROUTING_TABLE: dict[str, RoutingRule] = {
    # Light tasks — cheap models, low token limits
    "tool_result_parsing": RoutingRule(
        "tool_result_parsing", ModelTier.LIGHT, max_tokens=2000,
        description="Parse and structure raw tool output",
    ),
    "json_formatting": RoutingRule(
        "json_formatting", ModelTier.LIGHT, max_tokens=1000,
        description="Format data as JSON",
    ),
    "simple_classification": RoutingRule(
        "simple_classification", ModelTier.LIGHT, max_tokens=500,
        description="Binary or multi-class classification of short inputs",
    ),
    "status_summary": RoutingRule(
        "status_summary", ModelTier.LIGHT, max_tokens=1000,
        description="Summarize current agent state",
    ),

    # Standard tasks — balanced models
    "supervisor_planning": RoutingRule(
        "supervisor_planning", ModelTier.STANDARD, max_tokens=4000,
        description="Decompose user request into sub-tasks",
    ),
    "vulnerability_analysis": RoutingRule(
        "vulnerability_analysis", ModelTier.STANDARD, max_tokens=8000,
        description="Analyze vulnerability scan results",
    ),
    "cve_matching": RoutingRule(
        "cve_matching", ModelTier.STANDARD, max_tokens=4000,
        description="Match discovered services/versions to CVEs",
    ),
    "asset_analysis": RoutingRule(
        "asset_analysis", ModelTier.STANDARD, max_tokens=4000,
        description="Analyze asset discovery results",
    ),
    "report_generation": RoutingRule(
        "report_generation", ModelTier.STANDARD, max_tokens=8000,
        description="Generate security reports",
    ),
    "remediation_advice": RoutingRule(
        "remediation_advice", ModelTier.STANDARD, max_tokens=4000,
        description="Generate remediation recommendations",
    ),

    # Heavy tasks — strongest models for deep reasoning
    "code_security_audit": RoutingRule(
        "code_security_audit", ModelTier.HEAVY, max_tokens=16000,
        description="Deep code-level security analysis",
    ),
    "zero_day_analysis": RoutingRule(
        "zero_day_analysis", ModelTier.HEAVY, max_tokens=32000,
        description="Novel vulnerability research and analysis",
    ),
    "complex_exploit_analysis": RoutingRule(
        "complex_exploit_analysis", ModelTier.HEAVY, max_tokens=8000,
        description="Analyze complex exploit chains",
    ),
}

# Default fallback if task type is unknown
DEFAULT_RULE = RoutingRule(
    "default", ModelTier.STANDARD, max_tokens=4000,
    description="Fallback for unrecognized task types",
)


def get_routing_rule(task_type: str) -> RoutingRule:
    """Look up the routing rule for a given task type."""
    return ROUTING_TABLE.get(task_type, DEFAULT_RULE)


def get_tier_for_task(task_type: str) -> ModelTier:
    """Return the model tier for a task type."""
    return get_routing_rule(task_type).tier


def list_task_types() -> list[str]:
    """Return all known task types."""
    return list(ROUTING_TABLE.keys())
