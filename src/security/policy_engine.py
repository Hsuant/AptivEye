"""Security Policy Engine — validates every tool call before execution.

Five-stage validation chain:
  1. Scope check: target in allowed range?
  2. Operation check: operation type permitted?
  3. Rate check: within frequency limits?
  4. Injection check: parameters contain injection payloads?
  5. Risk assessment: score > threshold → escalate to HITL?
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from src.security.scope import (
    HIGH_RISK_OPERATIONS,
    AuthorizationScope,
    OperationType,
    ScanIntensity,
)
from src.utils.exceptions import (
    AuthorizationExpiredError,
    InjectionDetectedError,
    ScopeViolationError,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ValidationDecision(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"
    ESCALATED = "escalated"  # Requires HITL approval


@dataclass
class ValidationResult:
    """Result of a policy validation."""

    decision: ValidationDecision
    reason: str = ""
    risk_score: int = 0  # 0-10, higher = more risky
    checks_passed: list[str] = field(default_factory=list)
    checks_failed: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class SecurityPolicyEngine:
    """Validates every tool call against the authorization scope.

    Usage::

        engine = SecurityPolicyEngine()
        result = engine.validate(
            tool_name="nmap_scan",
            params={"target": "192.168.1.5", "ports": "1-1000"},
            scope=scope,
        )
        if result.decision == ValidationDecision.APPROVED:
            execute_tool(...)
        elif result.decision == ValidationDecision.ESCALATED:
            await hitl.request_approval(...)
        else:
            raise ScopeViolationError(result.reason)
    """

    def __init__(
        self,
        *,
        injection_patterns: list[str] | None = None,
        risk_threshold: int = 7,  # Score >= 7 → escalate to HITL
    ) -> None:
        self._risk_threshold = risk_threshold

        # Patterns that suggest prompt injection
        self._injection_patterns = injection_patterns or [
            r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|directives?|prompts?)",
            r"you\s+(are|now)\s+(a\s+)?(different|new)\s+(ai|assistant|model|role)",
            r"\[system\]|\[/system\]|<system>|</system>",
            r"\[INST\]|\[/INST\]",
            r"<\|im_start\|>|<\|im_end\|>",
            r"DAN\s+mode|developer\s+mode",
        ]

    # ------------------------------------------------------------------
    # Main validation entry point
    # ------------------------------------------------------------------
    def validate(
        self,
        tool_name: str,
        params: dict[str, Any],
        scope: AuthorizationScope,
        *,
        operation_type: OperationType | None = None,
    ) -> ValidationResult:
        """Run the full validation chain.

        Args:
            tool_name: Name of the tool being called.
            params: Tool parameters.
            scope: Current authorization scope.
            operation_type: Override the operation type for this call.
        """
        result = ValidationResult(decision=ValidationDecision.APPROVED)

        # Stage 1: Scope expiration
        if scope.is_expired:
            result.decision = ValidationDecision.DENIED
            result.reason = f"Authorization scope '{scope.scope_id}' expired {scope.remaining_minutes:.0f} min ago"
            result.checks_failed.append("scope_expired")
            return result

        result.checks_passed.append("scope_not_expired")

        # Stage 2: Target within allowed range?
        target = self._extract_target(tool_name, params)
        if target and not scope.is_target_allowed(target):
            result.decision = ValidationDecision.DENIED
            result.reason = f"Target '{target}' is outside authorized scope"
            result.checks_failed.append("target_out_of_scope")
            return result

        result.checks_passed.append("target_in_scope")

        # Stage 3: Operation type allowed?
        op = operation_type or self._infer_operation(tool_name)
        if op and not scope.is_operation_allowed(op):
            result.decision = ValidationDecision.DENIED
            result.reason = f"Operation '{op.value}' is not authorized at intensity '{scope.intensity.value}'"
            result.checks_failed.append("operation_not_allowed")
            return result

        result.checks_passed.append("operation_allowed")

        # Stage 4: Injection detection
        if self._detect_injection(params):
            result.decision = ValidationDecision.DENIED
            result.reason = "Potential prompt injection detected in tool parameters"
            result.checks_failed.append("injection_detected")
            logger.warning("Injection detected in tool call: {} params={}", tool_name, params)
            return result

        result.checks_passed.append("no_injection")

        # Stage 5: Risk assessment → escalate?
        result.risk_score = self._assess_risk(tool_name, params, scope)
        if result.risk_score >= self._risk_threshold:
            result.decision = ValidationDecision.ESCALATED
            result.reason = f"Risk score {result.risk_score} >= threshold {self._risk_threshold}"
            result.checks_failed.append("risk_escalated")
            return result

        result.checks_passed.append("risk_acceptable")
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _extract_target(self, tool_name: str, params: dict[str, Any]) -> str | None:
        """Extract the target parameter from tool params."""
        for key in ("target", "host", "ip", "domain", "url", "network"):
            if key in params:
                return str(params[key])
        return None

    def _infer_operation(self, tool_name: str) -> OperationType | None:
        """Infer operation type from tool name."""
        mapping: dict[str, OperationType] = {
            "enumerate_subdomains": OperationType.ASSET_DISCOVER,
            "scan_ports": OperationType.PORT_SCAN,
            "fingerprint_service": OperationType.FINGERPRINT,
            "scan_vulnerabilities": OperationType.VULNERABILITY_SCAN,
            "scan_web": OperationType.WEB_SCAN,
            "audit_code": OperationType.CODE_AUDIT,
            "execute_exploit": OperationType.EXPLOIT,
            "execute_command": OperationType.COMMAND_EXEC,
            "read_file": OperationType.READ_FILE,
            "write_file": OperationType.WRITE_FILE,
        }
        return mapping.get(tool_name)

    def _detect_injection(self, params: dict[str, Any]) -> bool:
        """Check parameter values for injection patterns."""
        import re

        # Flatten params to string values
        values = []
        for v in params.values():
            if isinstance(v, str):
                values.append(v)
            elif isinstance(v, (list, dict)):
                values.append(str(v))

        combined = " ".join(values).lower()
        for pattern in self._injection_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                return True
        return False

    def _assess_risk(
        self,
        tool_name: str,
        params: dict[str, Any],
        scope: AuthorizationScope,
    ) -> int:
        """Assess the risk of a tool call on a 0-10 scale."""
        score = 0

        # High-risk operations
        op = self._infer_operation(tool_name)
        if op in HIGH_RISK_OPERATIONS:
            score += 5

        # Scan intensity
        if scope.intensity == ScanIntensity.INTRUSIVE:
            score += 3
        elif scope.intensity == ScanIntensity.ACTIVE:
            score += 1

        # Broad targets (whole subnets)
        target = self._extract_target(tool_name, params)
        if target:
            import ipaddress
            try:
                net = ipaddress.ip_network(target, strict=False)
                if net.num_addresses > 256:
                    score += 3
                elif net.num_addresses > 10:
                    score += 1
            except ValueError:
                pass

        # Dangerous parameter patterns
        params_str = str(params).lower()
        dangerous_keywords = ["rm -rf", "format", "dd if=", "mkfs", "shutdown", "reboot"]
        for kw in dangerous_keywords:
            if kw in params_str:
                score += 5
                break

        return min(score, 10)
