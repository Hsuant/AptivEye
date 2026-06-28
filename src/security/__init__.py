"""Security cross-cutting layer.

All tool calls and agent decisions flow through these components:
- Scope: defines what the agent is authorized to do
- PolicyEngine: validates every tool call before execution
- Sanitizer: cleans tool outputs before they enter LLM context
- LoopDetector: prevents infinite agent loops
- HITL: human-in-the-loop breakpoints for high-risk operations
- Audit: immutable audit trail
- PromptGuard: prompt injection defense
"""

from src.security.scope import AuthorizationScope, OperationType, ScanIntensity
from src.security.policy_engine import SecurityPolicyEngine, ValidationResult
from src.security.sanitizer import OutputSanitizer, SanitizedOutput
from src.security.loop_detector import LoopDetector, LoopDetection
from src.security.hitl import HITLManager, ApprovalRequest, ApprovalStatus
from src.security.audit import AuditLogger, AuditEvent

__all__ = [
    "AuthorizationScope",
    "OperationType",
    "ScanIntensity",
    "SecurityPolicyEngine",
    "ValidationResult",
    "OutputSanitizer",
    "SanitizedOutput",
    "LoopDetector",
    "LoopDetection",
    "HITLManager",
    "ApprovalRequest",
    "ApprovalStatus",
    "AuditLogger",
    "AuditEvent",
]
