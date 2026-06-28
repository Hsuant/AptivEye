"""Custom exception hierarchy for AptivEye.

All domain exceptions inherit from AptivEyeError, enabling
clean error handling at every architecture layer.
"""

from __future__ import annotations


# =============================================================================
# Base
# =============================================================================
class AptivEyeError(Exception):
    """Base exception for all AptivEye errors."""

    def __init__(self, message: str, *, detail: dict | None = None):
        super().__init__(message)
        self.detail = detail or {}


# =============================================================================
# Configuration errors
# =============================================================================
class ConfigurationError(AptivEyeError):
    """Raised when configuration is invalid or missing."""


# =============================================================================
# LLM Gateway errors (L1)
# =============================================================================
class LLMGatewayError(AptivEyeError):
    """Base for LLM Gateway errors."""


class RateLimitError(LLMGatewayError):
    """LLM provider rate limit exceeded."""


class TokenLimitError(LLMGatewayError):
    """Request exceeds the model's token limit."""


class ModelUnavailableError(LLMGatewayError):
    """Requested model is not available."""


class ProviderAuthError(LLMGatewayError):
    """Authentication with LLM provider failed."""


# =============================================================================
# Tool execution errors (L3)
# =============================================================================
class ToolExecutionError(AptivEyeError):
    """Base for tool execution errors."""

    def __init__(self, message: str, *, tool_name: str = "", detail: dict | None = None):
        super().__init__(message, detail=detail)
        self.tool_name = tool_name


class ToolTimeoutError(ToolExecutionError):
    """Tool execution exceeded timeout."""


class ToolOutputError(ToolExecutionError):
    """Tool produced invalid or unparseable output."""


class ToolNotFoundError(ToolExecutionError):
    """Requested tool is not registered."""


# =============================================================================
# Security errors
# =============================================================================
class SecurityPolicyError(AptivEyeError):
    """Base for security policy violations."""


class ScopeViolationError(SecurityPolicyError):
    """Operation is outside the authorized scope."""


class InjectionDetectedError(SecurityPolicyError):
    """Potential prompt injection detected in input/output."""


class AuthorizationExpiredError(SecurityPolicyError):
    """Authorization scope has expired."""


# =============================================================================
# Sandbox errors (L1)
# =============================================================================
class SandboxError(AptivEyeError):
    """Base for sandbox/container errors."""


class SandboxUnavailableError(SandboxError):
    """Sandbox environment is not available."""


class SandboxExecutionError(SandboxError):
    """Code execution inside sandbox failed."""


# =============================================================================
# Agent loop errors (L4)
# =============================================================================
class AgentLoopError(AptivEyeError):
    """Base for agent execution errors."""


class InfiniteLoopDetectedError(AgentLoopError):
    """Agent is stuck in a repeating pattern."""


class AgentTimeoutError(AgentLoopError):
    """Global agent timeout exceeded."""


class WorkerFailureError(AgentLoopError):
    """A worker agent failed irrecoverably."""


# =============================================================================
# Memory errors (L2)
# =============================================================================
class MemoryError(AptivEyeError):
    """Base for memory/knowledge layer errors."""


class EmbeddingError(MemoryError):
    """Embedding generation failed."""


class VectorStoreError(MemoryError):
    """Vector database operation failed."""
