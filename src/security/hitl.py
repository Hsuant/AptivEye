"""Human-in-the-Loop (HITL) breakpoint manager.

High-risk operations are paused and require explicit human approval
before execution. This module manages the approval lifecycle.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"


@dataclass
class ApprovalRequest:
    """A request for human approval of a high-risk operation."""

    request_id: str = field(default_factory=lambda: f"hitl_{uuid.uuid4().hex[:12]}")
    tool_name: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    reason: str = ""
    scope_id: str = ""
    timestamp: float = field(default_factory=time.time)
    status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: str = ""
    response_time_ms: float = 0.0

    @property
    def summary(self) -> str:
        """Human-readable summary of the approval request."""
        return (
            f"[{self.request_id}] {self.tool_name}\n"
            f"  Risk: {self.risk_score}/10 | Scope: {self.scope_id}\n"
            f"  Params: {self.params}\n"
            f"  Reason: {self.reason}"
        )


class HITLManager:
    """Manages human-in-the-loop approval for high-risk operations.

    Phase 0: Console-based approval (input in terminal).
    Phase 5: WebSocket-based approval for remote operation.

    Usage::

        hitl = HITLManager()
        request = ApprovalRequest(
            tool_name="execute_exploit",
            params={"target": "192.168.1.5", "exploit": "CVE-2024-..."},
            risk_score=8,
            reason="Active exploitation of a production target",
        )
        decision = await hitl.request_approval(request)
        if decision.status == ApprovalStatus.APPROVED:
            execute(request)
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        timeout_seconds: float = 300.0,  # 5 minutes default
        auto_reject_on_timeout: bool = True,
        approval_callback: Callable[[ApprovalRequest], asyncio.Future] | None = None,
    ) -> None:
        self.enabled = enabled
        self.timeout_seconds = timeout_seconds
        self.auto_reject_on_timeout = auto_reject_on_timeout
        self._approval_callback = approval_callback
        self._history: list[ApprovalRequest] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def request_approval(self, request: ApprovalRequest) -> ApprovalRequest:
        """Request human approval for an operation.

        If HITL is disabled, auto-approves.
        If timeout expires, auto-rejects (configurable).
        """
        if not self.enabled:
            request.status = ApprovalStatus.APPROVED
            request.approved_by = "auto (HITL disabled)"
            self._history.append(request)
            return request

        logger.info("HITL approval requested: {}", request.summary)

        start = time.monotonic()

        try:
            if self._approval_callback:
                # Custom callback (e.g., WebSocket push)
                await asyncio.wait_for(
                    self._approval_callback(request),
                    timeout=self.timeout_seconds,
                )
            else:
                # Default: console-based approval
                await self._console_approval(request)
        except asyncio.TimeoutError:
            if self.auto_reject_on_timeout:
                request.status = ApprovalStatus.TIMED_OUT
                logger.warning("HITL approval timed out for {}", request.request_id)
            else:
                request.status = ApprovalStatus.APPROVED
                request.approved_by = "auto (timeout bypass)"
                logger.warning("HITL timeout bypassed for {}", request.request_id)

        request.response_time_ms = (time.monotonic() - start) * 1000
        self._history.append(request)

        logger.info(
            "HITL decision: {} for {} ({:.0f}ms)",
            request.status.value,
            request.request_id,
            request.response_time_ms,
        )
        return request

    def get_history(self) -> list[ApprovalRequest]:
        """Return all approval requests for the current session."""
        return list(self._history)

    def get_pending(self) -> list[ApprovalRequest]:
        """Return pending approval requests."""
        return [r for r in self._history if r.status == ApprovalStatus.PENDING]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    async def _console_approval(self, request: ApprovalRequest) -> None:
        """Prompt for approval via console input (Phase 0)."""
        import sys

        print("\n" + "=" * 60)
        print("⚠️  HUMAN APPROVAL REQUIRED")
        print("=" * 60)
        print(request.summary)
        print("=" * 60)

        # Use asyncio to read from stdin without blocking
        loop = asyncio.get_event_loop()
        answer = await loop.run_in_executor(
            None,
            lambda: input("Approve? [y/N]: ").strip().lower(),
        )

        if answer in ("y", "yes", "approve"):
            request.status = ApprovalStatus.APPROVED
            request.approved_by = "console_user"
            print("✅ Approved.\n")
        else:
            request.status = ApprovalStatus.REJECTED
            print("❌ Rejected.\n")
