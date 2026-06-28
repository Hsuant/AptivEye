"""Audit logger — immutable, timestamped trail of every security-relevant event.

All tool calls, policy decisions, and HITL approvals are recorded.
Audit logs are append-only and written to the configured path.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from config.settings import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AuditEventType(str, Enum):
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    POLICY_DECISION = "policy_decision"
    HITL_APPROVAL = "hitl_approval"
    AGENT_DECISION = "agent_decision"
    SCOPE_CREATED = "scope_created"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    ERROR = "error"
    INJECTION_DETECTED = "injection_detected"
    LOOP_DETECTED = "loop_detected"


@dataclass
class AuditEvent:
    """A single auditable event."""

    event_type: AuditEventType
    event_id: str = field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    session_id: str = ""
    scope_id: str = ""
    timestamp: float = field(default_factory=time.time)
    detail: dict[str, Any] = field(default_factory=dict)
    trace_id: str = ""


class AuditLogger:
    """Append-only audit trail for security-relevant events.

    Usage::

        audit = AuditLogger(session_id="sess_001")
        audit.log(AuditEvent(
            event_type=AuditEventType.TOOL_CALL,
            detail={"tool_name": "nmap_scan", "params": {...}},
        ))
    """

    def __init__(
        self,
        *,
        session_id: str = "",
        log_path: str | None = None,
    ) -> None:
        settings = get_settings().security
        self.session_id = session_id or f"sess_{uuid.uuid4().hex[:12]}"
        self._log_path = Path(log_path or settings.audit_log_path)
        self._log_path.mkdir(parents=True, exist_ok=True)
        self._events: list[AuditEvent] = []

        # File handle for append-only writes
        self._file_path = self._log_path / f"audit_{self.session_id}.jsonl"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def log(self, event: AuditEvent) -> None:
        """Record an audit event (in-memory + append to file)."""
        event.session_id = self.session_id
        self._events.append(event)

        # Write immediately to file (append-only, crash-safe)
        try:
            with open(self._file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(self._to_dict(event), ensure_ascii=False) + "\n")
        except OSError as exc:
            logger.error("Failed to write audit event to {}: {}", self._file_path, exc)

    def log_tool_call(
        self,
        tool_name: str,
        params: dict[str, Any],
        *,
        scope_id: str = "",
        decision: str = "approved",
        risk_score: int = 0,
        duration_ms: float = 0,
        token_used: int = 0,
    ) -> None:
        """Convenience method for logging a tool call."""
        self.log(AuditEvent(
            event_type=AuditEventType.TOOL_CALL,
            scope_id=scope_id,
            detail={
                "tool_name": tool_name,
                "params": params,
                "decision": decision,
                "risk_score": risk_score,
                "duration_ms": duration_ms,
                "token_used": token_used,
            },
        ))

    def log_policy_decision(
        self,
        tool_name: str,
        decision: str,
        reason: str,
        *,
        scope_id: str = "",
        risk_score: int = 0,
    ) -> None:
        """Convenience method for logging a policy decision."""
        self.log(AuditEvent(
            event_type=AuditEventType.POLICY_DECISION,
            scope_id=scope_id,
            detail={
                "tool_name": tool_name,
                "decision": decision,
                "reason": reason,
                "risk_score": risk_score,
            },
        ))

    def log_error(self, error_type: str, message: str, detail: dict | None = None) -> None:
        """Convenience method for logging errors."""
        self.log(AuditEvent(
            event_type=AuditEventType.ERROR,
            detail={
                "error_type": error_type,
                "message": message,
                **(detail or {}),
            },
        ))

    def get_events(self, event_type: AuditEventType | None = None) -> list[AuditEvent]:
        """Return filtered events from the in-memory log."""
        if event_type is None:
            return list(self._events)
        return [e for e in self._events if e.event_type == event_type]

    def count(self) -> int:
        return len(self._events)

    def summary(self) -> dict:
        """Return a summary of audit events."""
        by_type: dict[str, int] = {}
        for e in self._events:
            by_type[e.event_type.value] = by_type.get(e.event_type.value, 0) + 1

        tool_calls = [e for e in self._events if e.event_type == AuditEventType.TOOL_CALL]
        denied = [e for e in tool_calls if e.detail.get("decision") == "denied"]

        return {
            "session_id": self.session_id,
            "total_events": len(self._events),
            "by_type": by_type,
            "tool_calls": len(tool_calls),
            "denied_calls": len(denied),
            "audit_file": str(self._file_path),
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    @staticmethod
    def _to_dict(event: AuditEvent) -> dict:
        return {
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "session_id": event.session_id,
            "scope_id": event.scope_id,
            "timestamp": event.timestamp,
            "detail": event.detail,
            "trace_id": event.trace_id,
        }
