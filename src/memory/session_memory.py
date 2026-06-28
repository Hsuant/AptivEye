"""Session memory — short-term context for the current task.

Implements a sliding-window conversation buffer with summarization.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class MemoryEntry:
    """A single entry in the conversation memory."""

    role: str       # "user" | "assistant" | "system" | "tool"
    content: str
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


class SessionMemory:
    """Sliding-window conversation memory for a single agent session.

    Keeps the most recent N entries. Older entries are summarized
    to preserve context without overflowing the LLM context window.

    Design:
    - Short-term: last `max_entries` entries kept verbatim
    - Summary: older entries compressed into a single system message
    """

    def __init__(
        self,
        max_entries: int = 40,
        session_id: str = "",
    ) -> None:
        self.max_entries = max_entries
        self.session_id = session_id or f"sess_{int(time.time())}"
        self._entries: deque[MemoryEntry] = deque(maxlen=max_entries)
        self._summary: str = ""
        self._summary_count: int = 0  # Number of entries summarized away

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------
    def add(self, role: str, content: str, **metadata: Any) -> None:
        """Append an entry to the session memory."""
        entry = MemoryEntry(role=role, content=content, metadata=metadata)
        self._entries.append(entry)

        # When buffer fills, summarize the oldest half
        if len(self._entries) >= self.max_entries:
            self._compress()

    def add_user(self, content: str) -> None:
        self.add("user", content)

    def add_assistant(self, content: str) -> None:
        self.add("assistant", content)

    def add_tool_result(self, tool_name: str, content: str) -> None:
        self.add("tool", content, tool_name=tool_name)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------
    def get_messages(self) -> list[dict[str, Any]]:
        """Return messages for LLM consumption.

        If a summary exists, it is prepended as a system message.
        """
        messages: list[dict[str, Any]] = []

        if self._summary:
            messages.append({
                "role": "system",
                "content": f"[Prior context summary — {self._summary_count} earlier messages]:\n{self._summary}",
            })

        for entry in self._entries:
            msg: dict[str, Any] = {"role": entry.role, "content": entry.content}
            if entry.metadata.get("tool_name"):
                msg["name"] = entry.metadata["tool_name"]
            messages.append(msg)

        return messages

    def get_last_n(self, n: int) -> list[MemoryEntry]:
        """Return the most recent N entries."""
        entries = list(self._entries)
        return entries[-n:] if n < len(entries) else entries

    @property
    def entry_count(self) -> int:
        return len(self._entries) + self._summary_count

    @property
    def is_empty(self) -> bool:
        return len(self._entries) == 0 and not self._summary

    # ------------------------------------------------------------------
    # Management
    # ------------------------------------------------------------------
    def clear(self) -> None:
        """Reset the session memory."""
        self._entries.clear()
        self._summary = ""
        self._summary_count = 0

    def snapshot(self) -> dict:
        """Return a serializable snapshot for persistence."""
        return {
            "session_id": self.session_id,
            "entries": [
                {"role": e.role, "content": e.content, "timestamp": e.timestamp, "metadata": e.metadata}
                for e in self._entries
            ],
            "summary": self._summary,
            "summary_count": self._summary_count,
        }

    @classmethod
    def from_snapshot(cls, data: dict) -> "SessionMemory":
        """Restore from a snapshot."""
        mem = cls(session_id=data["session_id"])
        mem._summary = data.get("summary", "")
        mem._summary_count = data.get("summary_count", 0)
        for e in data.get("entries", []):
            mem._entries.append(MemoryEntry(
                role=e["role"],
                content=e["content"],
                timestamp=e.get("timestamp", time.time()),
                metadata=e.get("metadata", {}),
            ))
        return mem

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _compress(self) -> None:
        """Summarize the oldest half of entries and replace with a summary.

        Note: In Phase 0, this is a naive truncation. Phase 4+ should
        use an LLM call for intelligent summarization.
        """
        half = max(len(self._entries) // 2, 1)
        old_entries = [self._entries.popleft() for _ in range(half)]

        # Build a simple concatenation-based summary
        lines: list[str] = []
        for e in old_entries:
            role_prefix = e.role.upper()
            truncated = e.content[:200] + "..." if len(e.content) > 200 else e.content
            lines.append(f"[{role_prefix}] {truncated}")

        new_summary = f"Summarized {len(old_entries)} messages:\n" + "\n".join(lines)
        self._summary = (self._summary + "\n\n" + new_summary).strip() if self._summary else new_summary
        self._summary_count += len(old_entries)

        logger.debug(
            "Session memory compressed: {} entries → summary (total summarized: {})",
            len(old_entries),
            self._summary_count,
        )
