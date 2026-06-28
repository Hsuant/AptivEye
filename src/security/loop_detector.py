"""Loop detector — prevents agent from getting stuck in infinite loops.

Detects when the agent repeats the same tool call with the same parameters
multiple times in a sliding window.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from config.settings import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class LoopDetection:
    """Result of loop detection check."""

    is_looping: bool
    repeated_tool: str = ""
    repeat_count: int = 0
    message: str = ""


class LoopDetector:
    """Sliding-window detector for repeated tool calls.

    Triggers when the same tool is called with the same canonical
    parameters N times within the window.

    Usage::

        detector = LoopDetector(max_repeats=3, window_size=10)
        result = detector.check("nmap_scan", {"target": "192.168.1.1"})
        if result.is_looping:
            raise InfiniteLoopDetectedError(result.message)
    """

    def __init__(
        self,
        max_repeats: int | None = None,
        window_size: int = 10,
    ) -> None:
        settings = get_settings().security
        self.max_repeats = max_repeats or settings.loop_detection_threshold
        self.window_size = window_size
        self._history: deque[str] = deque(maxlen=window_size)
        self._total_calls: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def check(self, tool_name: str, params: dict[str, Any]) -> LoopDetection:
        """Check if calling this tool would create a loop.

        Args:
            tool_name: Name of the tool being called.
            params: Tool parameters.

        Returns:
            LoopDetection with is_looping=True if a loop is detected.
        """
        self._total_calls += 1
        fingerprint = self._make_fingerprint(tool_name, params)
        self._history.append(fingerprint)

        # Count consecutive occurrences of the same fingerprint
        consecutives = 0
        for fp in reversed(self._history):
            if fp == fingerprint:
                consecutives += 1
            else:
                break

        if consecutives >= self.max_repeats:
            logger.warning(
                "Loop detected: tool='{}' repeated {} times consecutively (total calls: {})",
                tool_name,
                consecutives,
                self._total_calls,
            )
            return LoopDetection(
                is_looping=True,
                repeated_tool=tool_name,
                repeat_count=consecutives,
                message=(
                    f"Loop detected: '{tool_name}' called {consecutives} times "
                    f"with the same parameters. The agent may be stuck. "
                    f"Consider changing strategy or skipping this sub-task."
                ),
            )

        return LoopDetection(is_looping=False)

    def reset(self) -> None:
        """Clear call history."""
        self._history.clear()
        self._total_calls = 0

    @property
    def call_count(self) -> int:
        return self._total_calls

    @property
    def unique_calls(self) -> int:
        return len(set(self._history))

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    @staticmethod
    def _make_fingerprint(tool_name: str, params: dict[str, Any]) -> str:
        """Create a canonical fingerprint for a tool call."""
        # Sort keys for deterministic hashing
        canonical = json.dumps(params, sort_keys=True, default=str)
        raw = f"{tool_name}:{canonical}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
