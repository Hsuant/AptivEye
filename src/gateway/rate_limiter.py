"""Simple token-bucket rate limiter for LLM API calls."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class RateLimiter:
    """Token-bucket rate limiter.

    Limits the number of calls per time window. Thread-safe via asyncio locks.
    """

    max_calls: int = 10          # Max calls per window
    window_seconds: float = 60.0  # Time window in seconds
    _timestamps: list[float] = field(default_factory=list)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def acquire(self) -> float:
        """Wait until a call is allowed. Returns wait time in seconds."""
        async with self._lock:
            now = time.monotonic()
            # Remove timestamps outside the window
            cutoff = now - self.window_seconds
            self._timestamps = [t for t in self._timestamps if t > cutoff]

            if len(self._timestamps) < self.max_calls:
                self._timestamps.append(now)
                return 0.0

            # Must wait until the oldest timestamp exits the window
            wait_time = self._timestamps[0] - cutoff + 0.1  # + small buffer
            self._timestamps.append(now + wait_time)
            return wait_time

    @property
    def current_count(self) -> int:
        """Number of calls in the current window."""
        cutoff = time.monotonic() - self.window_seconds
        return sum(1 for t in self._timestamps if t > cutoff)
