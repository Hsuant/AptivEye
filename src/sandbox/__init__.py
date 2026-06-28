"""Sandbox execution environment — Docker container isolation.

Phase 0 provides the interface and a no-op fallback.
Full Docker integration is implemented in Phase 5.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from config.settings import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class SandboxPolicy(str, Enum):
    """Pre-defined sandbox security profiles."""

    DEFAULT = "default"       # Network enabled, read-only code dir
    RESTRICTED = "restricted" # No network, read-only code dir
    READ_ONLY = "read_only"   # No network, entire filesystem read-only


@dataclass
class SandboxResult:
    """Result of sandbox execution."""

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


class SandboxManager:
    """Manages Docker-based sandbox environments.

    Phase 0: No-op implementation (sandbox disabled).
    Phase 5: Full Docker + gVisor integration.
    """

    def __init__(self) -> None:
        settings = get_settings().sandbox
        self._enabled = settings.enabled

        if self._enabled:
            logger.info("Sandbox enabled — image={}", settings.image)
        else:
            logger.info("Sandbox disabled — using no-op mode (Phase 5 for full Docker)")

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def execute(
        self,
        command: str | list[str],
        *,
        policy: SandboxPolicy = SandboxPolicy.RESTRICTED,
        timeout_seconds: int = 300,
        environment: dict[str, str] | None = None,
        workdir: str = "/workspace",
        input_data: str | None = None,
    ) -> SandboxResult:
        """Execute a command inside the sandbox.

        In Phase 0 (sandbox disabled), returns a warning result.
        Full implementation in Phase 5.
        """
        if not self._enabled:
            logger.warning(
                "Sandbox is disabled — command would have run: {}",
                command if isinstance(command, str) else " ".join(command),
            )
            return SandboxResult(
                exit_code=-1,
                stdout="",
                stderr="Sandbox disabled (Phase 5 feature). Enable with SANDBOX_ENABLED=true",
                duration_ms=0,
                timed_out=False,
            )

        # Phase 5: Full Docker implementation
        raise NotImplementedError("Docker sandbox execution — Phase 5")

    async def pull_image(self, image: str) -> bool:
        """Pull a Docker image. Phase 5 feature."""
        if not self._enabled:
            logger.info("Sandbox disabled — skipping image pull for {}", image)
            return False
        raise NotImplementedError("Image pull — Phase 5")

    async def cleanup(self) -> None:
        """Remove stale containers. Phase 5 feature."""
        if self._enabled:
            raise NotImplementedError("Cleanup — Phase 5")
