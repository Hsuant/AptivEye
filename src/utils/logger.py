"""Structured logging via loguru with OpenTelemetry integration hooks."""

from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger

from config.settings import get_settings


def setup_logging() -> None:
    """Configure loguru for AptivEye.

    - Console sink with colorized output (stderr)
    - File sink with rotation (when configured)
    - OpenTelemetry trace_id injection (when available)

    Called once at application startup.
    """
    settings = get_settings()

    # Remove default handler
    logger.remove()

    # Console sink — pretty, colorized
    logger.add(
        sys.stderr,
        level=settings.logging.log_level,
        format=(
            "<green>{time:HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level>"
        ),
        colorize=True,
        backtrace=True,
        diagnose=True,
    )

    # File sink — JSON-structured for log aggregation
    log_file = Path(settings.logging.log_file)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    logger.add(
        log_file,
        level="DEBUG",
        format=(
            '{{"time": "{time:YYYY-MM-DDTHH:mm:ss.SSSZ}", '
            '"level": "{level}", '
            '"name": "{name}", '
            '"function": "{function}", '
            '"line": {line}, '
            '"message": "{message}"}}'
        ),
        rotation="10 MB",
        retention="7 days",
        compression="gz",
        enqueue=True,  # Thread-safe, non-blocking writes
    )

    logger.info("Logging configured — level={}", settings.logging.log_level)


def get_logger(name: str):
    """Return a logger bound with the given module name."""
    return logger.bind(name=name)


# Auto-initialize on import — safe because loguru handles re-configuration
__all__ = ["logger", "setup_logging", "get_logger"]
