"""Tool output sanitizer — cleans outputs before they enter LLM context.

Prevents indirect prompt injection by stripping/escaping:
  - Markdown code blocks that could carry instructions
  - Suspicious prompt-like patterns
  - Raw URLs
  - base64-encoded payloads
  - Shell command patterns
  - Overly long content (truncation with head+tail preservation)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


# Max safe length for content entering LLM context
DEFAULT_MAX_LENGTH = 50_000

# Patterns that suggest prompt injection in tool output
SUSPICIOUS_PATTERNS = [
    # Direct instruction override attempts
    (r"<\|im_start\|>|<\|im_end\|>", "im_marker"),
    (r"\[system\]\(|\[/system\]", "fake_system_tag"),
    (r"ignore\s+(all\s+)?(previous|above)\s+instructions?", "ignore_instructions"),
    (r"your\s+new\s+(system\s+)?prompt\s+is", "new_prompt"),

    # Role manipulation
    (r"you\s+are\s+(?:now\s+)?acting\s+as", "role_change"),
    (r"from\s+now\s+on\s+you\s+(must|will|should)", "behavior_override"),

    # Hidden content markers
    (r"<!--\s*system\s*-->|<!--\s*instruction\s*-->", "html_comment_injection"),
]


@dataclass
class SanitizedOutput:
    """Result of output sanitization."""

    content: str
    truncated: bool = False
    suspicious_patterns: list[str] = field(default_factory=list)
    original_length: int = 0
    final_length: int = 0


class OutputSanitizer:
    """Sanitizes tool outputs before they enter the LLM context window.

    Every tool output must pass through sanitize() before being
    added to the agent's message history.

    Usage::

        sanitizer = OutputSanitizer()
        safe = sanitizer.sanitize(raw_tool_output)
        agent.add_tool_result(tool_name, safe.content)
    """

    def __init__(
        self,
        *,
        max_length: int = DEFAULT_MAX_LENGTH,
        strip_code_blocks: bool = True,
        redact_urls: bool = True,
        detect_base64: bool = True,
        strip_shell_commands: bool = True,
    ) -> None:
        self.max_length = max_length
        self.strip_code_blocks = strip_code_blocks
        self.redact_urls = redact_urls
        self.detect_base64 = detect_base64
        self.strip_shell_commands = strip_shell_commands

    # ------------------------------------------------------------------
    # Main sanitization entry point
    # ------------------------------------------------------------------
    def sanitize(self, output: str) -> SanitizedOutput:
        """Sanitize a raw tool output string.

        Returns a SanitizedOutput with the cleaned content and metadata.
        """
        original_length = len(output)
        content = output
        suspicious: list[str] = []

        # Rule 1: Detect and mark suspicious injection patterns
        for pattern, label in SUSPICIOUS_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                suspicious.append(label)
                logger.warning("Sanitizer: detected pattern '{}' in tool output", label)

        # Rule 2: Strip markdown code blocks (common injection vector)
        if self.strip_code_blocks:
            # Remove fenced code blocks — keep the language marker for context
            content = re.sub(r"```[\s\S]*?```", "[CODE_BLOCK_REMOVED]", content)
            # Remove inline code (but preserve short ones that are likely tech terms)
            content = re.sub(r"`([^`]{100,})`", "[LONG_INLINE_CODE_REMOVED]", content)

        # Rule 3: Redact URLs
        if self.redact_urls:
            content = re.sub(
                r"https?://[^\s<>\"{}|\\^`\[\]]+",
                "[URL_REDACTED]",
                content,
            )

        # Rule 4: Detect and remove potential base64 blobs
        if self.detect_base64:
            content = re.sub(
                r"(?:[A-Za-z0-9+/]{40,}={0,2}(?:\s|$)){3,}",
                "[BASE64_BLOB_REMOVED]",
                content,
            )

        # Rule 5: Strip shell command patterns
        if self.strip_shell_commands:
            dangerous_cmds = [
                r"\brm\s+-rf\b", r"\bdd\s+if=", r"\bmkfs\b",
                r"\bshutdown\b", r"\breboot\b", r"\bwget\s+\S+\s+-O\s+\S+\s*\|\s*sh\b",
                r"\bcurl\s+\S+\s*\|\s*(?:ba)?sh\b", r"\bchmod\s\+[xs]\b",
            ]
            for cmd_pattern in dangerous_cmds:
                if re.search(cmd_pattern, content, re.IGNORECASE):
                    content = re.sub(cmd_pattern, "[DANGEROUS_CMD_REMOVED]", content, flags=re.IGNORECASE)
                    suspicious.append(f"shell_command:{cmd_pattern}")

        # Rule 6: Truncate if too long (preserve head and tail)
        if len(content) > self.max_length:
            head_size = self.max_length // 2
            tail_size = self.max_length // 4
            head = content[:head_size]
            tail = content[-tail_size:]
            content = (
                f"{head}\n\n... [{len(content) - head_size - tail_size} characters truncated] ...\n\n{tail}"
            )
            truncated = True
        else:
            truncated = False

        return SanitizedOutput(
            content=content,
            truncated=truncated,
            suspicious_patterns=suspicious,
            original_length=original_length,
            final_length=len(content),
        )
