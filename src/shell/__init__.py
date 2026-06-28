"""Interactive shell (REPL) for AptivEye security assessments.

Provides a prompt_toolkit-based interactive CLI with command history,
auto-completion, session state management, and Rich-formatted output.

Exports:
    - InteractiveShell: main REPL engine
    - ShellSession: session state container
"""

from __future__ import annotations

from src.shell.session import ShellSession
from src.shell.engine import InteractiveShell

__all__ = ["InteractiveShell", "ShellSession"]
