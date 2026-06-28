"""Session state and command definitions for the interactive shell."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Optional

from prompt_toolkit.completion import NestedCompleter, WordCompleter

from src.security.scope import ScanIntensity

# ── Session State ────────────────────────────────────────────────────────


@dataclass
class ShellSession:
    """Mutable session state for the interactive shell.

    Persisted across commands within a single shell session.
    Not persisted to disk between shell invocations.
    """

    session_id: str = field(default_factory=lambda: f"sess_{uuid.uuid4().hex[:12]}")
    target: str = ""
    intensity: ScanIntensity = ScanIntensity.PASSIVE
    requires_approval: bool = True

    # Accumulated assessment reports
    reports: list[dict[str, Any]] = field(default_factory=list)

    # In-memory command log for the "history" command
    command_history: list[str] = field(default_factory=list)

    @property
    def run_count(self) -> int:
        return len(self.reports)

    @property
    def last_report(self) -> dict[str, Any] | None:
        return self.reports[-1] if self.reports else None

    @property
    def prompt_context(self) -> str:
        """Build a compact context string for the shell prompt."""
        parts: list[str] = []
        if self.target:
            parts.append(f"target={self.target}")
        if self.intensity != ScanIntensity.PASSIVE:
            parts.append(f"intensity={self.intensity.value}")
        if not self.requires_approval:
            parts.append("no-approval")
        if parts:
            return f" [{', '.join(parts)}]"
        return ""

    def add_command(self, line: str) -> None:
        """Record a command in the session history."""
        self.command_history.append(line)

    def add_report(self, task: str, report_data: dict[str, Any]) -> None:
        """Store an assessment report with metadata."""
        self.reports.append({
            "timestamp": time.time(),
            "task": task,
            "report": report_data.get("final_report", ""),
            "status": report_data.get("status", "unknown"),
            "stats": {
                "iterations": report_data.get("iteration_count", 0),
                "llm_calls": report_data.get("llm_usage", {}).get("calls", 0),
                "tokens": report_data.get("llm_usage", {}).get("total_tokens", 0),
                "cost": report_data.get("llm_usage", {}).get("cost_usd", 0.0),
                "audit_events": report_data.get("audit_summary", {}).get("total_events", 0),
                "denied_calls": report_data.get("audit_summary", {}).get("denied_calls", 0),
            },
        })


# ── Command Registry ─────────────────────────────────────────────────────

CommandHandler = Callable[[list[str]], Coroutine[Any, Any, None]]


@dataclass
class CommandMeta:
    """Metadata and handler for a shell command."""

    name: str
    handler: str  # method name on InteractiveShell
    help_text: str
    usage: str = ""
    category: str = "general"  # "session" | "assessment" | "info" | "general"


# Populated after InteractiveShell is defined (see engine.py)
COMMANDS: dict[str, CommandMeta] = {}


def register_commands() -> dict[str, CommandMeta]:
    """Build the command registry.

    Returns a dict mapping command name to CommandMeta.
    Called once at shell startup.
    """
    return {
        # ── Assessment ──
        "run": CommandMeta(
            name="run",
            handler="_cmd_run",
            help_text="Run a security assessment task.",
            usage='run "task description" [-t target] [-i intensity] [--no-approval]',
            category="assessment",
        ),
        "call": CommandMeta(
            name="call",
            handler="_cmd_call",
            help_text="Invoke a single tool directly.",
            usage="call <tool_name> [--params JSON] [-d domain] [-H host] [--ports ...] [-t target]",
            category="assessment",
        ),
        # ── Session ──
        "set": CommandMeta(
            name="set",
            handler="_cmd_set",
            help_text="Set session parameters: target, intensity, approval.",
            usage="set target <value> | set intensity <level> | set approval on|off",
            category="session",
        ),
        "show": CommandMeta(
            name="show",
            handler="_cmd_show",
            help_text="Show session state, report, or execution statistics.",
            usage="show state | show report [N] | show summary",
            category="session",
        ),
        "save": CommandMeta(
            name="save",
            handler="_cmd_save",
            help_text="Save the most recent report to a file.",
            usage="save [filepath]",
            category="session",
        ),
        "history": CommandMeta(
            name="history",
            handler="_cmd_history",
            help_text="Show in-session command history.",
            usage="history",
            category="session",
        ),
        # ── Information ──
        "tools": CommandMeta(
            name="tools",
            handler="_cmd_tools",
            help_text="List all registered security tools.",
            usage="tools [category]",
            category="info",
        ),
        "status": CommandMeta(
            name="status",
            handler="_cmd_status",
            help_text="Show system status and configuration.",
            usage="status",
            category="info",
        ),
        "health": CommandMeta(
            name="health",
            handler="_cmd_health",
            help_text="Quick connectivity check for LLM providers.",
            usage="health",
            category="info",
        ),
        "help": CommandMeta(
            name="help",
            handler="_cmd_help",
            help_text="Show available commands or detailed help for a command.",
            usage="help [command]",
            category="general",
        ),
        # ── Exit ──
        "quit": CommandMeta(
            name="quit",
            handler="_cmd_quit",
            help_text="Exit the shell (alias: exit, Ctrl+D).",
            usage="quit",
            category="general",
        ),
        "exit": CommandMeta(
            name="exit",
            handler="_cmd_quit",
            help_text="Exit the shell (alias: quit).",
            usage="exit",
            category="general",
        ),
    }


# ── Completer ────────────────────────────────────────────────────────────

# Intenisty values for tab completion
INTENSITY_COMPLETER = WordCompleter(
    ["passive", "active", "intrusive"],
    ignore_case=True,
    sentence=True,
)

# Approval toggle values
APPROVAL_COMPLETER = WordCompleter(
    ["on", "off"],
    ignore_case=True,
    sentence=True,
)

# Show sub-commands
SHOW_COMPLETER = WordCompleter(
    ["state", "report", "summary"],
    ignore_case=True,
    sentence=True,
)

# Set sub-commands
SET_COMPLETER = WordCompleter(
    ["target", "intensity", "approval"],
    ignore_case=True,
    sentence=True,
)


class AptivEyeCompleter:
    """Prompt-toolkit completer with dynamic tool name/category support.

    Wraps NestedCompleter and allows 'tools' and 'call' sub-completions
    to be refreshed when the tool registry is initialized.
    """

    def __init__(self) -> None:
        self._tool_categories: set[str] = set()
        self._tool_names: set[str] = set()
        self._nested = self._build_nested()

    def _build_nested(self) -> NestedCompleter:
        """Build the NestedCompleter from the current state."""
        categories: dict[str, WordCompleter | None] = {}
        if self._tool_categories:
            categories = {
                cat: None for cat in sorted(self._tool_categories)
            }

        return NestedCompleter.from_nested_dict({
            "run": None,  # free-form task description
            "call": WordCompleter(
                sorted(self._tool_names) if self._tool_names else [],
                ignore_case=True,
                sentence=True,
            ),
            "set": {
                "target": None,
                "intensity": INTENSITY_COMPLETER,
                "approval": APPROVAL_COMPLETER,
            },
            "show": SHOW_COMPLETER,
            "tools": WordCompleter(
                sorted(self._tool_categories) if self._tool_categories else [],
                ignore_case=True,
                sentence=True,
            ),
            "save": None,
            "history": None,
            "status": None,
            "health": None,
            "help": None,
            "quit": None,
            "exit": None,
        })

    def update_from_registry(self, categories: set[str], tool_names: set[str]) -> None:
        """Refresh tool categories and names from the registry."""
        self._tool_categories = categories
        self._tool_names = tool_names
        self._nested = self._build_nested()

    def get_completer(self) -> NestedCompleter:
        """Return the current NestedCompleter instance."""
        return self._nested
