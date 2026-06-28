"""Rich output formatting helpers for the interactive shell.

Adapted from the one-shot CLI formatting in src/cli.py, with
additional shell-specific displays (welcome banner, help table, history).
"""

from __future__ import annotations

import time
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config.settings import get_settings
from src.security.scope import AuthorizationScope

settings = get_settings()


def print_welcome(console: Console) -> None:
    """Print the welcome banner on shell startup."""
    banner = Text()
    banner.append("╔══════════════════════════════════════════╗\n", style="bold cyan")
    banner.append("║   ", style="bold cyan")
    banner.append("AptivEye Interactive Shell", style="bold white")
    banner.append("           ║\n", style="bold cyan")
    banner.append("║   AI-Powered Network Security Agent    ║\n", style="dim cyan")
    banner.append("╚══════════════════════════════════════════╝", style="bold cyan")

    console.print(banner)
    console.print("  Type [bold cyan]help[/bold cyan] for available commands, [bold cyan]quit[/bold cyan] to exit.")
    console.print(f"  Session: [dim]{settings.data_dir}[/dim]")
    console.print()


def print_task_summary(console: Console, task: str, scope: AuthorizationScope) -> None:
    """Print a task summary panel before running an assessment."""
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column(style="bold cyan", width=15)
    table.add_column()

    table.add_row("Task", task)
    table.add_row("Intensity", f"[yellow]{scope.intensity.value.upper()}[/yellow]")
    table.add_row(
        "Targets",
        ", ".join(scope.allowed_targets) if scope.allowed_targets else "[dim](any)[/dim]",
    )
    table.add_row(
        "Approval",
        "Required" if scope.requires_human_approval else "[yellow]Skipped[/yellow]",
    )
    table.add_row("Scope ID", scope.scope_id)

    console.print(Panel(table, title="🚀 Starting Assessment", border_style="blue"))


def print_report(console: Console, report_text: str) -> None:
    """Display an assessment report as a Rich Markdown panel."""
    console.print()
    console.print(
        Panel(
            Markdown(report_text),
            title="📋 Assessment Report",
            border_style="green",
        )
    )


def print_stats(console: Console, report_data: dict[str, Any]) -> None:
    """Print execution statistics from a report's metadata."""
    usage = report_data.get("llm_usage", {})
    audit = report_data.get("audit_summary", {})

    stats_table = Table(title="📊 Execution Statistics", border_style="dim")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="green")

    stats_table.add_row("Status", report_data.get("status", "unknown"))
    stats_table.add_row("Iterations", str(report_data.get("iteration_count", 0)))
    stats_table.add_row("LLM Calls", str(usage.get("calls", 0)))
    stats_table.add_row("Tokens Used", f"{usage.get('total_tokens', 0):,}")
    stats_table.add_row("Est. Cost", f"${usage.get('cost_usd', 0):.4f}")
    stats_table.add_row("Audit Events", str(audit.get("total_events", 0)))
    stats_table.add_row("Denied Calls", str(audit.get("denied_calls", 0)))

    console.print(stats_table)


def print_tools_table(console: Console, tools: list[Any]) -> None:
    """Display registered tools in a Rich table."""
    table = Table(title="🔧 Registered Tools", border_style="blue")
    table.add_column("Tool Name", style="cyan")
    table.add_column("Category", style="green")
    table.add_column("Risk", style="yellow")
    table.add_column("Description")

    for tool in tools:
        risk_color = (
            "red" if tool.risk_level >= 7
            else "yellow" if tool.risk_level >= 4
            else "green"
        )
        risk_icons = "🔴" * min(tool.risk_level // 3 + 1, 3)
        table.add_row(
            tool.name,
            tool.category,
            f"[{risk_color}]{risk_icons} {tool.risk_level}[/{risk_color}]",
            tool.description[:80],
        )

    console.print(table)


def print_help(console: Console, commands: dict, filter_cmd: str = "") -> None:
    """Display the help table for all commands or a specific command."""
    from src.shell.session import CommandMeta

    if filter_cmd:
        cmd: CommandMeta | None = commands.get(filter_cmd)
        if cmd is None:
            console.print(f"[yellow]Unknown command '{filter_cmd}'[/yellow]")
            return

        detail = Table(title=f"Help: {cmd.name}", border_style="cyan")
        detail.add_column("Field", style="cyan", width=12)
        detail.add_column("Value")
        detail.add_row("Command", cmd.name)
        detail.add_row("Category", cmd.category)
        detail.add_row("Usage", f"[bold]{cmd.usage}[/bold]")
        detail.add_row("Description", cmd.help_text)
        console.print(detail)
        return

    # Full command listing, grouped by category
    categories: dict[str, list[CommandMeta]] = {}
    for cmd in commands.values():
        categories.setdefault(cmd.category, []).append(cmd)

    category_order = ["session", "assessment", "info", "general"]
    category_labels = {
        "session": "📝 Session Management",
        "assessment": "🎯 Assessment",
        "info": "ℹ️  Information",
        "general": "⚙️  General",
    }

    for cat in category_order:
        cmds = categories.get(cat, [])
        if not cmds:
            continue

        table = Table(title=category_labels.get(cat, cat), border_style="dim")
        table.add_column("Command", style="bold cyan")
        table.add_column("Usage", style="dim")
        table.add_column("Description")

        for cmd in sorted(cmds, key=lambda c: c.name):
            table.add_row(cmd.name, cmd.usage, cmd.help_text)

        console.print(table)
        console.print()

    console.print("[dim]Type [bold]help <command>[/bold] for detailed help on a specific command.[/dim]")


def print_history(console: Console, session) -> None:
    """Display the in-session command history."""
    if not session.command_history:
        console.print("[dim]No commands executed yet.[/dim]")
        return

    table = Table(title="📜 Command History", border_style="dim")
    table.add_column("#", style="dim", width=4)
    table.add_column("Command", style="cyan")

    for i, cmd in enumerate(session.command_history, 1):
        table.add_row(str(i), cmd)

    console.print(table)


def print_session_state(console: Console, session) -> None:
    """Display current session state in a table."""
    table = Table(title="📋 Session State", border_style="cyan")
    table.add_column("Setting", style="bold cyan", width=18)
    table.add_column("Value", style="green")

    table.add_row("Session ID", session.session_id)
    table.add_row("Target", session.target or "[dim](not set)[/dim]")
    table.add_row(
        "Intensity",
        f"[yellow]{session.intensity.value.upper()}[/yellow]",
    )
    table.add_row(
        "HITL Approval",
        "[green]Enabled[/green]" if session.requires_approval else "[yellow]Disabled[/yellow]",
    )
    table.add_row("Reports", str(session.run_count))
    table.add_row("Commands Run", str(len(session.command_history)))

    console.print(table)


def print_report_summary(console: Console, session) -> None:
    """Display execution statistics for the most recent report."""
    report = session.last_report
    if not report:
        console.print("[yellow]No reports generated yet. Use [bold]run[/bold] to execute an assessment.[/yellow]")
        return

    # Display task info
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(report["timestamp"]))
    console.print(f"[dim]Task:[/dim] {report['task']}")
    console.print(f"[dim]Time:[/dim] {timestamp}")
    console.print(f"[dim]Status:[/dim] {report['status']}")

    # Display stats
    stats = report["stats"]
    stats_table = Table(title="📊 Last Assessment Statistics", border_style="dim")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="green")

    stats_table.add_row("Status", report["status"])
    stats_table.add_row("Iterations", str(stats["iterations"]))
    stats_table.add_row("LLM Calls", str(stats["llm_calls"]))
    stats_table.add_row("Tokens Used", f"{stats['tokens']:,}")
    stats_table.add_row("Est. Cost", f"${stats['cost']:.4f}")
    stats_table.add_row("Audit Events", str(stats["audit_events"]))
    stats_table.add_row("Denied Calls", str(stats["denied_calls"]))

    console.print(stats_table)
