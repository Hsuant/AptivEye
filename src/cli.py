"""AptivEye CLI — command-line interface for the AI security agent.

Powered by Typer (type-safe CLI) and Rich (beautiful terminal output).
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.tree import Tree

from config.settings import get_settings
from src.agent import AgentRunner
from src.gateway.router import LLMRouter
from src.security.scope import AuthorizationScope, ScanIntensity
from src.tools.registry import ToolRegistry
from src.utils.logger import setup_logging

# ── Windows UTF-8 fix ────────────────────────────────────────────────────
# Force UTF-8 on Windows to avoid GBK encoding errors with Rich emoji output.
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    os.environ.setdefault("PYTHONUTF8", "1")

# ── App ──────────────────────────────────────────────────────────────────

app = typer.Typer(
    name="aptiveye",
    help="AI-powered Network Security Agent",
    add_completion=False,
)

console = Console()
settings = get_settings()


# ── Callbacks ────────────────────────────────────────────────────────────

@app.callback()
def main(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
) -> None:
    """AptivEye — autonomous security assessment agent."""
    if verbose:
        settings.logging.log_level = "DEBUG"
    setup_logging()
    ctx.ensure_object(dict)


# ── Run command ──────────────────────────────────────────────────────────

@app.command()
def run(
    task: str = typer.Argument(..., help="Security assessment task description"),
    target: str = typer.Option("", "--target", "-t", help="Target IP, CIDR, or domain"),
    intensity: str = typer.Option(
        "passive", "--intensity", "-i",
        help="Scan intensity: passive, active, intrusive",
    ),
    output: Path = typer.Option(
        None, "--output", "-o",
        help="Save report to file",
    ),
    no_approval: bool = typer.Option(
        False, "--no-approval",
        help="Skip human approval for high-risk operations (use with caution)",
    ),
) -> None:
    """Run a security assessment task.

    Example:
        aptiveye run "Scan example.com for open ports and vulnerabilities" -t example.com -i active
    """
    # Parse intensity
    try:
        scan_intensity = ScanIntensity(intensity.lower())
    except ValueError:
        console.print(f"[red]Invalid intensity '{intensity}'. Choose: passive, active, intrusive[/red]")
        raise typer.Exit(1)

    # Build scope
    scope = AuthorizationScope(
        allowed_targets=[target] if target else [],
        intensity=scan_intensity,
        requires_human_approval=not no_approval,
        notes=f"CLI task: {task[:100]}",
    )

    # Validate target
    if target:
        from src.utils.validators import is_valid_cidr, is_valid_domain, is_valid_ip
        if not (is_valid_ip(target) or is_valid_cidr(target) or is_valid_domain(target)):
            console.print(f"[yellow]⚠️  Warning: '{target}' may not be a valid target[/yellow]")

    # Display task summary
    _print_task_summary(task, scope)

    # Run agent
    asyncio.run(_run_agent(task, scope, output))


async def _run_agent(task: str, scope: AuthorizationScope, output: Optional[Path]) -> None:
    """Execute the agent asynchronously with progress display."""
    # Initialize components
    llm = LLMRouter()
    registry = _setup_tools()

    runner = AgentRunner(llm, registry)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        agent_task = progress.add_task("[cyan]Agent analyzing task...", total=None)

        try:
            result = await runner.run(task, scope=scope)
        except Exception as exc:
            progress.stop()
            console.print(f"\n[red]❌ Agent execution failed: {exc}[/red]")
            raise typer.Exit(1)

        progress.update(agent_task, description="[green]✓ Agent completed")

    # Display results
    console.print("\n")
    report = result.get("final_report", "No report generated.")
    console.print(Panel(Markdown(report), title="📋 Assessment Report", border_style="green"))

    # Display stats
    _print_stats(result, runner)

    # Save to file if requested
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding="utf-8")
        console.print(f"\n[green]📁 Report saved to: {output}[/green]")

    # Warn if errors
    if result.get("error_count", 0) > 0:
        console.print(f"\n[yellow]⚠️  Completed with {result['error_count']} errors[/yellow]")


# ── Tools command ────────────────────────────────────────────────────────

@app.command()
def tools() -> None:
    """List all registered security tools."""
    registry = _setup_tools()

    table = Table(title="🔧 Registered Tools", border_style="blue")
    table.add_column("Tool Name", style="cyan")
    table.add_column("Category", style="green")
    table.add_column("Risk", style="yellow")
    table.add_column("Description")

    for tool in registry.list_tools():
        risk_color = (
            "red" if tool.risk_level >= 7
            else "yellow" if tool.risk_level >= 4
            else "green"
        )
        table.add_row(
            tool.name,
            tool.category,
            f"[{risk_color}]{'🔴' * min(tool.risk_level // 3 + 1, 3)} {tool.risk_level}[/{risk_color}]",
            tool.description[:80],
        )

    console.print(table)
    console.print(f"\nTotal: {registry.tool_count} tools in {len(registry.get_categories())} categories")


# ── Status command ───────────────────────────────────────────────────────

@app.command()
def status() -> None:
    """Check system status and configuration."""
    settings = get_settings()

    # Build a status tree
    tree = Tree("🏗️  AptivEye System Status")

    # LLM providers
    llm_tree = tree.add("🤖 LLM Providers")
    llm = LLMRouter()
    health = asyncio.run(llm.health_check())
    for provider, ok in health.items():
        icon = "✅" if ok else "❌"
        llm_tree.add(f"{icon} {provider}")

    # Model routing
    routing_tree = tree.add("📊 Model Routing")
    routing_tree.add(f"Light: {settings.llm.light_model}")
    routing_tree.add(f"Standard: {settings.llm.standard_model}")
    routing_tree.add(f"Heavy: {settings.llm.heavy_model}")

    # Security
    sec_tree = tree.add("🛡️  Security")
    sec_tree.add(f"HITL: {'Enabled' if settings.security.hitl_enabled else 'Disabled'}")
    sec_tree.add(f"Loop Detection: {settings.security.loop_detection_threshold} repeats")
    sec_tree.add(f"Sandbox: {'Enabled' if settings.sandbox.enabled else 'Disabled (Phase 5)'}")

    # Tools
    registry = _setup_tools()
    tools_tree = tree.add("🔧 Tools")
    tools_tree.add(f"Registered: {registry.tool_count}")
    for cat in registry.get_categories():
        tools_tree.add(f"  {cat}: {len(registry.list_tools(cat))} tools")

    # Config
    config_tree = tree.add("⚙️  Configuration")
    config_tree.add(f"Log level: {settings.logging.log_level}")
    config_tree.add(f"Data dir: {settings.data_dir}")

    console.print(tree)


# ── Health command ───────────────────────────────────────────────────────

@app.command()
def health() -> None:
    """Quick health check — verifies LLM connectivity."""
    console.print("[cyan]Checking LLM provider health...[/cyan]\n")

    llm = LLMRouter()
    results = asyncio.run(llm.health_check())

    table = Table(title="🏥 Provider Health")
    table.add_column("Provider")
    table.add_column("Status")

    all_ok = True
    for provider, ok in results.items():
        icon = "[green]✅ Connected[/green]" if ok else "[red]❌ Unavailable[/red]"
        table.add_row(provider, icon)
        if not ok:
            all_ok = False

    console.print(table)

    if not all_ok:
        console.print("\n[yellow]Some providers are unavailable. Check your API keys in .env[/yellow]")
    else:
        console.print("\n[green]All providers connected![/green]")


# ── Call command ────────────────────────────────────────────────────────

@app.command()
def call(
    tool: str = typer.Argument(..., help="Name of the tool to invoke"),
    params: str = typer.Option(
        "", "--params", "-p",
        help='Tool parameters as JSON string, e.g. \'{"domain":"example.com"}\'',
    ),
    domain: str = typer.Option(None, "--domain", "-d", help="Target domain"),
    host: str = typer.Option(None, "--host", "-H", help="Target host/IP"),
    ports: str = typer.Option(None, "--ports", help="Port range or preset (e.g. top100)"),
    target: str = typer.Option(None, "--target", "-t", help="Target for the tool"),
    query: str = typer.Option(None, "--query", "-q", help="Search query string"),
    source: str = typer.Option(None, "--source", "-s", help="Data source (e.g. fofa, zoomeye, auto)"),
    keyword: str = typer.Option(None, "--keyword", "-k", help="Keyword for search/lookup tools"),
    output: Path = typer.Option(None, "--output", "-o", help="Save result to JSON file"),
) -> None:
    """Invoke a single tool directly and display its result.

    Example:
        aptiveye call whois -d example.com
        aptiveye call nmap -H 192.168.1.1 --ports top10
        aptiveye call subdomain -d example.com
        aptiveye call fingerprint -H 192.168.1.1 -p '{"ports":[{"port":80,"service":"http"}]}'
        aptiveye call fofa -q 'app="nginx"'
        aptiveye call wechat -k 青海大学
        aptiveye call icp -k example.cn
    """
    import json

    registry = _setup_tools()

    # Check tool exists
    tool_def = registry.get_tool(tool)
    if tool_def is None:
        console.print(f"[red]Unknown tool '{tool}'. Use [bold]aptiveye tools[/bold] to list available tools.[/red]")
        raise typer.Exit(1)

    # Build params from flags and JSON
    tool_params: dict[str, Any] = {}

    # Merge JSON params first
    if params:
        try:
            tool_params.update(json.loads(params))
        except json.JSONDecodeError as exc:
            console.print(f"[red]Invalid JSON in --params: {exc}[/red]")
            raise typer.Exit(1)

    # Overlay flag-based params (flags take precedence over JSON)
    flag_params = {
        "domain": domain,
        "host": host,
        "ports": ports,
        "target": target,
        "query": query,
        "source": source,
        "keyword": keyword,
    }
    for key, value in flag_params.items():
        if value is not None:
            tool_params[key] = value

    # Display invocation info
    console.print(f"[cyan]Calling [bold]{tool}[/bold]...[/cyan]")
    if tool_params:
        console.print(f"[dim]Params: {json.dumps(tool_params, ensure_ascii=False)}[/dim]")

    # Execute
    try:
        result = registry.call_sync(tool, **tool_params)
    except Exception as exc:
        console.print(f"[red]Tool execution failed: {exc}[/red]")
        raise typer.Exit(1)

    # Display result
    from rich.panel import Panel

    if isinstance(result, dict):
        # Pretty-print dict results
        result_str = json.dumps(result, indent=2, ensure_ascii=False, default=str)
    elif isinstance(result, str):
        result_str = result
    else:
        result_str = str(result)

    console.print(
        Panel(
            result_str[:10000],  # Truncate huge outputs
            title=f"🔧 {tool} — Result",
            border_style="green",
        )
    )

    # Save to file if requested
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(result, (dict, list)):
            output.write_text(json.dumps(result, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        else:
            output.write_text(str(result), encoding="utf-8")
        console.print(f"[green]📁 Result saved to: {output}[/green]")


# ── Shell command ────────────────────────────────────────────────────────

@app.command()
def shell(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
) -> None:
    """Launch the interactive AptivEye shell (REPL).

    Provides an interactive session with command history, auto-completion,
    and persistent session state. Use this for multi-step assessments
    where you want to chain commands and explore results interactively.

    Example:
        aptiveye shell
        aptiveye> set target example.com
        aptiveye> run "discover subdomains and open ports" -i active
        aptiveye> show report
    """
    from src.shell import InteractiveShell

    shell_instance = InteractiveShell(verbose=verbose)
    asyncio.run(shell_instance.run())


# ── Helpers ──────────────────────────────────────────────────────────────

def _setup_tools() -> ToolRegistry:
    """Initialize the tool registry with all available tools."""
    from src.tools.registry import ToolRegistry, ToolDefinition
    from src.tools.asset import register_all as register_asset_tools

    registry = ToolRegistry()

    # ── Phase 0: general tools ──
    registry.register(
        ToolDefinition(
            name="echo",
            description="Echo back the input message. Used for testing the agent pipeline.",
            parameters={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The message to echo back",
                    },
                },
                "required": ["message"],
            },
            category="general",
            risk_level=0,
        ),
        handler=lambda message, **kwargs: {"echo": message, "received_at": __import__("time").time()},
    )

    registry.register(
        ToolDefinition(
            name="system_info",
            description="Get system information for the current environment.",
            parameters={
                "type": "object",
                "properties": {},
            },
            category="general",
            risk_level=0,
        ),
        handler=lambda **kwargs: {
            "python_version": sys.version,
            "platform": sys.platform,
            "cwd": str(Path.cwd()),
        },
    )

    # ── Phase 1: asset discovery tools ──
    register_asset_tools(registry)

    return registry


def _print_task_summary(task: str, scope: AuthorizationScope) -> None:
    """Print a task summary panel."""
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column(style="bold cyan", width=15)
    table.add_column()

    table.add_row("Task", task)
    table.add_row("Intensity", f"[yellow]{scope.intensity.value.upper()}[/yellow]")
    table.add_row("Targets", ", ".join(scope.allowed_targets) if scope.allowed_targets else "[dim](any)[/dim]")
    table.add_row("Approval", "Required" if scope.requires_human_approval else "[yellow]Skipped[/yellow]")
    table.add_row("Scope ID", scope.scope_id)

    console.print(Panel(table, title="🚀 Starting Assessment", border_style="blue"))


def _print_stats(result: dict, runner: AgentRunner) -> None:
    """Print execution statistics."""
    usage = result.get("llm_usage", {})
    audit = result.get("audit_summary", {})

    stats_table = Table(title="📊 Execution Statistics", border_style="dim")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="green")

    stats_table.add_row("Status", result.get("status", "unknown"))
    stats_table.add_row("Iterations", str(result.get("iteration_count", 0)))
    stats_table.add_row("LLM Calls", str(usage.get("calls", 0)))
    stats_table.add_row("Tokens Used", f"{usage.get('total_tokens', 0):,}")
    stats_table.add_row("Est. Cost", f"${usage.get('cost_usd', 0):.4f}")
    stats_table.add_row("Audit Events", str(audit.get("total_events", 0)))
    stats_table.add_row("Denied Calls", str(audit.get("denied_calls", 0)))

    console.print(stats_table)


# ── Entry Point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
