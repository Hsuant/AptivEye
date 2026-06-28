"""Interactive shell engine — the REPL core.

Provides the InteractiveShell class that drives the prompt_toolkit REPL,
dispatches commands, manages session state, and integrates with AgentRunner.
"""

from __future__ import annotations

import asyncio
import shlex
import sys
from pathlib import Path
from typing import Any

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from rich.console import Console

from config.settings import get_settings
from src.security.scope import AuthorizationScope, ScanIntensity
from src.shell.formatting import (
    print_help,
    print_history,
    print_report,
    print_report_summary,
    print_session_state,
    print_stats,
    print_task_summary,
    print_tools_table,
    print_welcome,
)
from src.shell.session import (
    COMMANDS,
    AptivEyeCompleter,
    CommandMeta,
    ShellSession,
    register_commands,
)
from src.utils.logger import get_logger, setup_logging

logger = get_logger(__name__)


# ── Shell prompt style ────────────────────────────────────────────────────

SHELL_STYLE = Style.from_dict({
    "prompt": "bold cyan",
    "separator": "bold white",
    "context": "dim italic",
})


class ExitShell(Exception):
    """Raised to signal clean shell exit."""


class InteractiveShell:
    """REPL shell for AptivEye security assessments.

    Usage::

        shell = InteractiveShell()
        await shell.run()
    """

    def __init__(self, *, verbose: bool = False) -> None:
        self._console = Console()
        self._session = ShellSession()
        self._verbose = verbose

        # Set up logging
        if verbose:
            settings = get_settings()
            settings.logging.log_level = "DEBUG"
        setup_logging()

        # Command registry
        self._commands: dict[str, CommandMeta] = register_commands()

        # Completer (categories updated after registry init)
        self._completer = AptivEyeCompleter()

        # Lazily initialized components
        self._llm = None
        self._registry = None
        self._runner = None

    # ── Public API ───────────────────────────────────────────────────────

    async def run(self) -> None:
        """Run the interactive REPL loop. Blocks until user quits."""
        print_welcome(self._console)

        # Build prompt_toolkit session
        prompt_session = self._build_session()

        while True:
            try:
                line = await prompt_session.prompt_async(
                    self._build_prompt(),
                )
                line = line.strip()

                if not line:
                    continue

                # Record before handling (skip empty lines)
                self._session.add_command(line)

                await self._handle_line(line)

            except KeyboardInterrupt:
                # Ctrl+C on empty line → show hint
                self._console.print("[dim](Press Ctrl+D or type [bold]quit[/bold] to exit)[/dim]")
                continue

            except EOFError:
                # Ctrl+D → clean exit
                self._console.print("\n[dim]Goodbye.[/dim]")
                break

            except ExitShell:
                break

            except Exception as exc:
                logger.error("Unhandled error in REPL: {}", exc)
                # Fatal terminal errors — exit gracefully
                if self._is_terminal_error(exc):
                    self._console.print(f"[red]Terminal error — {exc}[/red]")
                    self._console.print("[dim]Shell cannot continue. Exiting.[/dim]")
                    break
                self._console.print(f"[red]Internal error: {exc}[/red]")

        # Persist history on exit
        self._save_history(prompt_session)

    # ── Command Dispatch ──────────────────────────────────────────────────

    async def _handle_line(self, line: str) -> None:
        """Parse input and dispatch to the appropriate command handler."""
        # Parse with shlex for POSIX-compliant tokenization
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            self._console.print(f"[yellow]Invalid syntax: {exc}[/yellow]")
            return

        if not parts:
            return

        cmd_name = parts[0].lower()
        args = parts[1:]

        # Look up command
        cmd_meta = self._commands.get(cmd_name)
        if cmd_meta is None:
            self._console.print(
                f"[yellow]Unknown command '{cmd_name}'. "
                f"Type [bold]help[/bold] for available commands.[/yellow]"
            )
            return

        # Dispatch to handler method
        handler = getattr(self, cmd_meta.handler, None)
        if handler is None:
            self._console.print(f"[red]Bug: handler '{cmd_meta.handler}' not found.[/red]")
            return

        try:
            await handler(args)
        except ExitShell:
            raise
        except Exception as exc:
            logger.error("Command '{}' failed: {}", cmd_name, exc)
            self._console.print(
                f"[red]Command failed: {exc}[/red]"
            )

    # ── Command: run ──────────────────────────────────────────────────────

    async def _cmd_run(self, args: list[str]) -> None:
        """Execute a security assessment task."""
        # Parse flags from args
        task_parts, target_flag, intensity_flag, no_approval = self._parse_run_args(args)

        task = " ".join(task_parts).strip()
        if not task:
            self._console.print("[red]Error: 'run' requires a task description.[/red]")
            return

        # Determine target: flag > session default
        target = target_flag or self._session.target

        # Determine intensity: flag > session default
        intensity = self._session.intensity
        if intensity_flag:
            try:
                intensity = ScanIntensity(intensity_flag.lower())
            except ValueError:
                self._console.print(
                    f"[red]Invalid intensity '{intensity_flag}'. "
                    f"Choose: passive, active, intrusive[/red]"
                )
                return

        # Determine approval: flag overrides session default
        requires_approval = self._session.requires_approval
        if no_approval:
            requires_approval = False

        # Validate target
        if target:
            from src.utils.validators import is_valid_cidr, is_valid_domain, is_valid_ip
            if not (is_valid_ip(target) or is_valid_cidr(target) or is_valid_domain(target)):
                self._console.print(f"[yellow]⚠️  Warning: '{target}' may not be a valid target[/yellow]")

        # Build scope
        scope = AuthorizationScope(
            allowed_targets=[target] if target else [],
            intensity=intensity,
            requires_human_approval=requires_approval,
            notes=f"Shell task: {task[:100]}",
        )

        # Ensure components are initialized
        await self._init_components()

        # Display task summary
        print_task_summary(self._console, task, scope)

        # Run the agent with progress display
        from rich.progress import Progress, SpinnerColumn, TextColumn

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self._console,
        ) as progress:
            agent_task = progress.add_task("[cyan]Agent analyzing task...", total=None)

            try:
                result = await self._runner.run(
                    task=task,
                    scope=scope,
                    session_id=self._session.session_id,
                )
            except asyncio.CancelledError:
                progress.stop()
                self._console.print("\n[yellow]⚠️  Assessment cancelled.[/yellow]")
                return
            except Exception as exc:
                progress.stop()
                self._console.print(f"\n[red]❌ Agent execution failed: {exc}[/red]")
                return

            progress.update(agent_task, description="[green]✓ Agent completed")

        # Store report in session
        self._session.add_report(task, result)

        # Display results
        report_text = result.get("final_report", "No report generated.")
        print_report(self._console, report_text)
        print_stats(self._console, result)

        # Warn if errors
        if result.get("error_count", 0) > 0:
            self._console.print(
                f"\n[yellow]⚠️  Completed with {result['error_count']} errors[/yellow]"
            )

    def _parse_run_args(
        self, args: list[str]
    ) -> tuple[list[str], str, str, bool]:
        """Parse flags from run command arguments.

        Returns: (task_parts, target, intensity, no_approval)
        """
        task_parts: list[str] = []
        target = ""
        intensity = ""
        no_approval = False

        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-t", "--target"):
                if i + 1 < len(args):
                    target = args[i + 1]
                    i += 2
                else:
                    i += 1
            elif arg in ("-i", "--intensity"):
                if i + 1 < len(args):
                    intensity = args[i + 1]
                    i += 2
                else:
                    i += 1
            elif arg == "--no-approval":
                no_approval = True
                i += 1
            else:
                task_parts.append(arg)
                i += 1

        return task_parts, target, intensity, no_approval

    # ── Command: call ─────────────────────────────────────────────────────

    async def _cmd_call(self, args: list[str]) -> None:
        """Invoke a single tool directly with parameters."""
        await self._init_components()

        # Parse tool name and flags
        tool_name, tool_params = self._parse_call_args(args)

        if not tool_name:
            self._console.print(
                "[yellow]Usage: call <tool_name> [-p JSON] [-d domain] [-H host] [--ports ...] [-t target] [-q query] [-s source][/yellow]"
            )
            self._console.print("[dim]Use [bold]tools[/bold] to see available tools.[/dim]")
            return

        # Check tool exists
        tool_def = self._registry.get_tool(tool_name)
        if tool_def is None:
            self._console.print(
                f"[red]Unknown tool '{tool_name}'. Use [bold]tools[/bold] to list available tools.[/red]"
            )
            return

        # Validate params against tool schema
        import json
        schema_props = tool_def.parameters.get("properties", {})
        if schema_props:
            unknown = [k for k in tool_params if k not in schema_props]
            if unknown:
                known = list(schema_props.keys())
                self._console.print(
                    f"[yellow]⚠ Unknown params {unknown} — "
                    f"[bold]{tool_name}[/bold] accepts: {', '.join(known)}[/yellow]"
                )
                self._console.print(
                    f"[dim]Tip: use [bold]-p[/bold] JSON syntax for exact params: "
                    f"-p '{{\"{known[0] if known else 'key'}\":\"value\"}}'[/dim]"
                )

        # Execute
        self._console.print(f"[cyan]Calling [bold]{tool_name}[/bold]...[/cyan]")
        if tool_params:
            self._console.print(f"[dim]Params: {json.dumps(tool_params, ensure_ascii=False)}[/dim]")

        try:
            result = await self._registry.call(tool_name, **tool_params)
        except TypeError as exc:
            # Likely a parameter name mismatch — show the tool's actual params
            error_msg = str(exc)
            self._console.print(f"[red]Parameter error: {error_msg}[/red]")

            # Extract the tool's accepted parameter names
            props = tool_def.parameters.get("properties", {})
            required = tool_def.parameters.get("required", [])
            if props:
                param_list = []
                for pname, pinfo in props.items():
                    req_mark = " *required" if pname in required else ""
                    ptype = pinfo.get("type", "any")
                    param_list.append(f"  [cyan]{pname}[/cyan] ({ptype}){req_mark}")
                self._console.print(f"\n[bold]{tool_name}[/bold] accepts:")
                self._console.print("\n".join(param_list))
                self._console.print(f"\n[dim]Tip: use [bold]-p[/bold] for complex params: -p '{{\"{props.popitem()[0] if props else 'key'}\":\"...\"}}'[/dim]")
            return
        except Exception as exc:
            self._console.print(f"[red]Tool execution failed: {exc}[/red]")
            return

        # Display result
        from rich.panel import Panel

        if isinstance(result, dict):
            result_str = json.dumps(result, indent=2, ensure_ascii=False, default=str)
        elif isinstance(result, str):
            result_str = result
        else:
            result_str = str(result)

        self._console.print(
            Panel(
                result_str[:10000],
                title=f"🔧 {tool_name} — Result",
                border_style="green",
            )
        )

    @staticmethod
    def _parse_call_args(args: list[str]) -> tuple[str, dict[str, Any]]:
        """Parse call command arguments. Returns (tool_name, params_dict)."""
        import json

        tool_name = ""
        params: dict[str, Any] = {}

        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-p", "--params"):
                if i + 1 < len(args):
                    try:
                        params.update(json.loads(args[i + 1]))
                    except json.JSONDecodeError:
                        pass
                    i += 2
                else:
                    i += 1
            elif arg in ("-d", "--domain"):
                if i + 1 < len(args):
                    params["domain"] = args[i + 1]
                    i += 2
                else:
                    i += 1
            elif arg in ("-H", "--host"):
                if i + 1 < len(args):
                    params["host"] = args[i + 1]
                    i += 2
                else:
                    i += 1
            elif arg == "--ports":
                if i + 1 < len(args):
                    params["ports"] = args[i + 1]
                    i += 2
                else:
                    i += 1
            elif arg in ("-t", "--target"):
                if i + 1 < len(args):
                    params["target"] = args[i + 1]
                    i += 2
                else:
                    i += 1
            elif arg in ("-q", "--query"):
                if i + 1 < len(args):
                    params["query"] = args[i + 1]
                    i += 2
                else:
                    i += 1
            elif arg in ("-s", "--source"):
                if i + 1 < len(args):
                    params["source"] = args[i + 1]
                    i += 2
                else:
                    i += 1
            elif arg in ("-k", "--keyword"):
                if i + 1 < len(args):
                    params["keyword"] = args[i + 1]
                    i += 2
                else:
                    i += 1
            elif arg.startswith("-"):
                # Unknown flag — show helpful error instead of silently skipping
                flag_name = arg
                if i + 1 < len(args) and not args[i + 1].startswith("-"):
                    params[arg.lstrip("-")] = args[i + 1]
                    i += 2
                else:
                    i += 1
                if i + 1 < len(args) and not args[i + 1].startswith("-"):
                    i += 2
                else:
                    i += 1
            else:
                if not tool_name:
                    tool_name = arg
                i += 1

        return tool_name, params

    # ── Command: set ──────────────────────────────────────────────────────

    async def _cmd_set(self, args: list[str]) -> None:
        """Set session parameters."""
        if len(args) < 2:
            self._console.print(
                "[yellow]Usage: set target <value> | set intensity <level> | set approval on|off[/yellow]"
            )
            return

        param = args[0].lower()
        value = args[1]

        if param == "target":
            self._session.target = value
            self._console.print(f"[green]✓ Target set to: {value}[/green]")

        elif param == "intensity":
            try:
                self._session.intensity = ScanIntensity(value.lower())
                self._console.print(
                    f"[green]✓ Intensity set to: {self._session.intensity.value}[/green]"
                )
            except ValueError:
                self._console.print(
                    f"[red]Invalid intensity '{value}'. Choose: passive, active, intrusive[/red]"
                )

        elif param == "approval":
            if value.lower() in ("on", "true", "yes", "enable"):
                self._session.requires_approval = True
                self._console.print("[green]✓ HITL approval: Enabled[/green]")
            elif value.lower() in ("off", "false", "no", "disable"):
                self._session.requires_approval = False
                self._console.print("[yellow]✓ HITL approval: Disabled (use with caution)[/yellow]")
            else:
                self._console.print("[red]Use: set approval on | set approval off[/red]")

        else:
            self._console.print(
                f"[yellow]Unknown setting '{param}'. Available: target, intensity, approval[/yellow]"
            )

    # ── Command: show ─────────────────────────────────────────────────────

    async def _cmd_show(self, args: list[str]) -> None:
        """Show session state, report, or summary."""
        if not args:
            self._console.print("[yellow]Usage: show state | show report [N] | show summary[/yellow]")
            return

        sub = args[0].lower()

        if sub == "state":
            print_session_state(self._console, self._session)

        elif sub == "report":
            # Optional numeric index for historical reports
            index = -1
            if len(args) > 1:
                try:
                    index = int(args[1]) - 1  # 1-based to 0-based
                except ValueError:
                    self._console.print(f"[red]Invalid report number: {args[1]}[/red]")
                    return

            if not self._session.reports:
                self._console.print("[yellow]No reports yet. Use [bold]run[/bold] to execute an assessment.[/yellow]")
                return

            try:
                report = self._session.reports[index]
            except IndexError:
                self._console.print(
                    f"[red]Report #{args[1] if len(args) > 1 else 1} not found. "
                    f"Available: 1-{self._session.run_count}[/red]"
                )
                return

            report_text = report.get("report", "No content.")
            print_report(self._console, report_text)

        elif sub == "summary":
            print_report_summary(self._console, self._session)

        else:
            self._console.print(f"[yellow]Unknown show target '{sub}'. Use: state, report, summary[/yellow]")

    # ── Command: tools ────────────────────────────────────────────────────

    async def _cmd_tools(self, args: list[str]) -> None:
        """List registered tools, optionally filtered by category."""
        await self._init_components()

        category = args[0].lower() if args else None

        if category:
            tools = self._registry.list_tools(category)
        else:
            tools = self._registry.list_tools()

        if not tools:
            self._console.print(f"[yellow]No tools found{' in category: ' + category if category else ''}.[/yellow]")
            return

        print_tools_table(self._console, tools)

        if category:
            self._console.print(f"\nTotal: {len(tools)} tools in category '{category}'")
        else:
            self._console.print(
                f"\nTotal: {len(tools)} tools in {len(self._registry.get_categories())} categories"
            )

    # ── Command: status ────────────────────────────────────────────────────

    async def _cmd_status(self, args: list[str]) -> None:
        """Show system status tree."""
        settings = get_settings()
        await self._init_components()

        from rich.tree import Tree

        tree = Tree("🏗️  AptivEye System Status")

        # LLM providers
        llm_tree = tree.add("🤖 LLM Providers")
        try:
            health = await self._llm.health_check()
            for provider, ok in health.items():
                icon = "✅" if ok else "❌"
                llm_tree.add(f"{icon} {provider}")
        except Exception as exc:
            llm_tree.add(f"❌ Health check failed: {exc}")

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
        tools_tree = tree.add("🔧 Tools")
        tools_tree.add(f"Registered: {self._registry.tool_count}")
        for cat in self._registry.get_categories():
            tools_tree.add(f"  {cat}: {len(self._registry.list_tools(cat))} tools")

        # Config
        config_tree = tree.add("⚙️  Configuration")
        config_tree.add(f"Log level: {settings.logging.log_level}")
        config_tree.add(f"Data dir: {settings.data_dir}")

        self._console.print(tree)

    # ── Command: health ────────────────────────────────────────────────────

    async def _cmd_health(self, args: list[str]) -> None:
        """Quick LLM provider connectivity check."""
        self._console.print("[cyan]Checking LLM provider health...[/cyan]\n")
        await self._init_components()

        results = await self._llm.health_check()

        from rich.table import Table

        table = Table(title="🏥 Provider Health")
        table.add_column("Provider")
        table.add_column("Status")

        all_ok = True
        for provider, ok in results.items():
            icon = "[green]✅ Connected[/green]" if ok else "[red]❌ Unavailable[/red]"
            table.add_row(provider, icon)
            if not ok:
                all_ok = False

        self._console.print(table)

        if not all_ok:
            self._console.print("\n[yellow]Some providers are unavailable. Check your API keys in .env[/yellow]")
        else:
            self._console.print("\n[green]All providers connected![/green]")

    # ── Command: save ─────────────────────────────────────────────────────

    async def _cmd_save(self, args: list[str]) -> None:
        """Save the most recent report to a file."""
        report = self._session.last_report
        if not report:
            self._console.print("[yellow]No report to save. Run an assessment first.[/yellow]")
            return

        # Determine output path
        if args:
            output_path = Path(args[0])
        else:
            settings = get_settings()
            output_dir = Path(settings.report.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / f"report_{self._session.session_id}.md"

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report["report"], encoding="utf-8")
            self._console.print(f"[green]📁 Report saved to: {output_path}[/green]")
        except OSError as exc:
            self._console.print(f"[red]Failed to save report: {exc}[/red]")

    # ── Command: history ───────────────────────────────────────────────────

    async def _cmd_history(self, args: list[str]) -> None:
        """Show in-session command history."""
        print_history(self._console, self._session)

    # ── Command: help ─────────────────────────────────────────────────────

    async def _cmd_help(self, args: list[str]) -> None:
        """Show available commands or detailed help for a specific command."""
        filter_cmd = args[0].lower() if args else ""
        print_help(self._console, self._commands, filter_cmd)

    # ── Command: quit ─────────────────────────────────────────────────────

    async def _cmd_quit(self, args: list[str]) -> None:
        """Exit the shell."""
        self._console.print("[dim]Goodbye.[/dim]")
        raise ExitShell()

    # ── Component Initialization ──────────────────────────────────────────

    async def _init_components(self) -> None:
        """Lazily initialize LLM router, tool registry, and agent runner."""
        if self._registry is not None:
            return  # Already initialized

        from src.gateway.router import LLMRouter
        from src.tools.registry import ToolRegistry, ToolDefinition
        from src.tools.asset import register_all as register_asset_tools

        # LLM router
        self._llm = LLMRouter()

        # Tool registry
        self._registry = ToolRegistry()

        # General tools
        self._registry.register(
            ToolDefinition(
                name="echo",
                description="Echo back the input message. Used for testing the agent pipeline.",
                parameters={
                    "type": "object",
                    "properties": {
                        "message": {"type": "string", "description": "The message to echo back"},
                    },
                    "required": ["message"],
                },
                category="general",
                risk_level=0,
            ),
            handler=lambda message, **kwargs: {"echo": message, "received_at": __import__("time").time()},
        )

        self._registry.register(
            ToolDefinition(
                name="system_info",
                description="Get system information for the current environment.",
                parameters={"type": "object", "properties": {}},
                category="general",
                risk_level=0,
            ),
            handler=lambda **kwargs: {
                "python_version": sys.version,
                "platform": sys.platform,
                "cwd": str(Path.cwd()),
            },
        )

        # Asset discovery tools
        register_asset_tools(self._registry)

        # Update completer with tool categories
        self._completer.update_from_registry(
            self._registry.get_categories(),
            {t.name for t in self._registry.list_tools()},
        )

        # Agent runner
        from src.agent import AgentRunner
        self._runner = AgentRunner(self._llm, self._registry)

        logger.info(
            "Shell components initialized: {} tools, {} categories",
            self._registry.tool_count,
            len(self._registry.get_categories()),
        )

    # ── Prompt Configuration ──────────────────────────────────────────────

    def _build_session(self) -> PromptSession:
        """Configure and return a prompt_toolkit PromptSession."""
        import os

        history = self._load_history()

        # On Windows with Git Bash / MSYS2 / Cygwin (xterm-style PTY),
        # prompt_toolkit's Win32Output fails because there is no Windows
        # console screen buffer. Force Vt100 output for these terminals.
        kwargs: dict[str, Any] = {}
        if sys.platform == "win32":
            term = os.environ.get("TERM", "")
            if "xterm" in term.lower():
                from prompt_toolkit.output.vt100 import Vt100_Output
                import shutil
                def _get_size():
                    s = shutil.get_terminal_size()
                    from prompt_toolkit.output.vt100 import Size
                    return Size(rows=s.lines, columns=s.columns)
                kwargs["output"] = Vt100_Output(sys.stdout, _get_size, term=term)

        return PromptSession(
            history=history,
            completer=self._completer.get_completer(),
            style=SHELL_STYLE,
            enable_history_search=True,
            complete_while_typing=True,
            **kwargs,
        )

    def _build_prompt(self) -> list[tuple[str, str]]:
        """Build the prompt_toolkit prompt with session context.

        Returns a list of (style, text) tuples for prompt_toolkit.
        """
        context = self._session.prompt_context
        parts: list[tuple[str, str]] = [
            ("class:prompt", "aptiveye"),
            ("class:separator", "> "),
        ]
        if context:
            parts.insert(1, ("class:context", context))
        return parts

    @staticmethod
    def _is_terminal_error(exc: Exception) -> bool:
        """Check if an exception is a fatal terminal/output error."""
        # NoConsoleScreenBufferError is only raised on Windows, but the
        # module is pure Python and importable on all platforms.
        try:
            from prompt_toolkit.output.win32 import NoConsoleScreenBufferError
            if isinstance(exc, NoConsoleScreenBufferError):
                return True
        except ImportError:
            pass
        return False

    @staticmethod
    def _load_history() -> FileHistory:
        """Load persistent command history from the user's home directory."""
        history_path = Path.home() / ".aptiveye_history"
        try:
            return FileHistory(str(history_path))
        except Exception:
            logger.warning("Could not load history from {}", history_path)
            # Fallback: in-memory-only history (no path)
            from prompt_toolkit.history import InMemoryHistory
            return InMemoryHistory()  # type: ignore[return-value]

    @staticmethod
    def _save_history(prompt_session: PromptSession) -> None:
        """Persist command history to disk."""
        try:
            # FileHistory auto-saves, nothing extra needed
            pass
        except Exception:
            logger.debug("Could not persist history")
