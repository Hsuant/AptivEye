"""MCP Tool Registry — manages tool discovery, registration, and invocation.

The registry is the central hub for all tools. Tools can be:
  - Local MCP Servers (in-process)
  - Remote MCP Servers (via stdio/HTTP)
  - Direct Python callables (simplified mode for Phase 0)

Design principle: MCP is the ONLY tool access protocol. All tools,
regardless of implementation, are exposed through the same interface.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ToolDefinition:
    """Metadata for a registered tool.

    Compatible with MCP Tool schema and OpenAI function-calling schema.
    """

    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)  # JSON Schema for params
    category: str = "general"  # asset, vuln, pentest, code_audit, cve, assess
    risk_level: int = 0  # 0-10, used by policy engine
    requires_approval: bool = False

    def to_openai_function(self) -> dict[str, Any]:
        """Convert to OpenAI function-calling format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_mcp_tool(self) -> dict[str, Any]:
        """Convert to MCP tool definition format."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.parameters,
        }


# Type for tool implementation callables
ToolHandler = Callable[..., Any]


@dataclass
class RegisteredTool:
    """A tool registered in the registry, with its handler."""

    definition: ToolDefinition
    handler: ToolHandler
    enabled: bool = True


class ToolRegistry:
    """Central registry for all MCP tools.

    Manages:
      - Tool registration (local + MCP Server)
      - Tool discovery (list all available tools)
      - Tool invocation (call a tool by name)
      - Lifecycle (enable/disable tools)

    Usage::

        registry = ToolRegistry()
        registry.register(
            definition=ToolDefinition(name="echo", ...),
            handler=lambda **kwargs: kwargs,
        )
        result = await registry.call("echo", message="hello")
    """

    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}
        self._mcp_connections: dict[str, Any] = {}  # server_name → MCP session
        self._call_counts: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------
    def register(
        self,
        definition: ToolDefinition,
        handler: ToolHandler,
    ) -> None:
        """Register a tool with its handler.

        Args:
            definition: Tool metadata (name, description, parameter schema).
            handler: Async or sync callable that implements the tool.
        """
        if definition.name in self._tools:
            logger.warning("Tool '{}' already registered — overwriting.", definition.name)

        self._tools[definition.name] = RegisteredTool(
            definition=definition,
            handler=handler,
        )
        self._call_counts.setdefault(definition.name, 0)

        logger.info(
            "Registered tool: '{}' (category={}, risk={})",
            definition.name,
            definition.category,
            definition.risk_level,
        )

    def register_many(
        self,
        tools: list[tuple[ToolDefinition, ToolHandler]],
    ) -> None:
        """Register multiple tools at once."""
        for definition, handler in tools:
            self.register(definition, handler)

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def list_tools(self, category: str | None = None) -> list[ToolDefinition]:
        """List all registered tools, optionally filtered by category."""
        tools = [
            rt.definition
            for rt in self._tools.values()
            if rt.enabled
        ]
        if category:
            tools = [t for t in tools if t.category == category]
        return tools

    def get_tool(self, name: str) -> ToolDefinition | None:
        """Get a tool definition by name."""
        rt = self._tools.get(name)
        return rt.definition if rt and rt.enabled else None

    def get_tool_definitions_for_llm(
        self,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get tool definitions in OpenAI function-calling format."""
        return [
            t.to_openai_function()
            for t in self.list_tools(category=category)
        ]

    def get_tool_definitions_for_mcp(
        self,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get tool definitions in MCP format."""
        return [
            t.to_mcp_tool()
            for t in self.list_tools(category=category)
        ]

    # ------------------------------------------------------------------
    # Invocation
    # ------------------------------------------------------------------
    async def call(self, tool_name: str, **params: Any) -> Any:
        """Invoke a tool by name with the given parameters.

        Args:
            tool_name: Registered tool name.
            **params: Tool parameters (keyword arguments).

        Returns:
            Tool execution result.

        Raises:
            KeyError: If tool is not registered.
            Exception: Re-raises any exception from the tool handler.
        """
        rt = self._tools.get(tool_name)
        if rt is None:
            raise KeyError(f"Tool '{tool_name}' is not registered.")
        if not rt.enabled:
            raise RuntimeError(f"Tool '{tool_name}' is disabled.")

        self._call_counts[tool_name] += 1

        logger.debug("Calling tool: '{}' (call #{})", tool_name, self._call_counts[tool_name])

        try:
            # Support both sync and async handlers
            if asyncio.iscoroutinefunction(rt.handler):
                result = await rt.handler(**params)
            else:
                result = rt.handler(**params)
        except Exception as exc:
            logger.error("Tool '{}' failed: {}", tool_name, exc)
            raise

        return result

    def call_sync(self, tool_name: str, **params: Any) -> Any:
        """Synchronous wrapper around call()."""
        return asyncio.run(self.call(tool_name, **params))

    # ------------------------------------------------------------------
    # Management
    # ------------------------------------------------------------------
    def enable(self, tool_name: str) -> None:
        """Enable a tool."""
        if tool_name in self._tools:
            self._tools[tool_name].enabled = True

    def disable(self, tool_name: str) -> None:
        """Disable a tool (it won't appear in listings or accept calls)."""
        if tool_name in self._tools:
            self._tools[tool_name].enabled = False

    def unregister(self, tool_name: str) -> None:
        """Remove a tool from the registry."""
        self._tools.pop(tool_name, None)

    def get_categories(self) -> list[str]:
        """Return all unique tool categories."""
        return list({t.definition.category for t in self._tools.values()})

    @property
    def tool_count(self) -> int:
        return len([t for t in self._tools.values() if t.enabled])

    @property
    def stats(self) -> dict:
        return {
            "total_registered": len(self._tools),
            "enabled": self.tool_count,
            "categories": self.get_categories(),
            "call_counts": dict(self._call_counts),
        }

    # ------------------------------------------------------------------
    # MCP Server integration
    # ------------------------------------------------------------------
    async def connect_mcp_server(
        self,
        server_name: str,
        command: str | None = None,
        url: str | None = None,
    ) -> None:
        """Connect to an external MCP Server via stdio or HTTP.

        Phase 0: Stub — full implementation in Phase 1+.
        Phase 1+: Uses mcp.Client to connect and discover tools.
        """
        logger.info(
            "MCP Server connection stub: name={} command={} url={}",
            server_name,
            command,
            url,
        )
        # Full implementation in Phase 1:
        #   from mcp import Client
        #   client = Client(command=command, url=url)
        #   await client.connect()
        #   tools = await client.list_tools()
        #   for tool in tools:
        #       self.register(tool.definition, tool.handler)
        #   self._mcp_connections[server_name] = client
        raise NotImplementedError("MCP Server connection — Phase 1+ feature")

    def reset(self) -> None:
        """Clear all registered tools and stats."""
        self._tools.clear()
        self._call_counts.clear()
        self._mcp_connections.clear()


# ------------------------------------------------------------------
# Singleton
# ------------------------------------------------------------------
_registry: ToolRegistry | None = None


def get_registry() -> ToolRegistry:
    """Return the global singleton ToolRegistry."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry
