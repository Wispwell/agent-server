"""MCP transport. M2. Trusted.

Tools are implemented by MCP servers; this is the connection to them. The
client speaks the real protocol — an in-process `MCPServer` object or a stdio
subprocess are both valid targets, and the gateway does not care which.

The behaviour-tree engine is synchronous and the MCP client is asynchronous, so
a blocking portal runs the client on a background event loop and lets
synchronous code call into it. That is cheaper and less invasive than making
every tree node async for the sake of one boundary.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Self

import anyio.from_thread
from mcp import Client

__all__ = ["MCPTransport", "ToolInfo"]


class ToolInfo:
    __slots__ = ("description", "input_schema", "name")

    def __init__(self, name: str, input_schema: dict[str, Any], description: str = ""):
        self.name = name
        self.input_schema = input_schema
        self.description = description


class MCPTransport:
    """A live connection to one MCP server, usable from synchronous code."""

    def __init__(self, name: str, target: Any):
        self.name = name
        self.target = target
        self._portal_cm = None
        self._client_cm = None
        self.client: Client | None = None

    def __enter__(self) -> Self:
        self._portal_cm = anyio.from_thread.start_blocking_portal()
        portal = self._portal_cm.__enter__()
        self._client_cm = portal.wrap_async_context_manager(Client(self.target))
        self.client = self._client_cm.__enter__()
        self._portal = portal
        return self

    def __exit__(self, *exc) -> None:
        if self._client_cm is not None:
            self._client_cm.__exit__(*exc)
        if self._portal_cm is not None:
            self._portal_cm.__exit__(*exc)
        self.client = None

    def list_tools(self) -> dict[str, ToolInfo]:
        result = self._portal.call(self.client.list_tools)
        return {
            t.name: ToolInfo(t.name, dict(t.input_schema or {}), t.description or "")
            for t in result.tools
        }

    def call(self, tool: str, args: Mapping[str, Any]) -> tuple[bool, str]:
        """Invoke a tool. Returns (ok, text); a tool error is a value, not a raise."""
        result = self._portal.call(lambda: self.client.call_tool(tool, dict(args)))
        text = "\n".join(
            getattr(block, "text", "") for block in (result.content or [])
        )
        return (not result.is_error, text)
