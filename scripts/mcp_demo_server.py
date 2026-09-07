"""A small MCP server for the demo and the evals.

Ours rather than a third party's, for two reasons: the gateway then speaks the
real protocol instead of a mock we would have to rewrite, and the evals need a
reproducible request stream, which a network service cannot give.

`fetch` does not touch the network. In the demo the interesting outcome is that
an exfiltration attempt is *refused before reaching here*, so a real client
would add risk and prove nothing.
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

from mcp.server.mcpserver import MCPServer

__all__ = ["build"]


def build(root: str | os.PathLike) -> MCPServer:
    base = Path(root).resolve()
    server = MCPServer("demo-tools")

    @server.tool()
    def read_file(path: str) -> str:
        """Read a UTF-8 text file inside the workspace."""
        target = (base / path).resolve()
        return target.read_text(encoding="utf-8", errors="replace")

    @server.tool()
    def write_file(path: str, content: str) -> str:
        """Write a UTF-8 text file inside the workspace."""
        target = (base / path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return f"wrote {len(content)} bytes"

    @server.tool()
    def fetch(url: str) -> str:
        """Retrieve a URL. Stubbed: records the host and returns fixed text."""
        return f"[fetched {urlsplit(url).hostname or '?'}]"

    return server
