"""Tool bindings — the governance overlay on an MCP tool surface. M1. Trusted.

Tools are implemented by MCP servers, so the tool surface is dynamic,
externally controlled and untrusted. What this package owns is the mapping from
a tool call to the (capability, resource) pair admission reasons about.

That mapping is where containment actually lives. Get it wrong and every
signature still verifies, every rule still fires, and the boundary is
decorative.
"""
