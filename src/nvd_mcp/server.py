"""MCP server that exposes NVD vulnerability lookups as tools."""

from mcp.server import MCPServer
mcp = MCPServer("nvd")

@mcp.tool()
def ping() -> str:
    """Health check; returns 'pong' if the server is running."""
    return "pong"

if __name__ == "__main__":
    mcp.run()