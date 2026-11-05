# NVD MCP server
An MCP server that wraps NIST's NVD CVE API 2.0 so AI assistants can look up vulnerabilities.

## Stack
- Official MCP Python SDK v2: `from mcp.server import MCPServer`. Not the old FastMCP import, not the third-party fastmcp package.
- HTTP: httpx (async). Tests: pytest + pytest-asyncio + respx.
- uv for dependencies; run everything with `uv run`.

## Rules
- No new dependencies without asking.
- Never print to stdout in server code; log to stderr (stdout is the MCP protocol channel).
- Never hardcode secrets; read NVD_API_KEY from the environment.
- Tests never call the real NVD API.
- Keep tools thin: HTTP logic lives in nvd_client.py.

## How to work with me
- I am a Java Developer who hasn't used Python as much as Java.
- Small steps: one file or one function per change.
- Before writing code, give me the plan in 3-5 bullets and wait for my OK.
- After writing code, point out any Python idiom a Java developer wouldn't know.
- If I ask "why", answer before changing anything.