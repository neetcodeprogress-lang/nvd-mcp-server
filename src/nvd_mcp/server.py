"""MCP server that exposes NVD vulnerability lookups as tools.

Tools stay thin: they check input, call NvdClient, and map results with from_nvd.
All HTTP logic lives in nvd_client.py.
"""

import os
import re

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from nvd_mcp.models import CveSummary, from_nvd
from nvd_mcp.nvd_client import NvdClient, NvdError

# keeps one search from flooding the assistant's context
# Note: 100 went over Claude Code's tool-output limit (~50k chars) in a real run
MAX_SEARCH_RESULTS = 50

DEFAULT_SEARCH_RESULTS = 20

# NVD IDs look like CVE-2021-44228: a 4-digit year, then 4 or more digits.
CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

mcp = MCPServer("nvd")

# One client for the whole server, so every tool call reuses the same HTTP connection.
# No key is fine: NVD still answers, we just pause longer between pages.
_client = NvdClient(api_key=os.environ.get("NVD_API_KEY"))


@mcp.tool()
def ping() -> str:
    """Health check; returns 'pong' if the server is running."""
    return "pong"


@mcp.tool()
async def search_cves(keyword: str, max_results: int = DEFAULT_SEARCH_RESULTS) -> list[CveSummary]:
    """Search NVD for CVEs whose description matches a keyword (e.g. "log4j", "openssl").

    Returns up to max_results summaries (capped at 50), newest first. If more CVEs
    match than max_results, you get the newest ones. Descriptions are shortened;
    use get_cve for the full text of one CVE.
    """
    keyword = keyword.strip()
    if not keyword:
        raise ToolError("keyword must not be empty.")
    # Clamp into 1..50 instead of failing: a too-big number is a request we can still serve.
    max_results = max(1, min(max_results, MAX_SEARCH_RESULTS))

    try:
        # search_newest, not search: NVD returns oldest first, so plain search would
        # answer "what's recent?" with CVEs from years ago (found in the end-to-end run).
        items = await _client.search_newest({"keywordSearch": keyword}, max_results)
    except NvdError as e:
        raise ToolError(f"NVD request failed: {e}") from e

    return [from_nvd(item) for item in items]


@mcp.tool()
async def get_cve(cve_id: str) -> CveSummary:
    """Look up one CVE by ID (e.g. "CVE-2021-44228") and return its full description."""
    normalized = cve_id.strip().upper()  # accept "cve-2021-44228" and stray spaces
    if not CVE_ID_PATTERN.fullmatch(normalized):
        raise ToolError(f"{cve_id!r} is not a CVE ID. Expected a form like CVE-2021-44228.")
    cve_id = normalized

    try:
        items = await _client.search({"cveId": cve_id}, max_results=1)
    except NvdError as e:
        raise ToolError(f"NVD request failed: {e}") from e

    if not items:
        raise ToolError(f"{cve_id} was not found in NVD.")
    return from_nvd(items[0], max_description=None)


if __name__ == "__main__":
    mcp.run()
