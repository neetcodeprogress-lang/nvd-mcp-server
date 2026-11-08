"""Tests for the MCP tools in server.py. respx fakes NVD, so these never touch the real API.

The @mcp.tool() decorator hands back the original function, so the tests call
search_cves / get_cve directly, like plain async functions.
"""

import httpx
import pytest
import respx
from mcp.server.mcpserver.exceptions import ToolError

from nvd_mcp import server
from nvd_mcp.models import SEARCH_DESCRIPTION_LIMIT
from nvd_mcp.nvd_client import NVD_URL, NvdClient

LONG_TEXT = "x" * 500  # longer than the 300-character search limit


def make_item(cve_id: str = "CVE-2021-44228", description: str = LONG_TEXT) -> dict:
    """A minimal raw NVD item: just an ID and an English description."""
    return {"cve": {"id": cve_id, "descriptions": [{"lang": "en", "value": description}]}}


def nvd_page(*items: dict) -> httpx.Response:
    """A fake NVD response holding the given items."""
    return httpx.Response(200, json={"totalResults": len(items), "vulnerabilities": list(items)})


@pytest.fixture(autouse=True)
def fresh_client(monkeypatch):
    """Give each test its own NvdClient with a no-op sleep, so retries don't really wait.

    autouse=True: every test in this file gets this without asking for it.
    """

    async def no_sleep(seconds: float) -> None:
        pass

    monkeypatch.setattr(server, "_client", NvdClient(api_key=None, sleep=no_sleep))


# --- search_cves ---


@respx.mock
async def test_search_sends_keyword_and_shortens_descriptions():
    route = respx.get(NVD_URL).mock(return_value=nvd_page(make_item("CVE-1"), make_item("CVE-2")))

    results = await server.search_cves("  log4j  ")

    assert route.calls.last.request.url.params["keywordSearch"] == "log4j"  # spaces trimmed
    assert [r.cve_id for r in results] == ["CVE-1", "CVE-2"]
    for r in results:
        assert len(r.description) == SEARCH_DESCRIPTION_LIMIT
        assert r.description.endswith("…")


@pytest.mark.parametrize(
    ("asked", "sent"),
    [(500, 100), (0, 1), (-5, 1), (42, 42)],
    ids=["too-big-capped", "zero-raised", "negative-raised", "in-range-kept"],
)
@respx.mock
async def test_search_clamps_max_results(asked, sent):
    route = respx.get(NVD_URL).mock(return_value=nvd_page())

    await server.search_cves("log4j", max_results=asked)

    assert route.calls.last.request.url.params["resultsPerPage"] == str(sent)


@pytest.mark.parametrize("keyword", ["", "   "], ids=["empty", "only-spaces"])
@respx.mock
async def test_search_rejects_empty_keyword_without_calling_nvd(keyword):
    route = respx.get(NVD_URL).mock(return_value=nvd_page())

    with pytest.raises(ToolError, match="keyword must not be empty"):
        await server.search_cves(keyword)

    assert not route.called


# --- get_cve ---


@respx.mock
async def test_get_cve_normalizes_id_and_keeps_full_description():
    route = respx.get(NVD_URL).mock(return_value=nvd_page(make_item("CVE-2021-44228")))

    result = await server.get_cve("  cve-2021-44228 ")

    assert route.calls.last.request.url.params["cveId"] == "CVE-2021-44228"
    assert result.cve_id == "CVE-2021-44228"
    assert result.description == LONG_TEXT  # not cut, unlike search


@pytest.mark.parametrize(
    "bad_id",
    ["log4j", "CVE-21-44228", "CVE-2021-123", "CVE-2021-44228x", ""],
    ids=["not-an-id", "2-digit-year", "3-digit-number", "trailing-junk", "empty"],
)
@respx.mock
async def test_get_cve_rejects_bad_id_without_calling_nvd(bad_id):
    route = respx.get(NVD_URL).mock(return_value=nvd_page())

    with pytest.raises(ToolError, match="is not a CVE ID"):
        await server.get_cve(bad_id)

    assert not route.called


@respx.mock
async def test_get_cve_not_found():
    respx.get(NVD_URL).mock(return_value=nvd_page())  # NVD answers, but with no items

    with pytest.raises(ToolError, match="CVE-2099-0001 was not found"):
        await server.get_cve("CVE-2099-0001")


# --- NVD failures, both tools ---


@pytest.mark.parametrize(
    "call_tool",
    [lambda: server.search_cves("log4j"), lambda: server.get_cve("CVE-2021-44228")],
    ids=["search_cves", "get_cve"],
)
@respx.mock
async def test_nvd_down_becomes_readable_tool_error(call_tool):
    respx.get(NVD_URL).mock(return_value=httpx.Response(503))  # every attempt fails

    with pytest.raises(ToolError, match="NVD request failed"):
        await call_tool()
