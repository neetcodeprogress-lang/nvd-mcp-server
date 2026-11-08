"""Tests for NvdClient. respx fakes every HTTP call, so these never touch the real NVD API."""

import httpx
import pytest
import respx

from nvd_mcp import nvd_client
from nvd_mcp.nvd_client import NVD_URL, NvdClient, NvdError

OK = httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})


def make_fake_sleep():
    """A stand-in for asyncio.sleep that records each wait instead of actually waiting."""
    waits = []

    async def fake_sleep(seconds: float) -> None:
        waits.append(seconds)

    return fake_sleep, waits


# --- Retries (Step 3) ---


@respx.mock
async def test_retries_503_then_succeeds():
    route = respx.get(NVD_URL).mock(side_effect=[httpx.Response(503), OK])
    sleep, waits = make_fake_sleep()
    client = NvdClient(api_key=None, sleep=sleep)

    data = await client._get({"keywordSearch": "fortigate"})

    assert route.call_count == 2
    assert len(waits) == 1
    assert data["totalResults"] == 0


@respx.mock
async def test_retries_network_error_then_succeeds():
    route = respx.get(NVD_URL).mock(side_effect=[httpx.ConnectError("connection refused"), OK])
    sleep, waits = make_fake_sleep()
    client = NvdClient(api_key=None, sleep=sleep)

    data = await client._get({})

    assert route.call_count == 2
    assert data["totalResults"] == 0


@respx.mock
async def test_429_waits_for_retry_after():
    route = respx.get(NVD_URL).mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "5"}), OK]
    )
    sleep, waits = make_fake_sleep()
    client = NvdClient(api_key=None, sleep=sleep)

    await client._get({})

    assert route.call_count == 2
    assert waits == [5.0]  # exactly what NVD asked for: no backoff, no jitter


@respx.mock
async def test_404_is_not_retried():
    route = respx.get(NVD_URL).mock(return_value=httpx.Response(404))
    sleep, waits = make_fake_sleep()
    client = NvdClient(api_key=None, sleep=sleep)

    with pytest.raises(NvdError, match="HTTP 404"):
        await client._get({})

    assert route.call_count == 1
    assert waits == []


@respx.mock
async def test_403_is_not_retried_and_explains_both_causes():
    route = respx.get(NVD_URL).mock(return_value=httpx.Response(403))
    sleep, waits = make_fake_sleep()
    client = NvdClient(api_key="bad-key", sleep=sleep)

    with pytest.raises(NvdError, match="NVD_API_KEY.*rate-limited"):
        await client._get({})

    assert route.call_count == 1
    assert waits == []


@respx.mock
async def test_gives_up_after_four_503s():
    route = respx.get(NVD_URL).mock(return_value=httpx.Response(503))
    sleep, waits = make_fake_sleep()
    client = NvdClient(api_key=None, sleep=sleep)

    with pytest.raises(NvdError, match="after 4 attempts"):
        await client._get({})

    assert route.call_count == 4
    assert len(waits) == 3  # no wait after the last attempt


# --- Pagination (Step 4) ---


def make_page(start: int, count: int, total: int) -> httpx.Response:
    """A fake NVD page: `count` CVEs numbered from `start`, out of `total` that exist."""
    items = [{"cve": {"id": f"CVE-2024-{n:05d}"}} for n in range(start, start + count)]
    return httpx.Response(200, json={"totalResults": total, "vulnerabilities": items})


def sent_params(route, call_number: int) -> dict:
    """The query parameters our client sent on one call (as strings, the way they travel in a URL)."""
    return dict(route.calls[call_number].request.url.params)


@respx.mock
async def test_search_stops_at_max_results(monkeypatch):
    # The guide's checkpoint: 45 exist, we want 30, pages of 20.
    monkeypatch.setattr(nvd_client, "MAX_PAGE_SIZE", 20)
    route = respx.get(NVD_URL).mock(side_effect=[make_page(0, 20, 45), make_page(20, 10, 45)])
    sleep, waits = make_fake_sleep()
    client = NvdClient(api_key=None, sleep=sleep)

    results = await client.search({"keywordSearch": "fortigate"}, max_results=30)

    assert len(results) == 30
    assert route.call_count == 2
    assert sent_params(route, 0) == {"keywordSearch": "fortigate", "startIndex": "0", "resultsPerPage": "20"}
    assert sent_params(route, 1) == {"keywordSearch": "fortigate", "startIndex": "20", "resultsPerPage": "10"}


@respx.mock
async def test_search_stops_when_nvd_runs_out(monkeypatch):
    # Only 25 exist, we'd take up to 100: the second page is short and we stop there.
    monkeypatch.setattr(nvd_client, "MAX_PAGE_SIZE", 20)
    route = respx.get(NVD_URL).mock(side_effect=[make_page(0, 20, 25), make_page(20, 5, 25)])
    sleep, waits = make_fake_sleep()
    client = NvdClient(api_key=None, sleep=sleep)

    results = await client.search({}, max_results=100)

    assert len(results) == 25
    assert route.call_count == 2


@respx.mock
async def test_search_with_no_matches_makes_one_request():
    route = respx.get(NVD_URL).mock(return_value=OK)  # OK = totalResults 0, no items
    sleep, waits = make_fake_sleep()
    client = NvdClient(api_key=None, sleep=sleep)

    results = await client.search({}, max_results=20)

    assert results == []
    assert route.call_count == 1
    assert waits == []  # no pause before the first (and only) page


@respx.mock
async def test_search_stops_on_empty_page_even_if_nvd_claims_more():
    # NVD says 50 exist but sends nothing: without the safety net this would loop forever.
    # side_effect with ONE response: a second request gets an error, so a broken loop fails fast instead of hanging.
    route = respx.get(NVD_URL).mock(side_effect=[make_page(0, 0, 50)])
    sleep, waits = make_fake_sleep()
    client = NvdClient(api_key=None, sleep=sleep)

    results = await client.search({}, max_results=20)

    assert results == []
    assert route.call_count == 1


@pytest.mark.parametrize(
    ("api_key", "expected_pause"),
    [(None, nvd_client.PAGE_DELAY_NO_KEY), ("a-key", nvd_client.PAGE_DELAY_WITH_KEY)],
)
@respx.mock
async def test_search_pauses_between_pages(monkeypatch, api_key, expected_pause):
    monkeypatch.setattr(nvd_client, "MAX_PAGE_SIZE", 20)
    respx.get(NVD_URL).mock(side_effect=[make_page(0, 20, 40), make_page(20, 20, 40)])
    sleep, waits = make_fake_sleep()
    client = NvdClient(api_key=api_key, sleep=sleep)

    await client.search({}, max_results=40)

    assert waits == [expected_pause]  # exactly one pause: between page 1 and page 2


# --- Newest first (Sunday fix: the end-to-end run showed NVD returns oldest first) ---


def ids(items: list[dict]) -> list[str]:
    """Just the CVE IDs, so a failing assert is easy to read."""
    return [item["cve"]["id"] for item in items]


@respx.mock
async def test_search_newest_when_everything_fits_makes_one_request():
    # 3 exist, we'd take 20: one request, then reverse so the newest is first.
    route = respx.get(NVD_URL).mock(side_effect=[make_page(0, 3, 3)])
    sleep, waits = make_fake_sleep()
    client = NvdClient(api_key=None, sleep=sleep)

    results = await client.search_newest({}, max_results=20)

    assert ids(results) == ["CVE-2024-00002", "CVE-2024-00001", "CVE-2024-00000"]
    assert route.call_count == 1
    assert waits == []


@respx.mock
async def test_search_newest_jumps_to_the_end_when_there_are_too_many():
    # 450 exist, we want 100: the first request only tells us the total,
    # the second starts at 450 - 100 = 350 and gets CVEs 350..449.
    route = respx.get(NVD_URL).mock(side_effect=[make_page(0, 100, 450), make_page(350, 100, 450)])
    sleep, waits = make_fake_sleep()
    client = NvdClient(api_key=None, sleep=sleep)

    results = await client.search_newest({"keywordSearch": "fortios"}, max_results=100)

    assert route.call_count == 2
    assert sent_params(route, 1) == {"keywordSearch": "fortios", "startIndex": "350", "resultsPerPage": "100"}
    assert ids(results)[0] == "CVE-2024-00449"  # newest first
    assert ids(results)[-1] == "CVE-2024-00350"
    assert len(results) == 100
    assert waits == [nvd_client.PAGE_DELAY_NO_KEY]  # one pause, between the two requests


@respx.mock
async def test_search_newest_with_no_matches_returns_empty_list():
    route = respx.get(NVD_URL).mock(side_effect=[OK])  # one response only: a second request would fail
    sleep, waits = make_fake_sleep()
    client = NvdClient(api_key=None, sleep=sleep)

    results = await client.search_newest({}, max_results=20)

    assert results == []
    assert route.call_count == 1
