"""Tests for NvdClient. respx fakes every HTTP call, so these never touch the real NVD API."""

import httpx
import pytest
import respx

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
