"""HTTP client for NIST's NVD CVE API 2.0. All network calls live here."""

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable

import httpx

logger = logging.getLogger(__name__)  # logs go to stderr, never stdout (stdout is the MCP channel)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT_SECONDS = 30.0  # NVD can be slow; without a timeout a hung request waits forever

# Retry settings (used by _get)
MAX_ATTEMPTS = 4  # 1 try + up to 3 retries
BASE_DELAY_SECONDS = 1.0  # backoff waits about 1s, 2s, 4s
MAX_RETRY_AFTER_SECONDS = 60.0  # never wait longer than this, even if NVD's Retry-After asks for more

# Paging settings (used by search)
MAX_PAGE_SIZE = 2000  # NVD's cap on resultsPerPage for the CVE API
# NVD's published limits: 5 requests per 30s without a key, 50 per 30s with one.
# Waiting this long between pages keeps us under them.
PAGE_DELAY_NO_KEY = 6.0
PAGE_DELAY_WITH_KEY = 0.6


class NvdError(Exception):
    """Raised when NVD can't give us a usable answer (after retrying, where retrying makes sense)."""


def _retry_delay(attempt: int, response: httpx.Response | None) -> float:
    """Seconds to wait before the next try.

    attempt counts from 0 (0 = the first try just failed).
    response is None when the failure was a network error (no HTTP response came back).
    """
    # 1. If NVD told us how long to wait, do that (but never longer than our cap).
    if response is not None:
        retry_after = response.headers.get("Retry-After")
        if retry_after is not None:
            try:
                return min(float(retry_after), MAX_RETRY_AFTER_SECONDS)
            except ValueError:
                pass  # Retry-After can also be a date; we don't handle that, so use backoff below

    # 2. Otherwise exponential backoff: 1s, 2s, 4s ...
    backoff = BASE_DELAY_SECONDS * 2**attempt
    # 3. Plus jitter: a random 0-1s extra, so many clients don't all retry at the same instant.
    return backoff + random.uniform(0, BASE_DELAY_SECONDS)


class NvdClient:
    """Sends requests to the NVD CVE API. Holds the API key and the HTTP connection."""

    def __init__(
        self,
        api_key: str | None,
        http: httpx.AsyncClient | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        # Only send the apiKey header when we actually have a key.
        self._headers = {"apiKey": api_key} if api_key else {}
        # A key buys a higher rate limit, so we can pause less between pages.
        self._page_delay = PAGE_DELAY_WITH_KEY if api_key else PAGE_DELAY_NO_KEY
        # Remember whether we created the HTTP client, so we only close what we own.
        self._owns_http = http is None
        self._http = http or httpx.AsyncClient()
        # How we wait between retries. Real code uses asyncio.sleep; tests pass a no-op so they don't wait.
        self._sleep = sleep

    async def _get(self, params: dict) -> dict:
        """GET the CVE endpoint and return the parsed JSON body.

        Retries temporary failures (429, 5xx, network errors) up to MAX_ATTEMPTS times.
        Raises NvdError on any other error, or when the attempts run out.
        """
        last_problem = ""
        for attempt in range(MAX_ATTEMPTS):  # attempt = 0, 1, 2, 3
            try:
                response = await self._http.get(
                    NVD_URL, params=params, headers=self._headers, timeout=TIMEOUT_SECONDS
                )
            except httpx.TransportError as exc:
                # No HTTP response at all: timeout, couldn't connect, or connection dropped.
                response = None
                last_problem = f"network error ({type(exc).__name__})"

            if response is not None:
                if response.is_success:  # any 2xx
                    return response.json()
                if response.status_code == 403:
                    # Usually a bad API key, so we don't retry. NVD might also use 403 for rate
                    # limits (we couldn't trigger one to check), so the message covers both.
                    raise NvdError(
                        "NVD refused the request (HTTP 403). Check that NVD_API_KEY is valid; "
                        "if it is, you may be rate-limited, so try again in a minute."
                    )
                if response.status_code != 429 and response.status_code < 500:
                    # Other 4xx: NVD understood us and said no. Asking again won't change that.
                    raise NvdError(f"NVD rejected the request (HTTP {response.status_code})")
                last_problem = f"HTTP {response.status_code}"

            # Temporary failure. Wait and try again, unless that was the last attempt.
            if attempt < MAX_ATTEMPTS - 1:
                delay = _retry_delay(attempt, response)
                logger.warning("NVD %s; retrying in %.1fs", last_problem, delay)
                await self._sleep(delay)

        raise NvdError(
            f"NVD request failed after {MAX_ATTEMPTS} attempts ({last_problem}). "
            "Try again in a minute."
        )

    async def search(self, params: dict, max_results: int) -> list[dict]:
        """Fetch up to max_results CVEs matching params, one page at a time.

        Returns NVD's raw items (each looks like {"cve": {...}}).
        Known limit: NVD pages by offset, so if a CVE is published mid-loop the
        results shift and we may skip one or see one twice. NVD offers no cursor.
        """
        results: list[dict] = []
        start_index = 0
        while len(results) < max_results:
            if start_index > 0:
                # Not the first page: pause so we stay under NVD's rate limit.
                await self._sleep(self._page_delay)

            # Never ask for more than we still need (or more than NVD allows per page).
            page_size = min(MAX_PAGE_SIZE, max_results - len(results))
            body = await self._get({**params, "startIndex": start_index, "resultsPerPage": page_size})

            page = body.get("vulnerabilities", [])
            results.extend(page)
            start_index += len(page)

            # Stop when NVD has nothing more. The empty-page check also prevents an
            # endless loop if NVD ever returns no items while claiming there are more.
            if not page or start_index >= body.get("totalResults", 0):
                break

        return results

    async def aclose(self) -> None:
        """Close the HTTP client, but only if this object created it."""
        if self._owns_http:
            await self._http.aclose()
