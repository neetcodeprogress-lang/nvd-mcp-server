"""HTTP client for NIST's NVD CVE API 2.0. All network calls live here."""

import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT_SECONDS = 30.0  # NVD can be slow; without a timeout a hung request waits forever


class NvdClient:
    """Sends requests to the NVD CVE API. Holds the API key and the HTTP connection."""

    def __init__(self, api_key: str | None, http: httpx.AsyncClient | None = None) -> None:
        # Only send the apiKey header when we actually have a key.
        self._headers = {"apiKey": api_key} if api_key else {}
        # Remember whether we created the HTTP client, so we only close what we own.
        self._owns_http = http is None
        self._http = http or httpx.AsyncClient()

    async def _get(self, params: dict) -> dict:
        """Send one GET to the CVE endpoint and return the parsed JSON body."""
        response = await self._http.get(
            NVD_URL, params=params, headers=self._headers, timeout=TIMEOUT_SECONDS
        )
        response.raise_for_status()  # turn 4xx/5xx into an exception (retries come in Step 3)
        return response.json()

    async def aclose(self) -> None:
        """Close the HTTP client, but only if this object created it."""
        if self._owns_http:
            await self._http.aclose()
