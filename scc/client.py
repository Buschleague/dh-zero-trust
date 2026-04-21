"""
HTTP client wrapper for Cisco Security Cloud Control API.

Handles bearer auth injection, page-based pagination, rate-limit
backoff (429), and retry logic.
"""

import logging
import time
from typing import Any

import httpx

from scc.auth import TokenManager, load_token_manager

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.sse.cisco.com"
MAX_RETRIES = 3
DEFAULT_PAGE_SIZE = 100


class SccClient:
    """Authenticated HTTP client for Secure Access API."""

    def __init__(self, token_manager: TokenManager, base_url: str = DEFAULT_BASE_URL):
        self._token_manager = token_manager
        self._base_url = base_url
        self._http = httpx.Client(timeout=30.0)

    def get(self, path: str, params: dict | None = None) -> Any:
        """GET with auth, rate-limit retry, and backoff."""
        url = f"{self._base_url}{path}"
        backoff = 1.0

        for attempt in range(MAX_RETRIES + 1):
            token = self._token_manager.get_bearer_token()
            headers = {"Authorization": f"Bearer {token}"}

            resp = self._http.request("GET", url, headers=headers, params=params)

            if resp.status_code == 429:
                if attempt == MAX_RETRIES:
                    resp.raise_for_status()
                wait = float(resp.headers.get("Retry-After", backoff))
                logger.info("Rate limited on %s, waiting %.1fs (attempt %d)", path, wait, attempt + 1)
                time.sleep(wait)
                backoff = min(backoff * 2, 60.0)
                continue

            resp.raise_for_status()
            return resp.json()

    def paginated_get(
        self,
        path: str,
        params: dict | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> list:
        """Fetch all pages from a paginated endpoint."""
        all_items: list = []
        page = 1
        base_params = dict(params or {})

        while True:
            query = {**base_params, "limit": page_size, "page": page}
            result = self.get(path, params=query)

            # Handle plain list responses (no pagination wrapper)
            if isinstance(result, list):
                return result

            items = result.get("data", [])
            all_items.extend(items)

            if not items or len(all_items) >= result.get("meta", {}).get("total", len(all_items)):
                break

            page += 1

        return all_items

    def close(self):
        """Close the underlying HTTP client."""
        self._http.close()


def get_scc_client(base_url: str = DEFAULT_BASE_URL) -> SccClient:
    """Create an SccClient from environment variables."""
    tm = load_token_manager()
    return SccClient(tm, base_url=base_url)
