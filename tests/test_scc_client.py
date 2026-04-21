"""Tests for scc.client — SccClient with pagination and rate limiting."""

import json
import time
from unittest.mock import patch, MagicMock, PropertyMock

import httpx
import pytest

from tests.conftest import FAKE_BEARER_TOKEN


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mock_token_manager():
    tm = MagicMock()
    tm.get_bearer_token.return_value = FAKE_BEARER_TOKEN
    return tm


def _mock_response(status_code, json_body=None, headers=None):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    resp.headers = headers or {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"{status_code}", request=MagicMock(), response=resp
        )
    return resp


# ── SccClient construction ───────────────────────────────────────────────────

class TestSccClientInit:
    def test_init_with_defaults(self):
        from scc.client import SccClient

        tm = _mock_token_manager()
        client = SccClient(tm)
        assert client._base_url == "https://api.sse.cisco.com"

    def test_init_with_custom_base_url(self):
        from scc.client import SccClient

        tm = _mock_token_manager()
        client = SccClient(tm, base_url="https://custom.api.com")
        assert client._base_url == "https://custom.api.com"


# ── GET requests ─────────────────────────────────────────────────────────────

class TestGet:
    def test_get_sends_auth_header(self):
        from scc.client import SccClient

        tm = _mock_token_manager()
        client = SccClient(tm)
        body = {"data": [{"id": 1}]}

        with patch.object(client._http, "request", return_value=_mock_response(200, body)) as mock_req:
            result = client.get("/admin/v2/test")

        call_kwargs = mock_req.call_args
        assert call_kwargs.kwargs["headers"]["Authorization"] == f"Bearer {FAKE_BEARER_TOKEN}"

    def test_get_returns_json(self):
        from scc.client import SccClient

        tm = _mock_token_manager()
        client = SccClient(tm)
        body = {"data": [{"id": 1}], "meta": {"total": 1}}

        with patch.object(client._http, "request", return_value=_mock_response(200, body)):
            result = client.get("/admin/v2/test")

        assert result == body

    def test_get_passes_params(self):
        from scc.client import SccClient

        tm = _mock_token_manager()
        client = SccClient(tm)
        body = {"data": []}

        with patch.object(client._http, "request", return_value=_mock_response(200, body)) as mock_req:
            client.get("/admin/v2/test", params={"limit": 50})

        call_kwargs = mock_req.call_args
        assert call_kwargs.kwargs["params"] == {"limit": 50}


# ── Pagination ───────────────────────────────────────────────────────────────

class TestPaginatedGet:
    def test_single_page(self):
        from scc.client import SccClient

        tm = _mock_token_manager()
        client = SccClient(tm)
        page1 = {"data": [{"id": 1}, {"id": 2}], "meta": {"total": 2}}

        with patch.object(client, "get", return_value=page1):
            result = client.paginated_get("/admin/v2/test", page_size=100)

        assert result == [{"id": 1}, {"id": 2}]

    def test_multi_page(self):
        from scc.client import SccClient

        tm = _mock_token_manager()
        client = SccClient(tm)
        page1 = {"data": [{"id": 1}, {"id": 2}], "meta": {"total": 3}}
        page2 = {"data": [{"id": 3}], "meta": {"total": 3}}

        with patch.object(client, "get", side_effect=[page1, page2]):
            result = client.paginated_get("/admin/v2/test", page_size=2)

        assert result == [{"id": 1}, {"id": 2}, {"id": 3}]

    def test_empty_response(self):
        from scc.client import SccClient

        tm = _mock_token_manager()
        client = SccClient(tm)
        page1 = {"data": [], "meta": {"total": 0}}

        with patch.object(client, "get", return_value=page1):
            result = client.paginated_get("/admin/v2/test")

        assert result == []

    def test_handles_list_response_without_data_key(self):
        from scc.client import SccClient

        tm = _mock_token_manager()
        client = SccClient(tm)
        # Some endpoints return a plain list
        response = [{"id": 1}, {"id": 2}]

        with patch.object(client, "get", return_value=response):
            result = client.paginated_get("/admin/v2/test")

        assert result == [{"id": 1}, {"id": 2}]


# ── Rate limiting ────────────────────────────────────────────────────────────

class TestRateLimiting:
    def test_retries_on_429(self):
        from scc.client import SccClient

        tm = _mock_token_manager()
        client = SccClient(tm)
        rate_limited = _mock_response(429, headers={"Retry-After": "1"})
        rate_limited.raise_for_status.side_effect = httpx.HTTPStatusError(
            "429", request=MagicMock(), response=rate_limited
        )
        success = _mock_response(200, {"data": []})

        with patch.object(client._http, "request", side_effect=[rate_limited, success]):
            with patch("time.sleep") as mock_sleep:
                result = client.get("/admin/v2/test")

        mock_sleep.assert_called_once_with(1.0)
        assert result == {"data": []}

    def test_raises_after_max_retries(self):
        from scc.client import SccClient

        tm = _mock_token_manager()
        client = SccClient(tm)
        rate_limited = _mock_response(429, headers={})
        rate_limited.raise_for_status.side_effect = httpx.HTTPStatusError(
            "429", request=MagicMock(), response=rate_limited
        )

        with patch.object(client._http, "request", return_value=rate_limited):
            with patch("time.sleep"):
                with pytest.raises(httpx.HTTPStatusError):
                    client.get("/admin/v2/test")

    def test_exponential_backoff_without_retry_after(self):
        from scc.client import SccClient

        tm = _mock_token_manager()
        client = SccClient(tm)
        rate_limited = _mock_response(429, headers={})
        rate_limited.raise_for_status.side_effect = httpx.HTTPStatusError(
            "429", request=MagicMock(), response=rate_limited
        )
        success = _mock_response(200, {"data": []})

        with patch.object(client._http, "request", side_effect=[rate_limited, rate_limited, success]):
            with patch("time.sleep") as mock_sleep:
                client.get("/admin/v2/test")

        # Backoff: 1s, 2s
        assert mock_sleep.call_count == 2
        assert mock_sleep.call_args_list[0].args[0] == 1.0
        assert mock_sleep.call_args_list[1].args[0] == 2.0


# ── Factory function ─────────────────────────────────────────────────────────

class TestGetSccClient:
    def test_factory_creates_client(self, scc_env_vars, tmp_token_path):
        from scc.client import get_scc_client

        with patch("scc.client.load_token_manager") as mock_load:
            mock_load.return_value = _mock_token_manager()
            client = get_scc_client()

        assert client is not None
