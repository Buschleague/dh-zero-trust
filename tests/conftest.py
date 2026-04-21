"""Shared fixtures for SCC client tests."""

import base64
import json
import time
import pytest
from pathlib import Path
from unittest.mock import MagicMock


FAKE_KEY_ID = "test_key_id_12345"
FAKE_ACCESS_TOKEN = "test_access_token_secret"  # non-JWT format
FAKE_REFRESH_TOKEN = "test_refresh_token_abc"
FAKE_BEARER_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.fake_bearer"
FAKE_NEW_REFRESH_TOKEN = "test_refresh_token_rotated_xyz"


def make_fake_jwt(exp_offset_seconds: int = 3600) -> str:
    """Build a fake JWT with a controllable exp claim."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
    payload_dict = {"exp": int(time.time()) + exp_offset_seconds, "sub": "test"}
    payload = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.fakesig"


@pytest.fixture
def fake_token_response():
    """Mock OAuth token response from /auth/v2/token."""
    return {
        "access_token": FAKE_BEARER_TOKEN,
        "token_type": "Bearer",
        "expires_in": 3600,
    }


@pytest.fixture
def fake_refresh_response():
    """Mock OAuth token response that includes a rotated refresh token."""
    return {
        "access_token": FAKE_BEARER_TOKEN,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": FAKE_NEW_REFRESH_TOKEN,
    }


@pytest.fixture
def scc_env_vars(monkeypatch):
    """Set SCC credential env vars for testing."""
    monkeypatch.setenv("SCC_KEY_ID", FAKE_KEY_ID)
    monkeypatch.setenv("SCC_ACCESS_TOKEN", FAKE_ACCESS_TOKEN)
    monkeypatch.setenv("SCC_REFRESH_TOKEN", FAKE_REFRESH_TOKEN)


@pytest.fixture
def tmp_token_path(tmp_path):
    """Temporary path for persisted token file."""
    return tmp_path / ".scc_tokens.json"


@pytest.fixture
def mock_paginated_responses():
    """Factory for building multi-page API responses."""
    def _build(items, page_size=2):
        pages = []
        for i in range(0, len(items), page_size):
            chunk = items[i : i + page_size]
            pages.append({"data": chunk, "meta": {"total": len(items)}})
        return pages
    return _build
