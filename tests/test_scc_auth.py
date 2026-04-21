"""Tests for scc.auth — TokenManager with probe-and-fallback OAuth."""

import json
import time
from unittest.mock import patch, MagicMock

import httpx
import pytest

from tests.conftest import (
    FAKE_KEY_ID,
    FAKE_ACCESS_TOKEN,
    FAKE_REFRESH_TOKEN,
    FAKE_BEARER_TOKEN,
    FAKE_NEW_REFRESH_TOKEN,
    make_fake_jwt,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _mock_response(status_code, json_body=None):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    resp.text = json.dumps(json_body or {})
    return resp


# ── Direct bearer (JWT access token) ────────────────────────────────────────

class TestDirectBearer:
    def test_uses_jwt_directly_without_http_call(self, tmp_token_path):
        from scc.auth import TokenManager

        jwt = make_fake_jwt(exp_offset_seconds=3600)
        tm = TokenManager(FAKE_KEY_ID, jwt, FAKE_REFRESH_TOKEN, tmp_token_path)

        with patch("httpx.post") as mock_post:
            token = tm.get_bearer_token()

        assert token == jwt
        mock_post.assert_not_called()

    def test_skips_expired_jwt_and_falls_through(self, tmp_token_path, fake_token_response):
        from scc.auth import TokenManager

        expired_jwt = make_fake_jwt(exp_offset_seconds=-100)
        tm = TokenManager(FAKE_KEY_ID, expired_jwt, FAKE_REFRESH_TOKEN, tmp_token_path)
        # Falls through to client_credentials which also fails, then refresh
        mock_resp = _mock_response(200, fake_token_response)

        with patch("httpx.post", side_effect=[_mock_response(401), mock_resp]):
            token = tm.get_bearer_token()

        assert token == FAKE_BEARER_TOKEN

    def test_non_jwt_skips_direct_bearer(self, tmp_token_path, fake_token_response):
        from scc.auth import TokenManager

        tm = TokenManager(FAKE_KEY_ID, "not-a-jwt", FAKE_REFRESH_TOKEN, tmp_token_path)
        mock_resp = _mock_response(200, fake_token_response)

        with patch("httpx.post", return_value=mock_resp):
            token = tm.get_bearer_token()

        assert token == FAKE_BEARER_TOKEN


# ── TokenManager construction ────────────────────────────────────────────────

class TestTokenManagerInit:
    def test_init_stores_credentials(self, tmp_token_path):
        from scc.auth import TokenManager

        tm = TokenManager(FAKE_KEY_ID, FAKE_ACCESS_TOKEN, FAKE_REFRESH_TOKEN, tmp_token_path)
        assert tm.key_id == FAKE_KEY_ID
        assert tm.access_token == FAKE_ACCESS_TOKEN
        assert tm.refresh_token == FAKE_REFRESH_TOKEN

    def test_init_with_no_token_path(self):
        from scc.auth import TokenManager

        tm = TokenManager(FAKE_KEY_ID, FAKE_ACCESS_TOKEN, FAKE_REFRESH_TOKEN)
        assert tm._token_path is not None  # defaults to config/.scc_tokens.json


# ── Client credentials flow ──────────────────────────────────────────────────

class TestClientCredentials:
    def test_client_credentials_success(self, tmp_token_path, fake_token_response):
        from scc.auth import TokenManager

        tm = TokenManager(FAKE_KEY_ID, FAKE_ACCESS_TOKEN, FAKE_REFRESH_TOKEN, tmp_token_path)
        mock_resp = _mock_response(200, fake_token_response)

        with patch("httpx.post", return_value=mock_resp) as mock_post:
            token = tm.get_bearer_token()

        assert token == FAKE_BEARER_TOKEN
        # Verify Basic auth was used with key_id:access_token
        call_kwargs = mock_post.call_args
        assert call_kwargs.kwargs.get("auth") == (FAKE_KEY_ID, FAKE_ACCESS_TOKEN)

    def test_client_credentials_sets_expiry(self, tmp_token_path, fake_token_response):
        from scc.auth import TokenManager

        tm = TokenManager(FAKE_KEY_ID, FAKE_ACCESS_TOKEN, FAKE_REFRESH_TOKEN, tmp_token_path)
        mock_resp = _mock_response(200, fake_token_response)

        with patch("httpx.post", return_value=mock_resp):
            tm.get_bearer_token()

        assert tm._expires_at > time.time()
        assert not tm.is_expired()


# ── Refresh token fallback ───────────────────────────────────────────────────

class TestRefreshTokenFallback:
    def test_falls_back_to_refresh_on_401(self, tmp_token_path, fake_refresh_response):
        from scc.auth import TokenManager

        tm = TokenManager(FAKE_KEY_ID, FAKE_ACCESS_TOKEN, FAKE_REFRESH_TOKEN, tmp_token_path)
        cred_fail = _mock_response(401, {"error": "invalid_client"})
        refresh_ok = _mock_response(200, fake_refresh_response)

        with patch("httpx.post", side_effect=[cred_fail, refresh_ok]):
            token = tm.get_bearer_token()

        assert token == FAKE_BEARER_TOKEN

    def test_both_fail_raises(self, tmp_token_path):
        from scc.auth import TokenManager

        tm = TokenManager(FAKE_KEY_ID, FAKE_ACCESS_TOKEN, FAKE_REFRESH_TOKEN, tmp_token_path)
        cred_fail = _mock_response(401, {"error": "invalid_client"})
        refresh_fail = _mock_response(401, {"error": "invalid_grant"})

        with patch("httpx.post", side_effect=[cred_fail, refresh_fail]):
            with pytest.raises(RuntimeError, match="All authentication methods failed"):
                tm.get_bearer_token()


# ── Token expiry ─────────────────────────────────────────────────────────────

class TestTokenExpiry:
    def test_is_expired_when_no_token(self, tmp_token_path):
        from scc.auth import TokenManager

        tm = TokenManager(FAKE_KEY_ID, FAKE_ACCESS_TOKEN, FAKE_REFRESH_TOKEN, tmp_token_path)
        assert tm.is_expired()

    def test_is_expired_when_past_expiry(self, tmp_token_path):
        from scc.auth import TokenManager

        tm = TokenManager(FAKE_KEY_ID, FAKE_ACCESS_TOKEN, FAKE_REFRESH_TOKEN, tmp_token_path)
        tm._bearer_token = FAKE_BEARER_TOKEN
        tm._expires_at = time.time() - 10  # expired 10s ago
        assert tm.is_expired()

    def test_not_expired_when_fresh(self, tmp_token_path):
        from scc.auth import TokenManager

        tm = TokenManager(FAKE_KEY_ID, FAKE_ACCESS_TOKEN, FAKE_REFRESH_TOKEN, tmp_token_path)
        tm._bearer_token = FAKE_BEARER_TOKEN
        tm._expires_at = time.time() + 3000
        assert not tm.is_expired()

    def test_reuses_valid_token(self, tmp_token_path, fake_token_response):
        from scc.auth import TokenManager

        tm = TokenManager(FAKE_KEY_ID, FAKE_ACCESS_TOKEN, FAKE_REFRESH_TOKEN, tmp_token_path)
        mock_resp = _mock_response(200, fake_token_response)

        with patch("httpx.post", return_value=mock_resp) as mock_post:
            token1 = tm.get_bearer_token()
            token2 = tm.get_bearer_token()

        assert token1 == token2
        assert mock_post.call_count == 1  # only one HTTP call


# ── Token persistence ────────────────────────────────────────────────────────

class TestTokenPersistence:
    def test_persist_tokens_writes_file(self, tmp_token_path, fake_refresh_response):
        from scc.auth import TokenManager

        tm = TokenManager(FAKE_KEY_ID, FAKE_ACCESS_TOKEN, FAKE_REFRESH_TOKEN, tmp_token_path)
        cred_fail = _mock_response(401)
        refresh_ok = _mock_response(200, fake_refresh_response)

        with patch("httpx.post", side_effect=[cred_fail, refresh_ok]):
            tm.get_bearer_token()

        assert tmp_token_path.exists()
        saved = json.loads(tmp_token_path.read_text())
        assert saved["access_token"] == FAKE_BEARER_TOKEN
        assert saved["refresh_token"] == FAKE_NEW_REFRESH_TOKEN

    def test_load_persisted_tokens_on_init(self, tmp_token_path):
        from scc.auth import TokenManager

        # Write a persisted token file
        persisted = {
            "access_token": "persisted_bearer",
            "refresh_token": "persisted_refresh",
            "expires_at": time.time() + 3000,
        }
        tmp_token_path.write_text(json.dumps(persisted))

        tm = TokenManager(FAKE_KEY_ID, FAKE_ACCESS_TOKEN, FAKE_REFRESH_TOKEN, tmp_token_path)

        with patch("httpx.post") as mock_post:
            token = tm.get_bearer_token()

        assert token == "persisted_bearer"
        mock_post.assert_not_called()

    def test_ignores_expired_persisted_tokens(self, tmp_token_path, fake_token_response):
        from scc.auth import TokenManager

        persisted = {
            "access_token": "old_bearer",
            "refresh_token": "old_refresh",
            "expires_at": time.time() - 100,
        }
        tmp_token_path.write_text(json.dumps(persisted))

        tm = TokenManager(FAKE_KEY_ID, FAKE_ACCESS_TOKEN, FAKE_REFRESH_TOKEN, tmp_token_path)
        mock_resp = _mock_response(200, fake_token_response)

        with patch("httpx.post", return_value=mock_resp) as mock_post:
            token = tm.get_bearer_token()

        assert token == FAKE_BEARER_TOKEN
        assert mock_post.call_count == 1


# ── Factory function ─────────────────────────────────────────────────────────

class TestLoadFromEnv:
    def test_load_from_env(self, scc_env_vars, tmp_token_path):
        from scc.auth import load_token_manager

        with patch("scc.auth.DEFAULT_TOKEN_PATH", tmp_token_path):
            tm = load_token_manager()

        assert tm.key_id == FAKE_KEY_ID
        assert tm.access_token == FAKE_ACCESS_TOKEN
        assert tm.refresh_token == FAKE_REFRESH_TOKEN

    def test_load_from_env_missing_vars_raises(self, monkeypatch):
        from scc.auth import load_token_manager

        monkeypatch.delenv("SCC_KEY_ID", raising=False)
        monkeypatch.delenv("SCC_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("SCC_REFRESH_TOKEN", raising=False)

        with pytest.raises(EnvironmentError, match="Missing SCC credentials"):
            load_token_manager()
