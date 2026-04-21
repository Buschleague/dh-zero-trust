"""
OAuth token management for Cisco Security Cloud Control.

Handles three authentication strategies with probe-and-fallback:
  1. Direct bearer — if ACCESS_TOKEN is already a JWT, use it directly
  2. Client credentials grant (KEY_ID as client_id, ACCESS_TOKEN as client_secret)
  3. Refresh token grant (if client credentials fail with 401)

Persists rotated tokens to config/.scc_tokens.json to survive restarts.
"""

import json
import logging
import os
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

_config_path = Path(__file__).parent.parent / "config" / ".env"
load_dotenv(_config_path)

TOKEN_URL = "https://api.sse.cisco.com/auth/v2/token"
DEFAULT_TOKEN_PATH = Path(__file__).parent.parent / "config" / ".scc_tokens.json"
_EXPIRY_BUFFER_SECONDS = 60


class TokenManager:
    """Manages OAuth bearer tokens with probe-and-fallback auth."""

    def __init__(
        self,
        key_id: str,
        access_token: str,
        refresh_token: str,
        token_path: Path | None = None,
    ):
        self.key_id = key_id
        self.access_token = access_token
        self.refresh_token = refresh_token
        self._token_path = token_path or DEFAULT_TOKEN_PATH
        self._bearer_token: str | None = None
        self._expires_at: float = 0.0
        self._load_persisted_tokens()

    def get_bearer_token(self) -> str:
        """Return a valid bearer token, fetching or refreshing as needed."""
        if not self.is_expired():
            return self._bearer_token

        # Strategy 1: if access_token looks like a JWT, use it directly
        direct = self._try_direct_bearer()
        if direct is not None:
            return self._apply_token(direct)

        # Strategy 2: client_credentials grant
        token_data = self._try_client_credentials()
        if token_data is not None:
            return self._apply_token(token_data)

        # Strategy 3: refresh_token grant
        token_data = self._try_refresh_token()
        if token_data is not None:
            return self._apply_token(token_data)

        raise RuntimeError(
            "All authentication methods failed. Check SCC_KEY_ID, "
            "SCC_ACCESS_TOKEN, and SCC_REFRESH_TOKEN in config/.env"
        )

    def _apply_token(self, token_data: dict) -> str:
        """Store token data and return the bearer string."""
        self._bearer_token = token_data["access_token"]
        self._expires_at = time.time() + token_data.get("expires_in", 3600) - _EXPIRY_BUFFER_SECONDS

        if "refresh_token" in token_data:
            self.refresh_token = token_data["refresh_token"]
            self._persist_tokens(token_data)

        return self._bearer_token

    def is_expired(self) -> bool:
        """True if there is no token or it has expired (with buffer)."""
        if self._bearer_token is None:
            return True
        return time.time() >= self._expires_at

    def _try_direct_bearer(self) -> dict | None:
        """Use access_token directly if it's a JWT (has 3 dot-separated parts)."""
        parts = self.access_token.split(".")
        if len(parts) != 3:
            return None

        # Decode expiry from JWT payload
        try:
            import base64
            payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
            exp = claims.get("exp", 0)
            # Handle millisecond timestamps (Webex uses ms)
            if exp > 1e12:
                exp = exp / 1000
            if exp > time.time():
                logger.info("Using access_token as direct bearer (expires %.0fs from now)", exp - time.time())
                return {"access_token": self.access_token, "expires_in": int(exp - time.time())}
            logger.info("Direct bearer JWT is expired")
        except Exception as e:
            logger.debug("Could not decode JWT: %s", e)
        return None

    def _try_client_credentials(self) -> dict | None:
        """Attempt OAuth2 client_credentials grant."""
        try:
            resp = httpx.post(
                TOKEN_URL,
                auth=(self.key_id, self.access_token),
                data={"grant_type": "client_credentials"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code == 200:
                return resp.json()
            logger.info("Client credentials returned %d", resp.status_code)
        except httpx.HTTPError as e:
            logger.warning("Client credentials request failed: %s", e)
        return None

    def _try_refresh_token(self) -> dict | None:
        """Attempt OAuth2 refresh_token grant."""
        try:
            resp = httpx.post(
                TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self.refresh_token,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code == 200:
                return resp.json()
            logger.info("Refresh token returned %d", resp.status_code)
        except httpx.HTTPError as e:
            logger.warning("Refresh token request failed: %s", e)
        return None

    def _persist_tokens(self, token_data: dict) -> None:
        """Save tokens to disk so they survive restarts."""
        to_save = {
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token", self.refresh_token),
            "expires_at": self._expires_at,
        }
        self._token_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._token_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(to_save, indent=2))
        tmp.replace(self._token_path)
        logger.debug("Persisted tokens to %s", self._token_path)

    def _load_persisted_tokens(self) -> None:
        """Load previously persisted tokens if they exist and are valid."""
        if not self._token_path.exists():
            return
        try:
            data = json.loads(self._token_path.read_text())
            expires_at = data.get("expires_at", 0)
            if time.time() < expires_at:
                self._bearer_token = data["access_token"]
                self._expires_at = expires_at
                if "refresh_token" in data:
                    self.refresh_token = data["refresh_token"]
                logger.debug("Loaded persisted token (expires in %.0fs)", expires_at - time.time())
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Could not load persisted tokens: %s", e)


def load_token_manager(token_path: Path | None = None) -> TokenManager:
    """Create a TokenManager from environment variables."""
    key_id = os.environ.get("SCC_KEY_ID")
    access_token = os.environ.get("SCC_ACCESS_TOKEN")
    refresh_token = os.environ.get("SCC_REFRESH_TOKEN")

    if not all([key_id, access_token, refresh_token]):
        raise EnvironmentError(
            "Missing SCC credentials. Ensure SCC_KEY_ID, SCC_ACCESS_TOKEN, "
            "and SCC_REFRESH_TOKEN are set in config/.env"
        )

    return TokenManager(
        key_id=key_id,
        access_token=access_token,
        refresh_token=refresh_token,
        token_path=token_path or DEFAULT_TOKEN_PATH,
    )
