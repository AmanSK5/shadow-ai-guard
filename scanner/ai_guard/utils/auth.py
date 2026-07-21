"""Authentication helpers for external APIs.

All credentials are read from environment variables, never from config files.
Env var naming convention: {PREFIX}_{FIELD}
  e.g. AIGUARD_ENTRA_TENANT_ID, AIGUARD_S1_API_TOKEN

Security notes:
  - Auth objects suppress __repr__ to prevent token leakage in tracebacks/logs
  - httpx clients enforce TLS and set reasonable timeouts
  - Credentials are validated on load (non-empty, no whitespace padding)
"""

from __future__ import annotations

import logging
import os
import ssl
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Re-acquire token if it expires within this many seconds.
_TOKEN_REFRESH_MARGIN = 300  # 5 minutes


class AuthError(Exception):
    """Raised when authentication fails or credentials are missing."""


def check_env_file_permissions(env_path: str = ".env") -> Optional[str]:
    """Warn if .env file has overly permissive permissions.

    Returns a warning string if permissions are too open, None if OK.
    Only checks on Unix-like systems (macOS/Linux).
    """
    path = Path(env_path)
    if not path.exists():
        return None

    try:
        mode = path.stat().st_mode
        # Check if group or others can read the file
        if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
            return (
                f"WARNING: {env_path} is readable by other users (mode {oct(mode)[-3:]}). "
                f"Run: chmod 600 {env_path}"
            )
    except (OSError, AttributeError):
        # Windows or permission error — skip check
        pass

    return None


def _clean_env_var(name: str) -> str:
    """Read and validate an environment variable.

    Strips whitespace and checks for common mistakes like
    surrounding quotes that got included literally.
    """
    value = os.environ.get(name, "")
    if value:
        value = value.strip().strip("'\"")
    return value


@dataclass
class MSGraphAuth:
    """Microsoft Graph API authentication via MSAL client credentials.

    Required env vars (prefix: AIGUARD_ENTRA):
      AIGUARD_ENTRA_TENANT_ID
      AIGUARD_ENTRA_CLIENT_ID
      AIGUARD_ENTRA_CLIENT_SECRET
    """

    tenant_id: str
    client_id: str
    client_secret: str = field(repr=False)  # Suppress in tracebacks/logs
    _token: Optional[str] = field(default=None, repr=False)
    _token_expiry: float = field(default=0.0, repr=False)

    @classmethod
    def from_env(cls, prefix: str = "AIGUARD_ENTRA") -> "MSGraphAuth":
        tenant_id = _clean_env_var(f"{prefix}_TENANT_ID")
        client_id = _clean_env_var(f"{prefix}_CLIENT_ID")
        client_secret = _clean_env_var(f"{prefix}_CLIENT_SECRET")

        missing = []
        if not tenant_id:
            missing.append(f"{prefix}_TENANT_ID")
        if not client_id:
            missing.append(f"{prefix}_CLIENT_ID")
        if not client_secret:
            missing.append(f"{prefix}_CLIENT_SECRET")

        if missing:
            raise AuthError(
                f"Missing environment variables for Microsoft Graph: {', '.join(missing)}"
            )

        return cls(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)

    def _token_is_valid(self) -> bool:
        """Check if the cached token exists and is not near expiry."""
        return (
            self._token is not None
            and time.time() < self._token_expiry - _TOKEN_REFRESH_MARGIN
        )

    async def get_token(self) -> str:
        """Acquire an access token using client credentials flow.

        Returns a cached token if still valid, otherwise acquires a new one.
        """
        if self._token_is_valid():
            return self._token

        if self._token is not None:
            logger.info("Graph token expired or near expiry — refreshing")

        try:
            import msal

            app = msal.ConfidentialClientApplication(
                self.client_id,
                authority=f"https://login.microsoftonline.com/{self.tenant_id}",
                client_credential=self.client_secret,
            )
            result = app.acquire_token_for_client(
                scopes=["https://graph.microsoft.com/.default"]
            )

            if "access_token" not in result:
                error_desc = result.get("error_description", "unknown error")
                raise AuthError(f"Failed to acquire Graph token: {error_desc}")

            self._token = result["access_token"]
            self._token_expiry = time.time() + result.get("expires_in", 3600)
            logger.info("Graph token acquired (expires in %ds)", result.get("expires_in", 3600))
            return self._token

        except ImportError:
            raise AuthError(
                "msal package required for Microsoft Graph auth: pip install msal"
            ) from None

    async def graph_client(self) -> httpx.AsyncClient:
        """Create an authenticated httpx client for Microsoft Graph."""
        token = await self.get_token()
        return httpx.AsyncClient(
            base_url="https://graph.microsoft.com/v1.0",
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "ai-guard/0.1.0",
            },
            timeout=30.0,
        )


@dataclass
class SentinelOneAuth:
    """SentinelOne API authentication.

    Required env vars (prefix: AIGUARD_S1):
      AIGUARD_S1_BASE_URL     (e.g. https://your-instance.sentinelone.net)
      AIGUARD_S1_API_TOKEN
    """

    base_url: str
    api_token: str = field(repr=False)  # Suppress in tracebacks/logs

    @classmethod
    def from_env(cls, prefix: str = "AIGUARD_S1") -> "SentinelOneAuth":
        base_url = _clean_env_var(f"{prefix}_BASE_URL")
        api_token = _clean_env_var(f"{prefix}_API_TOKEN")

        missing = []
        if not base_url:
            missing.append(f"{prefix}_BASE_URL")
        if not api_token:
            missing.append(f"{prefix}_API_TOKEN")

        if missing:
            raise AuthError(
                f"Missing environment variables for SentinelOne: {', '.join(missing)}"
            )

        # Validate base URL format
        if not base_url.startswith("https://"):
            raise AuthError(
                f"SentinelOne base URL must use HTTPS: {base_url}"
            )

        return cls(base_url=base_url.rstrip("/"), api_token=api_token)

    def client(self) -> httpx.AsyncClient:
        """Create an authenticated httpx client for SentinelOne."""
        return httpx.AsyncClient(
            base_url=f"{self.base_url}/web/api/v2.1",
            headers={
                "Authorization": f"APIToken {self.api_token}",
                "User-Agent": "ai-guard/0.1.0",
            },
            timeout=30.0,
        )


@dataclass
class JAMFAuth:
    """JAMF Pro API authentication.

    Required env vars (prefix: AIGUARD_JAMF):
      AIGUARD_JAMF_BASE_URL    (e.g. https://yourorg.jamfcloud.com)
      AIGUARD_JAMF_CLIENT_ID
      AIGUARD_JAMF_CLIENT_SECRET
    """

    base_url: str
    client_id: str
    client_secret: str = field(repr=False)  # Suppress in tracebacks/logs
    _token: Optional[str] = field(default=None, repr=False)
    _token_expiry: float = field(default=0.0, repr=False)

    @classmethod
    def from_env(cls, prefix: str = "AIGUARD_JAMF") -> "JAMFAuth":
        base_url = _clean_env_var(f"{prefix}_BASE_URL")
        client_id = _clean_env_var(f"{prefix}_CLIENT_ID")
        client_secret = _clean_env_var(f"{prefix}_CLIENT_SECRET")

        missing = []
        if not base_url:
            missing.append(f"{prefix}_BASE_URL")
        if not client_id:
            missing.append(f"{prefix}_CLIENT_ID")
        if not client_secret:
            missing.append(f"{prefix}_CLIENT_SECRET")

        if missing:
            raise AuthError(
                f"Missing environment variables for JAMF: {', '.join(missing)}"
            )

        if not base_url.startswith("https://"):
            raise AuthError(f"JAMF base URL must use HTTPS: {base_url}")

        return cls(
            base_url=base_url.rstrip("/"),
            client_id=client_id,
            client_secret=client_secret,
        )

    def _token_is_valid(self) -> bool:
        return (
            self._token is not None
            and time.time() < self._token_expiry - _TOKEN_REFRESH_MARGIN
        )

    async def get_token(self) -> str:
        if self._token_is_valid():
            return self._token

        if self._token is not None:
            logger.info("JAMF token expired or near expiry — refreshing")

        async with httpx.AsyncClient(verify=True) as client:
            resp = await client.post(
                f"{self.base_url}/api/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
            )
            resp.raise_for_status()
            token_data = resp.json()
            self._token = token_data["access_token"]
            self._token_expiry = time.time() + token_data.get("expires_in", 1800)
            logger.info("JAMF token acquired (expires in %ds)", token_data.get("expires_in", 1800))
            return self._token

    async def client(self) -> httpx.AsyncClient:
        token = await self.get_token()
        return httpx.AsyncClient(
            base_url=f"{self.base_url}/api/v1",
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "ai-guard/0.1.0",
            },
            timeout=30.0,
            verify=True,
        )
