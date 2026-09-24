"""
Client for interacting with Arch User Repository (AUR) RPC and Git endpoints.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

logger = logging.getLogger(__name__)

AUR_RPC_URL = "https://aur.archlinux.org/rpc/v5"
AUR_CGIT_RAW = "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h="
USER_AGENT = "AUR-Sentry-Bot/0.1.0 (+https://github.com/rebizzz/aur-sentry)"


class AURClient:
    def __init__(self, timeout: int = 15) -> None:
        self.timeout = timeout

    def _get(self, url: str) -> Optional[bytes]:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            logger.warning("HTTP %d for URL: %s", e.code, url)
            return None
        except Exception as e:
            logger.warning("Network error fetching %s: %s", url, e)
            return None

    def get_package_info(self, pkgname: str) -> Optional[dict[str, Any]]:
        """Fetch package metadata from AUR RPC v5 info endpoint."""
        url = f"{AUR_RPC_URL}/info/{urllib.parse.quote(pkgname)}"
        data = self._get(url)
        if not data:
            return None
        try:
            payload = json.loads(data.decode("utf-8"))
            results = payload.get("results", [])
            return results[0] if results else None
        except Exception as e:
            logger.error("Failed to parse AUR RPC response for %s: %s", pkgname, e)
            return None

    def search_recent(self, query: str = "") -> list[dict[str, Any]]:
        """Search packages via AUR RPC."""
        url = f"{AUR_RPC_URL}/search/{urllib.parse.quote(query)}"
        data = self._get(url)
        if not data:
            return []
        try:
            payload = json.loads(data.decode("utf-8"))
            return payload.get("results", [])
        except Exception as e:
            logger.error("Failed to parse search response: %s", e)
            return []

    def fetch_pkgbuild(self, pkgname: str) -> Optional[str]:
        """Fetch the raw PKGBUILD directly from AUR cgit."""
        url = f"{AUR_CGIT_RAW}{urllib.parse.quote(pkgname)}"
        data = self._get(url)
        if not data:
            return None
        try:
            return data.decode("utf-8", errors="replace")
        except Exception as e:
            logger.error("Failed to decode PKGBUILD for %s: %s", pkgname, e)
            return None
