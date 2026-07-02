from __future__ import annotations

from typing import Optional

from .config import Settings
from .detector import MockReputation

_SB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_SB_THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
               "POTENTIALLY_HARMFUL_APPLICATION"]


class GoogleSafeBrowsingReputation:
    """Live link reputation via Google Safe Browsing Lookup API (free with a
    key). SSRF-safe: we only submit the URL string to Google's API — we never
    fetch the suspicious URL ourselves. Phone/email are out of scope for SB and
    return 'unknown' (wire a phone/email feed behind the same interface later)."""

    def __init__(self, api_key: str, timeout: float = 8.0, client=None) -> None:
        self._key = api_key
        self._timeout = timeout
        self._client = client                       # injectable for tests

    def _http(self):
        if self._client is not None:
            return self._client
        import httpx
        return httpx.Client(timeout=self._timeout)

    def check_link(self, url: str) -> str:
        payload = {
            "client": {"clientId": "scamshield", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": _SB_THREATS,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            client = self._http()
            r = client.post(_SB_URL, params={"key": self._key}, json=payload)
            r.raise_for_status()
            data = r.json()
            return "malicious" if data.get("matches") else "unknown"
        except Exception:
            return "unknown"                        # graceful degradation (§11)

    def check_phone(self, phone: str) -> str:
        return "unknown"

    def check_email(self, email: str) -> str:
        return "unknown"


def get_reputation(settings: Settings):
    if settings.reputation_mode == "live":
        return GoogleSafeBrowsingReputation(settings.safe_browsing_api_key,
                                            timeout=settings.explanation_timeout)
    return MockReputation()
