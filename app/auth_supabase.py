from __future__ import annotations

from typing import Optional

from .config import Settings

# Server-side proxy to Supabase Auth (GoTrue) so the browser only ever talks to
# our own origin (keeps CSP connect-src 'self' and the anon key off the client).
# Passwordless email OTP: request a 6-digit code, then verify it for a JWT.


def _client(settings: Settings, injected=None):
    if injected is not None:
        return injected
    import httpx
    return httpx.Client(
        timeout=8.0,
        headers={"apikey": settings.supabase_anon_key, "Content-Type": "application/json"},
    )


def request_otp(settings: Settings, email: str, client=None) -> dict:
    """Ask GoTrue to email a login code (creating the user if new)."""
    url = settings.supabase_url.rstrip("/") + "/auth/v1/otp"
    try:
        r = _client(settings, client).post(url, json={"email": email, "create_user": True})
        if r.status_code // 100 == 2:
            return {"ok": True}
        return {"ok": False, "error": _msg(r)}
    except Exception:
        return {"ok": False, "error": "auth service unavailable"}


def verify_otp(settings: Settings, email: str, token: str, client=None) -> dict:
    """Verify the emailed code and return a short-lived access token (JWT)."""
    url = settings.supabase_url.rstrip("/") + "/auth/v1/verify"
    try:
        r = _client(settings, client).post(
            url, json={"email": email, "token": token, "type": "email"})
        if r.status_code // 100 == 2:
            d = r.json()
            uid = (d.get("user") or {}).get("id")
            if d.get("access_token") and uid:
                return {"ok": True, "access_token": d["access_token"],
                        "expires_in": d.get("expires_in", 3600), "user_id": uid}
            return {"ok": False, "error": "unexpected auth response"}
        return {"ok": False, "error": _msg(r)}
    except Exception:
        return {"ok": False, "error": "auth service unavailable"}


def _msg(r) -> str:
    try:
        d = r.json()
        return str(d.get("msg") or d.get("error_description") or d.get("error") or "invalid or expired code")
    except Exception:
        return "invalid or expired code"
