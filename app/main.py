from __future__ import annotations

import os
import time
from typing import List, Optional

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, auth_supabase
from .config import Settings
from .detector import Detector, _host, _link_structure
from .explain import build_explanation
from .i18n import detect_language, norm_lang, tips as i18n_tips, ui, verdict_label
from .india import HELPLINE, classify_scam_type, scam_type_name, tip_keys
from .privacy import content_hash, redact
from .ratelimit import RateLimiter
from .reputation import get_reputation
from .repository import ReportRecord, ScanRecord, get_repository
from .schemas import (AuthOut, CheckLinkIn, CheckLinkOut, HealthOut, HistoryItem,
                      OtpRequestIn, OtpVerifyIn, ReportIn, ReportOut, ScanIn, ScanOut)
from .web import render_community, render_legal, render_page

settings = Settings.from_env()
detector = Detector(reputation=get_reputation(settings))
repo = get_repository(settings)
limiter = RateLimiter(settings.rate_limit_per_min, settings.rate_limit_per_day)

if settings.sentry_mode == "live":                       # scrubbed error capture (§11)
    try:
        import sentry_sdk
        sentry_sdk.init(dsn=settings.sentry_dsn, send_default_pii=False,
                        traces_sample_rate=0.0, environment=settings.env)
    except Exception:
        pass

app = FastAPI(title="ScamShield — AI Scam & Fraud Detection (India)", version=__version__)

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_STATIC_DIR):
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# Cross-cutting: security headers, CORS, error envelope
# --------------------------------------------------------------------------- #
# script-src is 'self' only (no 'unsafe-inline'): the UI JS lives in
# /static/app.js and page data is passed via a non-executable JSON <script>.
_CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Content-Security-Policy"] = _CSP
    return resp


def _err(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})


@app.exception_handler(RequestValidationError)
async def _validation_handler(request: Request, exc: RequestValidationError):
    return _err(400, "invalid_request", "Request failed validation. Check content and size limits.")


# --------------------------------------------------------------------------- #
# Helpers: client ip, rate limit, auth
# --------------------------------------------------------------------------- #
def _client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    # Only trust X-Forwarded-For when the direct peer is a configured proxy;
    # otherwise the header is attacker-spoofable and would defeat rate limiting.
    if peer in settings.trusted_proxies:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return peer


def rate_limit(request: Request):
    allowed, retry = limiter.check(_client_ip(request))
    if not allowed:
        raise _RateLimited(retry)


class _RateLimited(Exception):
    def __init__(self, retry: int):
        self.retry = retry


@app.exception_handler(_RateLimited)
async def _rl_handler(request: Request, exc: _RateLimited):
    resp = _err(429, "rate_limited", "Too many requests. Please slow down.")
    resp.headers["Retry-After"] = str(exc.retry)
    return resp


_AUTH_CACHE: dict = {}          # token -> (uid, expiry_ts); short TTL to cap auth round-trips
_AUTH_TTL = 60.0


def _verify_supabase_token(token: str) -> Optional[str]:
    # cheap structural gate before any network call (a JWT has 3 dot-parts)
    if token.count(".") != 2 or len(token) < 20:
        return None
    now = time.time()
    hit = _AUTH_CACHE.get(token)
    if hit and hit[1] > now:
        return hit[0]
    try:
        import httpx
        r = httpx.get(f"{settings.supabase_url.rstrip('/')}/auth/v1/user",
                      headers={"Authorization": f"Bearer {token}",
                               "apikey": settings.supabase_anon_key}, timeout=4.0)
        uid = r.json().get("id") if r.status_code == 200 else None
    except Exception:
        uid = None
    if uid:
        _AUTH_CACHE[token] = (uid, now + _AUTH_TTL)
    return uid


def current_user(request: Request) -> Optional[str]:
    """Authenticated user id, or None (anonymous). Auth mode is decoupled from
    storage: 'debug' (non-prod only) trusts X-User-Id; 'jwt' verifies a Supabase
    token and FAILS CLOSED (401) if a token is present but invalid; 'none' is
    anonymous-only. A client-supplied identity header is never trusted in prod."""
    mode = settings.auth_mode
    if mode == "debug":
        return request.headers.get("x-user-id") or None
    if mode == "jwt":
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return None                      # no token => anonymous
        uid = _verify_supabase_token(auth[7:].strip())
        if not uid:
            raise _Unauthorized()            # token present but invalid => fail closed
        return uid
    return None                              # mode == "none"


def require_user(request: Request) -> str:
    uid = current_user(request)
    if not uid:
        raise _Unauthorized()
    return uid


class _Unauthorized(Exception):
    pass


@app.exception_handler(_Unauthorized)
async def _auth_handler(request: Request, exc: _Unauthorized):
    return _err(401, "unauthorized", "Sign in required for this action.")


# --------------------------------------------------------------------------- #
# UI + legal
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
def home(lang: str = ""):
    return HTMLResponse(render_page(lang or settings.default_language, settings))


@app.get("/privacy", response_class=HTMLResponse)
def privacy_page(lang: str = ""):
    return HTMLResponse(render_legal("privacy", lang or settings.default_language, settings))


@app.get("/terms", response_class=HTMLResponse)
def terms_page(lang: str = ""):
    return HTMLResponse(render_legal("terms", lang or settings.default_language, settings))


@app.get("/community", response_class=HTMLResponse)
def community_page(lang: str = ""):
    return HTMLResponse(render_community(repo.approved_reports(),
                                         lang or settings.default_language, settings))


@app.get("/health", response_model=HealthOut)
def health():
    return HealthOut(ok=True, version=__version__, modes=settings.modes())


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
@app.post("/api/scan", response_model=ScanOut)
def scan(body: ScanIn, request: Request, _rl=Depends(rate_limit)):
    lang = norm_lang(body.language or detect_language(body.content, settings.default_language))
    result = detector.scan(body.content, kind=body.type)
    stype = classify_scam_type(body.content)
    explanation = build_explanation(result, lang, settings, stype)
    tips = i18n_tips(tip_keys(result.categories, stype), lang)

    uid = current_user(request)
    scan_id = None
    if body.store or uid is not None:                     # persist only when useful
        store_raw = body.store or settings.store_raw_default
        rec = ScanRecord(
            content_hash=content_hash(body.content), type=body.type,
            score=result.risk_score, verdict=result.verdict, language=lang,
            user_id=uid,
            signals=[redact(s) for s in result.signals],  # never persist raw PII (§10)
            raw=(body.content if store_raw else None),
        )
        try:
            scan_id = repo.save_scan(rec)
        except Exception:
            scan_id = None

    return ScanOut(
        score=result.risk_score, verdict=result.verdict,
        label=verdict_label(result.verdict, lang),
        signals=result.signals, categories=result.categories,
        urls=result.urls, phones=result.phones, emails=result.emails,
        upi_ids=result.upi_ids, crypto=result.crypto, language=lang,
        scam_type=stype, scam_type_name=scam_type_name(stype),
        explanation=explanation, safety_tips=tips, helpline=HELPLINE,
        disclaimer=ui(lang)["disclaimer"], scan_id=scan_id,
    )


@app.post("/api/check-link", response_model=CheckLinkOut)
def check_link(body: CheckLinkIn, request: Request, _rl=Depends(rate_limit)):
    url = body.url.strip()
    rep = detector.rep.check_link(url)
    concerns = _link_structure(url)
    reasons: List[str] = []
    worst = "clean"
    if rep in ("malicious", "suspicious"):
        worst = rep
        reasons.append(f"threat intelligence: {rep}")
    for sev, msg in concerns:
        reasons.append(msg)
        if sev == "malicious":
            worst = "malicious"
        elif sev == "suspicious" and worst != "malicious":
            worst = "suspicious"
    if worst == "clean" and rep == "unknown" and not concerns:
        worst = "unknown"
    score = {"malicious": 85, "suspicious": 50}.get(worst, 0)
    # 'unknown' must NOT read as "Safe" — a scam tool should stay cautious about
    # links it has no intelligence on.
    label = {"malicious": "Dangerous", "suspicious": "Suspicious",
             "unknown": "Unknown — no rating", "clean": "Safe"}.get(worst, "Safe")
    return CheckLinkOut(url=url, reputation=worst, score=score, label=label,
                        reasons=reasons or ["No known threats found — treat unfamiliar links with caution."])


@app.post("/api/auth/request-otp")
def auth_request_otp(body: OtpRequestIn, request: Request, _rl=Depends(rate_limit)):
    if settings.auth_mode != "jwt":
        return _err(501, "auth_not_configured", "Sign-in is available on the hosted version.")
    res = auth_supabase.request_otp(settings, body.email)
    if not res.get("ok"):
        return _err(502, "auth_failed", res.get("error", "Could not send the code."))
    return {"sent": True}


@app.post("/api/auth/verify-otp", response_model=AuthOut)
def auth_verify_otp(body: OtpVerifyIn, request: Request, _rl=Depends(rate_limit)):
    if settings.auth_mode != "jwt":
        return _err(501, "auth_not_configured", "Sign-in is available on the hosted version.")
    res = auth_supabase.verify_otp(settings, body.email, body.token)
    if not res.get("ok"):
        return _err(401, "auth_failed", res.get("error", "Invalid or expired code."))
    return AuthOut(access_token=res["access_token"], expires_in=res["expires_in"],
                   user_id=res["user_id"])


@app.get("/api/reports")
def list_reports():
    rows = repo.approved_reports()
    return {"reports": [{"pattern": r.pattern, "category": r.category,
                         "upvotes": r.upvotes, "created_at": r.created_at} for r in rows]}


@app.post("/api/report", response_model=ReportOut)
def create_report(body: ReportIn, request: Request, _rl=Depends(rate_limit),
                  uid: str = Depends(require_user)):
    rec = ReportRecord(pattern=redact(body.pattern), category=body.category, user_id=uid)
    try:
        rid = repo.add_report(rec)
    except Exception:
        return _err(503, "store_unavailable", "Could not save the report right now.")
    return ReportOut(id=rid, status=rec.status)


@app.get("/api/history", response_model=List[HistoryItem])
def history(request: Request, uid: str = Depends(require_user)):
    rows = repo.list_scans(uid)
    return [HistoryItem(id=r.id, content_hash=r.content_hash, type=r.type,
                        score=r.score, verdict=r.verdict, language=r.language,
                        created_at=r.created_at) for r in rows]


@app.get("/api/export-my-data")
def export_my_data(request: Request, uid: str = Depends(require_user)):
    rows = repo.list_scans(uid)
    # explicit whitelist — never echo the raw column or unredacted internals
    return {"user_id": uid, "scans": [
        {"id": r.id, "content_hash": r.content_hash, "type": r.type,
         "score": r.score, "verdict": r.verdict, "signals": r.signals,
         "language": r.language, "created_at": r.created_at} for r in rows]}


@app.post("/api/delete-my-data")
def delete_my_data(request: Request, uid: str = Depends(require_user)):
    deleted = repo.delete_user_data(uid)
    return {"deleted": deleted}
