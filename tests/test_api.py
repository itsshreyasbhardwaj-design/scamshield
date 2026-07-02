from fastapi.testclient import TestClient

import app.main as m
from app.main import app
from app.ratelimit import RateLimiter

# Keep the shared limiter effectively unlimited for functional tests.
m.limiter = RateLimiter(1_000_000, 1_000_000)
client = TestClient(app)


# --------------------------------------------------------------------------- #
# UI + health
# --------------------------------------------------------------------------- #
def test_home_renders():
    r = client.get("/")
    assert r.status_code == 200
    assert "ScamShield" in r.text
    assert "manifest.webmanifest" in r.text


def test_home_hindi():
    r = client.get("/?lang=hi")
    assert "जाँच करें" in r.text                        # localised "Check now"


def test_home_has_qr_and_share_target_hooks():
    r = client.get("/").text
    assert 'id="qrfile"' in r and 'id="qr"' in r        # on-device QR scanner
    assert "/static/app.js" in r                        # share-target handled in app.js


def test_share_target_query_is_accepted():
    # PWA share target posts arrive as ?text=...; home must still render 200
    r = client.get("/?text=You%20won%20a%20lottery%20claim%20now")
    assert r.status_code == 200


def test_community_page_renders():
    r = client.get("/community?lang=hi")
    assert r.status_code == 200
    assert "कम्युनिटी रिपोर्ट्स" in r.text              # localised "Community reports"


def test_health_reports_mock_modes():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["modes"]["llm"] == "mock"
    assert body["modes"]["database"] == "memory"
    assert body["modes"]["country"] == "IN"


def test_security_headers_present():
    r = client.get("/")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" in r.headers
    assert r.headers["x-frame-options"] == "DENY"


# --------------------------------------------------------------------------- #
# /api/scan
# --------------------------------------------------------------------------- #
def test_scan_india_kyc_scam():
    body = {"content": "URGENT: Your SBI account KYC is pending. Update your KYC now at "
                       "http://sbi-kyc-verify.com and share your OTP or account will be blocked.",
            "type": "message"}
    r = client.post("/api/scan", json=body)
    assert r.status_code == 200
    d = r.json()
    assert d["verdict"] == "scam"
    assert d["score"] >= 60
    assert d["scam_type"] == "kyc_account"
    assert d["safety_tips"]
    assert d["helpline"]["cyber_helpline"] == "1930"
    assert d["language"] == "en"
    assert d["scan_id"] is None                        # anonymous + no opt-in => not stored


def test_scan_hindi_localised_label():
    r = client.post("/api/scan", json={"content": "तुरंत अपना OTP भेजें वरना खाता बंद हो जाएगा"})
    d = r.json()
    assert d["language"] == "hi"
    assert d["label"] == "संदिग्ध"                      # localised "Suspicious"


def test_scan_benign_is_safe():
    r = client.post("/api/scan", json={"content": "Hey, are we still on for lunch tomorrow at 1?"})
    d = r.json()
    assert d["verdict"] == "safe"


def test_scan_empty_content_returns_error_envelope():
    r = client.post("/api/scan", json={"content": ""})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_request"


# --------------------------------------------------------------------------- #
# /api/check-link
# --------------------------------------------------------------------------- #
def test_check_link_malicious():
    r = client.post("/api/check-link", json={"url": "http://secure-update.example"})
    d = r.json()
    assert d["reputation"] == "malicious"
    assert d["score"] >= 80


def test_check_link_clean():
    r = client.post("/api/check-link", json={"url": "https://www.google.com"})
    assert r.json()["score"] == 0


def test_check_link_unknown_is_not_labelled_safe():
    d = client.post("/api/check-link", json={"url": "https://some-unrated-xyz-123.com"}).json()
    assert d["reputation"] == "unknown"
    assert d["label"].startswith("Unknown")            # never falsely reassuring "Safe"


# --------------------------------------------------------------------------- #
# auth-gated: history, report, export, delete
# --------------------------------------------------------------------------- #
def test_history_requires_auth():
    r = client.get("/api/history")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"


def test_scan_persists_for_authenticated_user_and_history():
    h = {"x-user-id": "hist-user"}
    client.post("/api/scan", json={"content": "share your OTP now http://secure-update.example"}, headers=h)
    r = client.get("/api/history", headers=h)
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) >= 1
    assert rows[0]["content_hash"] and rows[0]["verdict"]


def test_report_flow_pending_not_public():
    h = {"x-user-id": "rep-user"}
    r = client.post("/api/report", json={"pattern": "Fake SBI KYC link asking for OTP", "category": "kyc"},
                    headers=h)
    assert r.status_code == 200 and r.json()["status"] == "pending"
    pub = client.get("/api/reports").json()["reports"]
    assert all(p["category"] != "kyc" or "OTP" not in p["pattern"] for p in pub)  # not shown until approved


def test_export_and_delete_my_data():
    h = {"x-user-id": "del-user"}
    client.post("/api/scan", json={"content": "you won a lottery, claim at http://claim-prize.example"}, headers=h)
    exp = client.get("/api/export-my-data", headers=h).json()
    assert exp["user_id"] == "del-user" and len(exp["scans"]) >= 1
    assert "raw" not in exp["scans"][0]                 # export never echoes the raw column
    d = client.post("/api/delete-my-data", headers=h).json()
    assert d["deleted"] >= 1
    assert client.get("/api/history", headers=h).json() == []


def test_stored_signals_are_redacted():
    h = {"x-user-id": "redact-user"}
    client.post("/api/scan", headers=h, json={
        "content": "pay the fee to fraudster@okhdfcbank right now", "store": True})
    exp = client.get("/api/export-my-data", headers=h).json()
    blob = str(exp["scans"])
    assert "fraudster@okhdfcbank" not in blob           # raw UPI VPA never persisted
    assert "[UPI]@okhdfcbank" in blob


def test_xff_spoofing_does_not_bypass_rate_limit():
    original = m.limiter
    m.limiter = RateLimiter(per_min=1, per_day=100)
    try:
        a = client.post("/api/scan", json={"content": "one"}, headers={"x-forwarded-for": "1.1.1.1"})
        b = client.post("/api/scan", json={"content": "two"}, headers={"x-forwarded-for": "2.2.2.2"})
        assert a.status_code == 200
        assert b.status_code == 429                      # same untrusted peer -> XFF ignored
    finally:
        m.limiter = original


def test_health_reports_auth_mode():
    assert client.get("/health").json()["modes"]["auth"] == "debug"


def test_home_has_signin_control():
    assert 'id="account"' in client.get("/").text


def test_auth_endpoints_501_when_not_configured():
    # in mock/dev mode (no Supabase JWT backend) sign-in is unavailable, cleanly
    r = client.post("/api/auth/request-otp", json={"email": "user@example.com"})
    assert r.status_code == 501 and r.json()["error"]["code"] == "auth_not_configured"


def test_auth_request_otp_validates_email():
    r = client.post("/api/auth/request-otp", json={"email": "notanemail"})
    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# rate limiting
# --------------------------------------------------------------------------- #
def test_rate_limit_returns_429():
    original = m.limiter
    m.limiter = RateLimiter(per_min=1, per_day=100)
    try:
        first = client.post("/api/scan", json={"content": "hello there"})
        second = client.post("/api/scan", json={"content": "hello again"})
        assert first.status_code == 200
        assert second.status_code == 429
        assert "retry-after" in second.headers
    finally:
        m.limiter = original
