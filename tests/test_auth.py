from app.auth_supabase import request_otp, verify_otp
from app.config import Settings

S = Settings(supabase_url="https://x.supabase.co", supabase_anon_key="anon")


class _Resp:
    def __init__(self, status, data=None):
        self.status_code = status
        self._data = data or {}

    def json(self):
        return self._data


class _Client:
    def __init__(self, resp, boom=False):
        self._resp = resp
        self._boom = boom
        self.calls = []

    def post(self, url, json=None):
        self.calls.append((url, json))
        if self._boom:
            raise RuntimeError("down")
        return self._resp


def test_request_otp_success():
    c = _Client(_Resp(200, {}))
    assert request_otp(S, "a@b.com", client=c)["ok"] is True
    assert c.calls[0][0].endswith("/auth/v1/otp")
    assert c.calls[0][1]["create_user"] is True


def test_request_otp_error_passthrough():
    r = request_otp(S, "a@b.com", client=_Client(_Resp(429, {"msg": "rate limited"})))
    assert r["ok"] is False and "rate" in r["error"].lower()


def test_request_otp_network_down_is_graceful():
    assert request_otp(S, "a@b.com", client=_Client(None, boom=True))["ok"] is False


def test_verify_otp_returns_token_and_uid():
    data = {"access_token": "jwt.tok.en", "expires_in": 3600, "user": {"id": "u-123"}}
    r = verify_otp(S, "a@b.com", "123456", client=_Client(_Resp(200, data)))
    assert r["ok"] is True and r["access_token"] == "jwt.tok.en" and r["user_id"] == "u-123"


def test_verify_otp_bad_code():
    r = verify_otp(S, "a@b.com", "000000", client=_Client(_Resp(403, {"msg": "invalid"})))
    assert r["ok"] is False
