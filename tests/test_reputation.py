from app.reputation import GoogleSafeBrowsingReputation, MockReputation


def test_mock_reputation_verdicts():
    m = MockReputation()
    assert m.check_link("http://secure-update.example") == "malicious"
    assert m.check_link("https://bit.ly/x") == "suspicious"
    assert m.check_link("https://www.google.com") == "unknown"


class _FakeResp:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        return None

    def json(self):
        return self._data


class _FakeClient:
    def __init__(self, data, raise_exc=False):
        self._data = data
        self._raise = raise_exc

    def post(self, url, params=None, json=None):
        if self._raise:
            raise RuntimeError("network down")
        return _FakeResp(self._data)


def test_safe_browsing_flags_matches():
    sb = GoogleSafeBrowsingReputation("key", client=_FakeClient({"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}))
    assert sb.check_link("http://evil.example") == "malicious"


def test_safe_browsing_no_match_is_unknown():
    sb = GoogleSafeBrowsingReputation("key", client=_FakeClient({}))
    assert sb.check_link("https://example.com") == "unknown"


def test_safe_browsing_degrades_gracefully_on_error():
    sb = GoogleSafeBrowsingReputation("key", client=_FakeClient({}, raise_exc=True))
    assert sb.check_link("https://example.com") == "unknown"
