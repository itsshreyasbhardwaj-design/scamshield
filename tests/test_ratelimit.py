from app.ratelimit import RateLimiter


def test_per_minute_window():
    t = [1000.0]
    rl = RateLimiter(per_min=2, per_day=100, clock=lambda: t[0])
    assert rl.check("ip")[0] is True
    assert rl.check("ip")[0] is True
    allowed, retry = rl.check("ip")
    assert allowed is False and retry > 0
    t[0] += 61                                        # next minute
    assert rl.check("ip")[0] is True


def test_keys_are_independent():
    t = [0.0]
    rl = RateLimiter(per_min=1, per_day=100, clock=lambda: t[0])
    assert rl.check("a")[0] is True
    assert rl.check("b")[0] is True                   # different key, own bucket
    assert rl.check("a")[0] is False


def test_daily_cap():
    t = [0.0]
    rl = RateLimiter(per_min=100, per_day=2, clock=lambda: t[0])
    assert rl.check("k")[0] is True
    assert rl.check("k")[0] is True
    assert rl.check("k")[0] is False
