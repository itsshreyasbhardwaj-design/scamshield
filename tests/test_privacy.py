from app.privacy import content_hash, redact


def test_content_hash_is_stable_sha256():
    h = content_hash("hello")
    assert h == content_hash("hello")
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)
    assert content_hash("hello") != content_hash("world")


def test_redacts_aadhaar_pan_card():
    assert "[AADHAAR]" in redact("my aadhaar is 1234 5678 9012 ok")
    assert "[PAN]" in redact("PAN ABCDE1234F here")
    assert "[CARD]" in redact("card 4111 1111 1111 1111")


def test_redacts_phone_but_keeps_email_domain():
    out = redact("call +91 98765 43210 or mail me at ravi@example.com")
    assert "[PHONE]" in out
    assert "98765" not in out
    assert "[EMAIL]@example.com" in out
    assert "ravi@example.com" not in out


def test_redacts_upi_keeps_bank():
    out = redact("send to victim@ybl now")
    assert "[UPI]@ybl" in out
    assert "victim@ybl" not in out


def test_redacts_hyphenated_aadhaar():
    assert "[AADHAAR]" in redact("aadhaar 1234-5678-9012")


def test_redacts_labelled_otp_but_not_amounts():
    out = redact("your OTP is 482913")
    assert "[CODE]" in out and "482913" not in out
    assert "2499" in redact("pay Rs 2499 for the order")   # bare amount not clobbered
