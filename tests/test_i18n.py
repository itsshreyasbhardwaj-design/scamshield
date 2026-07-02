from app.i18n import detect_language, tips, ui, verdict_label


def test_detects_english():
    assert detect_language("Hello, are we still on for lunch?") == "en"


def test_detects_hindi_devanagari():
    assert detect_language("तुरंत अपना OTP भेजें") == "hi"


def test_detects_hinglish():
    assert detect_language("Aapka khaata band ho gaya, turant OTP bhejein") == "hinglish"


def test_ui_is_localised():
    assert ui("hi")["check"] == "जाँच करें"
    assert ui("en")["check"] == "Check now"
    assert ui("zz")["check"] == "Check now"          # unknown -> english fallback


def test_verdict_labels_localised():
    assert verdict_label("scam", "hi") == "खतरनाक"
    assert verdict_label("scam", "en") == "Dangerous"


def test_tips_resolve_and_fallback():
    out = tips(["never_share_otp", "report_1930"], "hi")
    assert len(out) == 2 and all(out)
    assert tips(["nonexistent_key"], "en") == []
