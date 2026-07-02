from app.india import HELPLINE, classify_scam_type, scam_type_name, tip_keys


def test_classifies_kyc_scam():
    assert classify_scam_type("Complete your KYC update or your account will be blocked") == "kyc_account"


def test_classifies_digital_arrest():
    assert classify_scam_type("This is CBI. You are under digital arrest for money laundering.") == "digital_arrest"


def test_classifies_lottery_kbc():
    assert classify_scam_type("Congratulations! You have won the KBC lottery of Rs 25 lakh") == "lottery_kbc"


def test_classifies_upi_reversal():
    assert classify_scam_type("I accidentally sent money, please approve the collect request to return it") == "upi_reversal"


def test_benign_has_no_scam_type():
    assert classify_scam_type("Are we meeting for chai at 5?") is None


def test_tip_keys_include_type_and_reporting():
    keys = tip_keys(["credentials", "malicious link"], "kyc_account")
    assert "never_share_otp" in keys
    assert "dont_click_links" in keys
    assert "kyc_tip" in keys
    assert keys[-1] == "report_1930"                  # always end with where to report


def test_helpline_is_1930():
    assert HELPLINE["cyber_helpline"] == "1930"
    assert scam_type_name("digital_arrest")
