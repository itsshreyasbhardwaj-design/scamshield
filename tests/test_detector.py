import time

from app.detector import Detector, MockReputation, Weights

D = Detector()


# --------------------------------------------------------------------------- #
# Original suite (must stay green)
# --------------------------------------------------------------------------- #
def test_obvious_scam_scores_high():
    text = ("URGENT: your account is suspended. Verify now at http://secure-update.example "
            "and share your OTP to claim your prize.")
    r = D.scan(text)
    assert r.verdict == "scam"
    assert r.risk_score >= 60
    assert any("malicious" in s for s in r.signals)
    assert "http://secure-update.example" in r.urls


def test_benign_message_is_safe():
    r = D.scan("Hey, are we still on for lunch tomorrow at 1?")
    assert r.verdict == "safe"
    assert r.risk_score < 30


def test_shortener_flagged_suspicious():
    assert MockReputation().check_link("https://bit.ly/abc") == "suspicious"
    r = D.scan("Check this out https://bit.ly/abc")
    assert any("suspicious" in s for s in r.signals)


def test_urls_extracted():
    r = D.scan("see http://a.com and https://b.org/x")
    assert r.urls == ["http://a.com", "https://b.org/x"]


# --------------------------------------------------------------------------- #
# Verdict thresholds / labels / configurability / determinism
# --------------------------------------------------------------------------- #
def test_labels_map_to_product_language():
    assert D.scan("Hey there").label == "Safe"
    assert D.scan("URGENT: your account is suspended, verify now http://secure-update.example "
                  "and send your OTP").label == "Dangerous"


def test_weights_are_configurable():
    d = Detector(weights=Weights(link_suspicious=70, threshold_scam=60))
    assert d.scan("check this https://bit.ly/abc").verdict == "scam"   # 70 >= custom 60
    assert D.scan("check this https://bit.ly/abc").verdict == "safe"   # default 20 < 30


def test_scan_is_deterministic():
    text = "URGENT verify now http://secure-update.example send OTP"
    assert D.scan(text).risk_score == D.scan(text).risk_score


# --------------------------------------------------------------------------- #
# Indicator extraction
# --------------------------------------------------------------------------- #
def test_extracts_phone_email():
    r = D.scan("Call +1 415 555 0176 or email winner@prize-claim.net to claim.")
    assert any("415" in p for p in r.phones)
    assert "winner@prize-claim.net" in r.emails


def test_extracts_upi_but_not_email_domain():
    r = D.scan("Send the fee to fraudster@paytm right now")
    assert "fraudster@paytm" in r.upi_ids
    assert r.emails == []                       # a UPI VPA is not an email


def test_extracts_crypto_address():
    r = D.scan("Transfer to 0x" + "a" * 40 + " immediately")
    assert any(c.startswith("0x") for c in r.crypto)


# --------------------------------------------------------------------------- #
# Link structure: homoglyph / typosquat / punycode / subdomain / IP
# --------------------------------------------------------------------------- #
def test_homoglyph_domain_is_malicious():
    r = D.scan("Verify your account at http://paypаl.com to continue")   # Cyrillic 'а'
    assert r.risk_score >= 40
    assert any("impersonat" in s or "look-alike" in s for s in r.signals)


def test_typosquat_domain_flagged():
    r = D.scan("Update your details at http://paypall.com")
    assert any("paypal" in s.lower() for s in r.signals)


def test_punycode_domain_flagged():
    r = D.scan("Login here http://xn--pypal-4ve.com now")
    assert any("punycode" in s.lower() for s in r.signals)


def test_brand_subdomain_impersonation_flagged():
    r = D.scan("Sign in at http://paypal.secure-billing.com")
    assert any("subdomain" in s.lower() for s in r.signals)


def test_raw_ip_link_flagged():
    r = D.scan("Verify your account: http://185.53.178.9/login")
    assert any("ip address" in s.lower() for s in r.signals)


# --------------------------------------------------------------------------- #
# Multilingual / attachments
# --------------------------------------------------------------------------- #
def test_apk_lure_flagged():
    r = D.scan("Download our app: bank-update.apk and enable unknown sources")
    assert any("APK" in s or "attachment" in s.lower() for s in r.signals)


def test_hinglish_scam_detected():
    r = D.scan("Aapka SBI khaata band ho gaya, turant apna OTP share karein")
    assert r.risk_score >= 30
    assert r.verdict in ("suspicious", "scam")


def test_hindi_devanagari_scam_detected():
    r = D.scan("तुरंत अपना OTP भेजें वरना खाता बंद हो जाएगा")
    assert r.risk_score >= 30


# --------------------------------------------------------------------------- #
# Regression tests for confirmed audit findings
# --------------------------------------------------------------------------- #
def test_legit_subdomain_not_malicious():          # audit: _BAD_DOMAIN_HINTS on full URL
    r = D.scan("Log in at https://account-center.google.com to manage your profile.")
    assert not any("malicious" in s for s in r.signals)
    assert r.label != "Dangerous"


def test_gift_card_retailer_not_malicious():        # audit: bare 'gift' hint
    r = D.scan("Redeem your gift card at https://www.amazon.com/gift-cards")
    assert not any("malicious" in s for s in r.signals)


def test_tco_substring_not_flagged():               # audit: 't.co' substring shortener
    r = D.scan("Reach us at https://contact.company.com for help.")
    assert r.verdict == "safe"
    assert not any("shortener" in s.lower() for s in r.signals)


def test_single_script_idn_not_flagged():           # audit: any-non-ASCII => mixed-script
    r = D.scan("Besuchen Sie uns unter https://müller.de für weitere Informationen.")
    assert not any("mixed-script" in s for s in r.signals)


def test_word_containing_brand_not_impersonation():  # audit: unanchored 'apple' in 'pineapple'
    r = D.scan("Shop at https://pineapple.com/sale today")
    assert not any("apple" in s.lower() and ("impersonat" in s.lower() or "embedded" in s.lower())
                   for s in r.signals)


def test_short_numeric_domain_not_malicious():       # audit: '5bi' -> 'sbi' via digit confusable
    r = D.scan("visit http://5bi.com now")
    assert not any("impersonat" in s.lower() for s in r.signals)


def test_bare_domain_is_extracted_and_analyzed():    # audit: scheme-less scam links ignored
    r = D.scan("Your Amazon account is on hold. Verify: amaz0n-account-verify.com")
    assert any("amaz0n" in u for u in r.urls)
    assert r.risk_score >= 40


def test_defanged_url_is_analyzed():                 # audit: hxxps:// bypasses extraction
    r = D.scan("Your parcel is held. Update address: hxxps://usps-redelivery.help/track")
    assert any("usps" in s.lower() for s in r.signals)


def test_bank_fraud_alert_not_dangerous():           # audit: keyword-only stacking -> scam
    r = D.scan("We blocked a suspicious payment on your account. "
               "If this wasn't you, log in to verify.")
    assert r.label != "Dangerous"
    assert r.verdict != "scam"


def test_otp_delivery_is_safe():                     # audit: legit OTP delivery flagged
    r = D.scan("123456 is your OTP for a payment of Rs 2499 at Amazon. "
               "Do not share it with anyone.")
    assert r.verdict == "safe"


def test_same_host_two_schemes_not_double_counted():  # audit: per-URL score double-count
    r = D.scan("go to http://paypa1.com and also https://paypa1.com")
    assert r.risk_score == 40
    assert r.verdict == "suspicious"


def test_secret_harvesting_is_dangerous():
    # content-only (no link) but an explicit "share your OTP" -> Dangerous
    r = D.scan("You won a KBC lottery of Rs 25 lakh. Share your OTP to claim the prize.")
    assert r.verdict == "scam"
    assert r.risk_score >= 60
    assert any("secret code" in s or "harvest" in s.lower() for s in r.signals)


def test_login_to_verify_is_not_harvesting():
    # legit-alert phrasing (no secret handover) must NOT be treated as harvesting/Dangerous
    r = D.scan("We noticed a new login. If this wasn't you, log in to verify your account.")
    assert "credential harvesting" not in r.categories
    assert r.verdict != "scam"


def test_otp_delivery_not_harvested():
    r = D.scan("123456 is your OTP for a payment of Rs 2499. Do not share it with anyone.")
    assert "credential harvesting" not in r.categories
    assert r.verdict == "safe"


def test_no_redos_on_long_input():                   # audit: EMAIL_RE O(n^2) backtracking
    payload = "a" * 20000 + " no at symbol here"
    start = time.perf_counter()
    r = D.scan(payload)
    assert time.perf_counter() - start < 1.0
    assert r.emails == []
