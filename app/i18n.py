from __future__ import annotations

import re
from typing import Dict, List

SUPPORTED = ("en", "hi", "hinglish")

_DEVANAGARI_RE = re.compile(r"[ऀ-ॿ]")
_HINGLISH_TOKENS = re.compile(
    r"\b(aapka|aapke|apna|apni|turant|abhi|jaldi|kripya|dhanyavaad|khaata|khata|"
    r"paise|paisa|rupaye|bhejein|bhejo|karein|karo|nahi|hai|kaise|link|otp|band|"
    r"account|verify|update)\b", re.I)


def detect_language(text: str, default: str = "en") -> str:
    if not text:
        return default
    if _DEVANAGARI_RE.search(text):
        return "hi"
    hits = len(_HINGLISH_TOKENS.findall(text.lower()))
    # a couple of romanised-Hindi markers (that aren't plain English) => hinglish
    if hits >= 2 and re.search(r"\b(aapka|aapke|apna|apni|turant|khaata|khata|paise|"
                               r"bhejein|bhejo|karein|karo|kripya|band)\b", text.lower()):
        return "hinglish"
    return default if default in SUPPORTED else "en"


VERDICT_LABELS: Dict[str, Dict[str, str]] = {
    "en": {"safe": "Safe", "suspicious": "Suspicious", "scam": "Dangerous"},
    "hi": {"safe": "सुरक्षित", "suspicious": "संदिग्ध", "scam": "खतरनाक"},
    "hinglish": {"safe": "Safe", "suspicious": "Suspicious (dhyaan dein)", "scam": "Dangerous (Scam)"},
}

UI: Dict[str, Dict[str, str]] = {
    "en": {
        "title": "ScamShield",
        "tagline": "Paste a message or link. Know in seconds if it's a scam.",
        "placeholder": "Paste a suspicious SMS, WhatsApp message, email, or link…",
        "check": "Check now",
        "checking": "Checking…",
        "signals": "What we found",
        "tips": "How to stay safe",
        "safe_msg": "No common scam signals detected. Still, stay alert.",
        "empty": "Your result will appear here.",
        "share": "Copy result",
        "disclaimer": "Best-effort detection, not a guarantee. Not legal or financial advice.",
        "report_cta": "Report a scam you received",
        "lang": "Language",
        "score": "Risk score",
        "likely": "Likely scam type",
        "qr": "Scan a QR image",
        "qr_none": "No QR code found in that image.",
        "qr_unsupported": "QR scanning isn't supported on this browser — paste the link instead.",
        "community": "Community reports",
        "community_empty": "No community-reported scams yet.",
        "sign_in": "Sign in",
        "sign_out": "Sign out",
        "email_ph": "you@email.com",
        "send_code": "Email me a code",
        "code_ph": "6-digit code",
        "verify": "Verify & sign in",
        "code_sent": "We emailed you a code. Enter it below.",
        "signed_in": "Signed in",
        "history": "My history",
        "history_empty": "No saved scans yet.",
        "report_this": "Report as scam",
        "report_done": "Thanks — reported for review.",
        "auth_unavailable": "Sign-in is available on the hosted version.",
        "close": "Close",
    },
    "hi": {
        "title": "ScamShield",
        "tagline": "मैसेज या लिंक पेस्ट करें। सेकंडों में जानें कि यह स्कैम है या नहीं।",
        "placeholder": "संदिग्ध SMS, WhatsApp मैसेज, ईमेल या लिंक यहाँ पेस्ट करें…",
        "check": "जाँच करें",
        "checking": "जाँच हो रही है…",
        "signals": "हमें क्या मिला",
        "tips": "सुरक्षित कैसे रहें",
        "safe_msg": "कोई सामान्य स्कैम संकेत नहीं मिला। फिर भी सतर्क रहें।",
        "empty": "आपका परिणाम यहाँ दिखेगा।",
        "share": "परिणाम कॉपी करें",
        "disclaimer": "यह सर्वोत्तम-प्रयास जाँच है, गारंटी नहीं। यह कानूनी या वित्तीय सलाह नहीं है।",
        "report_cta": "मिला हुआ स्कैम रिपोर्ट करें",
        "lang": "भाषा",
        "score": "जोखिम स्कोर",
        "likely": "संभावित स्कैम प्रकार",
        "qr": "QR इमेज स्कैन करें",
        "qr_none": "उस इमेज में कोई QR कोड नहीं मिला।",
        "qr_unsupported": "इस ब्राउज़र में QR स्कैन उपलब्ध नहीं है — लिंक पेस्ट करें।",
        "community": "कम्युनिटी रिपोर्ट्स",
        "community_empty": "अभी तक कोई कम्युनिटी-रिपोर्टेड स्कैम नहीं।",
        "sign_in": "साइन इन",
        "sign_out": "साइन आउट",
        "email_ph": "you@email.com",
        "send_code": "मुझे कोड ईमेल करें",
        "code_ph": "6-अंकों का कोड",
        "verify": "सत्यापित करें और साइन इन",
        "code_sent": "हमने आपको एक कोड ईमेल किया है। नीचे दर्ज करें।",
        "signed_in": "साइन इन हो गए",
        "history": "मेरा इतिहास",
        "history_empty": "अभी तक कोई सेव्ड स्कैन नहीं।",
        "report_this": "स्कैम रिपोर्ट करें",
        "report_done": "धन्यवाद — समीक्षा के लिए रिपोर्ट किया गया।",
        "auth_unavailable": "साइन-इन होस्टेड वर्शन पर उपलब्ध है।",
        "close": "बंद करें",
    },
    "hinglish": {
        "title": "ScamShield",
        "tagline": "Message ya link paste karein. Seconds mein jaanein scam hai ya nahi.",
        "placeholder": "Suspicious SMS, WhatsApp message, email ya link yahan paste karein…",
        "check": "Check karein",
        "checking": "Check ho raha hai…",
        "signals": "Humein kya mila",
        "tips": "Safe kaise rahein",
        "safe_msg": "Koi common scam signal nahi mila. Phir bhi alert rahein.",
        "empty": "Aapka result yahan dikhega.",
        "share": "Result copy karein",
        "disclaimer": "Best-effort detection hai, guarantee nahi. Legal ya financial advice nahi.",
        "report_cta": "Mila hua scam report karein",
        "lang": "Bhasha",
        "score": "Risk score",
        "likely": "Sambhavit scam type",
        "qr": "QR image scan karein",
        "qr_none": "Us image mein koi QR code nahi mila.",
        "qr_unsupported": "Is browser mein QR scan support nahi hai — link paste karein.",
        "community": "Community reports",
        "community_empty": "Abhi tak koi community-reported scam nahi.",
        "sign_in": "Sign in",
        "sign_out": "Sign out",
        "email_ph": "you@email.com",
        "send_code": "Mujhe code email karein",
        "code_ph": "6-digit code",
        "verify": "Verify & sign in",
        "code_sent": "Humne aapko code email kiya hai. Neeche enter karein.",
        "signed_in": "Signed in",
        "history": "Mera history",
        "history_empty": "Abhi tak koi saved scan nahi.",
        "report_this": "Scam report karein",
        "report_done": "Dhanyavaad — review ke liye report kiya.",
        "auth_unavailable": "Sign-in hosted version par available hai.",
        "close": "Close",
    },
}

_TIPS: Dict[str, Dict[str, str]] = {
    "never_share_otp": {
        "en": "Never share an OTP, UPI PIN, CVV or password — no bank or company ever asks for them.",
        "hi": "OTP, UPI PIN, CVV या पासवर्ड कभी साझा न करें — कोई बैंक या कंपनी इन्हें नहीं माँगती।",
        "hinglish": "OTP, UPI PIN, CVV ya password kabhi share na karein — koi bank/company kabhi nahi maangti.",
    },
    "no_pay_to_claim": {
        "en": "You never pay a fee to receive a prize, refund or loan. Paying to 'claim' money is always a scam.",
        "hi": "इनाम, रिफंड या लोन पाने के लिए कभी शुल्क नहीं देना पड़ता। 'क्लेम' के लिए पैसे माँगना हमेशा स्कैम है।",
        "hinglish": "Prize/refund/loan lene ke liye kabhi fee nahi deni padti. 'Claim' ke liye paisa maangna scam hai.",
    },
    "dont_click_links": {
        "en": "Don't tap links in unexpected messages. Open the official app or type the website yourself.",
        "hi": "अनचाहे मैसेज के लिंक पर टैप न करें। आधिकारिक ऐप खोलें या वेबसाइट खुद टाइप करें।",
        "hinglish": "Anchahe message ke links par tap na karein. Official app kholein ya website khud type karein.",
    },
    "verify_official_number": {
        "en": "Verify by calling the official number printed on your card or the bank's website — not the number in the message.",
        "hi": "अपने कार्ड या बैंक की वेबसाइट पर छपे आधिकारिक नंबर पर कॉल करके पुष्टि करें — मैसेज वाले नंबर पर नहीं।",
        "hinglish": "Card ya bank website par diye official number par call karke verify karein — message wale number par nahi.",
    },
    "digital_arrest_tip": {
        "en": "Police, CBI or customs NEVER arrest you over a video call or ask for money. 'Digital arrest' is a scam — hang up.",
        "hi": "पुलिस, CBI या कस्टम कभी वीडियो कॉल पर गिरफ्तार नहीं करते और न पैसे माँगते हैं। 'डिजिटल अरेस्ट' स्कैम है — कॉल काट दें।",
        "hinglish": "Police/CBI/customs kabhi video call par arrest nahi karte na paise maangte. 'Digital arrest' scam hai — call kaat dein.",
    },
    "kyc_tip": {
        "en": "Banks never ask you to complete KYC via a link or app. Do KYC only at a branch or the official app.",
        "hi": "बैंक कभी लिंक या ऐप से KYC पूरा करने को नहीं कहते। KYC केवल शाखा या आधिकारिक ऐप में करें।",
        "hinglish": "Banks kabhi link/app se KYC karne ko nahi kehte. KYC sirf branch ya official app mein karein.",
    },
    "parcel_tip": {
        "en": "Couriers and customs don't ask for fees or your OTP over the phone. Don't pay 'clearance' charges.",
        "hi": "कूरियर और कस्टम फोन पर शुल्क या OTP नहीं माँगते। 'क्लीयरेंस' चार्ज न दें।",
        "hinglish": "Courier/customs phone par fees ya OTP nahi maangte. 'Clearance' charge na dein.",
    },
    "lottery_tip": {
        "en": "You can't win a lottery you never entered. KBC/lucky-draw winnings on WhatsApp are always fake.",
        "hi": "जिस लॉटरी में आपने भाग ही नहीं लिया, वह नहीं जीत सकते। WhatsApp पर KBC/लकी-ड्रॉ हमेशा फर्जी है।",
        "hinglish": "Jis lottery mein aap gaye hi nahi, woh jeet nahi sakte. WhatsApp par KBC/lucky-draw hamesha fake hai.",
    },
    "loan_tip": {
        "en": "Genuine lenders don't demand a fee before disbursing a loan, or ask for full phone access.",
        "hi": "असली ऋणदाता लोन देने से पहले शुल्क नहीं माँगते, न पूरे फोन का एक्सेस माँगते हैं।",
        "hinglish": "Genuine lenders loan se pehle fee nahi maangte, na poore phone ka access maangte.",
    },
    "upi_reversal_tip": {
        "en": "You never need to enter a PIN to RECEIVE money. Approving a 'collect request' sends money away.",
        "hi": "पैसे प्राप्त करने के लिए कभी PIN नहीं डालना होता। 'कलेक्ट रिक्वेस्ट' मंज़ूर करने से पैसे चले जाते हैं।",
        "hinglish": "Paise RECEIVE karne ke liye kabhi PIN nahi daalna hota. 'Collect request' approve karne se paise chale jaate hain.",
    },
    "job_tip": {
        "en": "Real jobs don't ask you to pay to start, or pay via Telegram 'tasks'. Deposits you're asked to make are lost.",
        "hi": "असली नौकरी शुरू करने के लिए पैसे नहीं माँगती, न Telegram 'टास्क' से भुगतान करती है। जमा किया पैसा वापस नहीं आता।",
        "hinglish": "Real job shuru karne ke liye paisa nahi maangti, na Telegram 'task' se pay karti. Jama kiya paisa wapas nahi aata.",
    },
    "investment_tip": {
        "en": "'Guaranteed returns' and WhatsApp/Telegram stock tips are scams. Check SEBI-registered advisers only.",
        "hi": "'गारंटीड रिटर्न' और WhatsApp/Telegram स्टॉक टिप्स स्कैम हैं। केवल SEBI-पंजीकृत सलाहकार देखें।",
        "hinglish": "'Guaranteed returns' aur WhatsApp/Telegram stock tips scam hain. Sirf SEBI-registered advisers dekhein.",
    },
    "report_1930": {
        "en": "Report scams: call 1930 (within the hour for financial fraud) or file at cybercrime.gov.in.",
        "hi": "स्कैम रिपोर्ट करें: 1930 पर कॉल करें (वित्तीय धोखाधड़ी के लिए एक घंटे के भीतर) या cybercrime.gov.in पर दर्ज करें।",
        "hinglish": "Scam report karein: 1930 par call karein (financial fraud ke liye ek ghante mein) ya cybercrime.gov.in par file karein.",
    },
}


def norm_lang(lang: str) -> str:
    lang = (lang or "").lower()
    return lang if lang in SUPPORTED else "en"


def ui(lang: str) -> Dict[str, str]:
    return UI[norm_lang(lang)]


def verdict_label(verdict: str, lang: str) -> str:
    return VERDICT_LABELS[norm_lang(lang)].get(verdict, verdict)


def tips(keys: List[str], lang: str) -> List[str]:
    lang = norm_lang(lang)
    out = []
    for k in keys:
        entry = _TIPS.get(k)
        if entry:
            out.append(entry.get(lang, entry["en"]))
    return out
