from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FTimeout
from typing import List, Optional

from .config import Settings
from .detector import ScanResult
from .india import scam_type_name
from .i18n import norm_lang, ui
from .privacy import redact

# Cache explanations by (signals-signature, language) to save free-tier quota.
_CACHE: dict = {}
_EXECUTOR = ThreadPoolExecutor(max_workers=4)

_LANG_NAME = {"en": "English", "hi": "Hindi", "hinglish": "Hinglish (Hindi written in the Latin alphabet)"}

# Localised, non-technical phrasing for each detector category.
_CAT_PHRASE = {
    "en": {
        "urgency": "it pressures you to act urgently",
        "credentials": "it asks for secret codes (OTP / PIN / password)",
        "money": "it dangles money, a prize, or a payment",
        "attachment": "it pushes you to install an app or file",
        "malicious link": "it contains a known-dangerous link",
        "suspicious link": "it contains a suspicious or look-alike link",
        "sender anomaly": "the sender address or number looks fake",
        "payment handle": "it asks you to pay a UPI ID",
        "crypto payment": "it asks for cryptocurrency",
        "callback": "it wants you to call an unknown number",
    },
    "hi": {
        "urgency": "यह आप पर तुरंत कार्रवाई का दबाव डालता है",
        "credentials": "यह गुप्त कोड (OTP / PIN / पासवर्ड) माँगता है",
        "money": "यह पैसे, इनाम या भुगतान का लालच देता है",
        "attachment": "यह ऐप या फ़ाइल इंस्टॉल करवाना चाहता है",
        "malicious link": "इसमें एक ज्ञात-खतरनाक लिंक है",
        "suspicious link": "इसमें संदिग्ध या नकली दिखने वाला लिंक है",
        "sender anomaly": "भेजने वाला पता या नंबर नकली लगता है",
        "payment handle": "यह किसी UPI आईडी पर भुगतान माँगता है",
        "crypto payment": "यह क्रिप्टोकरेंसी माँगता है",
        "callback": "यह किसी अनजान नंबर पर कॉल करवाना चाहता है",
    },
    "hinglish": {
        "urgency": "yeh turant action ka pressure daalta hai",
        "credentials": "yeh secret code (OTP / PIN / password) maangta hai",
        "money": "yeh paise, prize ya payment ka laalach deta hai",
        "attachment": "yeh app ya file install karwana chahta hai",
        "malicious link": "isme ek known-dangerous link hai",
        "suspicious link": "isme suspicious ya nakli-dikhne wala link hai",
        "sender anomaly": "bhejne wala address ya number nakli lagta hai",
        "payment handle": "yeh kisi UPI ID par payment maangta hai",
        "crypto payment": "yeh cryptocurrency maangta hai",
        "callback": "yeh kisi anjaan number par call karwana chahta hai",
    },
}

_VERDICT_LEAD = {
    "en": {
        "scam": "This looks dangerous — very likely a scam.",
        "suspicious": "Be careful — this shows warning signs.",
    },
    "hi": {
        "scam": "यह खतरनाक लगता है — बहुत संभवतः यह स्कैम है।",
        "suspicious": "सावधान रहें — इसमें चेतावनी के संकेत हैं।",
    },
    "hinglish": {
        "scam": "Yeh dangerous lagta hai — bahut likely scam hai.",
        "suspicious": "Careful rahein — isme warning signs hain.",
    },
}

_ACTION = {
    "en": {
        "scam": "Do not reply, click, pay, or share any code.",
        "suspicious": "Verify through official channels before you act.",
    },
    "hi": {
        "scam": "जवाब न दें, क्लिक न करें, भुगतान न करें, कोई कोड साझा न करें।",
        "suspicious": "कार्रवाई से पहले आधिकारिक माध्यम से पुष्टि करें।",
    },
    "hinglish": {
        "scam": "Reply/click/pay na karein, koi code share na karein.",
        "suspicious": "Action se pehle official channel se verify karein.",
    },
}


def _reasons(categories: List[str], lang: str) -> str:
    phrases = _CAT_PHRASE[lang]
    picked = [phrases[c] for c in categories if c in phrases]
    return "; ".join(picked)


def template_explanation(result: ScanResult, lang: str, scam_type: Optional[str]) -> str:
    lang = norm_lang(lang)
    if result.verdict == "safe":
        return ui(lang)["safe_msg"]
    lead = _VERDICT_LEAD[lang][result.verdict]
    parts = [lead]
    name = scam_type_name(scam_type)
    if name:
        parts.append({"en": f"It resembles a known pattern: {name}.",
                      "hi": f"यह एक ज्ञात पैटर्न जैसा है: {name}।",
                      "hinglish": f"Yeh ek known pattern jaisa hai: {name}."}[lang])
    reasons = _reasons(result.categories, lang)
    if reasons:
        parts.append({"en": f"Warning signs: {reasons}.",
                      "hi": f"चेतावनी संकेत: {reasons}।",
                      "hinglish": f"Warning signs: {reasons}."}[lang])
    parts.append(_ACTION[lang][result.verdict])
    return " ".join(parts)


def _llm_prompt(result: ScanResult, lang: str, scam_type: Optional[str]) -> tuple:
    lang_name = _LANG_NAME[norm_lang(lang)]
    system = (
        f"You are a careful fraud-awareness assistant for users in India. "
        f"Explain in {lang_name}, simply and without alarmism, why this message was "
        f"flagged, referencing ONLY the provided signals. Never invent facts, numbers, "
        f"or URLs, and never output instructions for committing fraud. "
        f"Write 2-3 short sentences a non-technical person understands, then one line "
        f"telling them what to do."
    )
    name = scam_type_name(scam_type) or "unknown"
    signals = "; ".join(redact(s) for s in result.signals) or "none"
    prompt = (f"Verdict: {result.verdict} (risk {result.risk_score}/100). "
              f"Likely scam type: {name}. Signals detected: {signals}.")
    return system, prompt


def build_explanation(result: ScanResult, lang: str, settings: Settings,
                      scam_type: Optional[str] = None) -> str:
    lang = norm_lang(lang)
    if settings.llm_mode != "live" or result.verdict == "safe":
        return template_explanation(result, lang, scam_type)

    key = (result.verdict, tuple(result.categories), scam_type, lang)
    if key in _CACHE:
        return _CACHE[key]

    system, prompt = _llm_prompt(result, lang, scam_type)
    try:
        from agentcore.config import Settings as ACSettings  # lazy
        from agentcore.llm import get_llm
        ac = ACSettings(llm_provider="openai", openai_base_url=settings.openai_base_url,
                        openai_api_key=settings.openai_api_key, openai_model=settings.openai_model)
        llm = get_llm(ac)
        fut = _EXECUTOR.submit(llm.complete_text, system, prompt)
        text = (fut.result(timeout=settings.explanation_timeout) or "").strip()
        if not text:
            raise ValueError("empty LLM response")
        _CACHE[key] = text
        return text
    except (FTimeout, Exception):
        return template_explanation(result, lang, scam_type)   # graceful fallback (§8)
