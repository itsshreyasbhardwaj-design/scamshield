from __future__ import annotations

import re
from typing import List, Optional

# --------------------------------------------------------------------------- #
# India-specific fraud knowledge. Official reporting channels shown in every
# result so victims know exactly where to go.
# --------------------------------------------------------------------------- #
HELPLINE = {
    "cyber_helpline": "1930",                       # National Cyber Crime Helpline
    "cyber_portal": "https://cybercrime.gov.in",
    "note_en": "Report financial fraud within the golden hour by calling 1930.",
    "note_hi": "वित्तीय धोखाधड़ी होने पर तुरंत 1930 पर कॉल करें (गोल्डन ऑवर)।",
}

# Common India scam archetypes. Each has cheap keyword heuristics used only to
# LABEL the likely scam type — the risk score itself comes from the Detector.
_SCAM_TYPES = [
    ("digital_arrest", "Digital arrest / fake police-CBI",
     r"\b(digital arrest|cbi|c\.?b\.?i|narcotics|ncb|police|court summon|arrest warrant|"
     r"custom(s)? officer|money laundering|ed officer|enforcement directorate)\b"),
    ("parcel_customs", "Courier / customs parcel scam",
     r"\b(parcel|courier|fedex|dhl|blue dart|customs duty|clearance fee|package (is )?held|"
     r"shipment held|illegal items)\b"),
    ("kyc_account", "KYC / bank-account fraud",
     r"\b(kyc|k\.?y\.?c|update your kyc|pan (card )?update|aadhaar link|account (will be )?block|"
     r"account suspend|re-?kyc|sim (will be )?block)\b"),
    ("lottery_kbc", "Lottery / KBC lucky-draw scam",
     r"\b(kbc|kaun banega|lottery|lucky draw|you have won|winner|prize of rs|jackpot)\b"),
    ("loan_app", "Instant loan-app scam",
     r"\b(instant loan|loan approved|pre-?approved loan|loan offer|emi|quick cash|"
     r"loan app|processing fee)\b"),
    ("upi_reversal", "UPI collect-request / wrong-transfer scam",
     r"\b(collect request|upi request|wrongly sent|accidentally (sent|transferred)|"
     r"return the money|refund the amount|scan (this )?qr to receive)\b"),
    ("job_task", "Task / work-from-home job scam",
     r"\b(work from home|part[- ]?time job|task (based )?job|prepaid task|earn daily|"
     r"telegram (job|task)|like and subscribe|rating job)\b"),
    ("electricity_bill", "Electricity-bill disconnection scam",
     r"\b(electricity bill|power (will be )?disconnect|bijli|meter update|"
     r"pending bill|update your meter)\b"),
    ("investment_stock", "Investment / stock-tip scam",
     r"\b(stock tip|guaranteed returns|trading platform|sebi|ipo allotment|"
     r"double your (money|investment)|telegram (group|channel)|crypto investment)\b"),
    ("fake_support", "Fake customer-care / refund scam",
     r"\b(customer care|helpline number|call this number|refund (support|team)|"
     r"toll[- ]?free|call back)\b"),
]
_SCAM_RES = [(tid, name, re.compile(rx, re.I)) for tid, name, rx in _SCAM_TYPES]

# Official domains — never impersonate these; used for user education.
OFFICIAL_DOMAINS = {
    "sbi": "onlinesbi.sbi", "hdfc": "hdfcbank.com", "icici": "icicibank.com",
    "paytm": "paytm.com", "phonepe": "phonepe.com", "irctc": "irctc.co.in",
    "uidai": "uidai.gov.in", "incometax": "incometax.gov.in",
}


def classify_scam_type(text: str) -> Optional[str]:
    low = (text or "").lower()
    for tid, _name, rx in _SCAM_RES:
        if rx.search(low):
            return tid
    return None


def scam_type_name(scam_type: Optional[str]) -> Optional[str]:
    if not scam_type:
        return None
    for tid, name, _rx in _SCAM_TYPES:
        if tid == scam_type:
            return name
    return None


def tip_keys(categories: List[str], scam_type: Optional[str]) -> List[str]:
    """Which safety-tip keys apply (resolved to localised text in i18n)."""
    keys: List[str] = []
    cats = set(categories or [])
    if "credentials" in cats:
        keys.append("never_share_otp")
    if "money" in cats or "payment handle" in cats or "crypto payment" in cats:
        keys.append("no_pay_to_claim")
    if {"malicious link", "suspicious link"} & cats:
        keys.append("dont_click_links")
    if "sender anomaly" in cats or "callback" in cats:
        keys.append("verify_official_number")
    # scam-type specific
    keys += {
        "digital_arrest": ["digital_arrest_tip"],
        "kyc_account": ["kyc_tip"],
        "parcel_customs": ["parcel_tip"],
        "lottery_kbc": ["lottery_tip"],
        "loan_app": ["loan_tip"],
        "upi_reversal": ["upi_reversal_tip"],
        "job_task": ["job_tip"],
        "investment_stock": ["investment_tip"],
    }.get(scam_type or "", [])
    keys.append("report_1930")                      # always: where to report
    # de-dupe, preserve order
    seen, out = set(), []
    for k in keys:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out
