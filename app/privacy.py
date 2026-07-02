from __future__ import annotations

import hashlib
import re

# Redaction patterns — applied before ANY logging or LLM call (§10).
# Order matters: redact the most specific/sensitive identifiers first.
_AADHAAR_RE = re.compile(r"\b\d{4}[\s.\-]?\d{4}[\s.\-]?\d{4}\b")  # 12-digit Aadhaar (space/dot/hyphen)
_PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")                 # Indian PAN
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")               # payment card / long PAN
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_UPI_RE = re.compile(r"\b[\w.\-]{2,64}@[a-zA-Z]{2,64}\b")      # UPI VPA (name@bank)
_PHONE_RE = re.compile(r"\+?\d[\d\-\s().]{7,}\d")
# One-time codes only when clearly labelled, so amounts/years aren't clobbered.
_OTP_CTX_RE = re.compile(r"(?i)\b(otp|o\.t\.p|code|pin|password|passcode|verification code)\b(\D{0,12})(\d{4,8})\b")


def content_hash(text: str) -> str:
    """SHA-256 of the raw content. This — not the content — is what we store by
    default, so a user can look up / dedupe a scan without us retaining the text."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def redact(text: str) -> str:
    """Mask PII so message bodies never reach logs or LLM telemetry.
    Emails/UPI keep the domain (useful for scam analysis); everything else is
    fully masked. Deterministic and lossless-of-structure."""
    if not text:
        return ""
    t = text
    # card (13-19 digits) before Aadhaar (exactly 12) so a card isn't split.
    t = _CARD_RE.sub(lambda m: "[CARD]" if sum(c.isdigit() for c in m.group()) >= 13 else m.group(), t)
    t = _AADHAAR_RE.sub("[AADHAAR]", t)
    t = _PAN_RE.sub("[PAN]", t)
    t = _EMAIL_RE.sub(lambda m: "[EMAIL]@" + m.group().split("@")[-1], t)
    t = _UPI_RE.sub(lambda m: "[UPI]@" + m.group().split("@")[-1]
                    if "." not in m.group().split("@")[-1] else m.group(), t)
    t = _PHONE_RE.sub("[PHONE]", t)
    t = _OTP_CTX_RE.sub(lambda m: m.group(1) + m.group(2) + "[CODE]", t)
    return t
