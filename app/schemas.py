import re
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

ContentType = Literal["message", "link", "email", "qr"]
MAX_CONTENT = 20_000
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class ScanIn(BaseModel):
    content: str = Field(..., min_length=1, max_length=MAX_CONTENT)
    type: ContentType = "message"
    store: bool = False                      # opt-in raw storage (§10)
    language: Optional[str] = None           # override auto-detect: en | hi | hinglish


class ScanOut(BaseModel):
    score: int
    verdict: str                             # safe | suspicious | scam
    label: str                               # localised Safe/Suspicious/Dangerous
    signals: List[str] = []
    categories: List[str] = []
    urls: List[str] = []
    phones: List[str] = []
    emails: List[str] = []
    upi_ids: List[str] = []
    crypto: List[str] = []
    language: str = "en"
    scam_type: Optional[str] = None
    scam_type_name: Optional[str] = None
    explanation: str = ""
    safety_tips: List[str] = []
    helpline: dict = {}
    disclaimer: str = ""
    scan_id: Optional[str] = None


class CheckLinkIn(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)


class CheckLinkOut(BaseModel):
    url: str
    reputation: str                          # clean | suspicious | malicious | unknown
    score: int
    label: str
    reasons: List[str] = []


class ReportIn(BaseModel):
    pattern: str = Field(..., min_length=3, max_length=2000)
    category: str = Field("other", max_length=64)


class ReportOut(BaseModel):
    id: str
    status: str                              # pending | approved


class HistoryItem(BaseModel):
    id: str
    content_hash: str
    type: str
    score: int
    verdict: str
    language: str
    created_at: str


class OtpRequestIn(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("invalid email")
        return v


class OtpVerifyIn(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)
    token: str = Field(..., min_length=4, max_length=12)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("invalid email")
        return v

    @field_validator("token")
    @classmethod
    def _token(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit():
            raise ValueError("code must be digits")
        return v


class AuthOut(BaseModel):
    access_token: str
    expires_in: int
    user_id: str


class HealthOut(BaseModel):
    ok: bool
    version: str
    modes: dict


class ErrorEnvelope(BaseModel):
    error: dict
