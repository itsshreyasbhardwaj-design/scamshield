from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional, Protocol

# --------------------------------------------------------------------------- #
# Extraction patterns (deterministic, bounded -> ReDoS-safe)
# --------------------------------------------------------------------------- #
URL_RE = re.compile(r"\bhttps?://[^\s<>()]+", re.I)
# Scheme-less host (+ optional path). TLD is validated against an allowlist so
# ordinary "file.py"/"e.g." tokens are not mistaken for domains.
HOST_RE = re.compile(
    r"(?<![\w@.\-/])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?:/[^\s<>()]*)?",
    re.I)
PHONE_RE = re.compile(r"\+?\d[\d\-\s().]{7,}\d")
# Local part bounded ({1,64}) and domain requires a dot -> no quadratic backtracking.
EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,255}(?:\.[\w-]{1,255}){1,4}", re.I)
# UPI VPA: handle@bank where the bank part has NO dot (distinguishes from email).
UPI_RE = re.compile(r"(?<![\w.@\-])[\w.\-]{2,64}@([a-zA-Z][a-zA-Z0-9]{1,63})(?![\w.@\-])")
BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

_TRAILING_PUNCT = "!\"'),.:;?]}>"
MAX_INPUT_CHARS = 20_000  # input hardening: bound all downstream work

# Refang common obfuscations before extraction (hxxp, [.] , [dot], [at]).
_DEFANG = [
    (re.compile(r"h\s*x\s*x\s*p(s?)(?=\s*:)", re.I), r"http\1"),
    (re.compile(r"\[\s*\.\s*\]"), "."),
    (re.compile(r"\(\s*\.\s*\)"), "."),
    (re.compile(r"\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*dot\s*\]", re.I), "."),
    (re.compile(r"\(\s*dot\s*\)", re.I), "."),
    (re.compile(r"\[\s*(?:@|at)\s*\]", re.I), "@"),
    (re.compile(r"\(\s*(?:@|at)\s*\)", re.I), "@"),
]

_UPI_SUFFIXES = {
    "ybl", "okhdfcbank", "okhdfc", "oksbi", "okaxis", "okicici", "paytm", "apl",
    "upi", "axl", "ibl", "axisbank", "hdfcbank", "sbi", "icici", "pnb", "kotak",
    "yesbank", "fbl", "idfcbank", "rbl", "cnrb", "barodampay", "aubank", "fam",
    "naviaxis", "superyes", "yapl", "pockets", "freecharge", "airtel", "jio",
    "gpay", "phonepe", "waaxis", "wahdfcbank", "wasbi", "abfspay",
}

# TLDs accepted for scheme-less host extraction. Deliberately omits file-ext
# look-alikes (py, js, sh, md, zip, mov, exe, apk) to avoid false domains.
_TLD_ALLOW = {
    "com", "net", "org", "info", "biz", "io", "co", "app", "dev", "xyz", "top",
    "site", "online", "shop", "store", "live", "link", "click", "buzz", "icu",
    "vip", "win", "pro", "me", "tv", "cc", "name", "email", "help", "support",
    "tech", "cloud", "page", "fun", "world", "today", "life", "work", "company",
    "gift", "gq", "cf", "ga", "ml", "tk",
    "us", "uk", "in", "cn", "ru", "br", "de", "fr", "es", "it", "nl", "au", "ca",
    "jp", "kr", "sg", "hk", "tw", "za", "ng", "ph", "id", "my", "th", "vn", "pk",
    "bd", "lk", "ae", "sa", "ir", "tr", "mx", "ar", "cl", "pe", "ch", "se", "no",
    "fi", "dk", "pl", "pt", "gr", "ie", "nz", "ua",
}

# --------------------------------------------------------------------------- #
# Keyword taxonomy — multilingual (EN + Hinglish/Hindi + ES/FR/PT high-value
# terms). Matched with word boundaries to avoid substring false positives.
# --------------------------------------------------------------------------- #
_URGENCY = [
    "urgent", "immediately", "act now", "within 24 hours", "account suspended",
    "verify now", "limited time", "final notice", "blocked", "suspended",
    "expire", "expires", "deadline", "right now", "without delay", "last warning",
    "turant", "abhi", "jaldi", "foran", "तुरंत", "अभी", "जल्दी",
    "urgente", "inmediatamente", "suspendida", "bloqueada",
    "immédiatement", "suspendu", "bloqué", "imediatamente", "suspensa",
]
_CREDS = [
    "otp", "password", "pin", "cvv", "verify your account", "login", "log in",
    "kyc", "one time password", "one-time password", "aadhaar", "aadhar",
    "card number", "expiry date", "net banking password", "upi pin", "mpin",
    "ओटीपी", "पासवर्ड", "केवाईसी", "पिन",
    "contraseña", "verifique su cuenta", "mot de passe", "carte bancaire", "senha",
]
_MONEY = [
    "payment", "bank", "upi", "gift card", "gift cards", "gift card code",
    "google play card", "steam card", "itunes card", "wire", "wire transfer",
    "western union", "moneygram", "zelle", "venmo", "cash app", "cashapp",
    "refund", "prize", "won", "lottery", "claim", "reward", "bitcoin", "crypto",
    "cashback", "processing fee", "trading platform", "guaranteed returns",
    "send the codes", "send me the codes",
    "inaam", "paisa", "paise", "lakh", "crore", "इनाम", "लॉटरी", "पैसे",
    "premio", "lotería", "reembolso", "recompensa", "prix", "remboursement", "prêmio",
]
_ATTACH = [
    "apk", "exe", "scr", "msi", "unknown sources", "install the app",
    "download our app", "install app", "apk file", "enable installation",
    "sideload",
]

# Credential keyword scores strongly only when the message REQUESTS the secret,
# not when it merely DELIVERS a code ("123456 is your OTP. Do not share.").
_CRED_REQUEST = re.compile(
    r"\b(?:share|send|enter|provide|give|tell|confirm|update|verify|resend|"
    r"forward|submit|type|reply with)\b", re.I)
_CRED_DELIVERY = re.compile(
    r"(?:\bis your\b|\bdo not share\b|\bdon'?t share\b|\bnever share\b|"
    r"\bvalid for\b|\bdo not disclose\b)", re.I)
# An explicit request to HAND OVER a secret (OTP/PIN/CVV/password) — the actual
# credential-harvesting action. Bounded gaps keep it ReDoS-safe. Legit "log in to
# verify" notices do NOT match (no share/send + secret token).
_SECRET = r"(?:otp|o\.t\.p|pin|cvv|password|passcode|mpin|upi pin|one[- ]time password)"
_GIVE = r"(?:share|send|enter|provide|give|tell|forward|submit|reply with|batayein|bhejein|bhejo|bataye|bata do)"
_CRED_HARVEST_RE = re.compile(
    rf"(?:\b{_GIVE}\b[^.\n]{{0,20}}\b{_SECRET}\b)|(?:\b{_SECRET}\b[^.\n]{{0,20}}\b{_GIVE}\b)", re.I)
_CALLBACK_RE = re.compile(
    r"\b(?:call|dial|contact|phone|ring)\b[^.]{0,40}?"
    r"(?:back|us|now|immediately|our (?:support|security|team)|this number|toll[- ]?free)",
    re.I)

_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "is.gd",
               "cutt.ly", "ow.ly", "tiny.cc", "rebrand.ly", "shorturl.at"}
_BAD_DOMAIN_HINTS = ["free-", "-verify", "login-", "secure-update", "claim-",
                     "account-", "-support", "verify-", "-secure"]

# Brands scam messages commonly impersonate.
_BRANDS = {
    "paypal", "google", "apple", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "gmail", "outlook", "paytm", "phonepe",
    "sbi", "hdfc", "icici", "axis", "kotak", "flipkart", "irctc", "uidai",
    "dhl", "fedex", "coinbase", "binance", "metamask", "usps",
}

# Letter confusables always map; digit/symbol confusables map only when adjacent
# to a letter (so "5000" stays numeric but "paypa1" -> "paypal").
_CONF_LETTER = {
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i",
    "ј": "j", "ԁ": "d", "ո": "n", "ց": "g",
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "τ": "t", "χ": "x", "υ": "u", "β": "b",
}
_CONF_DIGIT = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"}

_TWO_LEVEL_TLDS = {
    "co.uk", "co.in", "com.au", "co.jp", "gov.in", "gov.uk", "ac.in", "ac.uk",
    "org.in", "net.in", "co.nz", "com.br", "com.sg", "co.za", "org.uk",
}


def _compile_kw(words: list[str]) -> re.Pattern:
    return re.compile(r"\b(?:" + "|".join(re.escape(w) for w in words) + r")\b", re.I)


_URGENCY_RE = _compile_kw(_URGENCY)
_CREDS_RE = _compile_kw(_CREDS)
_MONEY_RE = _compile_kw(_MONEY)
_ATTACH_RE = _compile_kw(_ATTACH)


# --------------------------------------------------------------------------- #
# Reputation provider interface (swappable + mockable)
# --------------------------------------------------------------------------- #
class ReputationProvider(Protocol):
    def check_link(self, url: str) -> str: ...    # clean | suspicious | malicious | unknown
    def check_phone(self, phone: str) -> str: ...
    def check_email(self, email: str) -> str: ...


class MockReputation:
    """Offline, deterministic stand-in. Swap for a live provider in production
    (Google Safe Browsing for links, plus urlscan.io / VirusTotal free tiers).
    Heuristics are applied to the REGISTRABLE domain only, never the full URL or
    subdomains, so legitimate hosts (account-center.google.com) are not condemned."""

    def check_link(self, url: str) -> str:
        host = _host(url)
        if not host or _is_ip(host):
            return "unknown"
        reg = _registrable(host)
        if reg in _SHORTENERS or host in _SHORTENERS:
            return "suspicious"
        if any(h in reg for h in _BAD_DOMAIN_HINTS):
            return "malicious"
        return "unknown"

    def check_phone(self, phone: str) -> str:
        return "unknown"

    def check_email(self, email: str) -> str:
        return "unknown"


# --------------------------------------------------------------------------- #
# Configurable scoring
# --------------------------------------------------------------------------- #
@dataclass
class Weights:
    urgency: int = 25
    credentials: int = 30
    money: int = 15
    attachment: int = 20
    credential_harvest: int = 35         # explicit "share your OTP/PIN" — a real attack action
    link_malicious: int = 40
    link_suspicious: int = 20
    handle_suspicious: int = 15          # UPI / crypto / look-alike email / callback
    threshold_suspicious: int = 30       # score >= -> "suspicious"
    threshold_scam: int = 60             # score >= -> "scam" (Dangerous)


DEFAULT_WEIGHTS = Weights()

_LABELS = {"safe": "Safe", "suspicious": "Suspicious", "scam": "Dangerous"}


@dataclass
class ScanResult:
    risk_score: int                                  # 0-100
    verdict: str                                     # safe | suspicious | scam
    label: str = "Safe"                              # Safe | Suspicious | Dangerous
    signals: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    upi_ids: list[str] = field(default_factory=list)
    crypto: list[str] = field(default_factory=list)
    explanation: str = ""


# --------------------------------------------------------------------------- #
# Structural helpers (deterministic, provider-independent)
# --------------------------------------------------------------------------- #
def _skeleton(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).lower()
    out = []
    for i, ch in enumerate(s):
        if ch in _CONF_LETTER:
            out.append(_CONF_LETTER[ch])
        elif ch in _CONF_DIGIT and (
                (i > 0 and s[i - 1].isalpha()) or (i + 1 < len(s) and s[i + 1].isalpha())):
            out.append(_CONF_DIGIT[ch])
        else:
            out.append(ch)
    return "".join(out).replace("rn", "m").replace("vv", "w")


def _lev1(a: str, b: str) -> int:
    """Levenshtein distance, accurate up to 1 (returns 2 for anything larger)."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 1:
        return 2
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _host(url_or_domain: str) -> str:
    m = re.match(r"[a-z][a-z0-9+.\-]*://([^/?#]+)", url_or_domain, re.I)
    authority = (m.group(1) if m else url_or_domain).split("@")[-1]
    if authority.startswith("["):                  # IPv6 literal
        end = authority.find("]")
        return authority[1:end].lower() if end != -1 else authority.lower()
    return authority.split(":")[0].strip().strip(".").lower()


def _is_ip(host: str) -> bool:
    if ":" in host:                                # IPv6
        return True
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _TWO_LEVEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _has_mixed_script(host: str) -> bool:
    """True only if a single label mixes Latin with another script — the actual
    homoglyph vector. Whole-non-Latin IDNs (müller.de, 中国银行.cn) are not flagged."""
    for label in host.split("."):
        scripts = set()
        for c in label:
            if not c.isalpha():
                continue
            if ord(c) < 128:
                scripts.add("LATIN")
            else:
                try:
                    scripts.add(unicodedata.name(c).split(" ")[0])
                except ValueError:
                    scripts.add("OTHER")
        if "LATIN" in scripts and (scripts - {"LATIN"}):
            return True
    return False


def _brand_anchored(sld_sk: str, brand: str) -> bool:
    return bool(re.search(r"(?:^|[-.])" + re.escape(brand) + r"(?:$|[-.])", sld_sk))


def _brand_concern(host: str) -> Optional[tuple[str, str]]:
    """Return (severity, message) if the host impersonates a known brand."""
    if _is_ip(host):
        return None
    sld = _registrable(host).split(".")[0]
    if sld in _BRANDS:                              # genuine brand on some TLD
        return None
    sld_sk = _skeleton(sld)
    labels = set(host.split("."))
    fallback: Optional[tuple[str, str]] = None
    for brand in _BRANDS:
        if len(brand) >= 4 and sld_sk == brand and sld != brand:
            return ("malicious",
                    f"look-alike domain impersonating '{brand}' with confusable characters: {host}")
        if len(brand) >= 5 and _lev1(sld_sk, brand) == 1:
            fallback = fallback or ("suspicious", f"possible typosquat of '{brand}': {host}")
        if len(brand) >= 4 and _brand_anchored(sld_sk, brand) and sld_sk != brand:
            fallback = fallback or ("suspicious", f"'{brand}' embedded in an unofficial domain: {host}")
        if len(brand) >= 4 and brand in labels and sld != brand:
            fallback = fallback or ("suspicious", f"'{brand}' used as a subdomain of an unrelated site: {host}")
    return fallback


def _link_structure(url: str) -> list[tuple[str, str]]:
    host = _host(url)
    if not host:
        return []
    if _is_ip(host):
        return [("suspicious", f"link points to a raw IP address instead of a domain: {host}")]
    concerns: list[tuple[str, str]] = []
    if any(l.startswith("xn--") for l in host.split(".")):
        concerns.append(("suspicious", f"punycode / IDN domain that can hide look-alike text: {host}"))
    if _has_mixed_script(host):
        concerns.append(("suspicious", f"mixed-script (homoglyph) characters in domain: {host}"))
    bc = _brand_concern(host)
    if bc:
        concerns.append(bc)
    if _registrable(host) in _SHORTENERS or host in _SHORTENERS:
        concerns.append(("suspicious", f"link shortener hides the true destination: {host}"))
    return concerns


def _refang(text: str) -> str:
    for rx, rep in _DEFANG:
        text = rx.sub(rep, text)
    return text


def _extract_urls(text: str) -> list[str]:
    spans: list[tuple[int, str]] = []
    masked = list(text)
    for m in URL_RE.finditer(text):
        spans.append((m.start(), m.group(0).rstrip(_TRAILING_PUNCT)))
        for i in range(m.start(), m.end()):
            masked[i] = " "
    masked_text = "".join(masked)
    if "." in masked_text:
        for m in HOST_RE.finditer(masked_text):
            if m.group(2).lower() in _TLD_ALLOW:
                spans.append((m.start(), m.group(0).rstrip(_TRAILING_PUNCT)))
    spans.sort(key=lambda x: x[0])
    out, seen = [], set()
    for _, u in spans:
        k = u.lower()
        if k and k not in seen:
            seen.add(k)
            out.append(u)
    return out


def _dedupe(items) -> list[str]:
    out, seen = [], set()
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def _valid_crypto(tok: str) -> bool:
    if tok.startswith("0x") or tok.startswith("bc1"):
        return True
    return sum(c.isdigit() for c in tok) >= 2      # legacy: reject CamelCase words


# --------------------------------------------------------------------------- #
# Detector
# --------------------------------------------------------------------------- #
class Detector:
    def __init__(self, reputation: Optional[ReputationProvider] = None,
                 weights: Optional[Weights] = None) -> None:
        self.rep = reputation or MockReputation()
        self.w = weights or DEFAULT_WEIGHTS

    def _extract(self, text: str) -> dict:
        urls = _extract_urls(text)
        body = URL_RE.sub(" ", text)
        emails, upi = [], []
        if "@" in body:                            # skip O(n) email/UPI work otherwise
            emails = _dedupe(EMAIL_RE.findall(body))
            upi = _dedupe([m.group(0) for m in UPI_RE.finditer(body)
                           if m.group(1).lower() in _UPI_SUFFIXES])
        crypto = _dedupe([t for t in (BTC_RE.findall(body) + ETH_RE.findall(body))
                          if _valid_crypto(t)])
        phones = _dedupe([p.strip() for p in PHONE_RE.findall(body)])
        return {"urls": urls, "emails": emails, "upi": upi,
                "crypto": crypto, "phones": phones}

    def scan(self, text: str, kind: str = "message") -> ScanResult:
        text = _refang((text or "")[:MAX_INPUT_CHARS])
        low = text.lower()
        ind = self._extract(text)

        signals: list[str] = []
        categories: list[str] = []
        content = 0
        struct = 0

        # 1) content signals -------------------------------------------------- #
        if _URGENCY_RE.search(low):
            signals.append("urgency / pressure language"); categories.append("urgency")
            content += self.w.urgency
        if _CREDS_RE.search(low):
            delivery = bool(_CRED_DELIVERY.search(low))
            # strip delivery phrases first so "do not share" isn't read as a request
            requests = bool(_CRED_REQUEST.search(_CRED_DELIVERY.sub(" ", low)))
            categories.append("credentials")
            if delivery and not requests:          # benign OTP/code delivery
                signals.append("mentions credentials in a delivery/notice style (not a request)")
                content += 5
            else:
                signals.append("asks for credentials (OTP / password / PIN / KYC)")
                content += self.w.credentials
            # explicit "share/send your OTP/PIN/CVV" = credential harvesting -> a
            # structural signal, so real harvesting scams reach "Dangerous" even with
            # no link, while legit "log in to verify" notices stay lower.
            if _CRED_HARVEST_RE.search(_CRED_DELIVERY.sub(" ", low)):
                signals.append("asks you to hand over a secret code (OTP / PIN / CVV)")
                categories.append("credential harvesting")
                struct += self.w.credential_harvest
        if _MONEY_RE.search(low):
            signals.append("money / prize / payment bait"); categories.append("money")
            content += self.w.money
        if _ATTACH_RE.search(low):
            signals.append("attachment / app-install lure (APK / EXE)")
            categories.append("attachment"); content += self.w.attachment

        # 2) links — provider verdict + structure, scored once per host ------- #
        host_concerns: dict[str, dict] = {}
        for u in ind["urls"]:
            cs: list[tuple[str, str]] = []
            rep = self.rep.check_link(u)
            if rep == "malicious":
                cs.append(("malicious", f"malicious link flagged by threat intelligence: {u}"))
            elif rep == "suspicious":
                cs.append(("suspicious", f"suspicious link flagged by threat intelligence: {u}"))
            cs += _link_structure(u)
            if not cs:
                continue
            key = _registrable(_host(u)) or u.lower()
            entry = host_concerns.setdefault(key, {"sev": "suspicious", "msgs": []})
            if any(s == "malicious" for s, _ in cs):
                entry["sev"] = "malicious"
            for _, m in cs:
                if m not in entry["msgs"]:
                    entry["msgs"].append(m)
        for entry in host_concerns.values():
            for m in entry["msgs"]:
                if m not in signals:
                    signals.append(m)
            categories.append("malicious link" if entry["sev"] == "malicious" else "suspicious link")
            struct += self.w.link_malicious if entry["sev"] == "malicious" else self.w.link_suspicious

        # 3) look-alike email sender domains ---------------------------------- #
        for e in ind["emails"]:
            bc = _brand_concern(_host(e.split("@")[-1]))
            check = _safe_call(self.rep, "check_email", e)
            if (bc and bc[0] == "malicious") or check == "malicious":
                signals.append(f"sender address impersonates a known brand: {e}")
                categories.append("sender anomaly"); struct += self.w.link_malicious
            elif bc or check == "suspicious":
                signals.append(f"sender domain looks suspicious: {e}")
                categories.append("sender anomaly"); struct += self.w.handle_suspicious

        # 4) payment handles (UPI / crypto) ----------------------------------- #
        if ind["upi"]:
            signals.append("payment handle requested (UPI): " + ", ".join(ind["upi"]))
            categories.append("payment handle"); struct += self.w.handle_suspicious
        if ind["crypto"]:
            signals.append("cryptocurrency address present: " + ", ".join(ind["crypto"]))
            categories.append("crypto payment"); struct += self.w.handle_suspicious

        # 5) phone reputation + callback lure --------------------------------- #
        for ph in ind["phones"]:
            if _safe_call(self.rep, "check_phone", ph) in ("malicious", "suspicious"):
                signals.append(f"phone number linked to reported scams: {ph}")
                categories.append("sender anomaly"); struct += self.w.handle_suspicious
        if ind["phones"] and _CALLBACK_RE.search(low):
            signals.append("call-back / support-number lure")
            categories.append("callback"); struct += self.w.handle_suspicious

        # scoring ------------------------------------------------------------- #
        if struct > 0:
            score = min(content + struct, 100)
        else:
            score = min(content, self.w.threshold_scam - 1)   # content-only can't be "Dangerous"
        verdict = ("scam" if score >= self.w.threshold_scam
                   else "suspicious" if score >= self.w.threshold_suspicious
                   else "safe")
        explanation = ("This message shows " + "; ".join(signals) + "."
                       if signals else "No common scam signals detected.")
        return ScanResult(
            risk_score=score, verdict=verdict, label=_LABELS[verdict],
            signals=signals, categories=_dedupe(categories),
            urls=ind["urls"], phones=ind["phones"], emails=ind["emails"],
            upi_ids=ind["upi"], crypto=ind["crypto"], explanation=explanation,
        )


def _safe_call(rep: object, method: str, arg: str) -> str:
    fn = getattr(rep, method, None)
    try:
        return fn(arg) if callable(fn) else "unknown"
    except Exception:
        return "unknown"
