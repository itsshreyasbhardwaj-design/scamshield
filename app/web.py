from __future__ import annotations

import html
import json

from .config import Settings
from .i18n import VERDICT_LABELS, norm_lang, ui

_LANG_NAMES = {"en": "English", "hi": "हिन्दी", "hinglish": "Hinglish"}

_PAGE = r"""<!doctype html>
<html lang="__LANG__" dir="ltr">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
<meta name="theme-color" content="#0b1020"/>
<meta name="description" content="ScamShield — check if a message, link or email is a scam. Built for India."/>
<title>__TITLE__ — scam & fraud check</title>
<link rel="manifest" href="/static/manifest.webmanifest"/>
<link rel="icon" href="/static/icon.svg" type="image/svg+xml"/>
<link rel="icon" href="/static/icon-192.png" sizes="192x192" type="image/png"/>
<link rel="apple-touch-icon" href="/static/apple-touch-icon.png"/>
<style>
:root{
  --bg:#0b1020; --card:#141b30; --card2:#1b2440; --ink:#eef2ff; --muted:#9aa6c7;
  --line:#26304f; --accent:#6ea8fe; --safe:#22c55e; --warn:#f59e0b; --danger:#ef4444;
  --focus:#a5c8ff;
}
@media (prefers-color-scheme: light){
  :root{--bg:#f5f7ff;--card:#ffffff;--card2:#eef2ff;--ink:#0b1020;--muted:#51608a;
        --line:#dbe3fb;--accent:#2563eb;--focus:#1d4ed8;}
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--ink);
  font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans",Arial,sans-serif;
  -webkit-font-smoothing:antialiased;padding:env(safe-area-inset-top) 0 env(safe-area-inset-bottom);}
.wrap{max-width:720px;margin:0 auto;padding:20px 16px 64px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:20px;letter-spacing:.2px}
.brand svg{width:28px;height:28px;flex:0 0 auto}
.langs{display:flex;gap:6px}
.langs a{font-size:12px;color:var(--muted);text-decoration:none;border:1px solid var(--line);
  padding:5px 9px;border-radius:999px}
.langs a[aria-current="true"]{color:var(--ink);border-color:var(--accent);background:var(--card2)}
h1{font-size:26px;line-height:1.2;margin:6px 0 6px}
.tagline{color:var(--muted);margin:0 0 18px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px}
textarea{width:100%;min-height:132px;resize:vertical;background:var(--card2);color:var(--ink);
  border:1px solid var(--line);border-radius:12px;padding:14px;font-size:16px}
textarea:focus,button:focus-visible,a:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
.row{display:flex;gap:10px;margin-top:12px;align-items:center;flex-wrap:wrap}
button.cta{flex:1;min-width:160px;background:var(--accent);color:#04122e;border:0;border-radius:12px;
  padding:14px 16px;font-size:16px;font-weight:800;cursor:pointer}
button.cta[disabled]{opacity:.6;cursor:progress}
button.ghost{flex:0 0 auto;background:var(--card2);border:1px solid var(--line);color:var(--ink);
  border-radius:12px;padding:14px 16px;font-size:15px;cursor:pointer}
.acctbar{display:flex;align-items:center;justify-content:flex-end;gap:10px;margin:14px 2px 0}
.acct{background:transparent;border:1px solid var(--line);color:var(--muted);border-radius:999px;
  padding:7px 14px;font-size:13px;font-weight:600;cursor:pointer}
.authpanel{margin-top:12px}
.authpanel input{width:100%;background:var(--card2);color:var(--ink);border:1px solid var(--line);
  border-radius:12px;padding:13px 14px;font-size:16px;margin:8px 0 10px}
#historylist li{font-size:14px}
.hint{color:var(--muted);font-size:12px}
.result{margin-top:18px}
.hidden{display:none}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;margin-top:14px}
.verdict{display:flex;align-items:center;gap:16px}
.ring{--v:0;--c:var(--muted);width:92px;height:92px;flex:0 0 auto;border-radius:50%;
  background:conic-gradient(var(--c) calc(var(--v)*1%), var(--line) 0);display:grid;place-items:center}
.ring>div{width:70px;height:70px;border-radius:50%;background:var(--card);display:grid;place-items:center;
  font-weight:800;font-size:22px}
.vlabel{font-size:22px;font-weight:800}
.vsub{color:var(--muted);font-size:13px;margin-top:2px}
.badge{display:inline-block;font-size:12px;font-weight:700;padding:3px 9px;border-radius:999px;margin-top:6px}
.explain{margin:14px 0 4px}
h3{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:16px 0 8px}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{background:var(--card2);border:1px solid var(--line);border-radius:999px;padding:6px 11px;font-size:13px}
ul.tips{margin:0;padding-left:18px}
ul.tips li{margin:6px 0}
.help{background:var(--card2);border:1px solid var(--line);border-radius:12px;padding:12px;margin-top:14px;font-size:14px}
.help a{color:var(--accent);font-weight:700;text-decoration:none}
.actions{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap}
.actions button{background:var(--card2);border:1px solid var(--line);color:var(--ink);
  border-radius:10px;padding:10px 14px;font-size:14px;cursor:pointer}
.skel{height:14px;background:linear-gradient(90deg,var(--line),var(--card2),var(--line));
  background-size:200% 100%;animation:sh 1.2s infinite;border-radius:7px;margin:10px 0}
@keyframes sh{0%{background-position:200% 0}100%{background-position:-200% 0}}
.err{color:var(--danger);font-size:14px;margin-top:12px}
footer{color:var(--muted);font-size:12px;margin-top:26px;text-align:center}
footer a{color:var(--muted)}
@media (prefers-reduced-motion: reduce){.skel{animation:none}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 2l8 3v6c0 5-3.4 8.4-8 11-4.6-2.6-8-6-8-11V5l8-3z" fill="#6ea8fe" opacity=".22"/><path d="M12 2l8 3v6c0 5-3.4 8.4-8 11-4.6-2.6-8-6-8-11V5l8-3z" stroke="#6ea8fe" stroke-width="1.4"/><path d="M8.5 12l2.3 2.3L15.6 9.5" stroke="#6ea8fe" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <span>__TITLE__</span>
    </div>
    <nav class="langs" aria-label="__LANGLABEL__">__LANG_LINKS__</nav>
  </header>

  <h1>__TITLE__</h1>
  <p class="tagline">__TAGLINE__</p>

  <div class="panel">
    <label for="content" class="hint">__TAGLINE__</label>
    <textarea id="content" aria-label="__PLACEHOLDER__" placeholder="__PLACEHOLDER__"></textarea>
    <div class="row">
      <button id="check" class="cta">__CHECK__</button>
      <button id="qr" class="ghost" type="button">📷 __QR__</button>
      <input id="qrfile" type="file" accept="image/*" capture="environment" hidden
             aria-label="__QR__"/>
    </div>
    <p class="hint" style="margin-top:10px">__DISCLAIMER__</p>
  </div>

  <div class="acctbar">
    <span id="acctstatus" class="hint"></span>
    <button id="account" class="acct" type="button">__SIGNIN__</button>
  </div>
  <div id="authpanel" class="panel authpanel hidden">
    <div id="auth-email">
      <label class="hint" for="email">__EMAIL_PH__</label>
      <input id="email" type="email" inputmode="email" autocomplete="email" placeholder="__EMAIL_PH__"/>
      <button id="sendcode" class="cta" type="button">__SEND_CODE__</button>
    </div>
    <div id="auth-code" class="hidden">
      <p class="hint">__CODE_SENT__</p>
      <input id="code" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="__CODE_PH__"/>
      <button id="verifycode" class="cta" type="button">__VERIFY__</button>
    </div>
    <div id="auth-in" class="hidden">
      <p id="whoami" class="hint"></p>
      <div class="row">
        <button id="showhistory" class="ghost" type="button">__HISTORY__</button>
        <button id="signout" class="ghost" type="button">__SIGN_OUT__</button>
      </div>
      <ul id="historylist" class="tips"></ul>
    </div>
    <p id="autherr" class="err hidden" role="alert"></p>
  </div>

  <div id="error" class="err hidden" role="alert" aria-live="assertive"></div>

  <div id="result" class="result">
    <div id="empty" class="card"><p class="hint" style="margin:0">__EMPTY__</p></div>
    <div id="loading" class="card hidden" aria-hidden="true">
      <div class="skel" style="width:40%"></div><div class="skel"></div><div class="skel" style="width:80%"></div>
    </div>
    <div id="out" class="card hidden" aria-live="polite">
      <div class="verdict">
        <div id="ring" class="ring" role="img" aria-label="risk score"><div id="ringn">0</div></div>
        <div>
          <div id="vlabel" class="vlabel"></div>
          <div id="vsub" class="vsub"></div>
          <div id="vtype" class="badge"></div>
        </div>
      </div>
      <p id="explain" class="explain"></p>
      <div id="signalsWrap"><h3>__SIGNALS__</h3><div id="chips" class="chips"></div></div>
      <div id="tipsWrap"><h3>__TIPS__</h3><ul id="tips" class="tips"></ul></div>
      <div class="help" id="help"></div>
      <div class="actions">
        <button id="copy">__SHARE__</button>
        <button id="report" class="hidden">__REPORT_THIS__</button>
      </div>
    </div>
  </div>

  <footer>
    <p>__DISCLAIMER__</p>
    <p><a href="/community?lang=__LANG__">__COMMUNITY__</a> · <a href="/privacy?lang=__LANG__">Privacy</a> · <a href="/terms?lang=__LANG__">Terms</a></p>
  </footer>
</div>

<script type="application/json" id="scamshield-ui">__UI_JSON__</script>
<script src="/static/app.js"></script>
</body>
</html>"""


def render_page(lang: str, settings: Settings) -> str:
    lang = norm_lang(lang)
    strings = ui(lang)
    ui_json = dict(strings)
    ui_json["lang"] = lang
    links = ""
    for code, name in _LANG_NAMES.items():
        cur = ' aria-current="true"' if code == lang else ""
        links += f'<a href="/?lang={code}"{cur}>{html.escape(name)}</a>'
    out = _PAGE
    repl = {
        "__LANG__": lang,
        "__TITLE__": html.escape(strings["title"]),
        "__TAGLINE__": html.escape(strings["tagline"]),
        "__PLACEHOLDER__": html.escape(strings["placeholder"]),
        "__CHECK__": html.escape(strings["check"]),
        "__CHECKING__": html.escape(strings["checking"]),
        "__EMPTY__": html.escape(strings["empty"]),
        "__SIGNALS__": html.escape(strings["signals"]),
        "__TIPS__": html.escape(strings["tips"]),
        "__SHARE__": html.escape(strings["share"]),
        "__DISCLAIMER__": html.escape(strings["disclaimer"]),
        "__REPORT_CTA__": html.escape(strings["report_cta"]),
        "__LANGLABEL__": html.escape(strings["lang"]),
        "__SCORE__": html.escape(strings["score"]),
        "__LIKELY__": html.escape(strings["likely"]),
        "__QR__": html.escape(strings["qr"]),
        "__COMMUNITY__": html.escape(strings["community"]),
        "__SIGNIN__": html.escape(strings["sign_in"]),
        "__EMAIL_PH__": html.escape(strings["email_ph"]),
        "__SEND_CODE__": html.escape(strings["send_code"]),
        "__CODE_SENT__": html.escape(strings["code_sent"]),
        "__CODE_PH__": html.escape(strings["code_ph"]),
        "__VERIFY__": html.escape(strings["verify"]),
        "__HISTORY__": html.escape(strings["history"]),
        "__SIGN_OUT__": html.escape(strings["sign_out"]),
        "__REPORT_THIS__": html.escape(strings["report_this"]),
        "__LANG_LINKS__": links,
        # escape "<" so the JSON data block can't be broken out of with </script>
        "__UI_JSON__": json.dumps(ui_json, ensure_ascii=False).replace("<", "\\u003c"),
    }
    for k, v in repl.items():
        out = out.replace(k, v)
    return out


_LEGAL = {
    "privacy": {
        "en": ("Privacy Policy",
               "ScamShield is built for privacy. By default we store only a one-way "
               "SHA-256 hash of what you scan and the verdict — never the raw message. "
               "We redact emails, phone numbers, Aadhaar, PAN and card numbers before any "
               "logging or AI processing. Saving raw content is opt-in, per scan, and you "
               "can export or delete your data at any time (DPDP & GDPR). We do not sell "
               "your data. Free AI providers may process text you scan; do not paste more "
               "than necessary."),
    },
    "terms": {
        "en": ("Terms of Service",
               "ScamShield provides best-effort scam detection to help you stay safe. It is "
               "not a guarantee and is not legal or financial advice. Always verify through "
               "official channels. Report financial fraud to 1930 or cybercrime.gov.in. "
               "Use the service lawfully; do not submit others' personal data without consent."),
    },
}


def render_community(reports, lang: str, settings: Settings) -> str:
    lang = norm_lang(lang)
    s = ui(lang)
    if reports:
        items = "".join(
            f"<li><span class='cat'>{html.escape(r.category)}</span> "
            f"{html.escape(r.pattern)}</li>" for r in reports)
        body = f"<ul class='reports'>{items}</ul>"
    else:
        body = f"<p class='empty'>{html.escape(s['community_empty'])}</p>"
    return (f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(s['community'])} — ScamShield</title>"
            f"<style>body{{background:#0b1020;color:#eef2ff;font:16px/1.6 system-ui,sans-serif;"
            f"max-width:680px;margin:0 auto;padding:28px 18px}}a{{color:#6ea8fe}}"
            f"h1{{font-size:22px}}.reports{{list-style:none;padding:0}}"
            f".reports li{{background:#141b30;border:1px solid #26304f;border-radius:12px;"
            f"padding:12px 14px;margin:10px 0}}.cat{{display:inline-block;font-size:12px;"
            f"font-weight:700;color:#6ea8fe;margin-right:8px;text-transform:uppercase}}"
            f".empty{{color:#9aa6c7}}</style></head><body>"
            f"<h1>🛡️ {html.escape(s['community'])}</h1>{body}"
            f"<p><a href='/?lang={lang}'>← Back to ScamShield</a></p></body></html>")


def render_legal(kind: str, lang: str, settings: Settings) -> str:
    title, body = _LEGAL.get(kind, _LEGAL["privacy"])["en"]
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)} — ScamShield</title>"
            f"<style>body{{background:#0b1020;color:#eef2ff;font:16px/1.6 system-ui,sans-serif;"
            f"max-width:680px;margin:0 auto;padding:32px 18px}}a{{color:#6ea8fe}}</style></head>"
            f"<body><h1>{html.escape(title)}</h1><p>{html.escape(body)}</p>"
            f"<p><a href='/?lang={norm_lang(lang)}'>← Back</a></p></body></html>")
