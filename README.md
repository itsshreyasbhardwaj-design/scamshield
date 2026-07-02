# ScamShield — AI Scam & Fraud Detection (built for India) 🛡️

[![CI](https://github.com/itsshreyasbhardwaj-design/scamshield/actions/workflows/ci.yml/badge.svg)](https://github.com/itsshreyasbhardwaj-design/scamshield/actions/workflows/ci.yml)
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/itsshreyasbhardwaj-design/scamshield)

**One-click deploy:** click the **Deploy to Render** button above → sign in → it reads `render.yaml`
and gives you a live public URL (free tier). The anonymous scanner works with zero keys; add the
Supabase/LLM env vars later to switch on accounts + AI explanations.

Paste a suspicious SMS, WhatsApp message, email, or link → get a **risk score (0–100)**,
a clear verdict (**Safe / Suspicious / Dangerous**), the exact **signals** found, a
**plain-language explanation** in your language, and **India-specific safety tips** — in
under a second. Installable mobile-first PWA. **₹0 to run.**

Built for India: English • हिन्दी • Hinglish, UPI/Aadhaar/KYC-aware, recognises digital-arrest,
courier-customs, KBC-lottery, loan-app, UPI-reversal and other local scams, and always shows the
national cyber-crime helpline **1930 / cybercrime.gov.in**.

## Why it's trustworthy
- **Deterministic engine, LLM only explains.** The score/verdict come from a tested, deterministic
  detector — reproducible and cheap. The LLM (optional) only writes the human explanation.
- **Privacy by default (§10).** We store only a SHA-256 **hash** of what you scan, never the raw
  text (raw storage is opt-in, per scan). Emails, phones, Aadhaar, PAN and card numbers are
  **redacted** before any logging or AI call.
- **Offline-first.** Runs fully with **zero API keys** (mock reputation, template explanations,
  in-memory store) and flips to live via env vars only.
- **Hardened.** RLS on every table, rate limiting, security headers + CSP, input caps, ReDoS-safe
  regexes, SSRF-safe (we never fetch the suspicious URL). Two adversarial audit passes applied.

## Quick start (offline, no keys)
```bash
git clone https://github.com/itsshreyasbhardwaj-design/scamshield && cd scamshield
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=. python -m pytest -q            # 97 tests, all green, zero keys
PYTHONPATH=. uvicorn app.main:app --reload  # open http://localhost:8000
```
Try it:
```bash
curl -s localhost:8000/api/scan -H 'content-type: application/json' \
  -d '{"content":"URGENT: SBI KYC pending. Update at http://sbi-kyc-verify.com and share your OTP"}'
```

## Go live (all free tiers — see ../Zero-Cost-Stack.md)
Copy `.env.example` → `.env` and set only what you want:
```bash
LLM_PROVIDER=openai                                  # AI explanations
OPENAI_BASE_URL=https://api.groq.com/openai/v1       # Groq (free) or Gemini
OPENAI_API_KEY=gsk_...                               # free key
SAFE_BROWSING_API_KEY=...                            # Google Safe Browsing (free)
SUPABASE_URL=... SUPABASE_ANON_KEY=... SUPABASE_SERVICE_ROLE_KEY=...
SENTRY_DSN=...
```
`GET /health` shows which providers are live vs mock. Missing a key just falls back to mock.

## API
| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/scan` | optional | score + verdict + signals + explanation + tips |
| POST | `/api/check-link` | – | link reputation + reasons |
| POST | `/api/auth/request-otp` | – | email a login code (Supabase Auth) |
| POST | `/api/auth/verify-otp` | – | verify code → access token (JWT) |
| GET  | `/api/history` | required | your past scans (if you opted to store) |
| POST | `/api/report` | required | submit a community scam report (moderated) |
| GET  | `/api/reports` | – | approved community patterns |
| GET  | `/api/export-my-data` | required | DPDP/GDPR data export |
| POST | `/api/delete-my-data` | required | DPDP/GDPR erasure |
| GET  | `/health` | – | status + provider modes |

**Accounts:** passwordless **email-OTP via Supabase Auth, proxied through this backend** — the browser stays same-origin (CSP `connect-src 'self'`) and the anon key never ships to the client. Sign-in activates only when `SUPABASE_URL` + `SUPABASE_ANON_KEY` are set; the core scanner works fully anonymously without it. In-browser: Sign in → history, and "Report as scam" on results.

## Database
The schema (`migrations/0001_init.sql`) is **already applied** to the provisioned Supabase
project `uxnbosmcerbgmqvwewbv` — `scans` and `reports` exist with **RLS + policies** on, and
`profiles` is reused. The DB write path was smoke-tested against the live schema. Re-running the
migration is safe (idempotent: `create table if not exists`, `drop policy if exists`).

## Deploy (free)
- **Render**: `render.yaml` blueprint (Singapore region, closest free to India), health check `/health`.
- **Any host**: `Procfile` → `uvicorn app.main:app`.
- Set secrets in the dashboard — never commit `.env`.
- CI: `.github/workflows/ci.yml` runs the offline test suite on every push.

## Architecture
```
PWA (mobile-first, en/hi/hinglish)  ──POST /api/scan──▶  FastAPI
  detector.py     deterministic signals + score (0–100)  ← the source of truth
  reputation.py   Google Safe Browsing | MockReputation (swappable)
  explain.py      agentcore LLM explanation + template fallback + cache
  india.py/i18n   scam-type classification, localised tips, 1930 helpline
  repository.py   Supabase (RLS) | in-memory   ·   privacy.py  redaction + hashing
```
Everything sits behind a small interface with a mock, so it's testable offline and $0 by default.

**Disclaimer:** best-effort detection, not a guarantee; not legal or financial advice. Report
financial fraud to **1930** within the golden hour, or file at **cybercrime.gov.in**.
