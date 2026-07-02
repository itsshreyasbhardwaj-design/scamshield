from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List


def _bool(v: str) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


# Only these environments may use the insecure X-User-Id debug header. Anything
# else (Production, prod, staging, a typo, empty) fails safe to no debug auth.
_DEV_ENVS = {"development", "dev", "local", "test", "testing"}


@dataclass
class Settings:
    """All configuration. Defaults keep everything OFFLINE (mock providers,
    in-memory store, template explanations) with zero API keys. Flip to live
    entirely via environment variables — no code changes.

    Built for India by default: default_country=IN, ₹ currency, +91 phones,
    English/Hindi/Hinglish UI, and the 1930 cyber-crime helpline.
    """
    app_name: str = "ScamShield"
    env: str = "development"

    # --- LLM (free OpenAI-compatible endpoint via agentcore) ---------------- #
    llm_provider: str = "mock"                 # mock | openai | claude
    openai_base_url: str = "https://api.groq.com/openai/v1"
    openai_api_key: str = ""
    openai_model: str = "llama-3.3-70b-versatile"
    explanation_timeout: float = 8.0

    # --- Link/threat reputation --------------------------------------------- #
    safe_browsing_api_key: str = ""            # Google Safe Browsing (free)

    # --- Supabase (Postgres + Auth + RLS) ----------------------------------- #
    supabase_url: str = ""
    supabase_anon_key: str = ""
    supabase_service_role_key: str = ""

    # --- Monitoring --------------------------------------------------------- #
    sentry_dsn: str = ""

    # --- Privacy defaults (data minimisation, §10) -------------------------- #
    store_raw_default: bool = False            # never store raw content unless opted in

    # --- Rate limiting (protect free tiers + abuse) ------------------------- #
    rate_limit_per_min: int = 20
    rate_limit_per_day: int = 500

    # --- Localisation ------------------------------------------------------- #
    default_country: str = "IN"
    default_language: str = "en"               # en | hi | hinglish

    allowed_origins: List[str] = field(default_factory=lambda: ["*"])
    trusted_proxies: List[str] = field(default_factory=list)   # peer IPs whose X-Forwarded-For we trust
    allow_debug_auth: bool = True                              # honour X-User-Id in non-prod only

    # -- derived provider modes (surfaced by /health) ------------------------ #
    @property
    def auth_mode(self) -> str:
        """How a caller is authenticated — decoupled from where data is stored.
        'jwt': verify a Supabase token. 'debug': trust X-User-Id (non-prod only).
        'none': anonymous only; authed endpoints return 401."""
        if self.supabase_url and self.supabase_anon_key:
            return "jwt"
        # fail-safe allowlist: only explicit dev markers enable header auth
        if (self.env or "").strip().lower() in _DEV_ENVS and self.allow_debug_auth:
            return "debug"
        return "none"

    @property
    def llm_mode(self) -> str:
        return "live" if self.llm_provider in ("openai", "claude") and self.openai_api_key else "mock"

    @property
    def reputation_mode(self) -> str:
        return "live" if self.safe_browsing_api_key else "mock"

    @property
    def database_mode(self) -> str:
        return "supabase" if (self.supabase_url and self.supabase_service_role_key) else "memory"

    @property
    def sentry_mode(self) -> str:
        return "live" if self.sentry_dsn else "off"

    def modes(self) -> dict:
        return {
            "llm": self.llm_mode,
            "reputation": self.reputation_mode,
            "database": self.database_mode,
            "auth": self.auth_mode,
            "sentry": self.sentry_mode,
            "country": self.default_country,
        }

    @classmethod
    def from_env(cls) -> "Settings":
        g = os.getenv
        origins = g("ALLOWED_ORIGINS", "*")
        return cls(
            app_name=g("APP_NAME", "ScamShield"),
            env=g("ENV", "development").strip().lower(),
            llm_provider=g("LLM_PROVIDER", "mock"),
            openai_base_url=g("OPENAI_BASE_URL", "https://api.groq.com/openai/v1"),
            openai_api_key=g("OPENAI_API_KEY", ""),
            openai_model=g("OPENAI_MODEL", "llama-3.3-70b-versatile"),
            explanation_timeout=float(g("EXPLANATION_TIMEOUT", "8.0")),
            safe_browsing_api_key=g("SAFE_BROWSING_API_KEY", ""),
            supabase_url=g("SUPABASE_URL", ""),
            supabase_anon_key=g("SUPABASE_ANON_KEY", ""),
            supabase_service_role_key=g("SUPABASE_SERVICE_ROLE_KEY", ""),
            sentry_dsn=g("SENTRY_DSN", ""),
            store_raw_default=_bool(g("STORE_RAW_DEFAULT", "false")),
            rate_limit_per_min=int(g("RATE_LIMIT_PER_MIN", "20")),
            rate_limit_per_day=int(g("RATE_LIMIT_PER_DAY", "500")),
            default_country=g("DEFAULT_COUNTRY", "IN"),
            default_language=g("DEFAULT_LANGUAGE", "en"),
            allowed_origins=[o.strip() for o in origins.split(",") if o.strip()],
            trusted_proxies=[p.strip() for p in g("TRUSTED_PROXIES", "").split(",") if p.strip()],
            allow_debug_auth=_bool(g("ALLOW_DEBUG_AUTH", "true")),
        )
