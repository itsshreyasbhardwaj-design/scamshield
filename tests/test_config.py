from app.config import Settings


def test_auth_mode_is_decoupled_from_storage():
    # production without a JWT backend must NOT fall back to header auth
    assert Settings(env="production").auth_mode == "none"
    # dev honours the debug header for local testing
    assert Settings(env="development").auth_mode == "debug"
    # a configured JWT backend requires real tokens, regardless of DB/service key
    assert Settings(supabase_url="https://x.supabase.co", supabase_anon_key="anon").auth_mode == "jwt"


def test_prod_gate_is_case_and_variant_safe():
    # any non-dev env value fails safe to 'none' (no spoofable header auth)
    for e in ("Production", "PRODUCTION", "prod", "staging", "prod ", "weird", ""):
        assert Settings(env=e).auth_mode == "none", e


def test_prod_debug_auth_can_be_disabled_but_is_already_off_in_prod():
    assert Settings(env="production", allow_debug_auth=True).auth_mode == "none"
    assert Settings(env="development", allow_debug_auth=False).auth_mode == "none"


def test_database_mode_independent_of_auth():
    assert Settings().database_mode == "memory"
    s = Settings(supabase_url="https://x.supabase.co", supabase_service_role_key="svc")
    assert s.database_mode == "supabase"


def test_trusted_proxies_default_empty():
    assert Settings().trusted_proxies == []
