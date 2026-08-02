"""Application + connector configuration, loaded from environment / .env."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Deployment environment. "production" turns on secure-by-default behavior
    # (secure cookies + same-origin checks) and requires an explicit SECRET_KEY.
    # Anything else (the default) is treated as development.
    environment: str = "development"

    database_url: str = "postgresql+psycopg://vulnunify:vulnunify@localhost:5432/vulnunify"
    log_level: str = "INFO"

    # Fernet key used to encrypt connector credentials at rest. Generate with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # If unset, a dev key is generated and persisted to .vulnunify_secret_key.
    # In production a missing key is a hard error (see services/crypto.py).
    secret_key: str = ""

    # Comma-separated browser origins allowed to call the API cross-origin.
    # Empty (default) = same-origin only; no CORS middleware is installed.
    cors_allow_origins: str = ""

    # --- Auth / sessions ---
    session_cookie_name: str = "vulnunify_session"
    session_ttl_hours: int = 12
    # None = auto (secure in production, off in dev). Set True/False to override.
    session_cookie_secure: bool | None = None
    # Bootstrap admin, created on first startup when no users exist. If the
    # password is blank, a random one is generated and logged once.
    initial_admin_username: str = "admin"
    initial_admin_password: str = ""

    # Background scheduler: run all connectors every N minutes (0 = disabled).
    sync_interval_minutes: int = 0

    # SLA windows (days from first_seen) by severity. info has no SLA.
    sla_critical_days: int = 7
    sla_high_days: int = 30
    sla_medium_days: int = 90
    sla_low_days: int = 180

    # Audit-log retention in days; 0 (default) keeps the trail forever.
    audit_retention_days: int = 0

    # --- Vuln radar (ambient threat-intel from curated social accounts) ---
    # Off by default: no outbound social-API polling until enabled. Sources are
    # free/keyless (Mastodon, Bluesky).
    radar_enabled: bool = False
    radar_poll_minutes: int = 30
    radar_max_age_days: int = 7      # ignore posts older than this when polling
    radar_retention_days: int = 30   # prune radar items older than this (0 = keep)
    # Only surface items scoring at/above this after the funnel (0..1).
    radar_min_confidence: float = 0.35
    # Optional LLM classification layer (precision upgrade; costs per item).
    # Off by default; needs an Anthropic API key. When off, structural signals
    # alone score items.
    radar_llm_enabled: bool = False
    anthropic_api_key: str = ""
    # claude-opus-4-8 is the most capable default; claude-haiku-4-5 is far cheaper
    # per item and well-suited to this classify/extract task — operator's choice.
    radar_llm_model: str = "claude-opus-4-8"

    # --- OIDC / SSO (optional; local accounts remain the default login) ---
    # SSO is enabled only when issuer + client id + secret are all set.
    oidc_issuer: str = ""            # base URL, e.g. https://accounts.google.com
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    # Where the IdP redirects back. Blank = derive from the request's base URL
    # + /api/auth/oidc/callback (register that exact URL with the IdP).
    oidc_redirect_url: str = ""
    oidc_scopes: str = "openid email profile"
    oidc_button_label: str = "Single sign-on"
    # Which ID-token claim becomes the local username (falls back to sub).
    oidc_username_claim: str = "email"
    # Just-in-time provisioning: create a local account on first SSO login for an
    # identity that has none. OFF by default — only pre-created accounts sign in.
    oidc_auto_provision: bool = False
    oidc_default_role: str = "dev"   # role for auto-provisioned users
    # Comma-separated email domains allowed to sign in via SSO (empty = any).
    oidc_allowed_domains: str = ""
    # Trust X-Forwarded-For for audit IPs. Leave FALSE unless a reverse proxy
    # that OVERWRITES the header sits in front — otherwise any client can forge
    # the recorded source IP. When false, the socket peer is recorded.
    trust_proxy_headers: bool = False

    # --- Notifications (Slack-compatible incoming webhook; empty = disabled) ---
    notify_slack_webhook_url: str = ""
    # Open findings at/above this risk score (0..100) trigger a "high risk" alert.
    notify_risk_threshold: int = 80

    # --- Threat intelligence feeds (defaults ship enabled; both are free/no-auth) ---
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_api_url: str = "https://api.first.org/data/v1/epss"

    # --- Tenable ---
    tenable_access_key: str = ""
    tenable_secret_key: str = ""
    tenable_base_url: str = "https://cloud.tenable.com"

    # --- Rapid7 InsightVM Security Console (REST API v3, HTTP Basic auth) ---
    rapid7_base_url: str = ""          # e.g. https://insightvm.example.com:3780
    rapid7_username: str = ""
    rapid7_password: str = ""
    rapid7_verify_ssl: bool = True     # consoles often use self-signed certs

    # --- Wiz ---
    wiz_client_id: str = ""
    wiz_client_secret: str = ""
    wiz_api_url: str = "https://api.us1.app.wiz.io/graphql"
    wiz_auth_url: str = "https://auth.app.wiz.io/oauth/token"
    wiz_auth_audience: str = "wiz-api"   # older tenants may need "beyond-api"

    # --- Trend ---
    trend_api_key: str = ""
    trend_base_url: str = "https://api.xdr.trendmicro.com"

    # --- Defender for Cloud (PowerShell) ---
    defender_subscription_id: str = ""
    defender_pwsh_path: str = "pwsh"

    # --- SonarQube / SonarCloud ---
    sonarqube_token: str = ""
    sonarqube_base_url: str = "https://sonarcloud.io"
    sonarqube_organization: str = ""   # required for SonarCloud
    sonarqube_project_keys: str = ""    # optional comma-separated filter

    # --- Aikido ---
    aikido_client_id: str = ""
    aikido_client_secret: str = ""
    aikido_base_url: str = "https://app.aikido.dev/api"

    # --- Semgrep ---
    semgrep_app_token: str = ""
    semgrep_deployment_slug: str = ""
    semgrep_base_url: str = "https://semgrep.dev/api"

    # --- Snyk (container image scanning) ---
    snyk_token: str = ""
    snyk_org_id: str = ""
    snyk_base_url: str = "https://api.snyk.io"

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() in {"production", "prod"}

    @property
    def cookie_secure(self) -> bool:
        """Effective Secure flag for the session cookie: explicit override wins,
        else secure cookies in production only."""
        if self.session_cookie_secure is not None:
            return self.session_cookie_secure
        return self.is_production

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allow_origins.split(",") if o.strip()]

    @property
    def oidc_configured(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id and self.oidc_client_secret)

    @property
    def oidc_allowed_domain_list(self) -> list[str]:
        return [d.strip().lower() for d in self.oidc_allowed_domains.split(",") if d.strip()]

    @property
    def oidc_scope_list(self) -> list[str]:
        return [s for s in self.oidc_scopes.split() if s]


settings = Settings()
