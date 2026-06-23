"""Application + connector configuration, loaded from environment / .env."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://vulnunify:vulnunify@localhost:5432/vulnunify"
    log_level: str = "INFO"

    # Background scheduler: run all connectors every N minutes (0 = disabled).
    sync_interval_minutes: int = 0

    # SLA windows (days from first_seen) by severity. info has no SLA.
    sla_critical_days: int = 7
    sla_high_days: int = 30
    sla_medium_days: int = 90
    sla_low_days: int = 180

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


settings = Settings()
