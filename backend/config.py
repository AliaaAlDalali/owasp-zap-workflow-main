from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=BACKEND_DIR / ".env", extra="ignore")

    database_path: Path = BACKEND_DIR / "data" / "app.db"

    # Sessions: an HttpOnly cookie holding a random token; only its hash is stored.
    session_cookie_name: str = "himaak_session"
    session_days: int = 14
    cookie_secure: bool = True  # set COOKIE_SECURE=false only for local http development
    login_max_failures: int = 5
    login_lockout_minutes: int = 15

    # Front-end origins allowed to call the API with credentials (comma-separated JSON list in env).
    cors_origins: list[str] = []

    # Scanning
    zap_image: str = "ghcr.io/zaproxy/zaproxy:stable"
    scan_work_dir: Path = BACKEND_DIR / "data" / "scans"
    scan_timeout_seconds: int = 1800
    scan_memory_limit: str = "2g"
    scan_cpu_limit: str = "1.5"
    scan_worker_poll_seconds: float = 3.0
    max_active_scans_per_organization: int = 2

    # Ownership verification
    verification_timeout_seconds: float = 8.0


settings = Settings()
