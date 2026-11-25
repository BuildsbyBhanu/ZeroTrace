"""Pydantic-settings based configuration for ZeroTrace."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from .env and environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        env_prefix="ZEROTRACE_",
    )

    # ── Application ───────────────────────────────
    app_name: str = "ZeroTrace"
    app_version: str = "0.1.0"
    debug: bool = False
    host: str = "127.0.0.1"
    port: int = 8000

    # ── Database ──────────────────────────────────
    # Read from ZEROTRACE_DATABASE_URL env var if set, otherwise default to SQLite
    # Supports: sqlite+aiosqlite:///./data/zerotrace.db
    # Supports: postgresql+asyncpg://localhost:5432/zerotrace
    database_url: str = Field(
        default="sqlite+aiosqlite:///./data/zerotrace.db",
        alias="DATABASE_URL"
    )

    # Environment variable aliases (DATABASE_URL maps to database_url via pydantic-settings)

    # ── Scan Engine Defaults ──────────────────────
    max_concurrency: int = 10
    requests_per_second: float = 10.0
    connection_timeout: float = 10.0
    read_timeout: float = 30.0
    total_scan_timeout: float = 600.0
    max_redirect_depth: int = 5
    max_requests_per_scan: int = 5000

    # ── SSRF Protection ────────────────────────────
    # Allow scanning localhost/127.0.0.1 for local development/testing
    # When False (default): Blocks all private IP ranges including localhost
    # When True: Allows localhost/127.0.0.1 but still blocks cloud metadata (169.254.169.254)
    #          and non-loopback private networks (10.x, 172.16-31.x, 192.168.x)
    allow_localhost: bool = False

    # ── Security ──────────────────────────────────
    credential_encryption_key: str | None = None

    # ── Logging ───────────────────────────────────
    log_level: str = "INFO"
    log_format: Literal["json", "text"] = "json"

    # ── Computed Paths ────────────────────────────
    @property
    def data_dir(self) -> Path:
        return Path(__file__).parent.parent.parent / "data"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "zerotrace.db"

    @property
    def audit_log_path(self) -> Path:
        return self.data_dir / "audit.log.jsonl"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    # ── Validation ────────────────────────────────
    @classmethod
    def validate(cls, values: dict) -> dict:
        if values.get("credential_encryption_key"):
            import base64
            key = values["credential_encryption_key"]
            if isinstance(key, str):
                try:
                    base64.urlsafe_b64decode(key)
                except Exception:
                    raise ValueError(
                        "CREDENTIAL_ENCRYPTION_KEY must be a valid Fernet key "
                        "(base64-encoded 32-byte key). Generate one with:\n"
                        "  python -c \"from cryptography.fernet import Fernet; "
                        "print(Fernet.generate_key().decode())\""
                    )
        return values


# Module-level singleton
settings = Settings()


def get_settings() -> Settings:
    """Dependency injection getter for FastAPI."""
    return settings
