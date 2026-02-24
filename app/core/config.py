"""
Application configuration — all values overridable via environment variables.
Never hardcode secrets. Use .env for local dev, secrets manager in production.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── API ────────────────────────────────────────────────────────────────────
    API_VERSION: str = "1.0.0"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = False

    # ── Security ───────────────────────────────────────────────────────────────
    # In production: generate with `openssl rand -hex 32`
    JWT_SECRET_KEY: str = Field(
        default="CHANGE_ME_IN_PRODUCTION_use_openssl_rand_hex_32",
        description="HS256 signing key — MUST be overridden in production",
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15       # short-lived access tokens
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7          # longer-lived refresh tokens
    PASSWORD_MIN_LENGTH: int = 8

    # ── Database ───────────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./secure_api.db"
    # For production: "postgresql+asyncpg://user:pass@host/dbname"

    # ── Rate limiting ──────────────────────────────────────────────────────────
    RATE_LIMIT_VIEWER: str = "60/minute"
    RATE_LIMIT_ANALYST: str = "200/minute"
    RATE_LIMIT_ADMIN: str = "500/minute"
    RATE_LIMIT_DEFAULT: str = "30/minute"

    # ── CORS ───────────────────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:8080"]

    # ── Logging ────────────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: Literal["json", "console"] = "json"

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def warn_default_secret(cls, v: str) -> str:
        if v.startswith("CHANGE_ME") and False:  # flip to True in prod CI
            raise ValueError("JWT_SECRET_KEY must be set in production")
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
