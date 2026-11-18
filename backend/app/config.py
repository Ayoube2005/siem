"""Application configuration loaded from environment variables.

No secret is ever hardcoded. Every sensitive value comes from the environment
(.env in development, real secrets manager in production).
"""
from functools import lru_cache
from typing import Annotated, List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- Core ---
    app_name: str = "AI-SIEM"
    environment: str = Field(default="development")
    debug: bool = Field(default=False)

    # --- Database ---
    # Async URL used by the app (asyncpg driver).
    database_url: str = Field(
        default="postgresql+asyncpg://siem:siem@db:5432/siem"
    )

    # --- Security / Auth ---
    secret_key: str = Field(default="CHANGE_ME_IN_ENV")
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=60)

    # First admin user, created on startup if the users table is empty.
    first_admin_username: str = Field(default="admin")
    first_admin_password: str = Field(default="admin")  # override in .env!

    # --- CORS ---
    cors_origins: Annotated[List[str], NoDecode] = Field(default=["http://localhost:5173", "http://localhost:8080"])

    # --- Rate limiting ---
    ingest_rate_limit: str = Field(default="240/minute")
    auth_rate_limit: str = Field(default="10/minute")

    # --- Detection tuning ---
    bruteforce_threshold: int = Field(default=5)
    bruteforce_window_seconds: int = Field(default=300)
    spray_distinct_users: int = Field(default=5)
    portscan_distinct_ports: int = Field(default=15)
    portscan_window_seconds: int = Field(default=120)

    # --- AI triage (optional & modular) ---
    ai_enabled: bool = Field(default=True)          # heuristic engine still works offline
    ai_provider: str = Field(default="heuristic")   # heuristic | anthropic | openai
    ai_api_key: str = Field(default="")
    ai_model: str = Field(default="")
    ai_timeout_seconds: int = Field(default=20)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @property
    def sync_database_url(self) -> str:
        """psycopg2 URL for Alembic migrations."""
        return self.database_url.replace("+asyncpg", "+psycopg2")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
