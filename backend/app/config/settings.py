"""Application configuration for NetWatch AI."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Values are read from the environment and an optional ``.env`` file.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "NetWatch AI"
    app_version: str = "0.1.0"
    app_env: str = "development"

    # Backend server
    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"

    # Database
    database_url: str = "sqlite:///./netwatch.db"

    # Capture
    default_capture_interface: str = ""


@lru_cache
def get_settings() -> Settings:
    """Return a cached ``Settings`` instance."""
    return Settings()


settings = get_settings()
