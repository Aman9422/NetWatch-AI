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

    # Device discovery (M8)
    # Seconds after a device's last sighting before it becomes "inactive" (M8.9).
    device_inactivity_threshold_seconds: float = 120.0
    # Seconds after a device's last sighting before cleanup may remove it (M8.14).
    device_retention_seconds: float = 3600.0
    # Hard cap on tracked devices, so spoofed addresses cannot exhaust memory.
    device_max_tracked: int = 4096

    # Packet persistence (M7)
    # Master switch for persisting normalized packet metadata to SQLite. When
    # disabled the persistence layer accepts nothing and performs no writes.
    packet_persistence_enabled: bool = True
    # Number of buffered packets that triggers a database write (M7.6).
    packet_batch_size: int = 500
    # Seconds a non-empty buffer may wait before it is flushed anyway (M7.6).
    packet_flush_interval_seconds: float = 2.0
    # Hard cap on buffered, not-yet-persisted packets. The buffer is bounded so
    # a slow database can never grow memory without limit (M7.9).
    packet_queue_max: int = 10000
    # Days a packet row is kept before retention cleanup may delete it (M7.13).
    packet_retention_days: int = 30


@lru_cache
def get_settings() -> Settings:
    """Return a cached ``Settings`` instance."""
    return Settings()


settings = get_settings()
