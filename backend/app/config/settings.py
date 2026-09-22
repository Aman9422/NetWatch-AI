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

    # Connection tracking (M9)
    # Master switch for the connection-tracking consumer of the pipeline. When
    # disabled the capture pipeline stops grouping packets into conversations,
    # while the read-only connection API keeps working (M9.20).
    connection_tracking_enabled: bool = True
    # Seconds a TCP connection may stay idle before it is retired (M9.15).
    connection_tcp_timeout_seconds: float = 300.0
    # Seconds a UDP conversation may stay idle before it is retired (M9.15).
    connection_udp_timeout_seconds: float = 60.0
    # Seconds an ICMP conversation may stay idle before it is retired (M9.15).
    connection_icmp_timeout_seconds: float = 30.0
    # Hard cap on active connections, so a flow flood cannot exhaust memory.
    connection_max_tracked: int = 8192
    # Cap on retired connections retained for reporting (M9.16).
    connection_max_historical: int = 1024
    # Period of the background idle sweep in seconds (M9.15).
    connection_cleanup_interval_seconds: float = 5.0
    # Master switch for writing aggregated connections to SQLite (M9.17).
    connection_persistence_enabled: bool = True
    # Cap on connection rows written per persistence pass (M9.17).
    connection_persistence_max_per_pass: int = 500


@lru_cache
def get_settings() -> Settings:
    """Return a cached ``Settings`` instance."""
    return Settings()


settings = get_settings()
