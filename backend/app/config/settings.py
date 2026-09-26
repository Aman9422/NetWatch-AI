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

    # Detection (M10)
    # Master switch for the detection consumer of the pipeline. When disabled
    # the capture path stops evaluating rules, while the read-only findings API
    # keeps working (M10.21).
    detection_enabled: bool = True
    # Hard cap on the findings the engine retains for querying (M10.22).
    detection_max_findings: int = 1000
    # Hard cap on the subjects one detector tracks at once, so a spoofed flood
    # cannot exhaust memory (M10.19).
    detection_max_state_keys: int = 4096
    # Cap on the distinct values tracked per subject within one window (M10.19).
    detection_max_values_per_key: int = 4096

    # Port scan detector (M10.8). A finding requires more than
    # ``port_scan_unique_port_threshold`` distinct destination ports from one
    # source inside the window; when SYN evidence exists, the SYN share of that
    # source's traffic must also reach ``port_scan_syn_ratio_threshold``.
    port_scan_time_window_seconds: float = 10.0
    port_scan_unique_port_threshold: int = 20
    port_scan_syn_ratio_threshold: float = 0.5

    # SYN flood detector (M10.9): SYN packets per second aimed at one
    # destination, averaged over the window.
    syn_flood_time_window_seconds: float = 5.0
    syn_flood_rate_threshold: float = 200.0

    # ICMP flood detector (M10.10): ICMP packets per second aimed at one
    # destination, averaged over the window.
    icmp_flood_time_window_seconds: float = 5.0
    icmp_flood_rate_threshold: float = 100.0

    # Internal scan detector (M10.11): distinct internal destinations contacted
    # by one source inside the window.
    internal_scan_time_window_seconds: float = 10.0
    internal_scan_unique_destination_threshold: int = 15

    # High bandwidth detector (M10.12): observed bytes per second over the M6
    # one-second rate window.
    high_bandwidth_time_window_seconds: float = 5.0
    high_bandwidth_bytes_per_second_threshold: float = 1_000_000.0

    # Alerts (M11)
    # Master switch for the alert consumer of the pipeline. When disabled the
    # capture path stops turning findings into alerts, while the read-only alert
    # API keeps working against the alerts already stored (M11.24).
    alerts_enabled: bool = True
    # Seconds a repeated observation is folded into an existing alert instead of
    # raising a new one (M11.9/M11.10). Bounded: see
    # ``app.alerts.dedup.MAX_DEDUP_WINDOW_SECONDS``.
    alert_dedup_window_seconds: float = 300.0
    # Hard cap on the evidence records one alert may carry (M11.12), so a flood
    # cannot turn a single alert into thousands of rows.
    alert_max_evidence_per_alert: int = 64
    # Whether packet evidence is resolved at all. Packet resolution is the only
    # evidence lookup that touches a table which grows without bound, so it has
    # its own switch (M11.13).
    alert_packet_evidence_enabled: bool = True
    # Most packet references attached to one alert, and how far either side of
    # the observation to look for them (M11.13).
    alert_packet_evidence_max_packets: int = 5
    alert_packet_evidence_window_seconds: float = 5.0
    # Most conversation references attached to one alert (M11.14).
    alert_connection_evidence_max: int = 5
    # Default and maximum page size for alert listings (M11.18), so a response
    # stays bounded however many alerts have accumulated.
    alert_default_page_size: int = 100
    alert_max_page_size: int = 1000


@lru_cache
def get_settings() -> Settings:
    """Return a cached ``Settings`` instance."""
    return Settings()


settings = get_settings()
