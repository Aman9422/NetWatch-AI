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

    # Correlation (M12)
    # Master switch for the correlation consumer of the pipeline. When disabled
    # the capture path stops grouping alerts into correlated incidents, while the
    # read-only correlation API keeps working against the incidents already held
    # (M12.25).
    correlation_enabled: bool = True
    # Seconds two events may be apart and still be considered for correlation
    # (M12.5). Bounded: see
    # ``app.correlation.window.MAX_CORRELATION_WINDOW_SECONDS``.
    correlation_window_seconds: float = 900.0
    # Seconds within which two related events count as *time-proximal*, which
    # strengthens an existing relationship but never creates one on its own
    # (M12.6).
    correlation_proximity_seconds: float = 300.0
    # Lowest correlation confidence at which an event joins an existing incident
    # (M12.7). Below it the event starts its own incident instead.
    correlation_min_confidence: float = 0.5
    # Lowest strength a single correlation relationship must reach on its own to
    # be accepted as an *anchor*. Time proximity and rule identity alone are
    # deliberately below this, so events are never merged merely because they
    # occurred close together (M12.4).
    correlation_min_anchor_strength: float = 0.55
    # Hard cap on the incidents held in runtime state, so a busy or spoofed
    # network cannot grow correlation memory without limit (M12.22).
    correlation_max_incidents: int = 1024
    # Seconds an incident may stay untouched before expiration may drop it
    # (M12.22). Bounded runtime state, not a security record.
    correlation_retention_seconds: float = 3600.0
    # Hard caps on an incident's membership lists, so one incident cannot
    # accumulate an unbounded set of related references (M12.22).
    correlation_max_related_alerts: int = 64
    correlation_max_correlation_reasons: int = 16
    # Whether an incident's risk score is written onto its member alerts through
    # the existing ``alerts.risk_score`` column (M12.24). No new table or column
    # is introduced: M11 left that column at 0 precisely because M12 owns it.
    correlation_risk_persistence_enabled: bool = True
    # Default and maximum page size for incident listings (M12.26), so a response
    # stays bounded however many incidents are held.
    correlation_default_page_size: int = 100
    correlation_max_page_size: int = 500

    # Risk scoring (M12)
    # Whether a future ML subsystem's contribution may be added to a risk score.
    # M12 ships no ML subsystem, so the default is False and the ML contribution
    # is pinned to 0 — the scoring model reserves the slot without inventing a
    # signal (M12.18).
    risk_ml_contribution_enabled: bool = False
    # Number of *additional* related alerts (beyond the first) that earns the
    # full volume share of the correlation term (M12.17). A lone alert earns no
    # correlation contribution at all, so the model reaches its maximum at
    # ``risk_max_volume_alerts + 1`` grouped alerts — the point at which the
    # documented contribution maxima add up to exactly 100.
    risk_max_volume_alerts: int = 5
    # Highest number of historical occurrences that contributes the full
    # historical term, so history stays bounded context and never dominates
    # (M12.20).
    risk_max_historical_occurrences: int = 5
    # Seconds over which the recency share of the context term decays to zero
    # (M12.15).
    risk_recency_seconds: float = 3600.0

    # WebSockets (M14)
    # Master switch for the real-time transport. When disabled the four
    # endpoints still exist and still answer the keepalive, but no event is
    # published, so the cost of the layer is zero rather than merely small
    # (M14.33). The REST API is unaffected either way (M14.1).
    websockets_enabled: bool = True
    # Hard cap on simultaneously connected WebSocket clients, so a connection
    # flood is refused instead of absorbed (M14.22).
    websocket_max_connections: int = 32
    # Hard cap per channel, so one channel's clients cannot crowd the others
    # out of the process-wide budget (M14.5).
    websocket_max_connections_per_channel: int = 16
    # Seconds a single socket write may take before the client is treated as
    # dead and removed. Bounds the lifetime of a stalled client (M14.14).
    websocket_send_timeout_seconds: float = 5.0
    # Seconds between server keepalives on each channel. Deliberately measured
    # in tens of seconds: one message per client per interval, not per second
    # (M14.24).
    websocket_heartbeat_interval_seconds: float = 20.0
    # Largest encoded event that may be queued for a client, in bytes. An
    # oversized event is refused rather than sent (M14.22/M14.26).
    websocket_max_event_bytes: int = 16384
    # Largest client message accepted, in bytes. Anything larger is refused
    # before it is parsed (M14.22).
    websocket_max_client_message_bytes: int = 512
    # How many invalid client messages one connection may send before it is
    # disconnected, so a garbage flood cannot consume the server (M14.23).
    websocket_max_invalid_messages: int = 5
    # How often the dashboard event is sampled (M14.9). The tick is the rate
    # limit for that channel: a dashboard wants a steady refresh rather than an
    # event per counter movement.
    websocket_dashboard_interval_seconds: float = 1.0
    # Per-connection outbound queue sizes (M14.15). Each is a hard cap: a full
    # queue drops its oldest entry rather than growing. Alerts get the largest
    # budget because they are the security-relevant stream, and the dashboard
    # the smallest because a stale dashboard sample is the most disposable.
    websocket_dashboard_queue_size: int = 32
    websocket_alert_queue_size: int = 512
    websocket_system_queue_size: int = 128
    # Packet streaming (M14.16). ``packet_ws_enabled`` gates the packet channel
    # specifically, so an operator can keep the other three channels live while
    # removing the one high-frequency stream from the hot path.
    packet_ws_enabled: bool = True
    # Ceiling on packet events broadcast per second, applied to the channel
    # rather than to one connection, so adding subscribers does not multiply
    # the work (M14.16).
    packet_ws_max_events_per_second: float = 200.0
    # Outbound queue size for a packet subscriber (M14.16).
    packet_ws_queue_size: int = 256


@lru_cache
def get_settings() -> Settings:
    """Return a cached ``Settings`` instance."""
    return Settings()


settings = get_settings()
