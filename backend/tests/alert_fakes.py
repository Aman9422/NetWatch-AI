"""Shared builders and doubles for the M11 alert tests.

Every alert test needs the same three things: a valid M10 finding, an
:class:`~app.alerts.service.AlertService` wired to an isolated database, and —
for the evidence tests — stand-ins for the packet, connection and rule sources
the resolvers read. They live here so each test file states only what is
*different* about the behaviour it exercises.

Nothing in this module touches the developer's real database. The service is
always built over the ``session_factory`` fixture, which points at an in-memory
engine created and dropped per test.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy.orm import Session

from app.alerts.dedup import DEFAULT_DEDUP_WINDOW_SECONDS
from app.alerts.resolvers import FindingResolvers, ResolutionLimits
from app.alerts.service import AlertService
from app.alerts.timestamps import to_utc_datetime
from app.detection.finding import DetectionFinding

#: A fixed observation time, so tests are deterministic.
ALERT_BASE_TIME = 1_767_268_800.0  # 2026-01-01T12:00:00Z
SOURCE_IP = "192.168.1.10"
DESTINATION_IP = "8.8.8.8"
OTHER_SOURCE_IP = "192.168.1.55"
OTHER_DESTINATION_IP = "1.1.1.1"
SOURCE_DEVICE_ID = "mac:AA:BB:CC:DD:EE:FF"
DESTINATION_DEVICE_ID = "mac:22:33:44:55:66:77"


def make_finding(**overrides: Any) -> DetectionFinding:
    """Build a valid M10 finding, overriding individual fields."""
    values: dict[str, Any] = {
        "rule_id": "port_scan",
        "rule_name": "Port Scan",
        "timestamp": ALERT_BASE_TIME,
        "source_ip": SOURCE_IP,
        "destination_ip": DESTINATION_IP,
        "protocol": "TCP",
        "description": "Possible port scan detected",
        "evidence": {"unique_destination_ports": 37, "unique_port_threshold": 20},
        "confidence": 0.8,
    }
    values.update(overrides)
    return DetectionFinding(**values)


def make_service(
    session_factory: Callable[[], Session],
    *,
    resolvers: FindingResolvers | None = None,
    dedup_window_seconds: float = DEFAULT_DEDUP_WINDOW_SECONDS,
    max_evidence: int = 64,
    packet_evidence_enabled: bool = True,
    enabled: bool = True,
    clock: Callable[[], float] | None = None,
) -> AlertService:
    """Build an alert service over an isolated database."""
    kwargs: dict[str, Any] = {
        "session_factory": session_factory,
        "resolvers": resolvers,
        "dedup_window_seconds": dedup_window_seconds,
        "max_evidence": max_evidence,
        "packet_evidence_enabled": packet_evidence_enabled,
        "enabled": enabled,
    }
    if clock is not None:
        kwargs["clock"] = clock
    return AlertService(**kwargs)


def make_resolvers(
    *,
    packet_source: Any | None = None,
    connection_source: Any | None = None,
    rule_source: Any | None = None,
    limits: ResolutionLimits | None = None,
) -> FindingResolvers:
    """Build a resolver set over the supplied doubles."""
    return FindingResolvers(
        packet_source=packet_source,
        connection_source=connection_source,
        rule_source=rule_source,
        limits=limits,
    )


class FakePacket:
    """A minimal persisted-packet double the evidence builder can read."""

    def __init__(
        self,
        packet_id: int,
        *,
        source_ip: str = SOURCE_IP,
        destination_ip: str = DESTINATION_IP,
        protocol: str = "TCP",
        packet_length: int = 74,
        timestamp: float = ALERT_BASE_TIME,
    ) -> None:
        self.id = packet_id
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.protocol = protocol
        self.packet_length = packet_length
        # A real ``packets.timestamp`` is a naive-UTC datetime and the evidence
        # builder converts it back to epoch seconds, so the double holds a
        # datetime rather than a raw float.
        self.timestamp = to_utc_datetime(timestamp)


class FakeConnection:
    """A minimal tracked-conversation double the evidence builder can read."""

    def __init__(
        self,
        connection_id: str = "conn-1",
        *,
        protocol: str = "TCP",
        source_ip: str = SOURCE_IP,
        destination_ip: str = DESTINATION_IP,
        packet_count: int = 12,
        byte_count: int = 900,
        state: str = "active",
    ) -> None:
        self.connection_id = connection_id
        self.protocol = protocol
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.source_port = 52000
        self.destination_port = 443
        self.packet_count = packet_count
        self.byte_count = byte_count
        self.state = state
        self.first_seen = ALERT_BASE_TIME
        self.last_seen = ALERT_BASE_TIME + 1


class FakePacketSource:
    """A packet source returning a fixed list, recording how often it is asked."""

    def __init__(self, packets: list[FakePacket] | None = None) -> None:
        self.packets = packets or []
        self.calls = 0

    def list(self, **filters: Any) -> list[FakePacket]:
        self.calls += 1
        return list(self.packets)


class FakeConnectionSource:
    """A connection source returning a fixed list."""

    def __init__(self, connections: list[FakeConnection] | None = None) -> None:
        self.connections = connections or []
        self.calls = 0

    def list_connections(self, **filters: Any) -> list[FakeConnection]:
        self.calls += 1
        return list(self.connections)


class FakeRule:
    """A minimal rule-catalogue row double: only the primary key is read."""

    def __init__(self, row_id: int) -> None:
        self.id = row_id


class FakeRuleSource:
    """A rule source returning a fixed row, or nothing when unset."""

    def __init__(self, rule: FakeRule | None = None) -> None:
        self.rule = rule
        self.calls = 0

    def get_by_rule_key(self, rule_key: str) -> FakeRule | None:
        self.calls += 1
        return self.rule


def insert_packet(
    session_factory: Callable[[], Session],
    *,
    source_ip: str = SOURCE_IP,
    destination_ip: str = DESTINATION_IP,
    protocol: str = "TCP",
    packet_length: int = 74,
    timestamp: float = ALERT_BASE_TIME,
) -> int:
    """Insert a real ``packets`` row and return its id.

    Packet evidence holds a foreign key into ``packets`` (M11.13) and SQLite
    enforces it, so a test that exercises packet evidence must reference a row
    that actually exists — which is exactly the property being tested: the
    alert points at the packet rather than copying it.
    """
    from app.models.packet import Packet

    session = session_factory()
    try:
        packet = Packet(
            timestamp=to_utc_datetime(timestamp),
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            packet_length=packet_length,
        )
        session.add(packet)
        session.commit()
        session.refresh(packet)
        return int(packet.id)
    finally:
        session.close()


def stored_alert_rows(session_factory: Callable[[], Session]) -> list[Any]:
    """Return every stored ``alerts`` row, newest first."""
    from app.repositories.alert import AlertRepository

    session = session_factory()
    try:
        return AlertRepository(session).list_alerts(limit=1000, offset=0)
    finally:
        session.close()


def stored_alert_count(session_factory: Callable[[], Session]) -> int:
    """Return how many ``alerts`` rows exist."""
    from app.repositories.alert import AlertRepository

    session = session_factory()
    try:
        return AlertRepository(session).count_alerts()
    finally:
        session.close()


__all__ = [
    "ALERT_BASE_TIME",
    "DESTINATION_DEVICE_ID",
    "DESTINATION_IP",
    "FakeConnection",
    "FakeConnectionSource",
    "FakePacket",
    "FakePacketSource",
    "FakeRule",
    "FakeRuleSource",
    "OTHER_DESTINATION_IP",
    "OTHER_SOURCE_IP",
    "SOURCE_DEVICE_ID",
    "SOURCE_IP",
    "make_finding",
    "insert_packet",
    "make_resolvers",
    "make_service",
    "stored_alert_count",
    "stored_alert_rows",
]
