"""Database tests for NetWatch AI (Milestone M2).

Covers the database foundation requirements:
* connection
* table creation
* model creation
* CRUD operations
* foreign keys
* constraints
* indexes
* repository methods
* initialisation
* seed data
"""

from datetime import timedelta

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.base import Base
from app.models.alert import Alert
from app.models.baseline import BehavioralBaseline
from app.models.detection_rule import DetectionRule
from app.models.device import Device
from app.models.mixins import utcnow
from app.models.user import User
from app.repositories.alert import AlertRepository
from app.repositories.baseline import BaselineRepository
from app.repositories.connection import ConnectionRepository
from app.repositories.detection_rule import DetectionRuleRepository
from app.repositories.device import DeviceRepository
from app.repositories.packet import PacketRepository


# ---------------------------------------------------------------------------
# Database connection
# ---------------------------------------------------------------------------
def test_database_connection(db_engine) -> None:
    """The engine connects successfully and executes a query."""
    with db_engine.connect() as conn:
        result = conn.execute(text("SELECT 1")).scalar()
    assert result == 1


def test_sqlite_foreign_keys_enabled(db_engine) -> None:
    """Foreign-key enforcement is active on every connection."""
    with db_engine.connect() as conn:
        result = conn.execute(text("PRAGMA foreign_keys")).scalar()
    assert result == 1


# ---------------------------------------------------------------------------
# Table creation
# ---------------------------------------------------------------------------
def test_all_tables_created(db_engine) -> None:
    """All 15 expected tables exist after ``create_all``."""
    Base.metadata.create_all(bind=db_engine)
    inspector = inspect(db_engine)
    tables = set(inspector.get_table_names())
    expected = {
        "users",
        "devices",
        "packets",
        "connections",
        "alerts",
        "alert_evidence",
        "detection_rules",
        "behavioral_baselines",
        "traffic_statistics",
        "protocol_statistics",
        "ai_insights",
        "reports",
        "settings",
        "system_status",
        "notifications",
    }
    assert expected.issubset(tables)


# ---------------------------------------------------------------------------
# Model creation and CRUD
# ---------------------------------------------------------------------------
def test_create_device(db_session: Session) -> None:
    """A device can be created and retrieved."""
    device = Device(
        ip_address="192.168.1.50",
        last_seen=utcnow(),
    )
    db_session.add(device)
    db_session.commit()

    fetched = db_session.query(Device).filter_by(ip_address="192.168.1.50").one()
    assert fetched.id == device.id
    assert fetched.status == "unknown"
    assert fetched.risk_score == 0


def test_unique_username_constraint(db_session: Session) -> None:
    """Duplicate usernames are rejected by the unique constraint."""
    db_session.add(User(username="admin", role="admin"))
    db_session.commit()

    db_session.add(User(username="admin", role="analyst"))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_unique_email_constraint(db_session: Session) -> None:
    """Duplicate emails are rejected by the unique constraint."""
    db_session.add(User(username="u1", email="a@example.com", role="viewer"))
    db_session.commit()

    db_session.add(User(username="u2", email="a@example.com", role="viewer"))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_alert_severity_constraint(db_session: Session) -> None:
    """An invalid severity is rejected by the check constraint."""
    alert = Alert(title="Test", severity="invalid", risk_score=10, confidence=10)
    db_session.add(alert)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_alert_risk_score_constraint(db_session: Session) -> None:
    """A risk score outside 0-100 is rejected."""
    alert = Alert(title="Test", severity="high", risk_score=150, confidence=10)
    db_session.add(alert)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# ---------------------------------------------------------------------------
# Foreign keys
# ---------------------------------------------------------------------------
def test_foreign_key_rejects_orphan_alert(db_session: Session) -> None:
    """An alert referencing a non-existent device is rejected."""
    alert = Alert(
        title="Orphan",
        severity="low",
        risk_score=5,
        confidence=5,
        device_id=99999,
    )
    db_session.add(alert)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_cascade_delete_device_baseline(db_session: Session) -> None:
    """Deleting a device cascades to its behavioral baseline."""
    device = Device(ip_address="192.168.1.60", last_seen=utcnow())
    db_session.add(device)
    db_session.flush()
    db_session.add(BehavioralBaseline(device_id=device.id))

    db_session.commit()
    db_session.delete(device)
    db_session.commit()

    remaining = db_session.query(BehavioralBaseline).all()
    assert remaining == []


# ---------------------------------------------------------------------------
# Indexes
# ---------------------------------------------------------------------------
def test_packet_indexes_exist(db_engine) -> None:
    """Packets table exposes the expected named indexes."""
    Base.metadata.create_all(bind=db_engine)
    inspector = inspect(db_engine)
    indexes = {ix["name"] for ix in inspector.get_indexes("packets")}
    assert {
        "idx_packets_timestamp",
        "idx_packets_source_ip",
        "idx_packets_destination_ip",
        "idx_packets_protocol",
        "idx_packets_device_id",
    }.issubset(indexes)


def test_alert_indexes_exist(db_engine) -> None:
    """Alerts table exposes the expected named indexes."""
    Base.metadata.create_all(bind=db_engine)
    inspector = inspect(db_engine)
    indexes = {ix["name"] for ix in inspector.get_indexes("alerts")}
    assert {
        "idx_alerts_created_at",
        "idx_alerts_severity",
        "idx_alerts_status",
        "idx_alerts_device_id",
        "idx_alerts_rule_id",
    }.issubset(indexes)


def test_connection_indexes_exist(db_engine) -> None:
    """Connections table exposes the expected named indexes."""
    Base.metadata.create_all(bind=db_engine)
    inspector = inspect(db_engine)
    indexes = {ix["name"] for ix in inspector.get_indexes("connections")}
    assert {
        "idx_connections_start_time",
        "idx_connections_source_ip",
        "idx_connections_destination_ip",
    }.issubset(indexes)


# ---------------------------------------------------------------------------
# Repositories
# ---------------------------------------------------------------------------
def test_device_repository_crud(db_session: Session) -> None:
    """DeviceRepository supports create, read, update, delete."""
    repo = DeviceRepository(db_session)
    device = repo.create(
        ip_address="10.0.0.1",
        hostname="server-1",
        last_seen=utcnow(),
    )
    assert device.id is not None

    fetched = repo.get(device.id)
    assert fetched is not None
    assert fetched.hostname == "server-1"

    updated = repo.update(fetched, status="online")
    assert updated.status == "online"

    assert repo.count() == 1
    repo.delete(updated)
    assert repo.count() == 0


def test_device_repository_lookups(db_session: Session) -> None:
    """DeviceRepository lookups return the right devices."""
    repo = DeviceRepository(db_session)
    repo.create(ip_address="10.0.0.1", last_seen=utcnow())
    repo.create(ip_address="10.0.0.2", hostname="web", last_seen=utcnow())
    repo.create(
        ip_address="10.0.0.3",
        hostname="attack",
        status="online",
        risk_score=90,
        last_seen=utcnow(),
    )

    by_ip = repo.get_by_ip("10.0.0.1")
    assert by_ip is not None
    assert by_ip.ip_address == "10.0.0.1"

    by_hostname = repo.get_by_hostname("web")
    assert by_hostname is not None
    assert by_hostname.hostname == "web"

    active = repo.get_active()
    assert len(active) == 1
    assert active[0].ip_address == "10.0.0.3"

    high_risk = repo.get_high_risk(70)
    assert len(high_risk) == 1
    assert high_risk[0].hostname == "attack"


def test_packet_repository_filters(db_session: Session) -> None:
    """PacketRepository filters by device, protocol, and time range."""
    now = utcnow()
    device = Device(ip_address="10.0.0.1", last_seen=now)
    db_session.add(device)
    db_session.flush()

    repo = PacketRepository(db_session)
    repo.create(
        timestamp=now,
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        protocol="TCP",
        packet_length=100,
        device_id=device.id,
    )
    repo.create(
        timestamp=now,
        source_ip="10.0.0.1",
        destination_ip="10.0.0.3",
        protocol="UDP",
        packet_length=200,
        device_id=device.id,
    )

    tcp = repo.get_by_protocol("TCP")
    assert len(tcp) == 1
    assert tcp[0].protocol == "TCP"

    by_device = repo.get_by_device(device.id)
    assert len(by_device) == 2

    recent = repo.get_between(now - timedelta(minutes=1), now + timedelta(minutes=1))
    assert len(recent) == 2

    assert repo.count_all() == 2
    assert repo.count_by_protocol("UDP") == 1


def test_alert_repository_queries(db_session: Session) -> None:
    """AlertRepository filters by severity, status, and device."""
    device = Device(ip_address="10.0.0.1", last_seen=utcnow())
    db_session.add(device)
    db_session.flush()

    repo = AlertRepository(db_session)
    repo.create(
        title="High alert",
        severity="high",
        risk_score=80,
        confidence=90,
        status="new",
        device_id=device.id,
    )
    repo.create(
        title="Low alert",
        severity="low",
        risk_score=10,
        confidence=10,
        status="resolved",
        device_id=device.id,
    )

    assert len(repo.get_by_severity("high")) == 1
    assert len(repo.get_by_status("resolved")) == 1
    assert len(repo.get_by_device(device.id)) == 2
    assert len(repo.get_unresolved()) == 1
    assert len(repo.get_high_priority("high")) == 1


def test_connection_repository_queries(db_session: Session) -> None:
    """ConnectionRepository filters by status and protocol."""
    start = utcnow()
    repo = ConnectionRepository(db_session)
    repo.create(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        protocol="TCP",
        start_time=start,
    )
    repo.create(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.3",
        protocol="UDP",
        start_time=start,
        status="completed",
    )

    assert len(repo.get_active()) == 1
    assert len(repo.get_completed()) == 1
    assert len(repo.get_by_protocol("TCP")) == 1


def test_detection_rule_repository_queries(db_session: Session) -> None:
    """DetectionRuleRepository retrieves enabled rules and by key."""
    repo = DetectionRuleRepository(db_session)
    repo.create(
        rule_key="port_scan",
        rule_name="Port Scan",
        detection_type="port_scan",
        severity="high",
        enabled=1,
    )
    repo.create(
        rule_key="syn_flood",
        rule_name="SYN Flood",
        detection_type="syn_flood",
        severity="critical",
        enabled=0,
    )

    rule = repo.get_by_rule_key("port_scan")
    assert rule is not None
    assert rule.rule_name == "Port Scan"

    assert len(repo.get_enabled()) == 1
    assert len(repo.get_by_detection_type("syn_flood")) == 1


def test_baseline_repository_queries(db_session: Session) -> None:
    """BaselineRepository retrieves baselines by device and state."""
    device = Device(ip_address="10.0.0.1", last_seen=utcnow())
    db_session.add(device)
    db_session.flush()

    repo = BaselineRepository(db_session)
    repo.create(device_id=device.id, status="learning")

    baseline = repo.get_by_device(device.id)
    assert baseline is not None
    assert baseline.status == "learning"

    assert len(repo.get_learning()) == 1
    assert len(repo.get_active()) == 0


# ---------------------------------------------------------------------------
# Initialisation and seed data
# ---------------------------------------------------------------------------
def test_database_initialisation(db_session: Session) -> None:
    """Initialising the database before any tables leaves it usable."""
    # The DB is already created by the fixture; verify a query works.
    result = db_session.execute(text("SELECT COUNT(*) FROM users")).scalar()
    assert result == 0


def test_seed_data(db_session: Session) -> None:
    """Seed data can be inserted and is idempotent."""
    from app.database.seed import (
        seed_detection_rules,
        seed_devices,
        seed_settings,
        seed_system_status,
    )

    seed_devices(db_session)
    seed_detection_rules(db_session)
    seed_settings(db_session)
    seed_system_status(db_session)

    assert db_session.query(Device).count() == 4
    assert db_session.query(DetectionRule).count() == 6
    assert db_session.query(Alert).count() == 0

    # Idempotency: running again adds no rows.
    seed_devices(db_session)
    seed_detection_rules(db_session)
    assert db_session.query(Device).count() == 4
    assert db_session.query(DetectionRule).count() == 6
