"""Development seed data for NetWatch AI.

This module inserts safe, non-sensitive sample data so the application is
usable during development. It must NEVER contain real credentials or real
network information.

The module is idempotent: each ``seed_*`` function checks whether the record
already exists before inserting it, so running the seed function repeatedly
will not create duplicate rows.
"""

import logging

from sqlalchemy.orm import Session

from app.database.session import SessionLocal
from app.models.baseline import BehavioralBaseline
from app.models.detection_rule import DetectionRule
from app.models.device import Device
from app.models.setting import Setting
from app.models.system_status import SystemStatus

logger = logging.getLogger(__name__)

# Safe, non-sensitive sample data. The IPs use RFC 1918 private ranges
# (192.168.x.x) which are never routable on the public internet, so they
# cannot leak real network information.
SAMPLE_DEVICES = [
    {
        "ip_address": "192.168.1.10",
        "mac_address": "00:1A:2B:3C:4D:5E",
        "hostname": "dev-laptop",
        "vendor": "Dell",
        "operating_system": "Ubuntu 22.04",
        "device_type": "laptop",
        "status": "online",
        "risk_score": 15,
        "trust_score": 85,
    },
    {
        "ip_address": "192.168.1.20",
        "mac_address": "00:1A:2B:3C:4D:6F",
        "hostname": "kali-vm",
        "vendor": "VMware",
        "operating_system": "Kali Linux",
        "device_type": "virtual_machine",
        "status": "online",
        "risk_score": 60,
        "trust_score": 40,
    },
    {
        "ip_address": "192.168.1.30",
        "mac_address": "00:1A:2B:3C:4D:70",
        "hostname": "metasploitable-vm",
        "vendor": "VMware",
        "operating_system": "Ubuntu 12.04",
        "device_type": "virtual_machine",
        "status": "online",
        "risk_score": 75,
        "trust_score": 25,
    },
    {
        "ip_address": "192.168.1.1",
        "mac_address": "00:1A:2B:3C:4D:81",
        "hostname": "router",
        "vendor": "Cisco",
        "operating_system": "IOS",
        "device_type": "router",
        "status": "online",
        "risk_score": 10,
        "trust_score": 90,
    },
]

SAMPLE_RULES = [
    {
        "rule_key": "port_scan",
        "rule_name": "Port Scan",
        "description": "Detects a high number of unique destination ports from a single source.",
        "detection_type": "port_scan",
        "severity": "high",
        "threshold_config": '{"unique_ports": 40, "time_window_seconds": 60}',
    },
    {
        "rule_key": "syn_flood",
        "rule_name": "SYN Flood",
        "description": "Detects an abnormally high SYN-to-SYN-ACK ratio indicating a flood attack.",
        "detection_type": "syn_flood",
        "severity": "critical",
        "threshold_config": '{"syn_ratio": 0.60, "time_window_seconds": 30}',
    },
    {
        "rule_key": "icmp_flood",
        "rule_name": "ICMP Flood",
        "description": "Detects a flood of ICMP echo requests from a single source.",
        "detection_type": "icmp_flood",
        "severity": "medium",
        "threshold_config": '{"packets_per_second": 200, "time_window_seconds": 30}',
    },
    {
        "rule_key": "internal_scan",
        "rule_name": "Internal Scan",
        "description": "Detects scanning behaviour originating inside the local network.",
        "detection_type": "internal_scan",
        "severity": "high",
        "threshold_config": '{"unique_devices": 10, "time_window_seconds": 120}',
    },
    {
        "rule_key": "dns_anomaly",
        "rule_name": "DNS Anomaly",
        "description": "Detects unusual DNS queries such as repeated NXDOMAIN responses.",
        "detection_type": "dns_anomaly",
        "severity": "medium",
        "threshold_config": '{"nxdomain_ratio": 0.30, "time_window_seconds": 60}',
    },
    {
        "rule_key": "bandwidth_abuse",
        "rule_name": "Bandwidth Abuse",
        "description": "Detects a source consuming an unusual share of total bandwidth.",
        "detection_type": "bandwidth_abuse",
        "severity": "high",
        "threshold_config": '{"bandwidth_share": 0.40, "time_window_seconds": 60}',
    },
]

SAMPLE_SETTINGS = [
    {"setting_key": "capture_interface", "setting_value": "eth0", "data_type": "string"},
    {"setting_key": "capture_enabled", "setting_value": "false", "data_type": "bool"},
    {"setting_key": "packet_retention_days", "setting_value": "30", "data_type": "int"},
    {"setting_key": "default_theme", "setting_value": "dark", "data_type": "string"},
    {"setting_key": "ai_enabled", "setting_value": "true", "data_type": "bool"},
    {"setting_key": "alert_threshold", "setting_value": "medium", "data_type": "string"},
]

SAMPLE_SYSTEM_STATUS = [
    {"component_name": "capture_engine", "status": "stopped", "message": "Capture is not running."},
    {"component_name": "database", "status": "healthy", "message": "Database connected."},
    {"component_name": "api", "status": "healthy", "message": "API is up."},
    {"component_name": "websocket", "status": "stopped", "message": "WebSocket server is not running."},
    {"component_name": "detection_engine", "status": "healthy", "message": "Detection engine ready."},
    {"component_name": "ml_engine", "status": "healthy", "message": "ML engine ready."},
    {"component_name": "ai_engine", "status": "healthy", "message": "AI engine ready."},
]


def seed_devices(db: Session) -> None:
    """Insert sample devices if they do not already exist."""
    for data in SAMPLE_DEVICES:
        existing = db.query(Device).filter(Device.ip_address == data["ip_address"]).first()
        if existing:
            continue
        db.add(Device(**data))
    db.commit()


def seed_detection_rules(db: Session) -> None:
    """Insert sample detection rules if they do not already exist."""
    for data in SAMPLE_RULES:
        existing = (
            db.query(DetectionRule).filter(DetectionRule.rule_key == data["rule_key"]).first()
        )
        if existing:
            continue
        db.add(DetectionRule(**data))
    db.commit()


def seed_settings(db: Session) -> None:
    """Insert sample settings if they do not already exist."""
    for data in SAMPLE_SETTINGS:
        existing = (
            db.query(Setting).filter(Setting.setting_key == data["setting_key"]).first()
        )
        if existing:
            continue
        db.add(Setting(**data))
    db.commit()


def seed_system_status(db: Session) -> None:
    """Insert sample system status entries if they do not already exist."""
    for data in SAMPLE_SYSTEM_STATUS:
        existing = (
            db.query(SystemStatus)
            .filter(SystemStatus.component_name == data["component_name"])
            .first()
        )
        if existing:
            continue
        db.add(SystemStatus(**data))
    db.commit()


def seed_baselines(db: Session) -> None:
    """Insert a sample behavioral baseline for each seeded device."""
    devices = db.query(Device).all()
    for device in devices:
        existing = (
            db.query(BehavioralBaseline)
            .filter(BehavioralBaseline.device_id == device.id)
            .first()
        )
        if existing:
            continue
        db.add(
            BehavioralBaseline(
                device_id=device.id,
                status="learning",
                observation_count=0,
            )
        )
    db.commit()


def seed_all() -> None:
    """Run every seed function using a fresh database session."""
    logger.info("Seeding development data...")
    db = SessionLocal()
    try:
        seed_devices(db)
        seed_detection_rules(db)
        seed_settings(db)
        seed_system_status(db)
        seed_baselines(db)
        logger.info("Database seeded successfully.")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_all()
