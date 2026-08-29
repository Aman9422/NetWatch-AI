"""Device repository for NetWatch AI."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.device import Device
from app.repositories.base import BaseRepository


class DeviceRepository(BaseRepository[Device]):
    """Repository for device queries.

    Extends ``BaseRepository`` with device-specific lookups so business logic
    does not write raw SQLAlchemy queries.
    """

    def __init__(self, db: Session) -> None:
        super().__init__(db, Device)

    def get_by_ip(self, ip_address: str) -> Device | None:
        """Return the first device matching an IP address."""
        stmt = select(Device).where(Device.ip_address == ip_address)
        return self.db.scalar(stmt)

    def get_by_mac(self, mac_address: str) -> Device | None:
        """Return the first device matching a MAC address."""
        stmt = select(Device).where(Device.mac_address == mac_address)
        return self.db.scalar(stmt)

    def get_by_hostname(self, hostname: str) -> Device | None:
        """Return the first device matching a hostname."""
        stmt = select(Device).where(Device.hostname == hostname)
        return self.db.scalar(stmt)

    def get_active(self) -> list[Device]:
        """Return devices with status ``online``."""
        stmt = select(Device).where(Device.status == "online").order_by(Device.id)
        return list(self.db.scalars(stmt).all())

    def get_offline(self) -> list[Device]:
        """Return devices with status ``offline``."""
        stmt = select(Device).where(Device.status == "offline").order_by(Device.id)
        return list(self.db.scalars(stmt).all())

    def get_high_risk(self, min_score: int = 70) -> list[Device]:
        """Return devices whose risk score is at or above a threshold."""
        stmt = (
            select(Device)
            .where(Device.risk_score >= min_score)
            .order_by(Device.risk_score.desc())
        )
        return list(self.db.scalars(stmt).all())

    def touch(
        self,
        device: Device,
        *,
        last_seen,
        total_packets: int | None = None,
        total_bytes: int | None = None,
    ) -> Device:
        """Update device activity counters and last-seen timestamp."""
        device.last_seen = last_seen
        if total_packets is not None:
            device.total_packets = total_packets
        if total_bytes is not None:
            device.total_bytes = total_bytes
        self.db.commit()
        self.db.refresh(device)
        return device
