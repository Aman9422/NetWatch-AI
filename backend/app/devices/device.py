"""The runtime device record (M8.3/M8.4/M8.6).

``ObservedDevice`` is plain, mutable state. It is only ever touched while the
registry lock is held, so it carries no lock of its own — the registry is the
single concurrency boundary. Keeping it a plain dataclass keeps the hot
per-packet path free of framework overhead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.schemas.device import DeviceStatus, DeviceView

# Default inactivity threshold, used when a record is rendered outside a
# configured manager. Kept in sync with ``Settings``.
DEFAULT_INACTIVITY_THRESHOLD_SECONDS = 120.0


def _to_iso(timestamp: float | None) -> str | None:
    """Render epoch seconds as an ISO-8601 UTC string, or ``None``."""
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def _earliest(first: float | None, second: float | None) -> float | None:
    """Return the earlier of two optional timestamps."""
    if first is None:
        return second
    if second is None:
        return first
    return min(first, second)


def _latest(first: float | None, second: float | None) -> float | None:
    """Return the later of two optional timestamps."""
    if first is None:
        return second
    if second is None:
        return first
    return max(first, second)


@dataclass
class ObservedDevice:
    """A device observed on the monitored network."""

    device_id: str
    mac_address: str | None = None
    ip_addresses: set[str] = field(default_factory=set)
    first_seen: float | None = None
    last_seen: float | None = None
    packet_count: int = 0
    byte_count: int = 0
    packets_sent: int = 0
    bytes_sent: int = 0
    packets_received: int = 0
    bytes_received: int = 0
    hostname: str | None = None
    vendor: str | None = None
    is_local: bool = False

    # -- identity ---------------------------------------------------------

    @property
    def has_mac(self) -> bool:
        """Return True when a MAC address has been observed for this device."""
        return self.mac_address is not None

    def add_ip(self, ip_address: str) -> None:
        """Record an observed IP address (M8.6)."""
        self.ip_addresses.add(ip_address)

    def remove_ip(self, ip_address: str) -> None:
        """Forget an IP address that now belongs to a different device."""
        self.ip_addresses.discard(ip_address)

    # -- observation ------------------------------------------------------

    def observe(
        self,
        *,
        length: int,
        at: float,
        as_source: bool,
        as_destination: bool,
    ) -> None:
        """Update counters and timestamps for one observed packet (M8.4/M8.5).

        Args:
            length: Captured frame length in bytes (already clamped to >= 0).
            at: Observation time in epoch seconds.
            as_source: True when this device is the packet's source.
            as_destination: True when this device is the packet's destination.
        """
        if self.first_seen is None:
            self.first_seen = at
        self.last_seen = at
        self.packet_count += 1
        self.byte_count += length
        if as_source:
            self.packets_sent += 1
            self.bytes_sent += length
        if as_destination:
            self.packets_received += 1
            self.bytes_received += length

    def merge(self, other: "ObservedDevice") -> None:
        """Adopt another record's observations (identity upgrade, M8.16).

        Used only when a MAC-less, IP-keyed record turns out to describe the
        same host as a newly seen MAC-keyed record. Never used to merge two
        records that both carry a MAC.
        """
        self.ip_addresses.update(other.ip_addresses)
        self.packet_count += other.packet_count
        self.byte_count += other.byte_count
        self.packets_sent += other.packets_sent
        self.bytes_sent += other.bytes_sent
        self.packets_received += other.packets_received
        self.bytes_received += other.bytes_received
        self.first_seen = _earliest(self.first_seen, other.first_seen)
        self.last_seen = _latest(self.last_seen, other.last_seen)
        if self.hostname is None:
            self.hostname = other.hostname
        if self.vendor is None:
            self.vendor = other.vendor
        self.is_local = self.is_local or other.is_local

    # -- status and cleanup ----------------------------------------------

    def status(self, *, now: float, inactivity_threshold: float) -> DeviceStatus:
        """Return the activity status derived from ``last_seen`` (M8.9).

        Status never depends on traffic volume — only on how long ago the
        device was last observed.
        """
        if self.last_seen is None:
            return DeviceStatus.UNKNOWN
        age = now - self.last_seen
        if age <= inactivity_threshold:
            return DeviceStatus.ACTIVE
        return DeviceStatus.INACTIVE

    def is_expired(self, *, now: float, retention_seconds: float) -> bool:
        """Return True when the device is old enough to be cleaned up (M8.14).

        A device with no timestamp is never considered expired.
        """
        if self.last_seen is None:
            return False
        return (now - self.last_seen) > retention_seconds

    # -- projection -------------------------------------------------------

    def to_view(self, *, now: float, inactivity_threshold: float) -> DeviceView:
        """Build the read-only API projection of this record (M8.3/M8.19)."""
        return DeviceView(
            device_id=self.device_id,
            mac_address=self.mac_address,
            ip_addresses=sorted(self.ip_addresses),
            first_seen=_to_iso(self.first_seen),
            last_seen=_to_iso(self.last_seen),
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            packets_sent=self.packets_sent,
            bytes_sent=self.bytes_sent,
            packets_received=self.packets_received,
            bytes_received=self.bytes_received,
            hostname=self.hostname,
            vendor=self.vendor,
            status=self.status(now=now, inactivity_threshold=inactivity_threshold),
            is_local=self.is_local,
        )
