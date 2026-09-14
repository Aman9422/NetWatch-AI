"""Read-only wire schemas for observed devices (M8).

These models describe how a device is exposed over the API. The runtime
representation used by the discovery engine is
``app.devices.device.ObservedDevice`` (a plain, lock-protected record); these
schemas are its serializable projection.
"""

from enum import Enum

from pydantic import BaseModel, Field


class DeviceStatus(str, Enum):
    """Activity status of an observed device (M8.9).

    This is an *activity* state derived from last-seen timing. It is not a
    security or risk verdict — M8 deliberately does not score risk.
    """

    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"


class DeviceView(BaseModel):
    """Serializable snapshot of one observed device (M8.3/M8.19)."""

    device_id: str = Field(description="Stable identity: 'mac:...' or 'ip:...'")
    mac_address: str | None = Field(
        default=None, description="Canonical MAC, if observed"
    )
    ip_addresses: list[str] = Field(
        default_factory=list, description="Observed addresses (IPv4 and/or IPv6)"
    )
    first_seen: str | None = Field(
        default=None, description="ISO-8601 UTC timestamp"
    )
    last_seen: str | None = Field(
        default=None, description="ISO-8601 UTC timestamp"
    )
    packet_count: int = Field(default=0, description="Total observed in + out")
    byte_count: int = Field(default=0, description="Total observed in + out")
    packets_sent: int = Field(
        default=0, description="Packets where the device is the source"
    )
    bytes_sent: int = Field(
        default=0, description="Bytes where the device is the source"
    )
    packets_received: int = Field(
        default=0, description="Packets where the device is the destination"
    )
    bytes_received: int = Field(
        default=0, description="Bytes where the device is the destination"
    )
    hostname: str | None = Field(
        default=None, description="Resolved hostname, if known"
    )
    vendor: str | None = Field(
        default=None, description="Hardware vendor, if known"
    )
    status: DeviceStatus = Field(default=DeviceStatus.UNKNOWN)
    is_local: bool = Field(
        default=False, description="True for the monitoring host"
    )


class DeviceListData(BaseModel):
    """Payload of the device-collection endpoint."""

    count: int = 0
    devices: list[DeviceView] = Field(default_factory=list)
