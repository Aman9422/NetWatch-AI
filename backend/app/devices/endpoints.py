"""Endpoint extraction from normalized packets (M8.5).

An *endpoint* is one side of a packet — the source or the destination. Each
endpoint is resolved to the identifiers a device can be tracked by and, when
those identifiers describe a real host, to a ``device_id``.

Only trackable endpoints are returned. Broadcast/multicast endpoints and
endpoints with no usable identifier are dropped here, so the discovery engine
never has to second-guess whether something is a device.
"""

from dataclasses import dataclass

from app.devices.identity import (
    device_id_for,
    is_trackable_endpoint,
    normalize_ip_address,
    normalize_mac_address,
)
from app.schemas.packet import NormalizedPacket

# Endpoint roles within a packet.
ROLE_SOURCE = "source"
ROLE_DESTINATION = "destination"


@dataclass(frozen=True)
class Endpoint:
    """One trackable side of a packet, resolved to device identifiers."""

    role: str
    device_id: str
    mac_address: str | None
    ip_address: str | None

    @property
    def is_source(self) -> bool:
        """Return True when this endpoint is the packet's source."""
        return self.role == ROLE_SOURCE

    @property
    def is_destination(self) -> bool:
        """Return True when this endpoint is the packet's destination."""
        return self.role == ROLE_DESTINATION


def extract_endpoints(packet: NormalizedPacket) -> list[Endpoint]:
    """Return the trackable endpoints of ``packet`` (zero, one or two).

    Args:
        packet: The normalized packet to inspect.

    Returns:
        A list containing a source endpoint, a destination endpoint, both, or
        neither, depending on which sides identify a real device.
    """
    endpoints: list[Endpoint] = []
    source = _build_endpoint(ROLE_SOURCE, packet.source_mac, packet.source_ip)
    if source is not None:
        endpoints.append(source)
    destination = _build_endpoint(
        ROLE_DESTINATION, packet.destination_mac, packet.destination_ip
    )
    if destination is not None:
        endpoints.append(destination)
    return endpoints


def _build_endpoint(
    role: str, mac: str | None, ip: str | None
) -> Endpoint | None:
    """Build one endpoint, or ``None`` when it is not a trackable device."""
    if not is_trackable_endpoint(mac, ip):
        return None
    normalized_mac = normalize_mac_address(mac)
    normalized_ip = normalize_ip_address(ip)
    device_id = device_id_for(normalized_mac, normalized_ip)
    if device_id is None:
        return None
    return Endpoint(
        role=role,
        device_id=device_id,
        mac_address=normalized_mac,
        ip_address=normalized_ip,
    )
