"""Local-host identity for device discovery (M8.10/M8.11).

The monitoring machine is identified from the interfaces M3/M4 already
discovered — nothing is hard-coded. If interface discovery is unavailable the
identity is simply empty, and no device is flagged as local.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LocalIdentity:
    """The identifiers of the monitoring host, as far as they are known."""

    mac_addresses: frozenset[str] = frozenset()
    ip_addresses: frozenset[str] = frozenset()

    def matches(self, mac_address: str | None, ip_address: str | None) -> bool:
        """Return True when either identifier belongs to the monitoring host."""
        if mac_address is not None and mac_address in self.mac_addresses:
            return True
        if ip_address is not None and ip_address in self.ip_addresses:
            return True
        return False

    @property
    def is_empty(self) -> bool:
        """Return True when no local identifier could be determined."""
        return not self.mac_addresses and not self.ip_addresses


# Identity used when the local host cannot be determined.
EMPTY_LOCAL_IDENTITY = LocalIdentity()


def interface_local_identity() -> LocalIdentity:
    """Build the local identity from the discovered network interfaces.

    The interface manager is imported lazily so this module never forms an
    import cycle with the capture layer. A discovery failure yields an empty
    identity rather than guessing.
    """
    from app.services.interface_manager import get_interface_manager

    try:
        interfaces = get_interface_manager().list_interfaces()
    except Exception:  # noqa: BLE001 - never let discovery break the caller
        logger.exception("Interface discovery failed while reading local identity")
        return EMPTY_LOCAL_IDENTITY

    mac_addresses: set[str] = set()
    ip_addresses: set[str] = set()
    for interface in interfaces:
        if interface.mac_address:
            mac_addresses.add(interface.mac_address)
        ip_addresses.update(interface.ip_addresses)
    return LocalIdentity(
        mac_addresses=frozenset(mac_addresses),
        ip_addresses=frozenset(ip_addresses),
    )


def local_hostname() -> str | None:
    """Return this machine's hostname, or ``None`` when unavailable.

    This reads local system information only; it performs no network lookup.
    """
    try:
        name = socket.gethostname()
    except Exception:  # noqa: BLE001 - hostname is best-effort
        return None
    name = name.strip()
    return name or None
