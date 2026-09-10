"""Network interface discovery and normalization.

Uses ``psutil`` to enumerate the host's network interfaces, then normalizes the
raw operating-system data into a common structure that the rest of the
application can rely on.
"""

import logging
import socket
from collections.abc import Callable
from typing import Any

import psutil

from app.schemas.interface import normalize_mac

logger = logging.getLogger(__name__)


class InterfaceDiscoveryError(Exception):
    """Raised when network interface discovery fails."""

    def __init__(self, message: str = "Unable to discover network interfaces") -> None:
        super().__init__(message)


def discover_interfaces() -> list[dict]:
    """Discover and normalize all network interfaces.

    Returns:
        A list of dictionaries matching the interface data contract defined by
        :class:`app.schemas.interface.NetworkInterface`. Interfaces with missing
        information are still returned, with unavailable fields set to ``None``
        or empty.

    Raises:
        InterfaceDiscoveryError: If ``psutil`` cannot enumerate interfaces.
    """
    try:
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except (psutil.Error, OSError) as exc:
        logger.error("Interface discovery failed: %s", exc)
        raise InterfaceDiscoveryError() from exc

    interfaces: list[dict] = []
    for name in addresses:
        interfaces.append(_normalize_interface(name, addresses[name], stats.get(name)))

    logger.info("Discovered %d network interface(s)", len(interfaces))
    return interfaces


def _normalize_interface(name: str, addrs: list[Any], stats: Any | None) -> dict:
    """Normalize a single interface from raw psutil data."""
    mac = _extract_mac(addrs)
    ip_addresses = _extract_ip_addresses(addrs)
    return {
        "name": name,
        "description": None,
        "mac_address": mac,
        "ip_addresses": ip_addresses,
        "is_up": bool(stats.isup) if stats is not None else False,
    }


def _extract_mac(addrs: list[Any]) -> str | None:
    """Return the MAC (link-layer) address for a list of addresses, if present.

    The raw value is normalized to a canonical ``AA:BB:CC:DD:EE:FF`` form so
    that discovery output is consistent across operating systems (e.g. Windows
    uses dashes, Unix uses colons or lowercase).
    """
    for addr in addrs:
        if addr.family == psutil.AF_LINK:
            return normalize_mac(addr.address)
    return None


def _extract_ip_addresses(addrs: list[Any]) -> list[str]:
    """Return the host IPv4 and IPv6 addresses for a list of addresses."""
    ips: list[str] = []
    for addr in addrs:
        if addr.family in (socket.AF_INET, socket.AF_INET6):
            ip = _clean_ip(addr.address)
            if ip and ip not in ips:
                ips.append(ip)
    return ips


def _clean_ip(ip: str) -> str:
    """Remove an IPv6 scope identifier (e.g. ``fe80::1%12`` → ``fe80::1``)."""
    if "%" in ip:
        return ip.split("%", 1)[0]
    return ip


def build_discovery_func() -> Callable[[], list[dict]]:
    """Return the default discovery callable.

    Exists mainly to make dependency injection explicit and keep tests simple.
    """
    return discover_interfaces
