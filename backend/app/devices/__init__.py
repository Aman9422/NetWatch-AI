"""Device discovery and tracking package for NetWatch AI (M8).

This package answers a single question: *which hosts are on the network, and how
much did each one talk?* It consumes
:class:`~app.schemas.packet.NormalizedPacket` objects and maintains a live,
thread-safe registry of observed devices.

Layer map:

    identity.py   how a device is identified (MAC/IP rules, device_id)
    endpoints.py  which sides of a packet are trackable devices
    device.py     the runtime record (ObservedDevice)
    registry.py   the MAC/IP mappings and the lock that guards them
    local.py      this machine's own identity
    manager.py    the M8 entry point (DeviceDiscoveryManager)

M8 deliberately stops at discovery and tracking: no detection, alerts,
baselines, risk scoring, or persistence.
"""

from app.devices.device import (
    DEFAULT_INACTIVITY_THRESHOLD_SECONDS,
    ObservedDevice,
)
from app.devices.endpoints import ROLE_DESTINATION, ROLE_SOURCE, Endpoint, extract_endpoints
from app.devices.identity import (
    derive_device_id,
    device_id_for,
    device_id_kind,
    is_trackable_endpoint,
    normalize_ip_address,
    normalize_mac_address,
)
from app.devices.local import (
    EMPTY_LOCAL_IDENTITY,
    LocalIdentity,
    interface_local_identity,
    local_hostname,
)
from app.devices.manager import (
    DEFAULT_RETENTION_SECONDS,
    DeviceDiscoveryManager,
    get_device_manager,
)
from app.devices.registry import DEFAULT_MAX_DEVICES, DeviceRegistry

__all__ = [
    "DEFAULT_INACTIVITY_THRESHOLD_SECONDS",
    "DEFAULT_MAX_DEVICES",
    "DEFAULT_RETENTION_SECONDS",
    "DeviceDiscoveryManager",
    "DeviceRegistry",
    "EMPTY_LOCAL_IDENTITY",
    "Endpoint",
    "LocalIdentity",
    "ObservedDevice",
    "ROLE_DESTINATION",
    "ROLE_SOURCE",
    "derive_device_id",
    "device_id_for",
    "device_id_kind",
    "extract_endpoints",
    "get_device_manager",
    "interface_local_identity",
    "is_trackable_endpoint",
    "local_hostname",
    "normalize_ip_address",
    "normalize_mac_address",
]
