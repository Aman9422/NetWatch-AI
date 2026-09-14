"""DeviceDiscoveryManager: turns normalized packets into tracked devices (M8).

This is the M8 entry point. It consumes
:class:`~app.schemas.packet.NormalizedPacket` objects produced by the M5
processor and maintains a live registry of the devices observed on the network.

It depends only on ``NormalizedPacket`` — it never imports Scapy, never writes
to the database, and never raises into the capture thread: an unusable packet is
counted and dropped so capture and statistics keep running.

Design: ``docs/12_M8_Device_Discovery_Design.md``.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from app.config.settings import settings
from app.devices.device import (
    DEFAULT_INACTIVITY_THRESHOLD_SECONDS,
    ObservedDevice,
)
from app.devices.endpoints import Endpoint, extract_endpoints
from app.devices.identity import normalize_ip_address, normalize_mac_address
from app.devices.local import (
    EMPTY_LOCAL_IDENTITY,
    LocalIdentity,
    interface_local_identity,
    local_hostname,
)
from app.devices.registry import DEFAULT_MAX_DEVICES, DeviceRegistry
from app.schemas.device import DeviceStatus, DeviceView
from app.schemas.packet import NormalizedPacket

logger = logging.getLogger(__name__)

# Default retention window before a stale device may be cleaned up (M8.14).
DEFAULT_RETENTION_SECONDS = 3600.0

# How long a resolved local identity is cached before re-discovery. Interface
# enumeration is comparatively expensive, so it must not run per packet.
_LOCAL_IDENTITY_TTL_SECONDS = 5.0

# Callable types used for the pluggable providers.
LocalIdentityProvider = Callable[[], LocalIdentity]
HostnameProvider = Callable[[], str | None]
HostnameResolver = Callable[[str], str | None]
VendorResolver = Callable[[str | None], str | None]
Clock = Callable[[], float]


class DeviceDiscoveryManager:
    """Discovers and tracks devices from normalized packets (M8)."""

    def __init__(
        self,
        *,
        registry: DeviceRegistry | None = None,
        max_devices: int = DEFAULT_MAX_DEVICES,
        inactivity_threshold: float = DEFAULT_INACTIVITY_THRESHOLD_SECONDS,
        retention_seconds: float = DEFAULT_RETENTION_SECONDS,
        local_identity_provider: LocalIdentityProvider | None = None,
        local_hostname_provider: HostnameProvider | None = None,
        hostname_resolver: HostnameResolver | None = None,
        vendor_resolver: VendorResolver | None = None,
        clock: Clock | None = None,
    ) -> None:
        """Create a discovery manager.

        Args:
            registry: Registry to use; a fresh one is built when omitted.
            max_devices: Capacity cap used only when building the registry.
            inactivity_threshold: Seconds after the last sighting before a
                device becomes ``inactive`` (M8.9).
            retention_seconds: Seconds after the last sighting before a device
                may be cleaned up (M8.14). Must exceed the inactivity threshold.
            local_identity_provider: Resolves this machine's own MACs/IPs
                (M8.10). When omitted, devices are never flagged as local.
            local_hostname_provider: Resolves this machine's hostname (M8.11).
            hostname_resolver: Resolves a hostname for an IP. Called on a
                background thread, so it may block without stalling capture.
            vendor_resolver: Maps a MAC to a vendor name (M8.12). No OUI
                database is shipped in M8, so this stays unused by default.
            clock: Time source in epoch seconds; injectable for tests.

        Raises:
            ValueError: If the thresholds are inconsistent or negative.
        """
        if inactivity_threshold < 0:
            raise ValueError("inactivity_threshold must not be negative")
        if retention_seconds <= inactivity_threshold:
            raise ValueError("retention_seconds must exceed inactivity_threshold")

        self._registry = (
            registry if registry is not None else DeviceRegistry(max_devices)
        )
        self._inactivity_threshold = inactivity_threshold
        self._retention_seconds = retention_seconds
        self._clock: Clock = clock or time.time

        self._local_identity_provider: LocalIdentityProvider | None = (
            local_identity_provider
        )
        self._local_hostname_provider: HostnameProvider | None = (
            local_hostname_provider
        )
        self._hostname_resolver: HostnameResolver | None = hostname_resolver
        self._vendor_resolver: VendorResolver | None = vendor_resolver

        self._local_lock = threading.Lock()
        self._local_identity_cache: LocalIdentity | None = None
        self._local_identity_cached_at = 0.0
        self._local_hostname_cache: str | None = None
        self._local_hostname_resolved = False

        self._hostname_lock = threading.Lock()
        self._pending_hostnames: set[str] = set()

        self._error_count = 0

    # -- configuration ----------------------------------------------------

    @property
    def inactivity_threshold(self) -> float:
        """Return the configured inactivity threshold in seconds."""
        return self._inactivity_threshold

    @property
    def retention_seconds(self) -> float:
        """Return the configured retention window in seconds."""
        return self._retention_seconds

    def set_local_identity_provider(
        self, provider: LocalIdentityProvider | None
    ) -> None:
        """Set (or clear) the provider of this machine's own identifiers (M8.10)."""
        with self._local_lock:
            self._local_identity_provider = provider
            self._local_identity_cache = None
            self._local_identity_cached_at = 0.0

    def set_local_hostname_provider(self, provider: HostnameProvider | None) -> None:
        """Set (or clear) the provider of this machine's hostname (M8.11)."""
        with self._local_lock:
            self._local_hostname_provider = provider
            self._local_hostname_cache = None
            self._local_hostname_resolved = False

    def set_hostname_resolver(self, resolver: HostnameResolver | None) -> None:
        """Set (or clear) the hostname resolver used for other devices (M8.11)."""
        self._hostname_resolver = resolver

    def set_vendor_resolver(self, resolver: VendorResolver | None) -> None:
        """Set (or clear) the MAC-to-vendor resolver (M8.12)."""
        self._vendor_resolver = resolver

    def set_clock(self, clock: Clock) -> None:
        """Replace the time source (used by tests)."""
        self._clock = clock

    @property
    def registry(self) -> DeviceRegistry:
        """Return the underlying device registry."""
        return self._registry

    # -- ingestion --------------------------------------------------------

    def process_packet(self, packet: NormalizedPacket) -> None:
        """Discover and attribute the devices in one normalized packet (M8.5).

        Errors are contained: a packet that cannot be processed is counted and
        dropped, so packet capture and statistics keep running (M8.17).
        """
        try:
            self._process(packet)
        except Exception:  # noqa: BLE001 - discovery must never stop capture
            self._error_count += 1
            logger.exception("Device discovery failed for a packet; continuing")

    def _process(self, packet: NormalizedPacket) -> None:
        """Attribute a single packet to the devices it names."""
        endpoints = extract_endpoints(packet)
        if not endpoints:
            return
        length = max(int(packet.length), 0)
        timestamp = packet.timestamp if packet.timestamp > 0 else self._clock()
        local = self._local_identity()
        for endpoint in endpoints:
            is_local = local.matches(endpoint.mac_address, endpoint.ip_address)
            device, created = self._registry.observe_endpoint(
                endpoint, length=length, at=timestamp, is_local=is_local
            )
            if created:
                self._on_new_device(device, endpoint)
            elif device.is_local and device.hostname is None:
                self._apply_local_hostname(device)

    # -- enrichment (best effort, never blocking) -------------------------

    def _on_new_device(self, device: ObservedDevice, endpoint: Endpoint) -> None:
        """Apply the enrichment only attempted for a newly seen device."""
        if device.is_local:
            self._apply_local_hostname(device)
        elif self._hostname_resolver is not None:
            self._schedule_hostname_resolution(device)
        self._apply_vendor(device, endpoint)

    def _apply_vendor(self, device: ObservedDevice, endpoint: Endpoint) -> None:
        """Attach a vendor name when a resolver is configured (M8.12)."""
        resolver = self._vendor_resolver
        if resolver is None or endpoint.mac_address is None:
            return
        try:
            vendor = resolver(endpoint.mac_address)
        except Exception:  # noqa: BLE001 - enrichment is best-effort
            logger.debug("Vendor resolution failed for %s", device.device_id)
            return
        if vendor:
            self._registry.update_device(device.device_id, vendor=vendor)

    def _schedule_hostname_resolution(self, device: ObservedDevice) -> None:
        """Resolve a device hostname off the capture thread (M8.11).

        Packet processing only pays for starting a daemon thread; the lookup
        itself runs elsewhere, so a slow resolver cannot stall capture.
        """
        with self._hostname_lock:
            if device.device_id in self._pending_hostnames:
                return
            self._pending_hostnames.add(device.device_id)
        thread = threading.Thread(
            target=self.resolve_hostname,
            args=(device.device_id,),
            name=f"hostname-{device.device_id}",
            daemon=True,
        )
        thread.start()

    def resolve_hostname(self, device_id: str) -> None:
        """Resolve and store one device's hostname (worker-thread entry point).

        Public and synchronous so tests can drive it deterministically; the
        scheduler above simply calls it on a background thread.
        """
        try:
            device = self._registry.get(device_id)
            resolver = self._hostname_resolver
            if device is None or resolver is None or not device.ip_addresses:
                return
            ip_address = sorted(device.ip_addresses)[0]
            hostname = resolver(ip_address)
            if hostname and hostname.strip():
                self._registry.update_device(device_id, hostname=hostname.strip())
        except Exception:  # noqa: BLE001 - hostname is best-effort
            logger.debug("Hostname resolution failed for %s", device_id)
        finally:
            with self._hostname_lock:
                self._pending_hostnames.discard(device_id)

    def _apply_local_hostname(self, device: ObservedDevice) -> None:
        """Fill in the monitoring host's own hostname for a local device."""
        if device.hostname is not None:
            return
        name = self._local_hostname()
        if name:
            self._registry.update_device(device.device_id, hostname=name)

    # -- local identity ---------------------------------------------------

    def _local_identity(self) -> LocalIdentity:
        """Return the cached local identity, refreshing periodically (M8.10)."""
        with self._local_lock:
            provider = self._local_identity_provider
            cached = self._local_identity_cache
            cached_at = self._local_identity_cached_at

        if provider is None:
            return EMPTY_LOCAL_IDENTITY

        now = time.monotonic()
        if cached is not None and now - cached_at < _LOCAL_IDENTITY_TTL_SECONDS:
            return cached

        try:
            resolved = provider()
        except Exception:  # noqa: BLE001 - provider failure → treat as unknown
            resolved = EMPTY_LOCAL_IDENTITY
        if resolved is None:
            resolved = EMPTY_LOCAL_IDENTITY

        with self._local_lock:
            self._local_identity_cache = resolved
            self._local_identity_cached_at = time.monotonic()
        return resolved

    def _local_hostname(self) -> str | None:
        """Return this machine's hostname, resolved at most once."""
        with self._local_lock:
            if self._local_hostname_resolved:
                return self._local_hostname_cache
            provider = self._local_hostname_provider

        name: str | None = None
        if provider is not None:
            try:
                name = provider()
            except Exception:  # noqa: BLE001 - hostname is best-effort
                name = None

        with self._local_lock:
            self._local_hostname_cache = name
            self._local_hostname_resolved = True
        return name

    # -- queries ----------------------------------------------------------

    def get_device(self, device_id: str) -> ObservedDevice | None:
        """Return the tracked device with ``device_id``, or ``None``."""
        return self._registry.get(device_id)

    def get_device_view(self, device_id: str) -> DeviceView | None:
        """Return the read-only projection of one device, or ``None``."""
        with self._registry.locked():
            device = self._registry.get(device_id)
            if device is None:
                return None
            return self._to_view(device)

    def list_devices(
        self,
        *,
        status: DeviceStatus | str | None = None,
        ip: str | None = None,
        mac: str | None = None,
        limit: int | None = None,
    ) -> list[ObservedDevice]:
        """Return tracked devices, most recently seen first (M8.18).

        Args:
            status: Keep only devices in this activity state.
            ip: Keep only devices currently owning this address.
            mac: Keep only the device owning this MAC.
            limit: Return at most this many devices.

        Returns:
            A snapshot list of matching devices, sorted by ``last_seen``
            descending and then by ``device_id`` for determinism.

        Raises:
            ValueError: If ``limit`` is not positive, or ``status`` is unknown.
        """
        if limit is not None and limit < 1:
            raise ValueError("limit must be at least 1")

        status_value = _status_value(status)
        normalized_ip = normalize_ip_address(ip) if ip is not None else None
        normalized_mac = normalize_mac_address(mac) if mac is not None else None
        now = self._clock()

        with self._registry.locked():
            selected: list[ObservedDevice] = []
            for device in self._registry.all():
                if (
                    normalized_mac is not None
                    and device.mac_address != normalized_mac
                ):
                    continue
                if (
                    normalized_ip is not None
                    and normalized_ip not in device.ip_addresses
                ):
                    continue
                if status_value is not None:
                    current = device.status(
                        now=now, inactivity_threshold=self._inactivity_threshold
                    )
                    if current.value != status_value:
                        continue
                selected.append(device)

        selected.sort(
            key=lambda device: (-(device.last_seen or 0.0), device.device_id)
        )
        if limit is not None:
            return selected[:limit]
        return selected

    def list_device_views(
        self,
        *,
        status: DeviceStatus | str | None = None,
        ip: str | None = None,
        mac: str | None = None,
        limit: int | None = None,
    ) -> list[DeviceView]:
        """Return the read-only projections of the filtered devices (M8.18)."""
        devices = self.list_devices(status=status, ip=ip, mac=mac, limit=limit)
        with self._registry.locked():
            return [self._to_view(device) for device in devices]

    def get_device_count(self) -> int:
        """Return the number of tracked devices."""
        return self._registry.count()

    def list_ip_addresses(self) -> list[str]:
        """Return every IP address currently attributed to a device."""
        with self._registry.locked():
            addresses: set[str] = set()
            for device in self._registry.all():
                addresses.update(device.ip_addresses)
        return sorted(addresses)

    # -- mutation ---------------------------------------------------------

    def update_device(
        self,
        device_id: str,
        *,
        hostname: str | None = None,
        vendor: str | None = None,
        is_local: bool | None = None,
    ) -> ObservedDevice | None:
        """Apply enrichment fields to a known device (M8.11/M8.12).

        Only the arguments that are not ``None`` are applied, so one field can
        be updated without clobbering the others. Returns ``None`` when the
        device is unknown.
        """
        return self._registry.update_device(
            device_id, hostname=hostname, vendor=vendor, is_local=is_local
        )

    def remove_expired_devices(self, now: float | None = None) -> int:
        """Remove devices untouched beyond the retention window (M8.14).

        Args:
            now: Override the current time (used by tests).

        Returns:
            How many devices were removed.
        """
        timestamp = now if now is not None else self._clock()
        removed = self._registry.remove_expired(
            now=timestamp, retention_seconds=self._retention_seconds
        )
        if removed:
            logger.info("Removed %d expired device(s)", removed)
        return removed

    def reset(self) -> None:
        """Drop every tracked device, mapping and diagnostic counter."""
        self._registry.reset()
        with self._hostname_lock:
            self._pending_hostnames.clear()
        self._error_count = 0
        with self._local_lock:
            self._local_identity_cache = None
            self._local_identity_cached_at = 0.0
            self._local_hostname_cache = None
            self._local_hostname_resolved = False

    # -- diagnostics ------------------------------------------------------

    def get_error_count(self) -> int:
        """Return how many packets failed device discovery (M8.17)."""
        return self._error_count

    def get_conflict_count(self) -> int:
        """Return how many IP mappings moved between devices (M8.16)."""
        return self._registry.conflict_count()

    def get_upgrade_count(self) -> int:
        """Return how many IP-only records were upgraded to MAC devices."""
        return self._registry.upgrade_count()

    def get_eviction_count(self) -> int:
        """Return how many devices were evicted by the capacity cap."""
        return self._registry.eviction_count()

    def get_local_identity(self) -> LocalIdentity:
        """Return this machine's identity as currently resolved (M8.10)."""
        return self._local_identity()

    # -- internals --------------------------------------------------------

    def _to_view(self, device: ObservedDevice) -> DeviceView:
        """Project one record using the current clock."""
        return device.to_view(
            now=self._clock(), inactivity_threshold=self._inactivity_threshold
        )


def _status_value(status: DeviceStatus | str | None) -> str | None:
    """Normalize a status filter to its lowercase string value.

    Raises:
        ValueError: If ``status`` is neither ``None`` nor a known state.
    """
    if status is None:
        return None
    if isinstance(status, DeviceStatus):
        return status.value
    text = str(status).strip().lower()
    if text not in {state.value for state in DeviceStatus}:
        raise ValueError(f"Unknown device status: {status!r}")
    return text


# Shared singleton used by the application at runtime.
_device_manager: DeviceDiscoveryManager | None = None


def get_device_manager() -> DeviceDiscoveryManager:
    """FastAPI dependency returning the shared device discovery manager."""
    global _device_manager
    if _device_manager is None:
        manager = DeviceDiscoveryManager(
            max_devices=settings.device_max_tracked,
            inactivity_threshold=settings.device_inactivity_threshold_seconds,
            retention_seconds=settings.device_retention_seconds,
        )
        manager.set_local_identity_provider(interface_local_identity)
        manager.set_local_hostname_provider(local_hostname)
        _device_manager = manager
    return _device_manager
