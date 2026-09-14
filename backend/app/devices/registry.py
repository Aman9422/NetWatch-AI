"""Thread-safe device registry: MAC/IP mappings and device store (M8.16/M8.15).

The registry is the one component that owns mutable device state. It keeps:

    _devices    device_id -> ObservedDevice
    _mac_index  MAC       -> device_id
    _ip_index   IP        -> device_id

and guarantees that every mutation happens under a single re-entrant lock, so
the capture thread and the read-only API can never race.

Mapping rules (see docs/12_M8_Device_Discovery_Design.md §7):

* one device has exactly one MAC and any number of IPs;
* an IP that moves to a different MAC is *repointed* and counted as a mapping
  conflict — the two devices are never silently merged;
* an IP-only record that later reveals a MAC is *upgraded* into that MAC
  device, the single deliberate merge, allowed only because the old record has
  no MAC and therefore cannot be an unrelated host.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from app.devices.device import ObservedDevice
from app.devices.endpoints import Endpoint
from app.devices.identity import normalize_ip_address, normalize_mac_address

logger = logging.getLogger(__name__)

# Default cap on the number of tracked devices. Protects against a flood of
# spoofed addresses growing memory without bound (M8.14).
DEFAULT_MAX_DEVICES = 4096


class DeviceRegistry:
    """Mutable, lock-protected store of observed devices and their mappings."""

    def __init__(self, max_devices: int = DEFAULT_MAX_DEVICES) -> None:
        if max_devices < 1:
            raise ValueError("max_devices must be at least 1")
        self._max_devices = max_devices
        self._lock = threading.RLock()
        self._devices: dict[str, ObservedDevice] = {}
        self._mac_index: dict[str, str] = {}
        self._ip_index: dict[str, str] = {}
        # Diagnostics (M8.16 error handling / M8.24 baseline).
        self._conflict_count = 0
        self._upgrade_count = 0
        self._eviction_count = 0

    # -- locking ----------------------------------------------------------

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Hold the registry lock for a compound read or write."""
        with self._lock:
            yield

    # -- ingestion --------------------------------------------------------

    def observe_endpoint(
        self,
        endpoint: Endpoint,
        *,
        length: int,
        at: float,
        is_local: bool = False,
    ) -> tuple[ObservedDevice, bool]:
        """Resolve ``endpoint`` to a device and attribute one packet to it.

        Args:
            endpoint: One trackable side of a packet.
            length: Captured frame length in bytes.
            at: Observation time in epoch seconds.
            is_local: True when the endpoint matches the monitoring host.

        Returns:
            ``(device, created)`` where ``created`` is True only when this
            observation produced a brand-new record.
        """
        with self._lock:
            device, created = self._resolve_device(endpoint)
            if is_local:
                device.is_local = True
            device.observe(
                length=length,
                at=at,
                as_source=endpoint.is_source,
                as_destination=endpoint.is_destination,
            )
            if endpoint.ip_address is not None:
                self._bind_ip(device, endpoint.ip_address)
            self._enforce_capacity(protected_id=device.device_id)
            return device, created

    # -- lookups ----------------------------------------------------------

    def get(self, device_id: str) -> ObservedDevice | None:
        """Return the device with ``device_id``, or ``None``."""
        with self._lock:
            return self._devices.get(device_id)

    def get_by_mac(self, mac_address: str) -> ObservedDevice | None:
        """Return the device owning ``mac_address``, or ``None``."""
        normalized = normalize_mac_address(mac_address)
        if normalized is None:
            return None
        with self._lock:
            device_id = self._mac_index.get(normalized)
            return self._devices.get(device_id) if device_id else None

    def get_by_ip(self, ip_address: str) -> ObservedDevice | None:
        """Return the device currently owning ``ip_address``, or ``None``."""
        normalized = normalize_ip_address(ip_address)
        if normalized is None:
            return None
        with self._lock:
            device_id = self._ip_index.get(normalized)
            return self._devices.get(device_id) if device_id else None

    def all(self) -> list[ObservedDevice]:
        """Return a snapshot list of every tracked device."""
        with self._lock:
            return list(self._devices.values())

    def count(self) -> int:
        """Return the number of tracked devices."""
        with self._lock:
            return len(self._devices)

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

        Only the arguments that are not ``None`` are applied, so a caller can
        update one field without clobbering the others.
        """
        with self._lock:
            device = self._devices.get(device_id)
            if device is None:
                return None
            if hostname is not None:
                device.hostname = hostname
            if vendor is not None:
                device.vendor = vendor
            if is_local is not None:
                device.is_local = is_local
            return device

    def remove(self, device_id: str) -> bool:
        """Remove a device and its mappings; return True if it existed."""
        with self._lock:
            return self._remove_locked(device_id)

    def remove_expired(self, *, now: float, retention_seconds: float) -> int:
        """Remove devices untouched for longer than the retention window."""
        with self._lock:
            victims = [
                device_id
                for device_id, device in self._devices.items()
                if device.is_expired(now=now, retention_seconds=retention_seconds)
            ]
            for device_id in victims:
                self._remove_locked(device_id)
            return len(victims)

    def reset(self) -> None:
        """Drop all devices, mappings and diagnostic counters."""
        with self._lock:
            self._devices.clear()
            self._mac_index.clear()
            self._ip_index.clear()
            self._conflict_count = 0
            self._upgrade_count = 0
            self._eviction_count = 0

    # -- diagnostics ------------------------------------------------------

    def conflict_count(self) -> int:
        """Return how many IP mappings have been repointed to another device."""
        with self._lock:
            return self._conflict_count

    def upgrade_count(self) -> int:
        """Return how many IP-only records were upgraded to MAC devices."""
        with self._lock:
            return self._upgrade_count

    def eviction_count(self) -> int:
        """Return how many devices were evicted by the capacity cap."""
        with self._lock:
            return self._eviction_count

    # -- internals (caller holds the lock) --------------------------------

    def _resolve_device(self, endpoint: Endpoint) -> tuple[ObservedDevice, bool]:
        """Return the device for an endpoint, creating one when needed."""
        mac = endpoint.mac_address
        if mac is not None:
            existing_id = self._mac_index.get(mac)
            if existing_id is not None:
                return self._devices[existing_id], False

            device = ObservedDevice(device_id=endpoint.device_id, mac_address=mac)
            self._devices[device.device_id] = device
            self._mac_index[mac] = device.device_id
            self._adopt_ip_only_device(endpoint, device)
            return device, True

        ip = endpoint.ip_address
        if ip is not None:
            existing_id = self._ip_index.get(ip)
            if existing_id is not None and existing_id in self._devices:
                return self._devices[existing_id], False

        device = ObservedDevice(device_id=endpoint.device_id)
        self._devices[device.device_id] = device
        return device, True

    def _adopt_ip_only_device(
        self, endpoint: Endpoint, device: ObservedDevice
    ) -> None:
        """Upgrade a MAC-less IP record into a newly seen MAC record (M8.16)."""
        if endpoint.ip_address is None:
            return
        old_id = self._ip_index.get(endpoint.ip_address)
        if old_id is None or old_id == device.device_id:
            return
        old = self._devices.get(old_id)
        if old is None or old.has_mac:
            # A record that already has a MAC is a different host: never merge.
            return
        device.merge(old)
        for ip in old.ip_addresses:
            self._ip_index[ip] = device.device_id
        self._devices.pop(old_id, None)
        self._upgrade_count += 1
        logger.debug("Upgraded IP-only device %s into %s", old_id, device.device_id)

    def _bind_ip(self, device: ObservedDevice, ip_address: str) -> None:
        """Map an IP to a device, counting a conflict if it moves (M8.16)."""
        current_id = self._ip_index.get(ip_address)
        if current_id == device.device_id:
            device.add_ip(ip_address)
            return
        if current_id is not None:
            previous = self._devices.get(current_id)
            if previous is not None:
                previous.remove_ip(ip_address)
            self._conflict_count += 1
            logger.debug(
                "IP %s moved from %s to %s", ip_address, current_id, device.device_id
            )
        self._ip_index[ip_address] = device.device_id
        device.add_ip(ip_address)

    def _remove_locked(self, device_id: str) -> bool:
        """Remove a device and every mapping pointing at it (caller holds lock)."""
        device = self._devices.pop(device_id, None)
        if device is None:
            return False
        if (
            device.mac_address is not None
            and self._mac_index.get(device.mac_address) == device_id
        ):
            del self._mac_index[device.mac_address]
        for ip in device.ip_addresses:
            if self._ip_index.get(ip) == device_id:
                del self._ip_index[ip]
        return True

    def _enforce_capacity(self, protected_id: str) -> None:
        """Evict the stalest device(s) when the registry is over capacity.

        ``protected_id`` is the device just observed; it is never evicted,
        because it is by definition the most recently active.
        """
        while len(self._devices) > self._max_devices:
            candidates = [d for d in self._devices if d != protected_id]
            if not candidates:
                return
            victim_id = min(
                candidates,
                key=lambda device_id: (
                    self._devices[device_id].last_seen or 0.0,
                    device_id,
                ),
            )
            self._remove_locked(victim_id)
            self._eviction_count += 1
