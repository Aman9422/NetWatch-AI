"""TrafficStatisticsManager: aggregates normalized packets into statistics (M6).

The manager consumes :class:`~app.schemas.packet.NormalizedPacket` objects and
maintains bounded, thread-safe counters for:

* total packets / bytes,
* per-protocol packets/bytes/percentage,
* per-source, per-destination, per-port and per-conversation activity,
* traffic direction (inbound/outbound/local/unknown),
* sliding-window packet/byte rates (1s, 10s, 60s).

It does NOT detect threats, build baselines, score risk, persist data, or talk
to the network. It only aggregates traffic.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from app.schemas.packet import NormalizedPacket
from app.schemas.statistics import (
    DirectionStat,
    ProtocolStat,
    TopEntry,
    TrafficDirection,
    TrafficSnapshot,
)
from app.statistics.bounded_counter import BoundedCounter
from app.statistics.rate_window import RateWindow

logger = logging.getLogger(__name__)

# Default number of distinct keys kept per high-cardinality counter.
DEFAULT_MAX_TRACKED_KEYS = 1024
# Default number of ranked entries returned by top-talkers queries.
DEFAULT_TOP_LIMIT = 10
# Supported rate windows: label -> seconds.
_RATE_WINDOWS: dict[str, float] = {"1s": 1.0, "10s": 10.0, "60s": 60.0}
# Human-readable label used for packets with no protocol.
_UNKNOWN_PROTOCOL = "OTHER"
# How long a resolved local-address set is cached before re-discovery (M6.7).
# Resolving local addresses costs several milliseconds (psutil enumeration), so
# calling the provider once per packet would dominate the per-packet cost and
# cap capture throughput. The address set changes rarely, so a short TTL keeps
# direction classification cheap without going meaningfully stale.
_LOCAL_ADDRESSES_TTL_SECONDS = 5.0


class TrafficStatisticsManager:
    """Thread-safe aggregation of normalized packets into traffic statistics."""

    def __init__(
        self,
        max_tracked_keys: int = DEFAULT_MAX_TRACKED_KEYS,
        local_addresses_provider: Callable[[], set[str]] | None = None,
    ) -> None:
        self._local_addresses_provider = local_addresses_provider
        self._addresses_lock = threading.Lock()
        self._local_addresses_cache: set[str] | None = None
        self._local_addresses_cached_at = 0.0
        self._lock = threading.Lock()

        self._total_packets = 0
        self._total_bytes = 0

        self._protocol_packets: dict[str, int] = {}
        self._protocol_bytes: dict[str, int] = {}

        self._direction_packets: dict[str, int] = {}
        self._direction_bytes: dict[str, int] = {}

        self._sources = BoundedCounter(max_tracked_keys)
        self._destinations = BoundedCounter(max_tracked_keys)
        self._source_ports = BoundedCounter(max_tracked_keys)
        self._destination_ports = BoundedCounter(max_tracked_keys)
        self._conversations = BoundedCounter(max_tracked_keys)

        self._rate_windows: dict[str, RateWindow] = {
            label: RateWindow(seconds) for label, seconds in _RATE_WINDOWS.items()
        }

    # -- ingestion --------------------------------------------------------

    def record_packet(self, packet: NormalizedPacket) -> None:
        """Aggregate a single normalized packet.

        Errors are contained: an unusable packet is logged and ignored rather
        than propagating into the capture thread.
        """
        try:
            self._record(packet)
        except Exception:  # noqa: BLE001 - never let stats kill capture
            logger.exception("Statistics update failed for a packet; continuing")

    def _record(self, packet: NormalizedPacket) -> None:
        """Update all counters for one packet (assumes a valid packet)."""
        length = max(int(packet.length), 0)
        protocol = _protocol_label(packet)
        direction = self._classify_direction(packet)
        timestamp = packet.timestamp if packet.timestamp > 0 else time.time()

        if packet.source_ip is not None:
            self._sources.add(packet.source_ip, 1, length)
        if packet.destination_ip is not None:
            self._destinations.add(packet.destination_ip, 1, length)
        source_port = _source_port_key(packet)
        if source_port is not None:
            self._source_ports.add(source_port, 1, length)
        destination_port = _destination_port_key(packet)
        if destination_port is not None:
            self._destination_ports.add(destination_port, 1, length)
        conversation = _conversation_key(packet)
        if conversation is not None:
            self._conversations.add(conversation, 1, length)

        with self._lock:
            self._total_packets += 1
            self._total_bytes += length
            self._protocol_packets[protocol] = self._protocol_packets.get(protocol, 0) + 1
            self._protocol_bytes[protocol] = self._protocol_bytes.get(protocol, 0) + length
            self._direction_packets[direction] = self._direction_packets.get(direction, 0) + 1
            self._direction_bytes[direction] = self._direction_bytes.get(direction, 0) + length

        for window in self._rate_windows.values():
            window.record(1, length, at=timestamp)

    # -- queries ----------------------------------------------------------

    def get_statistics(self) -> TrafficSnapshot:
        """Return a near-consistent, monotonic snapshot of the statistics.

        The ranked counters are snapshotted first, then the aggregate totals are
        read under the main lock. Counters only ever grow, so the totals are
        always at least as large as the ranked lists they accompany — the
        snapshot can never report more per-IP activity than it reports in total.
        """
        rates = self.get_rates("1s")
        top_sources = self._to_entries(self._sources.top(DEFAULT_TOP_LIMIT, "packets"))
        top_destinations = self._to_entries(
            self._destinations.top(DEFAULT_TOP_LIMIT, "packets")
        )
        top_ports = self._to_entries(
            self._destination_ports.top(DEFAULT_TOP_LIMIT, "packets")
        )

        with self._lock:
            protocols = [
                ProtocolStat(
                    protocol=name,
                    packets=self._protocol_packets[name],
                    bytes=self._protocol_bytes.get(name, 0),
                    percentage=(
                        round(100.0 * self._protocol_packets[name] / self._total_packets, 2)
                        if self._total_packets
                        else 0.0
                    ),
                )
                for name in sorted(self._protocol_packets)
            ]
            directions = [
                DirectionStat(
                    direction=TrafficDirection(name),
                    packets=self._direction_packets[name],
                    bytes=self._direction_bytes.get(name, 0),
                )
                for name in sorted(self._direction_packets)
            ]
            total_packets = self._total_packets
            total_bytes = self._total_bytes

        return TrafficSnapshot(
            timestamp=time.time(),
            total_packets=total_packets,
            total_bytes=total_bytes,
            packets_per_second=rates[0],
            bytes_per_second=rates[1],
            bits_per_second=rates[1] * 8.0,
            protocol_statistics=protocols,
            direction_statistics=directions,
            top_sources=top_sources,
            top_destinations=top_destinations,
            top_ports=top_ports,
        )

    def get_protocol_statistics(self) -> list[ProtocolStat]:
        """Return the protocol distribution with percentages."""
        return self.get_statistics().protocol_statistics

    def get_rates(self, window: str = "1s") -> tuple[float, float]:
        """Return ``(packets_per_second, bytes_per_second)`` for a window.

        Args:
            window: One of ``"1s"``, ``"10s"``, ``"60s"``.

        Raises:
            ValueError: If the window label is unknown.
        """
        rate_window = self._rate_windows.get(window)
        if rate_window is None:
            raise ValueError(f"Unknown rate window: {window}")
        return rate_window.rates()

    def get_top_talkers(
        self, limit: int = DEFAULT_TOP_LIMIT, by: str = "packets"
    ) -> dict[str, list[TopEntry]]:
        """Return the busiest sources, destinations and conversations."""
        return {
            "sources": self._to_entries(self._sources.top(limit, by)),
            "destinations": self._to_entries(self._destinations.top(limit, by)),
            "conversations": self._to_entries(self._conversations.top(limit, by)),
        }

    def get_top_ports(
        self,
        limit: int = DEFAULT_TOP_LIMIT,
        by: str = "packets",
        direction: str = "destination",
    ) -> list[TopEntry]:
        """Return the most active ports for the requested direction (M6.5/M6.6).

        Args:
            limit: Maximum number of entries to return.
            by: Ranking metric, ``"packets"`` or ``"bytes"``.
            direction: ``"source"`` or ``"destination"``.

        Raises:
            ValueError: If ``direction`` is neither source nor destination.
        """
        if direction == "source":
            counter = self._source_ports
        elif direction == "destination":
            counter = self._destination_ports
        else:
            raise ValueError(f"Unknown port direction: {direction}")
        return self._to_entries(counter.top(limit, by))

    def reset(self) -> None:
        """Clear all counters and time-window data."""
        with self._lock:
            self._total_packets = 0
            self._total_bytes = 0
            self._protocol_packets.clear()
            self._protocol_bytes.clear()
            self._direction_packets.clear()
            self._direction_bytes.clear()
        self._sources.reset()
        self._destinations.reset()
        self._source_ports.reset()
        self._destination_ports.reset()
        self._conversations.reset()
        for window in self._rate_windows.values():
            window.reset()

    # -- direction --------------------------------------------------------

    def set_local_addresses_provider(
        self, provider: Callable[[], set[str]] | None
    ) -> None:
        """Set the callable used to resolve local IPs for direction (M6.7).

        Passing ``None`` reverts to reporting ``unknown`` for every packet that
        has no clearly local endpoint.
        """
        with self._addresses_lock:
            self._local_addresses_provider = provider
            self._local_addresses_cache = None
            self._local_addresses_cached_at = 0.0

    def _classify_direction(self, packet: NormalizedPacket) -> str:
        """Classify packet direction using the local address set.

        Returns ``unknown`` when the local addresses are not known or when
        neither endpoint is local — we never guess a direction.
        """
        source = packet.source_ip
        destination = packet.destination_ip
        if source is None and destination is None:
            return TrafficDirection.UNKNOWN.value

        local = self._local_addresses()
        source_local = source in local if source else False
        destination_local = destination in local if destination else False

        if source_local and destination_local:
            return TrafficDirection.LOCAL.value
        if source_local:
            return TrafficDirection.OUTBOUND.value
        if destination_local:
            return TrafficDirection.INBOUND.value
        return TrafficDirection.UNKNOWN.value

    def _local_addresses(self) -> set[str]:
        """Return the current set of local IP addresses (empty if unknown).

        The provider (interface discovery) is comparatively expensive, so its
        result is cached for ``_LOCAL_ADDRESSES_TTL_SECONDS``. Without this the
        provider would run for every packet, which dominated the per-packet
        cost. A failed resolution is cached as an empty set for the same TTL,
        so a provider outage cannot stall packet ingestion.
        """
        provider = self._local_addresses_provider
        if provider is None:
            return set()

        now = time.monotonic()
        with self._addresses_lock:
            cached = self._local_addresses_cache
            if (
                cached is not None
                and now - self._local_addresses_cached_at < _LOCAL_ADDRESSES_TTL_SECONDS
            ):
                return cached

        try:
            resolved = provider()
        except Exception:  # noqa: BLE001 - provider failure → treat as unknown
            resolved = set()

        with self._addresses_lock:
            self._local_addresses_cache = resolved
            self._local_addresses_cached_at = time.monotonic()
        return resolved

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _to_entries(rows: list[tuple[str, int, int]]) -> list[TopEntry]:
        """Convert ``(key, packets, bytes)`` rows into ``TopEntry`` models."""
        return [TopEntry(key=key, packets=packets, bytes=num_bytes) for key, packets, num_bytes in rows]


def _protocol_label(packet: NormalizedPacket) -> str:
    """Return the classification label used for protocol statistics (M6.4).

    Uses the M5 ``packet_type`` classification so DNS traffic (which rides on
    UDP) is reported as its own protocol. The resulting labels are exactly the
    required set: TCP, UDP, ICMP, DNS, ARP, IPV4, IPV6, OTHER.
    """
    packet_type = packet.packet_type
    if packet_type is None:
        return _UNKNOWN_PROTOCOL
    return packet_type.value


def _source_port_key(packet: NormalizedPacket) -> str | None:
    """Return the source port as a string key, or None if absent."""
    if packet.source_port is None:
        return None
    return str(packet.source_port)


def _destination_port_key(packet: NormalizedPacket) -> str | None:
    """Return the destination port as a string key, or None if absent."""
    if packet.destination_port is None:
        return None
    return str(packet.destination_port)


def _conversation_key(packet: NormalizedPacket) -> str | None:
    """Return a deterministic ``src:port->dst:port`` conversation key."""
    if packet.source_ip is None or packet.destination_ip is None:
        return None
    source_port = packet.source_port if packet.source_port is not None else 0
    destination_port = (
        packet.destination_port if packet.destination_port is not None else 0
    )
    return (
        f"{packet.source_ip}:{source_port}->"
        f"{packet.destination_ip}:{destination_port}"
    )


# Shared singleton used by the application at runtime.
_statistics_manager: "TrafficStatisticsManager | None" = None


def _default_local_addresses_provider() -> set[str]:
    """Resolve the host's local IPs via the interface manager (M6.7).

    Imported lazily to avoid a module-level cycle: the capture manager imports
    this module, so importing the interface manager at module load could form a
    circular import. The call itself is cheap (results are cached by the
    manager); the underlying discovery is not, which is why the manager caches.
    """
    from app.services.interface_manager import get_interface_manager

    return get_interface_manager().get_local_addresses()


def get_statistics_manager() -> TrafficStatisticsManager:
    """Return the process-wide statistics manager, creating it on first use.

    The default local-address provider is attached on creation so that traffic
    direction is classified (M6.7) even if the capture manager is never built.
    """
    global _statistics_manager
    if _statistics_manager is None:
        manager = TrafficStatisticsManager()
        manager.set_local_addresses_provider(_default_local_addresses_provider)
        _statistics_manager = manager
    return _statistics_manager
