"""ConnectionTracker: turns normalized packets into conversations (M9.2).

This is the M9 entry point. It consumes
:class:`~app.schemas.packet.NormalizedPacket` objects produced by the M5
processor and maintains a live registry of the conversations observed on the
network.

It depends only on ``NormalizedPacket`` — it never imports Scapy, never writes
to the database on the capture path, and never raises into the capture thread:
an unusable packet is counted and dropped so capture, statistics, persistence
and device discovery keep running (M9.20).

Design: ``docs/13_M9_Connection_Tracking_Design.md``.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from app.connections.connection import Connection
from app.connections.identity import (
    PROTOCOL_TCP,
    TRACKED_PROTOCOLS,
    flow_of,
    normalize_port,
)
from app.connections.persistence import ConnectionPersistence
from app.connections.registry import (
    DEFAULT_MAX_HISTORICAL,
    DEFAULT_MAX_TRACKED,
    ConnectionRegistry,
)
from app.connections.state import TcpFlags
from app.devices.identity import normalize_ip_address
from app.devices.registry import DeviceRegistry
from app.schemas.connection import ConnectionState, ConnectionView
from app.schemas.packet import NormalizedPacket

logger = logging.getLogger(__name__)

# Protocol idle timeouts in seconds; configuration overrides these (M9.15).
DEFAULT_TCP_TIMEOUT_SECONDS = 300.0
DEFAULT_UDP_TIMEOUT_SECONDS = 60.0
DEFAULT_ICMP_TIMEOUT_SECONDS = 30.0

# Period of the background idle sweep (M9.15).
DEFAULT_CLEANUP_INTERVAL_SECONDS = 5.0

Clock = Callable[[], float]


class ConnectionTracker:
    """Tracks network conversations from normalized packets (M9)."""

    def __init__(
        self,
        *,
        registry: ConnectionRegistry | None = None,
        device_registry: DeviceRegistry | None = None,
        persistence: ConnectionPersistence | None = None,
        max_tracked: int = DEFAULT_MAX_TRACKED,
        max_historical: int = DEFAULT_MAX_HISTORICAL,
        tcp_timeout: float = DEFAULT_TCP_TIMEOUT_SECONDS,
        udp_timeout: float = DEFAULT_UDP_TIMEOUT_SECONDS,
        icmp_timeout: float = DEFAULT_ICMP_TIMEOUT_SECONDS,
        cleanup_interval: float = DEFAULT_CLEANUP_INTERVAL_SECONDS,
        autostart_cleanup: bool = True,
        clock: Clock | None = None,
    ) -> None:
        """Create a connection tracker.

        Args:
            registry: Registry to use; a fresh one is built when omitted.
            device_registry: The M8 device registry used to associate endpoints
                with devices (M9.14). When omitted, associations stay ``None``.
            persistence: Aggregated writer for the ``connections`` table
                (M9.17). When omitted, nothing is persisted.
            max_tracked: Capacity cap, used only when building the registry.
            max_historical: Historical cap, used only when building the registry.
            tcp_timeout: Idle seconds before a TCP conversation is retired.
            udp_timeout: Idle seconds before a UDP conversation is retired.
            icmp_timeout: Idle seconds before an ICMP conversation is retired.
            cleanup_interval: Period of the background idle sweep.
            autostart_cleanup: When True the sweep thread starts on the first
                packet; tests pass False and call
                :meth:`expire_connections` deterministically.
            clock: Time source in epoch seconds; injectable for tests.

        Raises:
            ValueError: If a timeout or interval is not positive.
        """
        if min(tcp_timeout, udp_timeout, icmp_timeout, cleanup_interval) <= 0:
            raise ValueError("timeouts and cleanup_interval must be positive")

        self._registry = (
            registry
            if registry is not None
            else ConnectionRegistry(
                max_tracked=max_tracked, max_historical=max_historical
            )
        )
        self._device_registry = device_registry
        self._persistence = persistence
        self._timeouts: dict[str, float] = {
            "TCP": tcp_timeout,
            "UDP": udp_timeout,
            "ICMP": icmp_timeout,
        }
        self._cleanup_interval = cleanup_interval
        self._autostart_cleanup = autostart_cleanup
        self._clock: Clock = clock or time.time

        self._lifecycle_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._cleanup_thread: threading.Thread | None = None

        self._counter_lock = threading.Lock()
        self._created_count = 0
        self._skipped_count = 0
        self._error_count = 0

    # -- configuration ----------------------------------------------------

    def set_clock(self, clock: Clock) -> None:
        """Replace the time source (used by tests)."""
        self._clock = clock

    def set_device_registry(self, registry: DeviceRegistry | None) -> None:
        """Set (or clear) the M8 registry used for device association (M9.14)."""
        self._device_registry = registry

    def set_persistence(self, persistence: ConnectionPersistence | None) -> None:
        """Set (or clear) the aggregated connection writer (M9.17)."""
        self._persistence = persistence

    @property
    def registry(self) -> ConnectionRegistry:
        """Return the underlying connection registry."""
        return self._registry

    # -- ingestion --------------------------------------------------------

    def process_packet(self, packet: NormalizedPacket) -> Connection | None:
        """Track the conversation one normalized packet belongs to (M9.2).

        Errors are contained: a packet that cannot be tracked is counted and
        dropped, so packet capture, statistics, persistence and device discovery
        keep running (M9.20). A single malformed packet can never terminate the
        pipeline.

        Returns:
            The connection this packet contributed to, or ``None`` when the
            packet was not trackable.
        """
        try:
            return self._process(packet)
        except Exception:  # noqa: BLE001 - tracking must never stop capture
            with self._counter_lock:
                self._error_count += 1
            logger.exception("Connection tracking failed for a packet; continuing")
            return None

    def _process(self, packet: NormalizedPacket) -> Connection | None:
        """Track one packet's conversation."""
        flow = flow_of(packet)
        if flow is None:
            # No usable endpoints, or a protocol that is not a conversation:
            # counted, never guessed at and never stored.
            with self._counter_lock:
                self._skipped_count += 1
            return None

        tcp_flags = (
            TcpFlags.parse(packet.tcp_flags) if flow.protocol == PROTOCOL_TCP else None
        )
        result = self._registry.observe(
            flow=flow,
            length=packet.length,
            at=self._timestamp(packet),
            ip_version=packet.ip_version,
            tcp_flags=tcp_flags,
            source_device_id=self._device_id_for(flow.source.ip),
            destination_device_id=self._device_id_for(flow.destination.ip),
        )
        if result.created:
            with self._counter_lock:
                self._created_count += 1
        self._ensure_cleanup_started()
        return result.connection

    def _timestamp(self, packet: NormalizedPacket) -> float:
        """Return the observation time for a packet.

        The capture timestamp is authoritative; the clock is used only when the
        packet carries none, so a packet is never dated to the epoch.
        """
        if packet.timestamp and packet.timestamp > 0:
            return packet.timestamp
        return self._clock()

    def _device_id_for(self, ip_address: str) -> str | None:
        """Return the M8 device id owning ``ip_address``, or ``None`` (M9.14).

        The M8 registry is the only device authority: M9 never creates a device
        and never keeps a second registry, so an unknown address simply leaves
        the association empty.
        """
        registry = self._device_registry
        if registry is None:
            return None
        try:
            device = registry.get_by_ip(ip_address)
        except Exception:  # noqa: BLE001 - association is enrichment
            logger.debug("Device lookup failed for %s", ip_address)
            return None
        return device.device_id if device is not None else None

    # -- expiration and persistence (M9.15/M9.17) -------------------------

    def expire_connections(self, now: float | None = None) -> int:
        """Retire the conversations idle past their protocol timeout.

        The retired records are handed to the persistence layer, because a
        conversation that has just ended is exactly the aggregate worth
        recording. Writing happens outside the registry lock and never on the
        capture thread.

        Args:
            now: Override the current time (used by tests).

        Returns:
            How many connections were retired by this sweep.
        """
        timestamp = now if now is not None else self._clock()
        expired = self._registry.expire(
            now=timestamp, timeout_for=self._timeout_for
        )
        if expired and self._persistence is not None:
            self._persistence.persist_many(expired)
        if expired:
            logger.info("Retired %d idle connection(s)", len(expired))
        return len(expired)

    def flush_persistence(self) -> int:
        """Write every connection with unwritten observations; return rows written.

        Used when a capture session stops and on shutdown, so aggregate rows
        exist even for conversations that were still in progress. Returns 0 when
        no persistence layer is wired.
        """
        if self._persistence is None:
            return 0
        return self._persistence.persist_many(self._registry.collect_dirty())

    def _timeout_for(self, protocol: str) -> float:
        """Return the configured idle timeout for ``protocol`` (M9.15)."""
        return self._timeouts.get(protocol, self._timeouts["TCP"])

    # -- cleanup thread ---------------------------------------------------

    def _ensure_cleanup_started(self) -> None:
        """Start the idle-sweep thread lazily on first use."""
        if not self._autostart_cleanup:
            return
        with self._lifecycle_lock:
            if self._cleanup_thread is not None and self._cleanup_thread.is_alive():
                return
            self._stop_event.clear()
            self._cleanup_thread = threading.Thread(
                target=self._cleanup_loop, name="connection-cleanup", daemon=True
            )
            self._cleanup_thread.start()

    def _cleanup_loop(self) -> None:
        """Sweep idle conversations and write pending aggregates, until stopped.

        Both steps are individually guarded: a database failure must not kill
        the sweep, and the sweep must never reach the capture thread.
        """
        while not self._stop_event.wait(self._cleanup_interval):
            try:
                self.expire_connections()
                self.flush_persistence()
            except Exception:  # noqa: BLE001 - the sweep must survive failures
                logger.exception("Connection cleanup sweep failed; continuing")

    def stop(self, *, flush: bool = True) -> int:
        """Stop the idle sweep, optionally writing pending aggregates first."""
        self._stop_event.set()
        with self._lifecycle_lock:
            thread = self._cleanup_thread
            self._cleanup_thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=self._cleanup_interval + 1.0)
        if not flush:
            return 0
        return self.flush_persistence()

    def shutdown(self) -> None:
        """Retire what is idle, write the rest, and stop the sweep (M9.18)."""
        self.expire_connections()
        written = self.stop(flush=True)
        logger.info("Connection tracking shut down (%d aggregate(s) written)", written)

    # -- queries (M9.21) --------------------------------------------------

    def get_connection(self, connection_id: str) -> Connection | None:
        """Return the tracked connection with ``connection_id``, or ``None``."""
        if not connection_id or not connection_id.strip():
            return None
        return self._registry.get(connection_id.strip())

    def get_connection_view(self, connection_id: str) -> ConnectionView | None:
        """Return the read-only projection of one connection, or ``None``."""
        connection = self.get_connection(connection_id)
        if connection is None:
            return None
        with self._registry.locked():
            return connection.to_view()

    def list_connections(
        self,
        *,
        protocol: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        source_port: int | None = None,
        destination_port: int | None = None,
        device_id: str | None = None,
        state: ConnectionState | str | None = None,
        active_only: bool = False,
        limit: int | None = None,
    ) -> list[Connection]:
        """Return tracked connections matching the given filters (M9.21).

        Args:
            protocol: Keep only this transport protocol (``TCP``/``UDP``/``ICMP``).
            source_ip: Keep only conversations whose recorded source is this
                address. The address is canonicalized before matching.
            destination_ip: Keep only conversations whose recorded destination
                is this address.
            source_port: Keep only this recorded source port.
            destination_port: Keep only this recorded destination port.
            device_id: Keep only conversations where either end is this M8 device.
            state: Keep only this connection state.
            active_only: Skip retired (historical) conversations.
            limit: Return at most this many connections.

        Returns:
            A snapshot list ordered by ``last_seen`` descending, then by
            ``connection_id`` for determinism. This is a *query* surface: it
            contains no detection logic and draws no conclusions.

        Raises:
            ValueError: If ``limit`` is not positive, or a filter value is
                unusable (unknown protocol or state, unparseable address,
                out-of-range port) — a typo must fail loudly rather than
                silently select the wrong conversations.
        """
        if limit is not None and limit < 1:
            raise ValueError("limit must be at least 1")

        protocol_value = _protocol_value(protocol)
        state_value = _state_value(state)
        source_ip_value = _normalized_ip(source_ip, "source_ip")
        destination_ip_value = _normalized_ip(destination_ip, "destination_ip")
        source_port_value = _port_value(source_port, "source_port")
        destination_port_value = _port_value(destination_port, "destination_port")
        device_value = _device_id_value(device_id)

        with self._registry.locked():
            selected = [
                connection
                for connection in self._registry.all_tracked()
                if _matches(
                    connection,
                    active_only=active_only,
                    protocol=protocol_value,
                    source_ip=source_ip_value,
                    destination_ip=destination_ip_value,
                    source_port=source_port_value,
                    destination_port=destination_port_value,
                    device_id=device_value,
                    state=state_value,
                )
            ]
            selected.sort(key=lambda item: (-item.last_seen, item.connection_id))
        if limit is not None:
            return selected[:limit]
        return selected

    def list_connection_views(
        self,
        *,
        protocol: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        source_port: int | None = None,
        destination_port: int | None = None,
        device_id: str | None = None,
        state: ConnectionState | str | None = None,
        active_only: bool = False,
        limit: int | None = None,
    ) -> list[ConnectionView]:
        """Return the read-only projections of the filtered connections."""
        connections = self.list_connections(
            protocol=protocol,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            device_id=device_id,
            state=state,
            active_only=active_only,
            limit=limit,
        )
        with self._registry.locked():
            return [connection.to_view() for connection in connections]

    def get_active_connections(self, *, limit: int | None = None) -> list[Connection]:
        """Return the conversations currently being observed (M9.21)."""
        return self.list_connections(active_only=True, limit=limit)

    def get_active_connection_views(
        self, *, limit: int | None = None
    ) -> list[ConnectionView]:
        """Return the projections of the currently active conversations."""
        return self.list_connection_views(active_only=True, limit=limit)

    def get_connections_for_device(
        self,
        device_id: str,
        *,
        limit: int | None = None,
        active_only: bool = False,
    ) -> list[Connection]:
        """Return the conversations touching ``device_id`` (M9.21)."""
        return self.list_connections(
            device_id=device_id, limit=limit, active_only=active_only
        )

    def get_connection_views_for_device(
        self,
        device_id: str,
        *,
        limit: int | None = None,
        active_only: bool = False,
    ) -> list[ConnectionView]:
        """Return the projections of the conversations touching ``device_id``."""
        return self.list_connection_views(
            device_id=device_id, limit=limit, active_only=active_only
        )

    # -- diagnostics (M9.18/M9.20/M9.27) ----------------------------------

    def get_created_count(self) -> int:
        """Return how many conversations have been created."""
        with self._counter_lock:
            return self._created_count

    def get_skipped_count(self) -> int:
        """Return how many packets were untrackable and skipped."""
        with self._counter_lock:
            return self._skipped_count

    def get_error_count(self) -> int:
        """Return how many packets failed connection tracking (M9.20)."""
        with self._counter_lock:
            return self._error_count

    def get_active_count(self) -> int:
        """Return how many conversations are currently active."""
        return self._registry.count_active()

    def get_historical_count(self) -> int:
        """Return how many retired conversations are retained."""
        return self._registry.count_historical()

    def get_tracked_count(self) -> int:
        """Return how many conversations are held in memory."""
        return self.get_active_count() + self.get_historical_count()

    def get_expired_count(self) -> int:
        """Return how many times a conversation has been retired."""
        return self._registry.expiration_count()

    def get_eviction_count(self) -> int:
        """Return how many conversations the capacity cap retired."""
        return self._registry.eviction_count()

    def get_dropped_count(self) -> int:
        """Return how many retired conversations the history cap discarded."""
        return self._registry.dropped_count()

    def get_persisted_count(self) -> int:
        """Return how many aggregate rows have been written (M9.17)."""
        if self._persistence is None:
            return 0
        return self._persistence.get_written_count()

    def get_persistence_failure_count(self) -> int:
        """Return how many aggregate writes failed (M9.17)."""
        if self._persistence is None:
            return 0
        return self._persistence.get_failed_count()

    def get_persistence_deferred_count(self) -> int:
        """Return how many aggregate writes waited for a later pass."""
        if self._persistence is None:
            return 0
        return self._persistence.get_deferred_count()

    # -- lifecycle --------------------------------------------------------

    def reset(self) -> None:
        """Drop every tracked conversation and diagnostic counter (M9.19)."""
        self._registry.reset()
        with self._counter_lock:
            self._created_count = 0
            self._skipped_count = 0
            self._error_count = 0
        if self._persistence is not None:
            self._persistence.reset()


# -- module-level filter helpers ------------------------------------------


def _matches(
    connection: Connection,
    *,
    active_only: bool,
    protocol: str | None,
    source_ip: str | None,
    destination_ip: str | None,
    source_port: int | None,
    destination_port: int | None,
    device_id: str | None,
    state: str | None,
) -> bool:
    """Return True when ``connection`` satisfies every supplied filter.

    ``None`` means "no filter", so an omitted argument never narrows the result.
    """
    if active_only and not connection.is_active:
        return False
    if protocol is not None and connection.protocol != protocol:
        return False
    if source_ip is not None and connection.source_ip != source_ip:
        return False
    if destination_ip is not None and connection.destination_ip != destination_ip:
        return False
    if source_port is not None and connection.source_port != source_port:
        return False
    if (
        destination_port is not None
        and connection.destination_port != destination_port
    ):
        return False
    if state is not None and connection.state.value != state:
        return False
    if device_id is not None and device_id not in (
        connection.source_device_id,
        connection.destination_device_id,
    ):
        return False
    return True


def _protocol_value(protocol: str | None) -> str | None:
    """Normalize a protocol filter to its tracked label.

    Raises:
        ValueError: If ``protocol`` is not a protocol M9 tracks, so a typo fails
            loudly instead of returning an empty result that looks like "no
            traffic".
    """
    if protocol is None:
        return None
    text = str(protocol).strip().upper()
    if text not in TRACKED_PROTOCOLS:
        raise ValueError(f"Unknown connection protocol: {protocol!r}")
    return text


def _state_value(state: ConnectionState | str | None) -> str | None:
    """Normalize a state filter to its lowercase string value.

    Raises:
        ValueError: If ``state`` is neither ``None`` nor a known state.
    """
    if state is None:
        return None
    if isinstance(state, ConnectionState):
        return state.value
    text = str(state).strip().lower()
    if text not in {member.value for member in ConnectionState}:
        raise ValueError(f"Unknown connection state: {state!r}")
    return text


def _normalized_ip(value: str | None, field: str) -> str | None:
    """Canonicalize an address filter so spellings cannot hide a match.

    Raises:
        ValueError: If ``value`` is not a usable IP address.
    """
    if value is None:
        return None
    normalized = normalize_ip_address(value)
    if normalized is None:
        raise ValueError(f"'{value}' is not a valid IP address for {field}")
    return normalized


def _port_value(value: int | None, field: str) -> int | None:
    """Normalize a port filter.

    Raises:
        ValueError: If ``value`` is not a usable port number.
    """
    if value is None:
        return None
    normalized = normalize_port(value)
    if normalized is None:
        raise ValueError(f"'{value}' is not a valid port for {field}")
    return normalized


def _device_id_value(value: str | None) -> str | None:
    """Normalize a device id filter.

    Raises:
        ValueError: If ``value`` is present but empty.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        raise ValueError("device_id must not be empty")
    return text


# Shared singleton used by the application at runtime.
_connection_tracker: ConnectionTracker | None = None


def get_connection_tracker() -> ConnectionTracker:
    """FastAPI dependency returning the shared connection tracker instance."""
    global _connection_tracker
    if _connection_tracker is None:
        from app.config.settings import settings
        from app.devices.manager import get_device_manager

        persistence = (
            ConnectionPersistence(
                max_per_pass=settings.connection_persistence_max_per_pass
            )
            if settings.connection_persistence_enabled
            else None
        )
        _connection_tracker = ConnectionTracker(
            device_registry=get_device_manager().registry,
            persistence=persistence,
            max_tracked=settings.connection_max_tracked,
            max_historical=settings.connection_max_historical,
            tcp_timeout=settings.connection_tcp_timeout_seconds,
            udp_timeout=settings.connection_udp_timeout_seconds,
            icmp_timeout=settings.connection_icmp_timeout_seconds,
            cleanup_interval=settings.connection_cleanup_interval_seconds,
        )
    return _connection_tracker
