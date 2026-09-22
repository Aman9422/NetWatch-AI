"""The runtime connection record (M9.6, M9.7, M9.8).

``Connection`` is plain, mutable state, exactly like ``ObservedDevice``: it is
only ever touched while the registry lock is held, so it carries no lock of its
own and the hot per-packet path stays free of nested locking.

The record is an *aggregate* of the packets observed for one conversation. It
never invents a value: a field the traffic did not justify stays ``None`` or
``0``, and ``packet_count`` always equals
``source_packet_count + destination_packet_count`` (likewise for bytes).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.connections.identity import (
    ConnectionKey,
    Direction,
    Endpoint,
    Flow,
    canonical_key,
    direction_of,
)
from app.connections.state import (
    TcpFlags,
    initial_state,
    is_terminal,
    state_after_expiry,
)
from app.connections.tcp import TcpObservation
from app.schemas.connection import ConnectionState, ConnectionView, to_iso_timestamp

# Protocol that owns a TCP-style observation.
_TCP_PROTOCOL = "TCP"

# Persisted status values, limited to what the M2 column already defines.
STATUS_ACTIVE = "active"
STATUS_COMPLETED = "completed"
STATUS_TIMEOUT = "timeout"


@dataclass
class Connection:
    """One observed network conversation (M9.6)."""

    connection_id: str
    key: ConnectionKey
    protocol: str
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    ip_version: int | None = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    source_packet_count: int = 0
    source_byte_count: int = 0
    destination_packet_count: int = 0
    destination_byte_count: int = 0
    state: ConnectionState = ConnectionState.UNKNOWN
    source_device_id: str | None = None
    destination_device_id: str | None = None
    tcp: TcpObservation | None = None
    expired_at: float | None = None
    persisted_row_id: int | None = None
    #: True when the record has observations not yet written to the database.
    dirty: bool = True

    # -- constructors -----------------------------------------------------

    @classmethod
    def create(
        cls,
        *,
        flow: Flow,
        ip_version: int | None = None,
    ) -> "Connection":
        """Build a fresh record for ``flow``'s conversation, oriented by it.

        The orientation — which endpoint is recorded as the source — comes from
        the *first* observed packet (this flow) and is never rewritten. That is
        what keeps both directions reported separately (M9.5): the recorded
        source is the peer that spoke first, and every later packet is
        attributed to one side or the other relative to it.
        """
        key = canonical_key(flow)
        return cls(
            connection_id=key.render(),
            key=key,
            protocol=key.protocol,
            source_ip=flow.source.ip,
            source_port=flow.source.port,
            destination_ip=flow.destination.ip,
            destination_port=flow.destination.port,
            ip_version=ip_version,
            state=initial_state(key.protocol),
            tcp=TcpObservation() if key.protocol == _TCP_PROTOCOL else None,
        )

    # -- identity helpers -------------------------------------------------

    @property
    def source_endpoint(self) -> Endpoint:
        """Return the conversation's recorded source endpoint."""
        return Endpoint(ip=self.source_ip, port=self.source_port)

    @property
    def destination_endpoint(self) -> Endpoint:
        """Return the conversation's recorded destination endpoint."""
        return Endpoint(ip=self.destination_ip, port=self.destination_port)

    def direction_for(self, flow: Flow) -> Direction:
        """Return where ``flow`` sits relative to this record's orientation."""
        return direction_of(flow, self.source_endpoint)

    # -- observation ------------------------------------------------------

    def observe(
        self,
        *,
        direction: Direction,
        length: int,
        at: float,
        tcp_flags: TcpFlags | None = None,
        source_device_id: str | None = None,
        destination_device_id: str | None = None,
    ) -> None:
        """Attribute one packet to this conversation (M9.7/M9.8).

        Args:
            direction: Where the packet sits relative to this record's
                orientation. ``UNKNOWN`` cannot occur for a key derived from the
                packet's own flow, and is folded into ``SOURCE`` so the
                directional counters always stay consistent with the totals.
            length: Captured frame length in bytes (clamped to ``>= 0``).
            at: Observation time in epoch seconds.
            tcp_flags: Parsed TCP flags, for TCP conversations only.
            source_device_id: M8 device id of the packet's source, if known.
            destination_device_id: M8 device id of the packet's destination.
        """
        size = max(int(length), 0)
        self._apply_restart_if_tuple_reused(tcp_flags)

        if direction is Direction.DESTINATION:
            self.destination_packet_count += 1
            self.destination_byte_count += size
            self._refresh_devices(
                source=destination_device_id, destination=source_device_id
            )
        else:
            self.source_packet_count += 1
            self.source_byte_count += size
            self._refresh_devices(
                source=source_device_id, destination=destination_device_id
            )

        self.packet_count += 1
        self.byte_count += size
        if self.first_seen == 0.0:
            self.first_seen = at
        self.last_seen = at
        self.dirty = True
        self._apply_state(direction, tcp_flags)
        self._unretire_if_revived()

    def restart(self) -> None:
        """Begin a new conversation on the same tuple (TCP tuple reuse, M9.10).

        The canonical key — and therefore ``connection_id`` — is unchanged,
        because the tuple being reused is the same tuple. Everything that
        describes the *previous* conversation is cleared, and
        ``persisted_row_id`` is dropped so the new aggregate is written as a
        fresh row rather than overwriting the earlier one.
        """
        self.first_seen = 0.0
        self.last_seen = 0.0
        self.packet_count = 0
        self.byte_count = 0
        self.source_packet_count = 0
        self.source_byte_count = 0
        self.destination_packet_count = 0
        self.destination_byte_count = 0
        self.expired_at = None
        self.persisted_row_id = None
        self.dirty = True
        self.tcp = TcpObservation() if self.protocol == _TCP_PROTOCOL else None
        self.state = initial_state(self.protocol)

    def retire(self, *, at: float) -> ConnectionState:
        """Mark the record as no longer active and return its new state (M9.15).

        A TCP conversation keeps its observed state, because a packet-less
        timeout proves nothing about its handshake. A UDP or ICMP conversation
        has no such evidence, so it becomes ``inactive``. Retirement is not
        destructive: the record and its counters survive in the registry's
        historical collection (M9.16).
        """
        self.expired_at = at
        self.state = state_after_expiry(self.protocol, self.state)
        self.dirty = True
        return self.state

    # -- state ------------------------------------------------------------

    @property
    def is_terminal(self) -> bool:
        """Return True when the conversation is over (M9.16)."""
        return is_terminal(self.state)

    @property
    def is_active(self) -> bool:
        """Return True while the conversation is still being observed."""
        return self.expired_at is None and not self.is_terminal

    @property
    def is_expired(self) -> bool:
        """Return True once the record has been retired from active state."""
        return self.expired_at is not None

    def idle_seconds(self, now: float) -> float:
        """Return how long ago the last packet of this conversation was seen."""
        if self.last_seen <= 0.0:
            return 0.0
        return max(now - self.last_seen, 0.0)

    def has_idled_out(self, *, now: float, timeout: float) -> bool:
        """Return True when the conversation has been idle past ``timeout``."""
        if self.expired_at is not None:
            return False
        if self.last_seen <= 0.0:
            return False
        return (now - self.last_seen) > timeout

    def persisted_status(self) -> str:
        """Return the ``connections.status`` value for this record (M9.17).

        Only values the M2 column already defines are used: a conversation that
        ended (clean close, or a connectionless flow that stopped) is
        ``completed``; one retired purely by idleness is ``timeout``; one still
        being observed is ``active``.
        """
        if self.is_terminal:
            return STATUS_COMPLETED
        if self.expired_at is not None:
            return STATUS_TIMEOUT
        return STATUS_ACTIVE

    # -- projection -------------------------------------------------------

    def to_view(self) -> ConnectionView:
        """Build the read-only API projection of this record (M9.6/M9.21)."""
        return ConnectionView(
            connection_id=self.connection_id,
            protocol=self.protocol,
            source_ip=self.source_ip,
            source_port=self.source_port,
            destination_ip=self.destination_ip,
            destination_port=self.destination_port,
            ip_version=self.ip_version,
            first_seen=to_iso_timestamp(self.first_seen or None),
            last_seen=to_iso_timestamp(self.last_seen or None),
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            source_packet_count=self.source_packet_count,
            source_byte_count=self.source_byte_count,
            destination_packet_count=self.destination_packet_count,
            destination_byte_count=self.destination_byte_count,
            state=self.state,
            source_device_id=self.source_device_id,
            destination_device_id=self.destination_device_id,
            active=self.is_active,
        )

    # -- internals --------------------------------------------------------

    def _unretire_if_revived(self) -> None:
        """Clear the retirement mark when a conversation has clearly resumed.

        Traffic on a retired conversation that is *not* over — an idle UDP flow
        that speaks again, or a TCP session whose state describes observed
        traffic rather than an ending — means it is being observed again, so it
        belongs back in the active store (M9.16). A conversation that genuinely
        ended stays retired: only a fresh SYN revives a ``closed`` TCP record,
        through :meth:`restart`.
        """
        if self.expired_at is not None and not self.is_terminal:
            self.expired_at = None

    def _apply_restart_if_tuple_reused(self, tcp_flags: TcpFlags | None) -> None:
        """Restart a closed TCP conversation when a fresh SYN reuses the tuple."""
        if self.protocol != _TCP_PROTOCOL or not self.is_terminal:
            return
        if self.state is not ConnectionState.CLOSED:
            return
        if tcp_flags is not None and tcp_flags.is_handshake_open:
            self.restart()

    def _apply_state(
        self, direction: Direction, tcp_flags: TcpFlags | None
    ) -> None:
        """Fold the packet into the conversation state."""
        if self.protocol == _TCP_PROTOCOL:
            if self.tcp is None:
                self.tcp = TcpObservation()
            self.tcp.observe(direction, tcp_flags or TcpFlags())
            self.state = self.tcp.state
            return
        # UDP and ICMP have no handshake: the only state they can show is
        # activity, and this packet is activity.
        if self.state is not ConnectionState.ACTIVE:
            self.state = ConnectionState.ACTIVE

    def _refresh_devices(
        self, *, source: str | None, destination: str | None
    ) -> None:
        """Refresh both device associations from the latest evidence (M9.14).

        A ``None`` never overwrites a known association: an unresolved address
        means "not known right now", not "no device".
        """
        if source is not None:
            self.source_device_id = source
        if destination is not None:
            self.destination_device_id = destination
