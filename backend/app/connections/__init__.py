"""Connection tracking package for NetWatch AI (M9).

This package answers a single question: *which conversations are happening on
the network, and how much did each side exchange?* It consumes
:class:`~app.schemas.packet.NormalizedPacket` objects and maintains a live,
thread-safe registry of network conversations.

Layer map:

    identity.py     how a conversation is identified (5-tuple, canonical key)
    state.py        the state vocabulary and TCP flag parsing rules
    tcp.py          the TCP evidence observed for one conversation
    connection.py   the runtime record (Connection) and its counters
    registry.py     the bounded, lock-protected store of conversations
    mapping.py      the projection onto the ``connections`` table columns
    persistence.py  aggregated writes to the ``connections`` table
    manager.py      the M9 entry point (ConnectionTracker)

M9 deliberately stops at tracking: no detection, alerts, baselines, risk
scoring, correlation, or AI. Those belong to later milestones.
"""

from app.connections.connection import (
    STATUS_ACTIVE,
    STATUS_COMPLETED,
    STATUS_TIMEOUT,
    Connection,
)
from app.connections.identity import (
    PROTOCOL_ICMP,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    TRACKED_PROTOCOLS,
    ConnectionKey,
    Direction,
    Endpoint,
    Flow,
    canonical_key,
    connection_id,
    direction_of,
    endpoint_of,
    flow_of,
    is_tracked_protocol,
    normalize_port,
    transport_of,
)
from app.connections.manager import (
    DEFAULT_CLEANUP_INTERVAL_SECONDS,
    DEFAULT_ICMP_TIMEOUT_SECONDS,
    DEFAULT_TCP_TIMEOUT_SECONDS,
    DEFAULT_UDP_TIMEOUT_SECONDS,
    ConnectionTracker,
    get_connection_tracker,
)
from app.connections.mapping import to_connection_values
from app.connections.persistence import (
    DEFAULT_MAX_PER_PASS,
    ConnectionPersistence,
)
from app.connections.registry import (
    DEFAULT_MAX_HISTORICAL,
    DEFAULT_MAX_TRACKED,
    ConnectionRegistry,
    ObservationResult,
)
from app.connections.state import (
    NO_FLAGS,
    TcpFlags,
    initial_state,
    is_terminal,
    state_after_expiry,
)
from app.schemas.connection import ConnectionListData, ConnectionState, ConnectionView

__all__ = [
    "DEFAULT_CLEANUP_INTERVAL_SECONDS",
    "DEFAULT_ICMP_TIMEOUT_SECONDS",
    "DEFAULT_MAX_HISTORICAL",
    "DEFAULT_MAX_PER_PASS",
    "DEFAULT_MAX_TRACKED",
    "DEFAULT_TCP_TIMEOUT_SECONDS",
    "DEFAULT_UDP_TIMEOUT_SECONDS",
    "NO_FLAGS",
    "PROTOCOL_ICMP",
    "PROTOCOL_TCP",
    "PROTOCOL_UDP",
    "STATUS_ACTIVE",
    "STATUS_COMPLETED",
    "STATUS_TIMEOUT",
    "TRACKED_PROTOCOLS",
    "TcpFlags",
    "Connection",
    "ConnectionKey",
    "ConnectionListData",
    "ConnectionPersistence",
    "ConnectionRegistry",
    "ConnectionState",
    "ConnectionTracker",
    "ConnectionView",
    "Direction",
    "Endpoint",
    "Flow",
    "ObservationResult",
    "canonical_key",
    "connection_id",
    "direction_of",
    "endpoint_of",
    "flow_of",
    "get_connection_tracker",
    "initial_state",
    "is_terminal",
    "is_tracked_protocol",
    "normalize_port",
    "state_after_expiry",
    "to_connection_values",
    "transport_of",
]
