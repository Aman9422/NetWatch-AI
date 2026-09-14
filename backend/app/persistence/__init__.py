"""Packet persistence package for NetWatch AI (M7).

Persisting normalized packet metadata is the whole responsibility of this
package. It does not detect threats, score risk, correlate events or talk to the
network; it stores what M5 produced and answers historical queries over it.

    mapping.py   NormalizedPacket → ``packets`` column values (no I/O)
    buffer.py    bounded, non-blocking buffer between capture and the database
    worker.py    background thread performing batch writes in transactions
    manager.py   the facade the packet pipeline talks to
    retention.py delete packets older than the configured retention period
"""

from app.persistence.buffer import BoundedPacketBuffer
from app.persistence.manager import PacketPersistence, get_packet_persistence
from app.persistence.mapping import (
    is_persistable,
    protocol_label,
    to_epoch_datetime,
    to_packet_values,
)
from app.persistence.retention import (
    PacketRetentionService,
    get_packet_retention_service,
)
from app.persistence.session_factory import SessionFactory, app_session_factory
from app.persistence.worker import PacketPersistenceWorker

__all__ = [
    "BoundedPacketBuffer",
    "PacketPersistence",
    "PacketPersistenceWorker",
    "PacketRetentionService",
    "SessionFactory",
    "app_session_factory",
    "get_packet_persistence",
    "get_packet_retention_service",
    "is_persistable",
    "protocol_label",
    "to_epoch_datetime",
    "to_packet_values",
]
