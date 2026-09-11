"""PacketProcessor: converts raw Scapy packets into normalized packets (M5).

The processor is the boundary between "raw capture" (Scapy types) and the rest
of NetWatch AI (Scapy-free ``NormalizedPacket``). It:

* extracts Layer-2/3/4 fields where present,
* classifies the packet deterministically,
* assigns a session-scoped sequential ``packet_id``,
* never invents values for missing layers.

It does NOT detect threats, score risk, store packets, or send data anywhere.
Downstream components depend on ``NormalizedPacket``, not on Scapy internals.
"""

import logging
import threading
from typing import Any

from app.processing.classifier import classify
from app.processing.errors import PacketProcessingError
from app.processing.extract import extract_fields
from app.schemas.packet import NormalizedPacket

logger = logging.getLogger(__name__)


class PacketProcessor:
    """Converts raw Scapy packets into :class:`NormalizedPacket` objects."""

    def __init__(self, interface: str | None = None) -> None:
        self._interface = interface
        self._lock = threading.Lock()
        self._counter = 0

    def set_interface(self, interface: str | None) -> None:
        """Record which interface subsequent packets are being captured on."""
        self._interface = interface

    def process(
        self, packet: Any, captured_at: float | None = None
    ) -> NormalizedPacket:
        """Normalize a single raw Scapy packet.

        Args:
            packet: The raw packet yielded by the capture sniffer.
            captured_at: Optional capture timestamp override (epoch seconds).

        Returns:
            The normalized representation of the packet.

        Raises:
            PacketProcessingError: If the packet cannot be normalized. The
                message is safe to log; it never contains a raw traceback.
        """
        if packet is None:
            raise PacketProcessingError("Empty packet")

        try:
            fields = extract_fields(packet, captured_at=captured_at)
            protocol, packet_type = classify(fields)
            packet_id = self._next_packet_id()
            return NormalizedPacket(
                packet_id=packet_id,
                timestamp=fields.timestamp,
                interface=self._interface,
                length=fields.length,
                source_mac=fields.source_mac,
                destination_mac=fields.destination_mac,
                ip_version=fields.ip_version,
                source_ip=fields.source_ip,
                destination_ip=fields.destination_ip,
                protocol=protocol,
                source_port=fields.source_port,
                destination_port=fields.destination_port,
                tcp_flags=fields.tcp_flags,
                packet_type=packet_type,
            )
        except PacketProcessingError:
            raise
        except Exception as exc:  # noqa: BLE001 - wrap anything Scapy throws
            raise PacketProcessingError("Malformed packet could not be processed") from exc

    # -- internal helpers -------------------------------------------------

    def _next_packet_id(self) -> int:
        """Return the next session-scoped packet identifier."""
        with self._lock:
            self._counter += 1
            return self._counter
