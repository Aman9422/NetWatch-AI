"""Packet processing package for NetWatch AI (M5).

Converts raw Scapy packets into Scapy-free :class:`~app.schemas.packet.NormalizedPacket`
objects that the rest of the application can depend on.
"""

from app.processing.errors import PacketProcessingError
from app.processing.processor import PacketProcessor

__all__ = ["PacketProcessingError", "PacketProcessor"]
