"""What a detector is allowed to look at (M10.4, M10.13).

A :class:`DetectionContext` is the *only* input a rule receives. Keeping it
narrow is what stops a detector from quietly reaching for a database, a socket
or another subsystem: it can see the current normalized packet, traffic
statistics already produced by M6, a device resolver, and the clock.

The context is a plain frozen dataclass rather than a Pydantic model because it
is internal — it never crosses the API boundary — and because it carries a
callable (:attr:`device_resolver`) that is not a wire value.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from app.schemas.packet import NormalizedPacket

# Resolves an IP address to the M8 device that owns it, or None when unknown.
DeviceResolver = Callable[[str], "str | None"]


@dataclass(frozen=True)
class DetectionWindow:
    """An explicit detection window (M10.13).

    Detectors reason over a clearly bounded period rather than an implicit
    "recently". ``start`` is inclusive and ``end`` exclusive, so two adjacent
    windows never both claim the same instant.
    """

    start: float
    end: float

    @property
    def duration(self) -> float:
        """Return the window length in seconds."""
        return self.end - self.start

    def contains(self, timestamp: float) -> bool:
        """Return True when ``timestamp`` falls inside this window."""
        return self.start <= timestamp < self.end


@dataclass(frozen=True)
class DetectionContext:
    """Everything one rule evaluation is allowed to observe (M10.4).

    Attributes:
        timestamp: The observation time in epoch seconds.
        packet: The normalized packet that triggered this evaluation. ``None``
            for a snapshot-only evaluation, such as a periodic statistics pass.
        packets_per_second: Traffic rate from M6, or ``None`` when unavailable.
        bytes_per_second: Traffic rate from M6, or ``None`` when unavailable.
        rate_window_seconds: Length of the M6 window the rates were measured
            over, so a finding can state the window it actually observed.
        total_packets: Lifetime normalized packet count, or ``None``.
        total_bytes: Lifetime normalized byte count, or ``None``.
        device_resolver: Optional address → M8 device id resolver.

    The context deliberately carries *no* connection registry, no database
    handle and no writer: M10 observes, it does not act.
    """

    timestamp: float
    packet: NormalizedPacket | None = None
    packets_per_second: float | None = None
    bytes_per_second: float | None = None
    rate_window_seconds: float | None = None
    total_packets: int | None = None
    total_bytes: int | None = None
    device_resolver: DeviceResolver | None = None

    # -- convenience accessors -------------------------------------------

    @property
    def source_ip(self) -> str | None:
        """Return the packet's source address, when there is a packet."""
        return self.packet.source_ip if self.packet is not None else None

    @property
    def destination_ip(self) -> str | None:
        """Return the packet's destination address, when there is a packet."""
        return self.packet.destination_ip if self.packet is not None else None

    @property
    def destination_port(self) -> int | None:
        """Return the packet's destination port, when there is a packet."""
        return self.packet.destination_port if self.packet is not None else None

    @property
    def protocol(self) -> str | None:
        """Return the packet's transport protocol label, when there is a packet."""
        return self.packet.protocol if self.packet is not None else None

    @property
    def packet_length(self) -> int:
        """Return the packet length in bytes (0 when there is no packet)."""
        if self.packet is None:
            return 0
        return max(int(self.packet.length), 0)

    def window(self, seconds: float) -> DetectionWindow:
        """Return the window of ``seconds`` ending at this observation."""
        return DetectionWindow(start=self.timestamp - seconds, end=self.timestamp)

    def resolve_device(self, ip_address: str | None) -> str | None:
        """Return the M8 device id owning ``ip_address``, or ``None``.

        A resolver failure is treated as "unknown" rather than propagating: a
        missing device association degrades a finding, it must never stop one.
        """
        if ip_address is None or self.device_resolver is None:
            return None
        try:
            return self.device_resolver(ip_address)
        except Exception:  # noqa: BLE001 - association is enrichment only
            return None
