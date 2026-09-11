"""Controlled errors for packet processing (M5)."""


class PacketProcessingError(Exception):
    """Raised when a raw packet cannot be normalized.

    This is a *controlled* error: it carries a short reason that is safe to
    log, never a raw traceback. The capture pipeline treats a single failed
    packet as non-fatal and continues processing subsequent packets.

    Attributes:
        reason: Human-readable, non-sensitive description of the failure.
    """

    def __init__(self, reason: str = "Packet could not be processed") -> None:
        super().__init__(reason)
        self.reason = reason
