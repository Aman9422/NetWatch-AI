"""Pydantic schemas for the packet capture engine (M4)."""

from pydantic import BaseModel


class CaptureStatusData(BaseModel):
    """Current state of the packet capture engine.

    Returned by ``GET /api/v1/capture/status`` and by the start/stop endpoints.
    """

    status: str
    interface: str | None = None
    packet_count: int = 0
