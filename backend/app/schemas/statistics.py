"""Traffic statistics schemas for NetWatch AI (M6)."""

from enum import Enum

from pydantic import BaseModel, Field


class TrafficDirection(str, Enum):
    """Direction of a packet relative to the local host's known IPs."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"
    LOCAL = "local"
    UNKNOWN = "unknown"


class ProtocolStat(BaseModel):
    """Traffic volume attributed to one protocol/classification."""

    protocol: str
    packets: int = 0
    bytes: int = 0
    percentage: float = Field(default=0.0, description="Share of total packets")


class TopEntry(BaseModel):
    """A single ranked item (an IP, a port, a conversation key)."""

    key: str
    packets: int = 0
    bytes: int = 0


class DirectionStat(BaseModel):
    """Traffic volume attributed to one direction."""

    direction: TrafficDirection
    packets: int = 0
    bytes: int = 0


class TopTalkers(BaseModel):
    """Most active sources, destinations and conversations."""

    sources: list[TopEntry] = Field(default_factory=list)
    destinations: list[TopEntry] = Field(default_factory=list)
    conversations: list[TopEntry] = Field(default_factory=list)


class TrafficSnapshot(BaseModel):
    """Consistent point-in-time view of aggregated traffic statistics."""

    timestamp: float
    total_packets: int = 0
    total_bytes: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    bits_per_second: float = 0.0
    protocol_statistics: list[ProtocolStat] = Field(default_factory=list)
    direction_statistics: list[DirectionStat] = Field(default_factory=list)
    top_sources: list[TopEntry] = Field(default_factory=list)
    top_destinations: list[TopEntry] = Field(default_factory=list)
    top_ports: list[TopEntry] = Field(default_factory=list)
