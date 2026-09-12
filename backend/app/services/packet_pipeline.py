"""Packet pipeline: normalize a raw packet, then aggregate its statistics (M6).

This is the seam the capture callback talks to. It chains the M5
PacketProcessor with the M6 TrafficStatisticsManager and isolates failures at
every stage:

* if normalization fails, the packet is counted as a normalization error and
  the exception is re-raised so the capture sniffer can isolate it too;
* if statistics aggregation fails, the normalized packet is still produced.

The statistics failure is logged, never raised, so packet capture keeps running.
"""

import logging
from typing import Any, Optional

from app.processing.processor import PacketProcessor
from app.statistics.manager import TrafficStatisticsManager

logger = logging.getLogger(__name__)


class PacketPipeline:
    """Normalizes raw packets and feeds the results to the statistics engine."""

    def __init__(
        self,
        processor: PacketProcessor | None = None,
        statistics: TrafficStatisticsManager | None = None,
    ) -> None:
        self._processor = processor or PacketProcessor()
        self._statistics = statistics or TrafficStatisticsManager()
        self._processed_count = 0
        self._normalization_error_count = 0
        self._statistics_error_count = 0

    def process(self, packet: Any, captured_at: Optional[float] = None) -> None:
        """Normalize a raw packet and record its statistics.

        Raises:
            Exception: Only if normalization fails, so the capture sniffer can
                count it as a processing error (mirroring the M5 contract). The
                failure is tallied before it propagates.
        """
        try:
            normalized = self._processor.process(packet, captured_at)
        except Exception:  # noqa: BLE001 - re-raised for the sniffer to isolate
            self._normalization_error_count += 1
            raise
        self._processed_count += 1
        try:
            self._statistics.record_packet(normalized)
        except Exception:  # noqa: BLE001 - stats must never stop capture
            self._statistics_error_count += 1
            logger.warning("Statistics update failed; capture continues")

    def set_interface(self, interface: str | None) -> None:
        """Forward the active capture interface to the processor."""
        self._processor.set_interface(interface)

    def get_processed_count(self) -> int:
        """Return how many packets were normalized successfully."""
        return self._processed_count

    def get_processing_error_count(self) -> int:
        """Return how many packets failed normalization (M5)."""
        return self._normalization_error_count

    def get_statistics_error_count(self) -> int:
        """Return how many statistics updates failed (M6)."""
        return self._statistics_error_count

    @property
    def processor(self) -> PacketProcessor:
        """Return the packet processor used by this pipeline."""
        return self._processor

    @property
    def statistics(self) -> TrafficStatisticsManager:
        """Return the statistics manager fed by this pipeline."""
        return self._statistics
