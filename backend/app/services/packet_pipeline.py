"""Packet pipeline: normalize a raw packet, then feed its M6/M7/M8 consumers.

This is the seam the capture callback talks to. It chains the M5
PacketProcessor with three independent consumers of the normalized packet:

* the M6 TrafficStatisticsManager, which aggregates traffic totals;
* the M7 PacketPersistence layer, which buffers the packet for SQLite;
* the M8 DeviceDiscoveryManager, which tracks the devices behind the traffic.

Failures are isolated per stage:

* if normalization fails, the packet is counted as a normalization error and
  the exception is re-raised so the capture sniffer can isolate it too;
* if statistics aggregation, persistence or device discovery fails, the
  normalized packet is still produced and the remaining stages still run.

A consumer failure is logged and counted, never raised, so packet capture keeps
running (M6.15/M7.11/M7.17/M8.17).

Persistence is *injected* rather than created here: the application wires the
real layer in :func:`app.services.capture_manager.get_capture_manager`. When no
persistence layer is supplied the pipeline simply does not persist, which keeps
the pipeline usable — and its tests free of a database — without changing the
runtime behaviour, where persistence is always present.
"""

import logging
from typing import Any, Optional

from app.devices.manager import DeviceDiscoveryManager
from app.persistence.manager import PacketPersistence
from app.processing.processor import PacketProcessor
from app.statistics.manager import TrafficStatisticsManager

logger = logging.getLogger(__name__)


class PacketPipeline:
    """Normalizes raw packets and feeds the M6/M7/M8 consumers."""

    def __init__(
        self,
        processor: PacketProcessor | None = None,
        statistics: TrafficStatisticsManager | None = None,
        devices: DeviceDiscoveryManager | None = None,
        persistence: PacketPersistence | None = None,
    ) -> None:
        self._processor = processor or PacketProcessor()
        self._statistics = statistics or TrafficStatisticsManager()
        self._devices = devices or DeviceDiscoveryManager()
        self._persistence = persistence
        self._processed_count = 0
        self._normalization_error_count = 0
        self._statistics_error_count = 0
        self._device_error_count = 0
        self._persistence_error_count = 0

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
        try:
            self._devices.process_packet(normalized)
        except Exception:  # noqa: BLE001 - discovery must never stop capture
            self._device_error_count += 1
            logger.warning("Device discovery failed; capture continues")
        if self._persistence is not None:
            try:
                self._persistence.record_packet(normalized)
            except Exception:  # noqa: BLE001 - persistence must never stop capture
                self._persistence_error_count += 1
                logger.warning("Packet persistence failed; capture continues")

    def flush_persistence(self) -> int:
        """Write every packet still buffered for persistence (M7.7/M7.18).

        Called when capture stops so the last, partial batch is not held until
        the next flush interval. Returns 0 when no persistence layer is wired.
        """
        if self._persistence is None:
            return 0
        return self._persistence.flush()

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

    def get_device_error_count(self) -> int:
        """Return how many device-discovery updates failed (M8.17)."""
        return self._device_error_count

    def get_persistence_error_count(self) -> int:
        """Return how many persistence updates failed (M7.11/M7.17)."""
        return self._persistence_error_count

    @property
    def processor(self) -> PacketProcessor:
        """Return the packet processor used by this pipeline."""
        return self._processor

    @property
    def statistics(self) -> TrafficStatisticsManager:
        """Return the statistics manager fed by this pipeline."""
        return self._statistics

    @property
    def devices(self) -> DeviceDiscoveryManager:
        """Return the device discovery manager fed by this pipeline."""
        return self._devices

    @property
    def persistence(self) -> PacketPersistence | None:
        """Return the persistence layer fed by this pipeline, if any."""
        return self._persistence
