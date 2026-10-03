"""Packet pipeline: normalize a raw packet, then feed its M6/M7/M8/M9/M10 consumers.

This is the seam the capture callback talks to. It chains the M5
PacketProcessor with seven independent consumers of the normalized packet:

* the M6 TrafficStatisticsManager, which aggregates traffic totals;
* the M7 PacketPersistence layer, which buffers the packet for SQLite;
* the M8 DeviceDiscoveryManager, which tracks the devices behind the traffic;
* the M9 ConnectionTracker, which groups the traffic into conversations;
* the M10 DetectionEngine, which observes the traffic for suspicious behaviour;
* the M11 AlertEngine, which turns those observations into alerts;
* the M12 CorrelationEngine, which groups related alerts into scored incidents.

Failures are isolated per stage:

* if normalization fails, the packet is counted as a normalization error and
  the exception is re-raised so the capture sniffer can isolate it too;
* if statistics aggregation, persistence, device discovery, connection tracking,
  detection, alerting or correlation fails, the normalized packet is still
  produced and the remaining stages still run.

A consumer failure is logged and counted, never raised, so packet capture keeps
running (M6.15/M7.11/M7.17/M8.17/M9.20/M10.21/M11.21/M12.25).

Device discovery runs *before* connection tracking on purpose: M9 associates a
conversation's endpoints with the M8 devices that own them (M9.14), so the
devices must already know about this packet's addresses when the tracker reads
them.

Detection runs after every traffic consumer. It observes the normalized packet
and the traffic rates M6 maintains, and it anchors findings to the M8 device
registry, so the data it consumes must already have been updated for this packet
before a rule is evaluated (M10.4/M10.21). It is also the consumer whose failure
is least able to matter: if detection is disabled or fails, the record of what
happened on the wire is still complete.

Correlation runs **last of all**, because it consumes what alerting produced
rather than the packet itself: an incident is a relationship between *alerts*, so
the alerts have to exist before it can group them (M12.25). It is fed the runtime
alerts the alert engine just returned — not a re-read of the alerts table — so a
finding that folded into an existing alert still contributes that alert under the
identity the alert layer reported. Correlation then deduplicates by alert
identity (M12.11), so a repeated observation of one alert cannot inflate an
incident or its score. Its failure is contained like every other stage's: a
correlation problem cannot stop capture, and M12.25 additionally requires that it
cannot damage the alert it was reading.

Persistence is *injected* rather than created here: the application wires the
real layer in :func:`app.services.capture_manager.get_capture_manager`. When no
persistence layer is supplied the pipeline simply does not persist, which keeps
the pipeline usable — and its tests free of a database — without changing the
runtime behaviour, where persistence is always present. Connection tracking is
injected the same way.
"""

import logging
from typing import Any, Optional

from app.alerts.engine import AlertEngine
from app.connections.manager import ConnectionTracker
from app.correlation.engine import CorrelationEngine
from app.detection.engine import DetectionEngine
from app.devices.manager import DeviceDiscoveryManager
from app.persistence.manager import PacketPersistence
from app.processing.processor import PacketProcessor
from app.statistics.manager import TrafficStatisticsManager

logger = logging.getLogger(__name__)


class PacketPipeline:
    """Normalizes raw packets and feeds the M6/M7/M8/M9/M10/M11 consumers."""

    def __init__(
        self,
        processor: PacketProcessor | None = None,
        statistics: TrafficStatisticsManager | None = None,
        devices: DeviceDiscoveryManager | None = None,
        persistence: PacketPersistence | None = None,
        connections: ConnectionTracker | None = None,
        detection: DetectionEngine | None = None,
        alerts: AlertEngine | None = None,
        correlation: CorrelationEngine | None = None,
    ) -> None:
        self._processor = processor or PacketProcessor()
        self._statistics = statistics or TrafficStatisticsManager()
        self._devices = devices or DeviceDiscoveryManager()
        self._persistence = persistence
        self._connections = connections
        self._detection = detection
        self._alerts = alerts
        self._correlation = correlation
        self._processed_count = 0
        self._normalization_error_count = 0
        self._statistics_error_count = 0
        self._device_error_count = 0
        self._persistence_error_count = 0
        self._connection_error_count = 0
        self._detection_error_count = 0
        self._alert_error_count = 0
        self._correlation_error_count = 0

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
        if self._connections is not None:
            try:
                self._connections.process_packet(normalized)
            except Exception:  # noqa: BLE001 - tracking must never stop capture
                self._connection_error_count += 1
                logger.warning("Connection tracking failed; capture continues")
        # Detection runs last: it consumes the rates M6 maintains and the
        # devices M8 has already attributed (M10.21). It returns its findings,
        # and those findings are handed straight to the alert engine (M11.21) —
        # the engine consumes the observations as they are produced rather than
        # re-reading a finding history that is bounded and may already have
        # evicted them. Alerting is only reached when detection produced
        # something, so the disabled or silent path costs nothing.
        findings: list[Any] = []
        if self._detection is not None:
            try:
                findings = self._detection.process_packet(normalized)
            except Exception:  # noqa: BLE001 - detection must never stop capture
                self._detection_error_count += 1
                logger.warning("Detection failed; capture continues")
        alerts: list[Any] = []
        if self._alerts is not None and findings:
            try:
                outcomes = self._alerts.process_findings(findings)
                # The runtime alerts the engine just produced — including an
                # alert a finding was folded into — so correlation sees the same
                # alert identity the alert layer reported rather than a re-read
                # that a concurrent write could already have moved on from.
                alerts = [
                    outcome.alert
                    for outcome in outcomes
                    if getattr(outcome, "alert", None) is not None
                ]
            except Exception:  # noqa: BLE001 - alerting must never stop capture
                self._alert_error_count += 1
                logger.warning("Alerting failed; capture continues")
        # Correlation runs last of all and only when alerting produced something,
        # so the disabled or quiet path costs nothing (M12.25). It is handed the
        # alerts themselves: the correlation engine normalizes each into a
        # correlation event and deduplicates by alert identity, so a repeated
        # observation of one alert cannot grow an incident twice (M12.11).
        if self._correlation is not None and alerts:
            try:
                self._correlation.correlate_alerts(alerts)
            except Exception:  # noqa: BLE001 - correlation must never stop capture
                self._correlation_error_count += 1
                logger.warning("Correlation failed; capture continues")

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

    def get_connection_error_count(self) -> int:
        """Return how many connection-tracking updates failed (M9.20)."""
        return self._connection_error_count

    def get_detection_error_count(self) -> int:
        """Return how many detection evaluations failed (M10.21).

        The engine already isolates a rule failure internally (M10.17), so this
        counter normally stays zero: it records only a failure that escaped the
        engine entirely, which M10.21 requires the pipeline to contain anyway.
        """
        return self._detection_error_count

    def get_alert_error_count(self) -> int:
        """Return how many alert-processing calls failed (M11.21).

        The alert engine and its service both contain their own failures
        (M11.26), so this normally stays zero: it records only a failure that
        escaped both, which M11.21 requires the pipeline to contain anyway.
        """
        return self._alert_error_count

    def get_correlation_error_count(self) -> int:
        """Return how many correlation calls failed (M12.25).

        The correlation engine contains its own failures (M12.25), so this
        normally stays zero: it records only a failure that escaped the engine
        entirely, which the same requirement asks the pipeline to contain anyway.
        """
        return self._correlation_error_count

    def flush_connections(self) -> int:
        """Write every tracked conversation with unwritten observations (M9.17).

        Called when capture stops, so the aggregate rows for a session exist
        even for conversations that were still in progress when it ended.
        Returns 0 when no tracker is wired.
        """
        if self._connections is None:
            return 0
        return self._connections.flush_persistence()

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

    @property
    def connections(self) -> ConnectionTracker | None:
        """Return the connection tracker fed by this pipeline, if any."""
        return self._connections

    @property
    def detection(self) -> DetectionEngine | None:
        """Return the detection engine fed by this pipeline, if any."""
        return self._detection

    @property
    def alerts(self) -> AlertEngine | None:
        """Return the alert engine fed by this pipeline, if any."""
        return self._alerts

    @property
    def correlation(self) -> CorrelationEngine | None:
        """Return the correlation engine fed by this pipeline, if any."""
        return self._correlation
