"""Capture manager: controls the packet capture lifecycle (M4/M5/M6/M8).

The manager owns the state of a capture session and delegates the actual
sniffing to a CaptureSniffer. It uses the interface selected by the M3
InterfaceManager, prevents two sessions at once, tracks the packet count,
exposes a thread-safe status snapshot, translates failures into controlled
errors, and feeds each captured packet through a PacketPipeline that normalizes
it (M5), records traffic statistics (M6) and tracks observed devices (M8).

It deliberately does NOT detect threats, correlate, score risk, or persist data.
"""

import logging
import threading
from collections.abc import Callable

from app.schemas.capture import CaptureStatusData
from app.services.capture_sniffer import CaptureSniffer, PacketSink, ScapyCaptureSniffer
from app.services.capture_state import (
    CaptureAlreadyRunningError,
    CaptureInterfaceError,
    CaptureNotRunningError,
    CaptureStartError,
    CaptureStatus,
    CaptureStopError,
)
from app.services.interface_manager import InterfaceManager, InterfaceValidationError
from app.services.packet_pipeline import PacketPipeline

logger = logging.getLogger(__name__)

# Statuses during which a capture session is considered active.
_ACTIVE_STATUSES = (CaptureStatus.STARTING, CaptureStatus.RUNNING, CaptureStatus.STOPPING)

# Callable that builds a sniffer for a given interface and packet sink. The
# factory returns the CaptureSniffer protocol so both the real Scapy sniffer and
# test doubles satisfy it structurally.
SnifferFactory = Callable[[str, PacketSink], CaptureSniffer]


class CaptureManager:
    """Owns the packet capture session lifecycle for a single process."""

    def __init__(
        self,
        interface_manager: InterfaceManager,
        sniffer_factory: SnifferFactory = ScapyCaptureSniffer,
        pipeline: PacketPipeline | None = None,
    ) -> None:
        self._interface_manager = interface_manager
        self._sniffer_factory = sniffer_factory
        self._pipeline = pipeline or PacketPipeline()

        self._lock = threading.RLock()
        self._status = CaptureStatus.STOPPED
        self._interface_name: str | None = None
        self._packet_count = 0
        self._sniffer: CaptureSniffer | None = None

    # -- public API -------------------------------------------------------

    def start(self) -> CaptureStatusData:
        """Start a capture session on the selected interface."""
        interface = self._begin_start()
        self._pipeline.set_interface(interface)
        try:
            sniffer = self._sniffer_factory(interface, self._pipeline)
            sniffer.start()
        except Exception as exc:  # noqa: BLE001 - translated to controlled error
            self._fail_start(exc)
            raise CaptureStartError() from exc

        with self._lock:
            self._sniffer = sniffer
            self._packet_count = sniffer.get_packet_count()
            self._status = CaptureStatus.RUNNING

        logger.info("Packet capture started successfully")
        return self._snapshot()

    def stop(self) -> CaptureStatusData:
        """Stop the active capture session."""
        with self._lock:
            if self._status not in _ACTIVE_STATUSES:
                raise CaptureNotRunningError()
            self._status = CaptureStatus.STOPPING
            sniffer = self._sniffer

        logger.info("Packet capture stopping")

        try:
            if sniffer is not None:
                self._packet_count = sniffer.get_packet_count()
                sniffer.stop()
        except Exception as exc:  # noqa: BLE001 - translated to controlled error
            with self._lock:
                self._sniffer = None
                self._status = CaptureStatus.ERROR
            logger.error("Packet capture failed to stop: %s", exc)
            raise CaptureStopError() from exc

        # Capture has stopped, so no new packets can arrive: flush whatever the
        # persistence layer still holds (M7.18). A persistence failure is
        # isolated — the session stopped successfully and must still report
        # STOPPED, because a database problem is not a capture problem.
        self._flush_persistence()

        with self._lock:
            self._sniffer = None
            self._status = CaptureStatus.STOPPED

        logger.info("Packet capture stopped (packets captured: %d)", self._packet_count)
        return self._snapshot()

    def get_status(self) -> CaptureStatusData:
        """Return a thread-safe snapshot of the current capture state."""
        self._refresh_state()
        return self._snapshot()

    def is_running(self) -> bool:
        """Return True while a capture session is active."""
        self._refresh_state()
        with self._lock:
            return self._status is CaptureStatus.RUNNING

    def get_packet_count(self) -> int:
        """Return the number of packets captured in the current/last session."""
        self._refresh_state()
        with self._lock:
            if self._sniffer is not None:
                self._packet_count = self._sniffer.get_packet_count()
            return self._packet_count

    def get_processed_packet_count(self) -> int:
        """Return how many packets were successfully normalized (M5)."""
        return self._pipeline.get_processed_count()

    def get_processing_error_count(self) -> int:
        """Return how many packets failed normalization (M5)."""
        return self._pipeline.get_processing_error_count()

    def get_statistics_error_count(self) -> int:
        """Return how many statistics updates failed (M6)."""
        return self._pipeline.get_statistics_error_count()

    def get_device_error_count(self) -> int:
        """Return how many device-discovery updates failed (M8.17)."""
        return self._pipeline.get_device_error_count()

    def get_pipeline(self) -> PacketPipeline:
        """Return the pipeline that normalizes packets and records statistics."""
        return self._pipeline

    # -- internal helpers -------------------------------------------------

    def _begin_start(self) -> str:
        """Validate preconditions and move to the STARTING state."""
        with self._lock:
            if self._status in _ACTIVE_STATUSES:
                raise CaptureAlreadyRunningError()

            interface = self._interface_manager.get_selected_interface()
            if interface is None:
                raise CaptureInterfaceError(
                    "No capture interface selected. Select an interface first."
                )
            try:
                self._interface_manager.validate_interface(interface.name)
            except InterfaceValidationError as exc:
                raise CaptureInterfaceError(
                    f"Selected interface '{interface.name}' is not available"
                ) from exc

            self._status = CaptureStatus.STARTING
            self._interface_name = interface.name
            self._packet_count = 0
            logger.info("Packet capture starting on interface: %s", interface.name)
            return interface.name

    def _fail_start(self, exc: Exception) -> None:
        """Record a failed start attempt and return to a clean state."""
        with self._lock:
            self._sniffer = None
            self._status = CaptureStatus.ERROR
        logger.error("Packet capture failed to start: %s", exc)

    def _flush_persistence(self) -> None:
        """Write pending packets after capture stops (M7.18).

        This runs after ``sniffer.stop()`` has returned, so the capture thread
        is no longer producing packets and a final flush cannot race with new
        arrivals. The pipeline swallows any persistence failure, but the call is
        guarded anyway: a persistence problem must never turn a successful stop
        into a ``CaptureStopError``.
        """
        try:
            written = self._pipeline.flush_persistence()
        except Exception:  # noqa: BLE001 - persistence must not fail a stop
            logger.exception("Failed to flush persisted packets during stop")
            return
        if written:
            logger.info("Flushed %d buffered packet(s) on capture stop", written)

    def _refresh_state(self) -> None:
        """Detect an unexpected worker termination and flag an error."""
        with self._lock:
            sniffer = self._sniffer
            if sniffer is None or self._status is not CaptureStatus.RUNNING:
                return
            self._packet_count = sniffer.get_packet_count()

            failed = False
            check_health = getattr(sniffer, "check_health", None)
            if callable(check_health):
                try:
                    check_health()
                except Exception:  # noqa: BLE001 - any failure means "not healthy"
                    failed = True
            if failed or not sniffer.is_running():
                self._sniffer = None
                self._status = CaptureStatus.ERROR
                logger.error("Packet capture worker terminated unexpectedly")

    def _snapshot(self) -> CaptureStatusData:
        """Build a status snapshot from the current state."""
        with self._lock:
            return CaptureStatusData(
                status=self._status.value,
                interface=self._interface_name,
                packet_count=self._packet_count,
            )


# Shared singleton used by the application at runtime.
_capture_manager: CaptureManager | None = None


def get_capture_manager() -> CaptureManager:
    """FastAPI dependency returning the shared capture manager instance."""
    global _capture_manager
    if _capture_manager is None:
        from app.devices.manager import get_device_manager
        from app.services.interface_manager import get_interface_manager
        from app.statistics.manager import get_statistics_manager

        interface_manager = get_interface_manager()
        statistics = get_statistics_manager()
        devices = get_device_manager()
        # Direction classification (M6.7) uses the real local IP addresses.
        statistics.set_local_addresses_provider(interface_manager.get_local_addresses)
        from app.persistence.manager import get_packet_persistence

        _capture_manager = CaptureManager(
            interface_manager=interface_manager,
            pipeline=PacketPipeline(
                statistics=statistics,
                devices=devices,
                persistence=get_packet_persistence(),
            ),
        )
    return _capture_manager
