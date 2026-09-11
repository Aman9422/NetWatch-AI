"""Capture manager: controls the packet capture lifecycle (M4/M5).

The manager owns the *state* of a capture session and delegates the actual
sniffing to a :class:`~app.services.capture_sniffer.CaptureSniffer`. It:

* uses the interface selected by the M3 :class:`InterfaceManager`,
* prevents two capture sessions from running at once,
* tracks the number of captured packets,
* exposes a thread-safe snapshot of the capture state,
* translates low-level failures into controlled errors,
* (M5) hands each captured packet to a :class:`PacketProcessor` for
  normalization, without detecting, scoring, or storing anything.

It deliberately does NOT detect threats, correlate, or persist packets.
"""

import logging
import threading
from collections.abc import Callable

from app.processing.processor import PacketProcessor
from app.schemas.capture import CaptureStatusData
from app.services.capture_sniffer import CaptureSniffer, ScapyCaptureSniffer
from app.services.capture_state import (
    CaptureAlreadyRunningError,
    CaptureInterfaceError,
    CaptureNotRunningError,
    CaptureStartError,
    CaptureStatus,
    CaptureStopError,
)
from app.services.interface_manager import InterfaceManager, InterfaceValidationError

logger = logging.getLogger(__name__)

# Statuses during which a capture session is considered active.
_ACTIVE_STATUSES = (CaptureStatus.STARTING, CaptureStatus.RUNNING, CaptureStatus.STOPPING)

# Type of the callable used to build a sniffer for a given interface and sink.
SnifferFactory = Callable[[str, PacketProcessor], CaptureSniffer]


class CaptureManager:
    """Owns the packet capture session lifecycle for a single process."""

    def __init__(
        self,
        interface_manager: InterfaceManager,
        sniffer_factory: SnifferFactory = ScapyCaptureSniffer,
        packet_processor: PacketProcessor | None = None,
    ) -> None:
        self._interface_manager = interface_manager
        self._sniffer_factory = sniffer_factory
        self._processor = packet_processor or PacketProcessor()

        self._lock = threading.RLock()
        self._status = CaptureStatus.STOPPED
        self._interface_name: str | None = None
        self._packet_count = 0
        self._sniffer: CaptureSniffer | None = None

    # -- public API -------------------------------------------------------

    def start(self) -> CaptureStatusData:
        """Start a capture session on the selected interface.

        Returns:
            A snapshot of the capture state after starting.

        Raises:
            CaptureAlreadyRunningError: If a session is already active.
            CaptureInterfaceError: If no valid interface is selected.
            CaptureStartError: If the underlying sniffer fails to start.
        """
        interface = self._begin_start()
        self._processor.set_interface(interface)
        try:
            sniffer = self._sniffer_factory(interface, self._processor)
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
        """Stop the active capture session.

        Returns:
            A snapshot of the capture state after stopping.

        Raises:
            CaptureNotRunningError: If no session is active.
            CaptureStopError: If the sniffer fails to stop cleanly.
        """
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
        return self._read_sniffer_count("get_processed_count")

    def get_processing_error_count(self) -> int:
        """Return how many packets failed normalization (M5)."""
        return self._read_sniffer_count("get_processing_error_count")

    def _read_sniffer_count(self, attribute: str) -> int:
        """Read an optional integer counter from the current sniffer.

        Returns 0 when there is no sniffer, or when the sniffer does not expose
        the requested counter (e.g. the M4-only fake).
        """
        sniffer = self._sniffer
        if sniffer is None:
            return 0
        getter: Callable[[], int] | None = getattr(sniffer, attribute, None)
        if getter is None:
            return 0
        return int(getter())

    def get_packet_processor(self) -> PacketProcessor:
        """Return the processor used to normalize captured packets."""
        return self._processor

    # -- internal helpers -------------------------------------------------

    def _begin_start(self) -> str:
        """Validate preconditions and move to the STARTING state.

        Returns:
            The selected interface name to capture on.
        """
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

    def _refresh_state(self) -> None:
        """Detect an unexpected worker termination and flag an error.

        If the sniffer thread died on its own (crash, permission revoked, cable
        unplugged), the manager would otherwise keep reporting ``running``.
        """
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
        from app.services.interface_manager import get_interface_manager

        _capture_manager = CaptureManager(interface_manager=get_interface_manager())
    return _capture_manager
