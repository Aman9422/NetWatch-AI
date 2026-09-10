"""Thin Scapy sniffer wrapper used by the capture manager.

This module isolates the third-party Scapy API. The capture manager depends on
the small :class:`CaptureSniffer` interface so it can be unit-tested with a fake
implementation and never has to know about Scapy internals.

The sniffer performs the minimum work per packet: increment a counter. It does
NOT parse, store, or analyse packets (that belongs to later milestones).
"""

import logging
import time
from typing import Any, Protocol, runtime_checkable

from scapy.all import AsyncSniffer

logger = logging.getLogger(__name__)

# How long to wait (seconds) for the capture thread to report it started.
_START_TIMEOUT_SECONDS = 3.0
# How often to poll the capture thread while waiting for it to start (seconds).
_START_POLL_INTERVAL_SECONDS = 0.02


@runtime_checkable
class CaptureSniffer(Protocol):
    """Interface the capture manager uses to control packet capture."""

    def start(self) -> None:
        """Start capturing. Raises an exception if capture cannot start."""
        ...

    def stop(self) -> None:
        """Stop capturing and release resources."""
        ...

    def is_running(self) -> bool:
        """Return True while capture is active."""
        ...

    def get_packet_count(self) -> int:
        """Return the number of packets seen so far."""
        ...


class ScapyCaptureSniffer:
    """CaptureSniffer implementation backed by ``scapy.all.AsyncSniffer``."""

    def __init__(self, interface: str) -> None:
        self._interface = interface
        self._sniffer: AsyncSniffer | None = None
        self._packet_count = 0

    def start(self) -> None:
        """Start an asynchronous Scapy sniffer on the configured interface."""
        sniffer = AsyncSniffer(
            iface=self._interface,
            prn=self._handle_packet,
            store=False,
            started_callback=self._handle_started,
        )
        self._sniffer = sniffer
        self._packet_count = 0
        sniffer.start()
        self._await_started(sniffer)

    def stop(self) -> None:
        """Ask the sniffer to stop and wait for its thread to finish.

        Raises:
            RuntimeError: If Scapy reports an error while stopping. The packet
                counter is preserved regardless of the outcome.
        """
        sniffer = self._sniffer
        self._sniffer = None
        if sniffer is None:
            return
        try:
            if sniffer.running:
                sniffer.stop()
        except Exception as exc:  # noqa: BLE001 - surfaced to the manager
            raise RuntimeError("Scapy sniffer failed to stop") from exc

    def is_running(self) -> bool:
        """Return True while the underlying Scapy sniffer reports running."""
        sniffer = self._sniffer
        return bool(sniffer and sniffer.running)

    def get_packet_count(self) -> int:
        """Return the number of packets seen in this session."""
        return self._packet_count

    def check_health(self) -> None:
        """Raise the sniffer's error if the worker thread died unexpectedly.

        Raises:
            Exception: Whatever exception terminated the capture worker.
        """
        sniffer = self._sniffer
        if sniffer is not None and sniffer.exception is not None:
            raise sniffer.exception

    # -- internal helpers -------------------------------------------------

    def _handle_started(self) -> None:
        """Callback invoked by Scapy once the capture session is live."""
        logger.debug("Scapy capture started on interface '%s'", self._interface)

    def _handle_packet(self, _packet: Any) -> None:
        """Count a captured packet.

        Intentionally minimal: no parsing, no storage, no detection. Packet
        payloads are never logged.
        """
        self._packet_count += 1

    def _await_started(self, sniffer: AsyncSniffer) -> None:
        """Block briefly until the sniffer is running or has failed.

        Scapy starts capture on a background thread, so ``start()`` returns
        before the interface is actually open. We wait for the ``running`` flag
        (set from the worker thread) or a recorded exception, so a bad
        interface or missing permission raises immediately instead of failing
        silently in the background.
        """
        if sniffer.thread is None:
            raise RuntimeError(
                f"Packet capture on interface '{self._interface}' did not start"
            )

        deadline = time.monotonic() + _START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if sniffer.exception is not None:
                raise sniffer.exception
            if sniffer.running:
                return
            time.sleep(_START_POLL_INTERVAL_SECONDS)

        if sniffer.exception is not None:
            raise sniffer.exception
        raise RuntimeError(
            f"Packet capture on interface '{self._interface}' did not start"
        )
