"""Unit tests for the CaptureManager (M4 capture engine)."""

import pytest

from app.services.capture_manager import CaptureManager
from app.services.capture_state import (
    CaptureAlreadyRunningError,
    CaptureInterfaceError,
    CaptureNotRunningError,
    CaptureStartError,
    CaptureStatus,
    CaptureStopError,
)
from tests.fakes import FakeCaptureSniffer, make_interface_manager, make_sniffer_factory


def _make_manager(
    registry: list[FakeCaptureSniffer] | None = None,
    select: str | None = "Wi-Fi",
    fail_on_start: bool = False,
    fail_on_stop: bool = False,
) -> CaptureManager:
    """Return a CaptureManager with a fake sniffer and an optional selection."""
    interface_manager = make_interface_manager()
    if select is not None:
        interface_manager.select_interface(select)
    return CaptureManager(
        interface_manager=interface_manager,
        sniffer_factory=make_sniffer_factory(
            fail_on_start=fail_on_start,
            fail_on_stop=fail_on_stop,
            registry=registry,
        ),
    )


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------


def test_initial_status_is_stopped() -> None:
    """A fresh manager reports 'stopped' with zero packets."""
    status = _make_manager(select=None).get_status()

    assert status.status == CaptureStatus.STOPPED.value
    assert status.interface is None
    assert status.packet_count == 0


def test_is_running_false_initially() -> None:
    """A fresh manager is not running."""
    manager = _make_manager(select=None)
    assert manager.is_running() is False


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------


def test_start_uses_selected_interface() -> None:
    """Starting capture uses the interface selected by the M3 manager."""
    registry: list[FakeCaptureSniffer] = []
    manager = _make_manager(registry=registry)

    status = manager.start()

    assert status.status == CaptureStatus.RUNNING.value
    assert status.interface == "Wi-Fi"
    assert registry[0].interface == "Wi-Fi"


def test_status_is_running_after_start() -> None:
    """After a successful start the manager reports 'running'."""
    manager = _make_manager()
    manager.start()

    assert manager.is_running() is True
    assert manager.get_status().status == CaptureStatus.RUNNING.value


def test_packet_count_tracks_sniffer() -> None:
    """The packet count reflects packets emitted by the sniffer."""
    registry: list[FakeCaptureSniffer] = []
    manager = _make_manager(registry=registry)
    manager.start()

    registry[0].emit(1200)

    assert manager.get_packet_count() == 1200
    assert manager.get_status().packet_count == 1200


def test_packet_count_resets_on_new_session() -> None:
    """A new capture session starts counting from zero."""
    registry: list[FakeCaptureSniffer] = []
    manager = _make_manager(registry=registry)

    manager.start()
    registry[0].emit(500)
    manager.stop()

    manager.start()
    assert manager.get_packet_count() == 0


# ---------------------------------------------------------------------------
# Stop
# ---------------------------------------------------------------------------


def test_stop_returns_to_stopped() -> None:
    """Stopping an active capture sets the state back to 'stopped'."""
    registry: list[FakeCaptureSniffer] = []
    manager = _make_manager(registry=registry)
    manager.start()

    status = manager.stop()

    assert status.status == CaptureStatus.STOPPED.value
    assert registry[0].stopped is True
    assert manager.is_running() is False


def test_stop_preserves_final_packet_count() -> None:
    """The final packet count is preserved after stopping."""
    registry: list[FakeCaptureSniffer] = []
    manager = _make_manager(registry=registry)
    manager.start()
    registry[0].emit(42)

    status = manager.stop()

    assert status.packet_count == 42
    assert manager.get_packet_count() == 42


def test_can_restart_after_stop() -> None:
    """A new capture can start after the previous one stopped."""
    manager = _make_manager()
    manager.start()
    manager.stop()

    status = manager.start()
    assert status.status == CaptureStatus.RUNNING.value


def test_stop_when_not_running_is_rejected() -> None:
    """Stopping an inactive capture raises a controlled error."""
    manager = _make_manager(select=None)

    with pytest.raises(CaptureNotRunningError) as exc_info:
        manager.stop()

    assert exc_info.value.code == "CAPTURE_NOT_RUNNING"


# ---------------------------------------------------------------------------
# Duplicate session prevention
# ---------------------------------------------------------------------------


def test_second_start_is_rejected() -> None:
    """Starting capture twice raises a controlled 'already running' error."""
    manager = _make_manager()
    manager.start()

    with pytest.raises(CaptureAlreadyRunningError) as exc_info:
        manager.start()

    assert exc_info.value.code == "CAPTURE_ALREADY_RUNNING"
    assert manager.is_running() is True


# ---------------------------------------------------------------------------
# Interface validation
# ---------------------------------------------------------------------------


def test_start_without_selection_is_rejected() -> None:
    """Starting capture without a selected interface is rejected."""
    manager = _make_manager(select=None)

    with pytest.raises(CaptureInterfaceError) as exc_info:
        manager.start()

    assert exc_info.value.code == "CAPTURE_NO_INTERFACE"
    assert manager.get_status().status == CaptureStatus.STOPPED.value


def test_start_with_unavailable_interface_is_rejected() -> None:
    """A selected interface that is no longer available is rejected."""
    manager = _make_manager(select="Wi-Fi")
    # Force the interface to disappear/go down after selection.
    manager._interface_manager._discovery = lambda: [  # noqa: SLF001
        {"name": "Wi-Fi", "ip_addresses": [], "is_up": False}
    ]

    with pytest.raises(CaptureInterfaceError):
        manager.start()

    assert manager.get_status().status == CaptureStatus.STOPPED.value


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


def test_start_failure_is_translated() -> None:
    """A sniffer start failure becomes a controlled CaptureStartError."""
    manager = _make_manager(fail_on_start=True)

    with pytest.raises(CaptureStartError) as exc_info:
        manager.start()

    assert exc_info.value.code == "CAPTURE_START_FAILED"
    assert manager.get_status().status == CaptureStatus.ERROR.value


def test_start_failure_allows_retry() -> None:
    """After a failed start the manager is not stuck in a running state."""
    manager = _make_manager(fail_on_start=True)

    with pytest.raises(CaptureStartError):
        manager.start()

    assert manager.is_running() is False
    with pytest.raises(CaptureStartError):
        manager.start()


def test_stop_failure_is_translated() -> None:
    """A sniffer stop failure becomes a controlled CaptureStopError."""
    registry: list[FakeCaptureSniffer] = []
    manager = _make_manager(registry=registry)
    manager.start()
    registry[0].fail_on_stop = True

    with pytest.raises(CaptureStopError) as exc_info:
        manager.stop()

    assert exc_info.value.code == "CAPTURE_STOP_FAILED"
    assert manager.get_status().status == CaptureStatus.ERROR.value


def test_worker_death_is_detected() -> None:
    """An unexpected worker termination is reported as an error state."""
    registry: list[FakeCaptureSniffer] = []
    manager = _make_manager(registry=registry)
    manager.start()

    registry[0].die()

    assert manager.is_running() is False
    assert manager.get_status().status == CaptureStatus.ERROR.value
