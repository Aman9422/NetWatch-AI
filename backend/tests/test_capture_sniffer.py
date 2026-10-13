"""Tests for the Scapy capture adapter (M18.2).

``app/services/capture_sniffer.py`` is the one module that touches Scapy's
``AsyncSniffer``, and it carries three responsibilities nothing else in the
project can absorb:

* **Translating a background-thread start into a synchronous verdict.** Scapy
  starts capture on its own thread, so ``AsyncSniffer.start()`` returns before the
  interface is open. Without the short wait here, a bad interface or a missing
  privilege would return successfully and produce a capture session that reports
  zero packets forever -- which is exactly the failure M18.2 says must be surfaced
  rather than allowed to look like an idle network.
* **Keeping one unprocessable packet from ending the session.** A malformed frame
  is counted and logged, and the next packet is still captured.
* **Carrying the worker's own exception back to the manager**, so a capture thread
  that died on its own becomes an error state rather than a silent stop.

Nothing here asserts Scapy's behaviour: ``AsyncSniffer`` is replaced with a
doubles that exposes exactly the surface this adapter uses (``start``, ``stop``,
``running``, ``thread``, ``exception``). That keeps the suite free of a network
interface, of elevated privileges and of timing luck -- the M18.2 requirement that
ordinary unit tests need none of the three.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services import capture_sniffer as sniffer_module
from app.services.capture_sniffer import (
    CaptureSniffer,
    ScapyCaptureSniffer,
)


# ---------------------------------------------------------------------------
# The double
# ---------------------------------------------------------------------------


class FakeAsyncSniffer:
    """A stand-in for ``scapy.all.AsyncSniffer``.

    Only the five attributes the adapter reads are modelled. ``start()`` is where
    the real class opens a socket on another thread, so the fake decides there what
    the session looks like: running, still starting, or already failed.
    """

    #: Every instance built during a test, so the constructor contract can be
    #: asserted without reaching into the adapter's private state.
    instances: list["FakeAsyncSniffer"] = []

    def __init__(
        self,
        *,
        iface: str,
        prn: Any,
        store: bool,
        started_callback: Any,
    ) -> None:
        self.iface = iface
        self.prn = prn
        self.store = store
        self.started_callback = started_callback

        self.running = False
        self.exception: BaseException | None = None
        self.thread: object | None = None
        self.stop_calls = 0
        # What ``start()`` should do, set by the test that builds the adapter.
        self.start_behaviour: str = "start"
        self.start_exception: BaseException | None = None
        self.stop_exception: BaseException | None = None
        FakeAsyncSniffer.instances.append(self)

    def start(self) -> None:
        """Model the real thread's start-up in one synchronous step."""
        if self.start_behaviour == "never_start":
            # A worker that was created but never reached the running state: the
            # case the adapter's wait exists to catch.
            self.thread = object()
            return
        if self.start_behaviour == "raise":
            self.thread = object()
            self.exception = self.start_exception or RuntimeError("interface is down")
            raise self.exception
        if self.start_behaviour == "error_then_start":
            self.thread = object()
            self.exception = self.start_exception or RuntimeError("permission denied")
            return
        self.thread = object()
        self.running = True
        if self.started_callback is not None:
            self.started_callback()

    def stop(self) -> None:
        self.stop_calls += 1
        if self.stop_exception is not None:
            raise self.stop_exception
        self.running = False


class BehaviourFactory:
    """Builds a :class:`FakeAsyncSniffer` already configured for a start-up outcome.

    The adapter constructs whatever class it holds, so a test that needs a start-up
    failure substitutes this for ``AsyncSniffer`` and the adapter builds it without
    knowing anything changed. That keeps the failure deterministic -- no sleeps, no
    real device, no privilege.
    """

    def __init__(self, behaviour: str, exception: BaseException | None = None) -> None:
        self.behaviour = behaviour
        self.exception = exception

    def __call__(
        self,
        *,
        iface: str,
        prn: Any,
        store: bool,
        started_callback: Any,
    ) -> FakeAsyncSniffer:
        sniffer = FakeAsyncSniffer(
            iface=iface, prn=prn, store=store, started_callback=started_callback
        )
        sniffer.start_behaviour = self.behaviour
        sniffer.start_exception = self.exception
        return sniffer


@pytest.fixture(autouse=True)
def _fake_scapy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace Scapy's sniffer with the double for every test in this module."""
    FakeAsyncSniffer.instances = []
    monkeypatch.setattr(sniffer_module, "AsyncSniffer", FakeAsyncSniffer)


@pytest.fixture(autouse=True)
def _fast_start_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shrink the start-up wait so a timeout test costs milliseconds, not seconds.

    The adapter reads both constants from its own module at call time, so patching
    them here changes what the code under test sees rather than what the test
    believes. The assertions are about *which* error is raised, not how long the
    wait is, so shortening it changes nothing about what is being proven.
    """
    monkeypatch.setattr(sniffer_module, "_START_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(sniffer_module, "_START_POLL_INTERVAL_SECONDS", 0.005)


class RecordingSink:
    """A ``PacketSink`` that records what it was handed and can be made to fail."""

    def __init__(self, *, fail_on: set[Any] | None = None) -> None:
        self.received: list[Any] = []
        self.fail_on = fail_on or set()

    def process(self, packet: Any, captured_at: float | None = None) -> None:
        """Record the packet, or raise if this test asked for a failure."""
        self.received.append(packet)
        if packet in self.fail_on:
            raise ValueError("unprocessable packet")


def _started_sniffer(**kwargs: Any) -> tuple[ScapyCaptureSniffer, FakeAsyncSniffer]:
    """Return an adapter that has started, plus the Scapy double behind it."""
    adapter = ScapyCaptureSniffer("Wi-Fi", **kwargs)
    adapter.start()
    assert FakeAsyncSniffer.instances, "the adapter did not construct a sniffer"
    return adapter, FakeAsyncSniffer.instances[-1]


# ---------------------------------------------------------------------------
# The protocol the manager depends on
# ---------------------------------------------------------------------------


def test_the_adapter_satisfies_the_capture_sniffer_protocol() -> None:
    """The manager is typed against the protocol, so the adapter must match it.

    A missing method here would be a runtime ``AttributeError`` in the capture
    thread rather than a type error, which is why it is asserted explicitly.
    """
    adapter = ScapyCaptureSniffer("Wi-Fi")

    assert isinstance(adapter, CaptureSniffer)
    for name in ("start", "stop", "is_running", "get_packet_count"):
        assert callable(getattr(adapter, name))


# ---------------------------------------------------------------------------
# Starting
# ---------------------------------------------------------------------------


def test_start_opens_capture_without_storing_packets() -> None:
    """``store=False`` is what keeps capture memory independent of traffic volume.

    Scapy's default keeps every captured packet in a list. A monitoring tool that
    accepted that default would grow without bound for as long as it captured, so
    the setting is part of the adapter's contract rather than an implementation
    detail.
    """
    _started_sniffer()

    sniffer = FakeAsyncSniffer.instances[-1]
    assert sniffer.iface == "Wi-Fi"
    assert sniffer.store is False
    assert callable(sniffer.prn)


def test_start_waits_until_the_worker_is_really_running() -> None:
    """``start()`` returns only once Scapy reports the session live."""
    adapter, sniffer = _started_sniffer()

    assert sniffer.running is True
    assert adapter.is_running() is True


def test_start_reports_a_worker_that_never_started(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A capture that never opened raises instead of reporting an idle network.

    This is the M18.2 requirement stated as a test: a capture error must be
    reported, not silently appear as zero traffic. The worker here is created and
    simply never reaches the running state -- a bad interface, a missing driver or
    a privilege that was not granted all look like this from the adapter's side.
    """
    adapter = ScapyCaptureSniffer("Wi-Fi")
    monkeypatch.setattr(sniffer_module, "AsyncSniffer", BehaviourFactory("never_start"))

    with pytest.raises(RuntimeError) as caught:
        adapter.start()

    assert "did not start" in str(caught.value)
    assert adapter.is_running() is False


def test_start_surfaces_the_worker_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """A worker that failed on its own thread raises on the caller's thread.

    Scapy records the thread's exception rather than re-raising it, so without the
    adapter reading it back the failure would be invisible and the session would
    look like an idle network.
    """
    adapter = ScapyCaptureSniffer("Wi-Fi")
    monkeypatch.setattr(
        sniffer_module,
        "AsyncSniffer",
        BehaviourFactory("error_then_start", RuntimeError("permission denied")),
    )

    with pytest.raises(RuntimeError) as caught:
        adapter.start()

    assert "permission denied" in str(caught.value)


def test_start_propagates_a_raise_from_the_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exception raised while starting is not swallowed."""
    adapter = ScapyCaptureSniffer("Wi-Fi")
    monkeypatch.setattr(
        sniffer_module,
        "AsyncSniffer",
        BehaviourFactory("raise", ValueError("no such device")),
    )

    with pytest.raises(ValueError):
        adapter.start()


def test_a_fresh_adapter_is_not_running() -> None:
    """Before ``start()`` there is no session, and no error to report."""
    adapter = ScapyCaptureSniffer("Wi-Fi")

    assert adapter.is_running() is False
    assert adapter.get_packet_count() == 0


def test_starting_again_resets_the_session_counters() -> None:
    """A new session begins at zero; a previous session's counters do not leak.

    The manager reports the count of the *current* session, so a reused adapter
    that kept the old totals would report a packet count the new capture never saw.
    """
    adapter, sniffer = _started_sniffer()
    sniffer.prn("something")
    sniffer.prn("something else")
    assert adapter.get_packet_count() == 2

    adapter.stop()
    adapter.start()

    assert adapter.get_packet_count() == 0
    assert adapter.get_processed_count() == 0
    assert adapter.get_processing_error_count() == 0


# ---------------------------------------------------------------------------
# Handing packets to the sink
# ---------------------------------------------------------------------------


def test_a_captured_packet_is_counted_and_forwarded() -> None:
    """The adapter counts every packet and gives the sink each one."""
    sink = RecordingSink()
    adapter, sniffer = _started_sniffer(packet_sink=sink)

    sniffer.prn("packet-a")
    sniffer.prn("packet-b")

    assert adapter.get_packet_count() == 2
    assert adapter.get_processed_count() == 2
    assert sink.received == ["packet-a", "packet-b"]


def test_a_packet_is_counted_even_with_no_sink() -> None:
    """Without a pipeline the adapter still reports what the wire carried."""
    adapter, sniffer = _started_sniffer()

    sniffer.prn("packet-a")

    assert adapter.get_packet_count() == 1
    assert adapter.get_processed_count() == 0


def test_one_unprocessable_packet_does_not_end_the_session() -> None:
    """A malformed frame is isolated, counted, and capture continues.

    The bad packet is one the sink raises on rather than a genuinely malformed
    Scapy object, because the adapter's contract is that *any* sink failure is
    contained -- it never inspects what the sink threw.
    """
    sink = RecordingSink(fail_on={"broken"})
    adapter, sniffer = _started_sniffer(packet_sink=sink)

    sniffer.prn("good")
    sniffer.prn("broken")
    sniffer.prn("good again")

    assert adapter.get_packet_count() == 3
    assert adapter.get_processed_count() == 2
    assert adapter.get_processing_error_count() == 1


def test_a_sink_failure_is_never_raised_into_the_capture_thread() -> None:
    """The callback returns normally, which is what keeps the sniffer alive."""
    sink = RecordingSink(fail_on={"broken"})
    _adapter, sniffer = _started_sniffer(packet_sink=sink)

    # No ``pytest.raises``: the assertion is that this call simply returns.
    sniffer.prn("broken")

    assert sniffer.running is True


def test_the_callback_is_the_adapters_own_handler() -> None:
    """Scapy is handed the bound method, so packets reach this adapter."""
    adapter, sniffer = _started_sniffer()

    assert sniffer.prn == adapter._handle_packet


# ---------------------------------------------------------------------------
# Stopping
# ---------------------------------------------------------------------------


def test_stop_closes_a_running_session() -> None:
    """A running sniffer is asked to stop and is no longer reported as running."""
    adapter, sniffer = _started_sniffer()

    adapter.stop()

    assert sniffer.stop_calls == 1
    assert adapter.is_running() is False


def test_stopping_without_starting_is_harmless() -> None:
    """A stop with no session is a no-op rather than an error.

    The capture manager can reach a stop path for a session that already failed to
    start, and shutdown may run after a failed start. Neither is an error.
    """
    adapter = ScapyCaptureSniffer("Wi-Fi")

    adapter.stop()

    assert FakeAsyncSniffer.instances == []


def test_a_stop_failure_is_reported_and_the_session_is_dropped() -> None:
    """A driver that refuses to stop becomes a controlled failure.

    The adapter clears its reference anyway, so a second stop cannot try to stop
    the same broken worker again.
    """
    adapter, sniffer = _started_sniffer()
    sniffer.stop_exception = OSError("driver busy")

    with pytest.raises(RuntimeError) as caught:
        adapter.stop()

    assert "failed to stop" in str(caught.value)
    # The reference is gone, so the next stop is the harmless no-op path.
    adapter.stop()
    assert sniffer.stop_calls == 1


def test_the_packet_count_survives_a_failed_stop() -> None:
    """The count of what was captured is not lost because stopping failed."""
    adapter, sniffer = _started_sniffer()
    sniffer.prn("a")
    sniffer.prn("b")
    sniffer.stop_exception = OSError("driver busy")

    with pytest.raises(RuntimeError):
        adapter.stop()

    assert adapter.get_packet_count() == 2


def test_a_sniffer_that_is_already_down_is_not_stopped_again() -> None:
    """Scapy reports a worker that stopped itself; the adapter does not re-stop it."""
    adapter, sniffer = _started_sniffer()
    sniffer.running = False

    adapter.stop()

    assert sniffer.stop_calls == 0
    assert adapter.is_running() is False


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def test_health_is_quiet_for_a_worker_that_is_fine() -> None:
    """A healthy session raises nothing, which is what the manager reads as OK."""
    adapter, _sniffer = _started_sniffer()

    adapter.check_health()


def test_health_reports_the_exception_that_killed_the_worker() -> None:
    """A worker that died on its own is an error, not a session that stopped.

    This is the path that turns "capture is running but nothing is arriving" into
    a reported capture error rather than a silently idle interface.
    """
    adapter, sniffer = _started_sniffer()
    sniffer.running = False
    sniffer.exception = RuntimeError("worker thread died")

    with pytest.raises(RuntimeError) as caught:
        adapter.check_health()

    assert "worker thread died" in str(caught.value)


def test_health_is_quiet_before_any_session() -> None:
    """A health check with no sniffer constructed raises nothing."""
    adapter = ScapyCaptureSniffer("Wi-Fi")

    adapter.check_health()
