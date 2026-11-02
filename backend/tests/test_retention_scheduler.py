"""Tests for the retention scheduler (M19.5).

The scheduler exists because a configured retention window that nothing invokes
protects nothing. What has to hold, therefore, is that it actually runs the
policies, that it runs them *independently* -- one store's failure must not stop
another store's cleanup -- and that it owns its thread: it starts when asked,
stops when asked, and never leaves one behind.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from app.persistence import retention as packet_retention_module
from app.reports import retention as report_retention_module
from app.reports.retention import ReportRetentionService
from app.reports.storage import ReportStorage
from app.repositories.packet import PacketRepository
from app.repositories.report import ReportRepository
from app.services.retention_scheduler import (
    RetentionPolicy,
    RetentionSweeper,
    build_retention_policies,
    get_retention_sweeper,
    reset_retention_sweeper,
)

NOW = datetime(2025, 1, 31, 12, 0, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class _Outcome:
    """A stand-in outcome, satisfying the scheduler's structural contract."""

    enabled: bool = True
    succeeded: bool = True
    text: str = "did something"

    def summary(self) -> str:
        """Return the description a policy would report."""
        return self.text


# ---------------------------------------------------------------------------
# one pass
# ---------------------------------------------------------------------------


def test_a_pass_runs_every_policy_in_order() -> None:
    """Policies run in the order they were declared, once each."""
    calls: list[str] = []

    def _make(name: str):
        def _run() -> _Outcome:
            calls.append(name)
            return _Outcome()

        return _run

    sweeper = RetentionSweeper(
        policies=[
            RetentionPolicy(name="first", cleanup=_make("first")),
            RetentionPolicy(name="second", cleanup=_make("second")),
        ],
        interval_seconds=60.0,
        autostart=False,
    )

    outcomes = sweeper.run_once()

    assert calls == ["first", "second"]
    assert [outcome.name for outcome in outcomes] == ["first", "second"]
    assert all(outcome.succeeded for outcome in outcomes)


def test_a_pass_with_no_policies_is_harmless() -> None:
    """An empty policy list is a pass that does nothing, not an error."""
    sweeper = RetentionSweeper(policies=[], interval_seconds=60.0, autostart=False)

    assert sweeper.run_once() == []


def test_one_failing_policy_does_not_stop_the_others() -> None:
    """A broken store must not be able to block an unrelated store's cleanup."""
    ran: list[str] = []

    def _explode() -> _Outcome:
        raise RuntimeError("this policy is broken")

    def _run() -> _Outcome:
        ran.append("fine")
        return _Outcome()

    sweeper = RetentionSweeper(
        policies=[
            RetentionPolicy(name="broken", cleanup=_explode),
            RetentionPolicy(name="fine", cleanup=_run),
        ],
        interval_seconds=60.0,
        autostart=False,
    )

    outcomes = sweeper.run_once()

    assert ran == ["fine"]
    assert outcomes[0].succeeded is False
    assert outcomes[1].succeeded is True


def test_a_policy_that_raised_is_described_safely() -> None:
    """The failure is described in a sentence, and names no internal."""

    def _explode() -> _Outcome:
        raise RuntimeError("C:\\some\\internal\\path")

    sweeper = RetentionSweeper(
        policies=[RetentionPolicy(name="broken", cleanup=_explode)],
        interval_seconds=60.0,
        autostart=False,
    )

    outcome = sweeper.run_once()[0]

    assert outcome.succeeded is False
    assert "internal" not in outcome.summary
    assert "C:" not in outcome.summary


def test_a_disabled_policy_is_reported_as_disabled() -> None:
    """Switched off is a success, and the pass says which policy was off."""
    sweeper = RetentionSweeper(
        policies=[
            RetentionPolicy(
                name="off", cleanup=lambda: _Outcome(enabled=False, text="disabled")
            )
        ],
        interval_seconds=60.0,
        autostart=False,
    )

    outcome = sweeper.run_once()[0]

    assert outcome.enabled is False
    assert outcome.succeeded is True
    assert outcome.summary == "disabled"


def test_a_failed_policy_is_reported_as_failed() -> None:
    """A policy that completed with a failure result is surfaced as one."""
    sweeper = RetentionSweeper(
        policies=[
            RetentionPolicy(
                name="failed",
                cleanup=lambda: _Outcome(succeeded=False, text="could not read"),
            )
        ],
        interval_seconds=60.0,
        autostart=False,
    )

    outcome = sweeper.run_once()[0]

    assert outcome.succeeded is False
    assert outcome.summary == "could not read"


# ---------------------------------------------------------------------------
# lifecycle
# ---------------------------------------------------------------------------


def test_zero_interval_starts_no_thread() -> None:
    """Zero means "run nothing automatically", so no scheduler is created."""
    sweeper = RetentionSweeper(policies=[], interval_seconds=0, autostart=False)

    assert sweeper.start() is False
    assert sweeper.is_running is False


def test_a_negative_interval_starting_nothing_is_safe() -> None:
    """A nonsensical interval is treated the same way as zero."""
    sweeper = RetentionSweeper(policies=[], interval_seconds=-5.0, autostart=False)

    assert sweeper.start() is False
    assert sweeper.is_running is False


def test_start_then_stop_leaves_no_thread_running() -> None:
    """A started sweep is joinable, so no thread outlives the application."""
    sweeper = RetentionSweeper(
        policies=[RetentionPolicy(name="noop", cleanup=lambda: _Outcome())],
        interval_seconds=60.0,
        autostart=False,
    )

    assert sweeper.start() is True
    assert sweeper.is_running is True

    sweeper.stop()

    assert sweeper.is_running is False


def test_starting_twice_does_not_create_a_second_thread() -> None:
    """A second start on a running sweep is a no-op, not a second sweeper."""
    sweeper = RetentionSweeper(
        policies=[RetentionPolicy(name="noop", cleanup=lambda: _Outcome())],
        interval_seconds=60.0,
        autostart=False,
    )
    sweeper.start()
    try:
        assert sweeper.start() is False
    finally:
        sweeper.stop()


def test_stopping_a_sweeper_that_never_started_is_safe() -> None:
    """Shutdown calls ``stop`` unconditionally, so it has to tolerate this."""
    sweeper = RetentionSweeper(policies=[], interval_seconds=60.0, autostart=False)

    sweeper.stop()
    sweeper.stop()

    assert sweeper.is_running is False


def test_autostart_starts_the_thread_and_can_be_stopped() -> None:
    """The default is to start immediately, which is what the lifespan uses."""
    sweeper = RetentionSweeper(
        policies=[RetentionPolicy(name="noop", cleanup=lambda: _Outcome())],
        interval_seconds=60.0,
    )
    try:
        assert sweeper.is_running is True
    finally:
        sweeper.stop()


def test_the_interval_and_policies_are_exposed() -> None:
    """Both are readable, because both are logged and reported."""
    sweeper = RetentionSweeper(policies=[], interval_seconds=42.0, autostart=False)

    assert sweeper.interval_seconds == 42.0
    assert [policy.name for policy in sweeper.policies] == []


def test_the_thread_runs_a_pass_once_the_interval_elapses() -> None:
    """The loop applies the policies on its own clock, not only when asked.

    This is the behaviour the whole module exists for, so it is verified against a
    real thread rather than inferred from ``run_once``.
    """
    ran = threading.Event()

    def _tick() -> _Outcome:
        ran.set()
        return _Outcome()

    sweeper = RetentionSweeper(
        policies=[RetentionPolicy(name="ticks", cleanup=_tick)],
        interval_seconds=0.01,
        autostart=False,
    )
    sweeper.start()
    try:
        assert ran.wait(5.0) is True
    finally:
        sweeper.stop()


# ---------------------------------------------------------------------------
# the application's own policies
# ---------------------------------------------------------------------------


def test_the_application_policies_are_named_and_ordered() -> None:
    """Packet rows are the high-volume store, so they are applied first."""
    policies = build_retention_policies()

    assert [policy.name for policy in policies] == ["packets", "reports"]


def test_get_retention_sweeper_returns_one_instance() -> None:
    """The sweeper is process-wide, so two callers share one thread (M13.28)."""
    reset_retention_sweeper()
    try:
        first = get_retention_sweeper()
        second = get_retention_sweeper()

        assert first is second
        assert [policy.name for policy in first.policies] == ["packets", "reports"]
    finally:
        reset_retention_sweeper()


def test_get_retention_sweeper_does_not_start_itself() -> None:
    """The lifespan decides when the thread starts; the factory stays inert."""
    reset_retention_sweeper()
    try:
        assert get_retention_sweeper().is_running is False
    finally:
        reset_retention_sweeper()


def test_reset_replaces_the_sweeper() -> None:
    """A reset drops the singleton so a test can build a fresh one."""
    reset_retention_sweeper()
    first = get_retention_sweeper()

    reset_retention_sweeper()

    assert get_retention_sweeper() is not first
    reset_retention_sweeper()


def _packet_row(timestamp: datetime) -> dict[str, object]:
    """Build a minimal but complete ``packets`` row."""
    return {
        "timestamp": timestamp,
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "source_port": None,
        "destination_port": None,
        "protocol": "TCP",
        "packet_length": 100,
        "tcp_flags": None,
        "ttl": None,
        "payload_length": None,
        "device_id": None,
        "processed": 0,
    }


def test_a_pass_cleans_both_stores_through_the_real_policies(
    session_factory, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The composed pass removes an expired packet and an expired report.

    This is the integration the application actually runs, so it is exercised as
    one: both real services, both real stores, driven by one ``run_once``. The
    factories are redirected at the test's isolated database and directory, which
    is also what proves the sweep reaches the stores through configuration rather
    than through a copy of anything.
    """
    from app.persistence.retention import PacketRetentionService

    # Both policies derive their cutoff from the real clock when no override is
    # supplied -- which is exactly how the sweep calls them -- so the data has to
    # be placed relative to the real clock too. A fixed instant would make every
    # row look ancient (or futuristic) and the test would pass for the wrong
    # reason.
    clock = datetime.now(timezone.utc)
    expired = clock - timedelta(days=90)
    recent = clock - timedelta(days=1)

    storage = ReportStorage(str(tmp_path / "artifacts"))
    storage.write(filename="old.csv", payload=b"report bytes")

    session = session_factory()
    try:
        PacketRepository(session).write_batch(
            [_packet_row(expired), _packet_row(recent)]
        )
        ReportRepository(session).create_report(
            name="Old",
            report_type="daily",
            report_format="CSV",
            file_path="old.csv",
            generated_at=expired.replace(tzinfo=None),
            status="completed",
        )
    finally:
        session.close()

    monkeypatch.setattr(
        packet_retention_module,
        "get_packet_retention_service",
        lambda: PacketRetentionService(
            session_factory=session_factory, retention_days=30
        ),
    )
    monkeypatch.setattr(
        report_retention_module,
        "get_report_retention_service",
        lambda: ReportRetentionService(
            session_factory=session_factory, storage=storage, retention_days=30
        ),
    )

    sweeper = RetentionSweeper(
        policies=build_retention_policies(), interval_seconds=60.0, autostart=False
    )
    outcomes = sweeper.run_once()

    assert [outcome.succeeded for outcome in outcomes] == [True, True]
    assert outcomes[0].summary == "1 packet row(s) deleted"
    assert outcomes[1].summary.startswith("1 report(s) and 1 file(s) removed")
    assert storage.exists("old.csv") is False

    session = session_factory()
    try:
        assert PacketRepository(session).count() == 1
        assert ReportRepository(session).count() == 0
    finally:
        session.close()
