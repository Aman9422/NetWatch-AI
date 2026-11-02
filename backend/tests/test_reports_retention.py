"""Tests for report artifact retention (M19.5).

Retention is the only code that deletes a report, and a report is something an
operator explicitly asked for. These tests are therefore written around the three
guarantees that make an automatic deletion defensible at all:

* **it is off unless it was switched on** — the default removes nothing;
* **it removes only what the window covers** — a recent report and its file are
  untouched, a row exactly at the boundary is kept, and a generation still in
  flight is never a candidate;
* **it leaves nothing inconsistent behind** — a row and its file go together, a
  file that was already missing is not misreported as a failure, and a pass that
  could not read the store says so instead of reporting a clean zero.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.reports.retention import (
    REPORT_RETENTION_FAILURE_MESSAGE,
    ReportRetentionService,
)
from app.reports.status import ReportStatus
from app.reports.storage import ReportStorage
from app.repositories.report import ReportRepository

# A fixed "now" so every assertion is deterministic.
NOW = datetime(2025, 1, 31, 12, 0, 0, tzinfo=timezone.utc)

# The retention window used by most of the tests.
RETENTION_DAYS = 7


def _at(days_ago: float) -> datetime:
    """Return a naive UTC instant ``days_ago`` before :data:`NOW`.

    Naive because ``reports.generated_at`` is a plain ``DateTime``: SQLite stores
    and returns it without a timezone, and the service has to compare like with
    like (M19.5).
    """
    return (NOW - timedelta(days=days_ago)).replace(tzinfo=None)


def _create(
    session_factory,
    *,
    name: str = "Daily report",
    days_ago: float = 0.0,
    status: str = ReportStatus.COMPLETED,
    file_path: str = "",
    file_size: int | None = None,
):
    """Insert one report metadata row and return it."""
    session = session_factory()
    try:
        return ReportRepository(session).create_report(
            name=name,
            report_type="daily",
            report_format="CSV",
            file_path=file_path,
            generated_at=_at(days_ago),
            status=status,
            file_size=file_size,
        )
    finally:
        session.close()


def _count(session_factory) -> int:
    """Return how many report rows remain."""
    session = session_factory()
    try:
        return ReportRepository(session).count()
    finally:
        session.close()


def _artifact(storage: ReportStorage, name: str) -> str:
    """Write a real artifact into the storage directory and return its file name."""
    storage.write(filename=name, payload=b"report bytes")
    return name


def _service(
    session_factory,
    storage: ReportStorage,
    *,
    retention_days: int = RETENTION_DAYS,
    max_per_run: int = 500,
) -> ReportRetentionService:
    """Build a retention service over the isolated database and directory."""
    return ReportRetentionService(
        session_factory=session_factory,
        storage=storage,
        retention_days=retention_days,
        max_per_run=max_per_run,
    )


@pytest.fixture
def storage(tmp_path: Path) -> ReportStorage:
    """A storage layer over a directory the test owns."""
    return ReportStorage(str(tmp_path / "artifacts"))


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------


def test_a_negative_window_is_rejected(session_factory, storage: ReportStorage) -> None:
    """A negative window is a configuration error."""
    with pytest.raises(ValueError):
        _service(session_factory, storage, retention_days=-1)


def test_a_non_positive_batch_size_is_rejected(
    session_factory, storage: ReportStorage
) -> None:
    """``max_per_run`` of zero would make a pass mean "remove nothing"."""
    with pytest.raises(ValueError):
        _service(session_factory, storage, max_per_run=0)


def test_the_window_and_the_batch_size_are_readable(
    session_factory, storage: ReportStorage
) -> None:
    """Both configured values are exposed, because both are reported."""
    service = _service(session_factory, storage, retention_days=14, max_per_run=25)

    assert service.retention_days == 14
    assert service.max_per_run == 25


def test_the_cutoff_is_now_minus_the_window(
    session_factory, storage: ReportStorage
) -> None:
    """The cutoff is exactly ``now - retention_days``."""
    service = _service(session_factory, storage)

    assert service.cutoff(now=NOW) == NOW - timedelta(days=RETENTION_DAYS)


# ---------------------------------------------------------------------------
# switched off by default
# ---------------------------------------------------------------------------


def test_retention_is_disabled_by_default(session_factory, storage: ReportStorage) -> None:
    """``REPORT_RETENTION_DAYS=0`` must remove nothing, however old a report is."""
    service = _service(session_factory, storage, retention_days=0)
    _create(session_factory, days_ago=365, name="Ancient")

    outcome = service.cleanup_outcome(now=NOW)

    assert service.is_enabled() is False
    assert outcome.enabled is False
    assert outcome.removed == 0
    assert outcome.failed is False
    assert _count(session_factory) == 1


def test_a_disabled_policy_reports_a_measured_zero(
    session_factory, storage: ReportStorage
) -> None:
    """A disabled policy is a success that did nothing, not a failure."""
    outcome = _service(session_factory, storage, retention_days=0).cleanup_outcome(
        now=NOW
    )

    assert outcome.succeeded is True
    assert outcome.removed_anything is False
    assert outcome.summary() == "report retention disabled"


# ---------------------------------------------------------------------------
# what is removed, and what is kept
# ---------------------------------------------------------------------------


def test_an_expired_report_and_its_file_are_both_removed(
    session_factory, storage: ReportStorage
) -> None:
    """The row and the file go together, so nothing is left claiming the other."""
    file_path = _artifact(storage, "old.csv")
    _create(session_factory, days_ago=10, file_path=file_path, file_size=12)

    outcome = _service(session_factory, storage).cleanup_outcome(now=NOW)

    assert outcome.removed == 1
    assert outcome.files_removed == 1
    assert outcome.files_missing == 0
    assert outcome.drained is True
    assert _count(session_factory) == 0
    assert storage.exists(file_path) is False
    assert list(storage.directory.iterdir()) == []


def test_a_recent_report_is_untouched(session_factory, storage: ReportStorage) -> None:
    """Only rows generated strictly before the cutoff are eligible."""
    file_path = _artifact(storage, "recent.csv")
    _create(session_factory, days_ago=1, name="Recent", file_path=file_path)

    outcome = _service(session_factory, storage).cleanup_outcome(now=NOW)

    assert outcome.removed == 0
    assert _count(session_factory) == 1
    assert storage.exists(file_path) is True


def test_a_row_exactly_at_the_boundary_is_kept(
    session_factory, storage: ReportStorage
) -> None:
    """A report generated exactly at the cutoff is inside the window."""
    _create(session_factory, days_ago=RETENTION_DAYS, name="Boundary")

    assert _service(session_factory, storage).cleanup_outcome(now=NOW).removed == 0
    assert _count(session_factory) == 1


def test_only_the_expired_reports_are_removed(
    session_factory, storage: ReportStorage
) -> None:
    """A mixed store keeps every report the policy does not cover."""
    old_file = _artifact(storage, "old.csv")
    new_file = _artifact(storage, "new.csv")
    _create(session_factory, days_ago=30, name="Old", file_path=old_file)
    _create(session_factory, days_ago=20, name="Older", file_path=old_file)
    _create(session_factory, days_ago=3, name="New", file_path=new_file)
    _create(session_factory, days_ago=0, name="Newest", file_path=new_file)

    outcome = _service(session_factory, storage).cleanup_outcome(now=NOW)

    assert outcome.removed == 2
    assert _count(session_factory) == 2
    assert storage.exists(new_file) is True


def test_a_generation_in_flight_is_never_a_candidate(
    session_factory, storage: ReportStorage
) -> None:
    """An old timestamp does not make a row that is being written right now old.

    This is the safety rule that lets retention run beside report generation: a
    ``generating`` row's artifact is produced *after* its row exists, so age alone
    would otherwise select it.
    """
    _create(
        session_factory,
        days_ago=90,
        name="In flight",
        status=ReportStatus.GENERATING,
    )
    _create(session_factory, days_ago=90, name="Finished")

    outcome = _service(session_factory, storage).cleanup_outcome(now=NOW)

    assert outcome.removed == 1
    assert _count(session_factory) == 1


def test_a_failed_row_is_removed_like_any_other(
    session_factory, storage: ReportStorage
) -> None:
    """A failed generation has no artifact, so only its metadata is removed."""
    _create(session_factory, days_ago=60, name="Failed", status=ReportStatus.FAILED)

    outcome = _service(session_factory, storage).cleanup_outcome(now=NOW)

    assert outcome.removed == 1
    assert outcome.files_removed == 0
    assert _count(session_factory) == 0


def test_an_artifact_already_absent_is_not_a_failure(
    session_factory, storage: ReportStorage
) -> None:
    """A file removed by hand before the pass is counted, not treated as an error."""
    _create(session_factory, days_ago=10, name="Missing file", file_path="gone.csv")

    outcome = _service(session_factory, storage).cleanup_outcome(now=NOW)

    assert outcome.removed == 1
    assert outcome.files_removed == 0
    assert outcome.files_missing == 1
    assert outcome.failed is False
    assert "already absent" in outcome.summary()


def test_a_row_without_a_file_name_removes_only_its_metadata(
    session_factory, storage: ReportStorage
) -> None:
    """A row interrupted before its name was assigned has nothing to delete."""
    _create(session_factory, days_ago=10, name="Unnamed", file_path="")

    outcome = _service(session_factory, storage).cleanup_outcome(now=NOW)

    assert outcome.removed == 1
    assert outcome.files_missing == 1


def test_retention_cannot_remove_a_file_outside_its_directory(
    session_factory, tmp_path: Path, storage: ReportStorage
) -> None:
    """The storage layer's containment check applies to deletion too (M17.9)."""
    outside = tmp_path / "secret.txt"
    outside.write_bytes(b"not a report")
    _create(session_factory, days_ago=10, name="Escaping", file_path=str(outside))

    outcome = _service(session_factory, storage).cleanup_outcome(now=NOW)

    assert outcome.removed == 1
    assert outcome.files_removed == 0
    assert outside.exists() is True


# ---------------------------------------------------------------------------
# bounded passes
# ---------------------------------------------------------------------------


def test_a_pass_is_bounded_and_says_so(session_factory, storage: ReportStorage) -> None:
    """A backlog is drained over several passes rather than in one unbounded one."""
    for index in range(3):
        _create(session_factory, days_ago=10 + index, name=f"Old {index}")

    service = _service(session_factory, storage, max_per_run=2)
    first = service.cleanup_outcome(now=NOW)

    assert first.removed == 2
    assert first.drained is False
    assert "backlog remains" in first.summary()

    second = service.cleanup_outcome(now=NOW)

    assert second.removed == 1
    assert second.drained is True
    assert _count(session_factory) == 0


def test_repeated_passes_are_idempotent(session_factory, storage: ReportStorage) -> None:
    """Once the expired set is empty, a pass removes nothing."""
    file_path = _artifact(storage, "old.csv")
    _create(session_factory, days_ago=30, file_path=file_path)
    service = _service(session_factory, storage)

    assert service.cleanup(now=NOW) == 1
    assert service.cleanup(now=NOW) == 0


# ---------------------------------------------------------------------------
# failures are reported, not folded into a zero
# ---------------------------------------------------------------------------


def test_a_failed_pass_is_reported_as_a_failure() -> None:
    """A store that cannot be read is a failure, not a clean zero (M19.3)."""
    def _explode():
        raise RuntimeError("the store is unreachable")

    service = ReportRetentionService(
        session_factory=_explode, retention_days=RETENTION_DAYS
    )

    outcome = service.cleanup_outcome(now=NOW)

    assert outcome.failed is True
    assert outcome.succeeded is False
    assert outcome.removed == 0
    assert outcome.error == REPORT_RETENTION_FAILURE_MESSAGE
    assert service.failure_count == 1


def test_a_failure_counts_across_attempts() -> None:
    """Each failed attempt is counted, so a stopped policy is observable (M19.3)."""
    def _explode():
        raise RuntimeError("the store is unreachable")

    service = ReportRetentionService(
        session_factory=_explode, retention_days=RETENTION_DAYS
    )

    service.cleanup(now=NOW)
    service.cleanup_outcome(now=NOW)

    assert service.failure_count == 2


def test_a_success_does_not_count_as_a_failure(
    session_factory, storage: ReportStorage
) -> None:
    """A pass that worked never increments the failure counter."""
    _create(session_factory, days_ago=10)

    _service(session_factory, storage).cleanup(now=NOW)

    assert _service(session_factory, storage).failure_count == 0


def test_the_failure_message_names_no_internal() -> None:
    """The safe sentence cannot leak a path, a statement or a driver (M13.30)."""
    lowered = REPORT_RETENTION_FAILURE_MESSAGE.lower()

    leaks = (
        "sqlite",
        "traceback",
        "operationalerror",
        "no such table",
        "delete from",
        "select ",
        "c:\\",
        "/app",
        "/backend",
    )
    for leak in leaks:
        assert leak not in lowered


def test_every_outcome_describes_itself(session_factory, storage: ReportStorage) -> None:
    """The sweep logs passes through one code path, so each outcome is a sentence."""
    service = _service(session_factory, storage)
    file_path = _artifact(storage, "old.csv")
    _create(session_factory, days_ago=30, file_path=file_path)

    summary = service.cleanup_outcome(now=NOW).summary()

    assert "1 report(s)" in summary
    assert "1 file(s)" in summary
