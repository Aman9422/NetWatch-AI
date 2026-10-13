"""Failure and recovery tests for the report artifact path (M18.12).

M18.12 asks the application to be tested under controlled failure conditions, and
to prove that errors are surfaced honestly, that resources are released, that state
is not silently corrupted, that partial artifacts are cleaned up, and that one
subsystem's failure does not break unrelated ones.

Most of that surface already had a dedicated owner before this file, and this file
does **not** restate it:

* a missing or invalid capture interface -- ``tests/test_capture_manager.py``,
  ``tests/test_interface_manager.py``
* malformed packets -- ``tests/test_packet_processor.py``,
  ``tests/test_statistics.py``
* a database write or read failure -- ``tests/test_packet_repository.py``,
  ``tests/test_persistence_worker.py``, ``tests/test_packet_persistence.py``
* a subsection of an API response failing -- ``tests/test_analytics_views.py``,
  ``tests/test_dashboard_api.py``
* failed and disconnected WebSocket clients -- ``tests/test_ws_broadcast.py``,
  ``tests/test_ws_manager.py``, ``tests/test_ws_reconnect.py``
* shutdown while work is in flight -- ``tests/test_packet_persistence.py``,
  ``tests/test_connections.py``, ``tests/test_ws_manager.py``
* one subsystem's failure not stopping another --
  ``tests/test_statistics_pipeline.py``, ``tests/test_devices_pipeline.py``,
  ``tests/test_connections_pipeline.py``, ``tests/test_detection_pipeline.py``,
  ``tests/test_persistence_pipeline.py``, ``tests/test_alerts_integration.py``,
  ``tests/test_correlation_integration.py``

What was **not** covered, and is what this file adds, is the failure that happens
*after* the reporting layer has a working storage directory:

* **A write that fails part-way.** Every existing failure test for the reporting
  layer uses a *blocker file* in place of the storage directory, so the failure
  always happens at ``mkdir`` and the artifact is never even attempted. The claim in
  ``app/reports/storage.py`` that a failed write "leaves no debris behind and no
  directory slowly accumulating ``.tmp`` files" was therefore only ever proven for a
  write that *succeeded*. A full disk is the realistic failure and it lands in the
  middle of the write, so each branch after the directory exists is injected here:
  the flush, the rename, and the measurement that follows it.
* **A cleanup that cannot run.** Removal of a partial file happens in a ``finally``
  block, so a failure there must not raise -- a second exception raised while
  cleaning up would replace the one that says what actually went wrong. That
  contract had no test, and the honest consequence of it (the partial file survives,
  because removing it failed) is asserted rather than glossed over.
* **Recovery.** A generation succeeds after a failed one, over the same directory,
  landing on the same name and leaving exactly one file.
* **Non-interference within the layer.** A failure must not reach backwards: an
  earlier, completed report keeps its artifact, its status and its ability to be
  downloaded while a later generation fails.

Failure is injected at the ``os`` boundary the storage layer calls -- ``fsync``,
``replace``, ``unlink`` -- because that is exactly the boundary a full disk,
a filesystem race or a permission change crosses, and because a double *above* the
storage layer would not exercise the cleanup this file exists to prove. Each
injection is scoped to the artifact's own temporary file wherever the call could
otherwise affect unrelated code, so a test never changes how the rest of the
process writes to disk.
"""

from __future__ import annotations

import errno
import os
from collections.abc import Callable, Generator
from pathlib import Path

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.analytics.service import AnalyticsService
from app.analytics.window import iso_from_epoch
from app.api.v1.deps import get_analytics_service, get_report_service
from app.database.session import get_db
from app.reports.errors import ReportGenerationError
from app.reports.requests import ReportRequest, build_request
from app.reports.service import ReportService
from app.reports.status import ReportStatus
from app.reports.storage import ReportStorage
from tests.analytics_fakes import WINDOW_END, WINDOW_START
from tests.m13_fakes import api_client, make_db_override
from tests.reports_fakes import ReportEnvironment, make_environment, make_service

REPORTS_URL = "/api/v1/reports"
GENERATE_URL = f"{REPORTS_URL}/generate"

#: The suffix a temporary file the storage layer writes ends with. Named rather
#: than repeated, because the injection points have to recognise their own file
#: and must not match anything else.
TEMP_SUFFIX = ".tmp"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def iso(epoch: float) -> str:
    """Render a window bound as the ISO-8601 string a request carries."""
    return iso_from_epoch(epoch)


def custom_request(**overrides: object) -> ReportRequest:
    """Return a valid custom-period request over the analytics test window."""
    values: dict[str, object] = {
        "report_type": "custom",
        "output_format": "CSV",
        "since": iso(WINDOW_START),
        "until": iso(WINDOW_END),
        "now": WINDOW_END,
    }
    values.update(overrides)
    return build_request(**values)  # type: ignore[arg-type]


def entries(storage: ReportStorage) -> list[str]:
    """Return the names in a storage directory, sorted; empty when it has none.

    The whole point of the no-debris claim is what is left in the directory, so the
    directory's contents are read directly rather than inferred from a ``.tmp``
    glob: a leftover under any other name would be equally wrong.
    """
    directory = storage.directory
    if not directory.exists():
        return []
    return sorted(entry.name for entry in directory.iterdir())


# ---------------------------------------------------------------------------
# injecting a failure at the filesystem boundary
#
# Each injector captures the real function *before* patching it, so a replacement
# that delegates for a name it does not own cannot call itself. Where a call could
# touch anything other than the artifact's own temporary file -- ``os.replace`` and
# ``os.unlink`` are process-wide -- the replacement delegates to the real function
# rather than failing, so a test never changes how the rest of the process writes.
# ---------------------------------------------------------------------------


def break_fsync(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the next artifact write fail after its bytes have been buffered.

    This is the position a full disk fails in: the bytes were accepted by the
    buffer and the flush to the filesystem is what cannot complete.
    """

    def failing_fsync(descriptor: int) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr("app.reports.storage.os.fsync", failing_fsync)


def break_replace(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the rename step of an artifact write fail, leaving its temp file."""
    real_replace = os.replace

    def failing_replace(source: str, destination: str) -> None:
        if not source.endswith(TEMP_SUFFIX):
            real_replace(source, destination)
            return
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr("app.reports.storage.os.replace", failing_replace)


def break_after_replace(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let the rename succeed and then remove the file, as a filesystem race would.

    Reaches the measurement that follows a successful write, which is the one
    branch left between a rename that reported success and the size being recorded.
    """
    real_replace = os.replace

    def vanishing_replace(source: str, destination: str) -> None:
        real_replace(source, destination)
        os.unlink(destination)

    monkeypatch.setattr("app.reports.storage.os.replace", vanishing_replace)


def break_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make removing a partial file fail too, so the ``finally`` contract is reached."""
    real_unlink = os.unlink

    def failing_unlink(path: str | os.PathLike[str]) -> None:
        if str(path).endswith(TEMP_SUFFIX):
            raise OSError(errno.EACCES, "Permission denied")
        real_unlink(path)

    monkeypatch.setattr("app.reports.storage.os.unlink", failing_unlink)


# ---------------------------------------------------------------------------
# storage: the directory exists, and the write still fails
# ---------------------------------------------------------------------------


@pytest.fixture
def storage(tmp_path: Path) -> ReportStorage:
    """A storage over a directory that does not exist until it is written to."""
    return ReportStorage(str(tmp_path / "artifacts"))


def test_a_disk_full_while_flushing_is_a_generation_failure_with_no_debris(
    storage: ReportStorage, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The write is refused, and the directory is left with nothing in it.

    This is the claim the module makes and the case it was never tested against: a
    failure *inside* the write, after the temporary file exists.
    """
    break_fsync(monkeypatch)

    with pytest.raises(ReportGenerationError) as caught:
        storage.write(filename="report.pdf", payload=b"report bytes")

    message = str(caught.value)
    assert "could not be written" in message
    assert str(storage.directory) not in message
    assert "Traceback" not in message
    assert entries(storage) == []


def test_a_disk_full_while_renaming_is_a_generation_failure_with_no_debris(
    storage: ReportStorage, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rename that cannot complete leaves neither an artifact nor a temp file."""
    break_replace(monkeypatch)

    with pytest.raises(ReportGenerationError):
        storage.write(filename="report.pdf", payload=b"report bytes")

    assert entries(storage) == []


def test_an_artifact_that_vanishes_after_the_rename_is_a_failure_with_no_debris(
    storage: ReportStorage, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file that disappeared between the rename and the size read fails cleanly.

    The measurement is the last step of a write, and it is the one that would be
    left uncovered by injecting only at the rename: the file is in place and then is
    not, which is what a concurrent cleanup or a failing volume looks like.
    """
    break_after_replace(monkeypatch)

    with pytest.raises(ReportGenerationError) as caught:
        storage.write(filename="report.pdf", payload=b"report bytes")

    assert "could not be read back" in str(caught.value)
    assert entries(storage) == []


def test_a_cleanup_failure_does_not_replace_the_failure_that_caused_it(
    storage: ReportStorage, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Removing a partial file runs in a ``finally``, so it must not raise.

    Two things are asserted, and the second is the honest half: the exception an
    operator sees is the write failure rather than the cleanup failure, and the
    partial file is genuinely still there. A cleanup that cannot run is a leak that
    shows up in the directory listing, not a silent success.
    """
    break_fsync(monkeypatch)
    break_cleanup(monkeypatch)

    with pytest.raises(ReportGenerationError) as caught:
        storage.write(filename="report.pdf", payload=b"report bytes")

    assert "could not be written" in str(caught.value)
    leftovers = entries(storage)
    assert len(leftovers) == 1
    assert leftovers[0].endswith(TEMP_SUFFIX)


def test_a_write_succeeds_after_a_failed_one(
    storage: ReportStorage, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed write leaves nothing behind, so the next write is unaffected.

    The second write uses the *same* name as the one that failed, which is what
    makes this a test of the debris rather than of a retry: it can only land
    cleanly if the first attempt left nothing on disk.
    """
    break_fsync(monkeypatch)
    with pytest.raises(ReportGenerationError):
        storage.write(filename="report.pdf", payload=b"first")
    monkeypatch.undo()

    artifact = storage.write(filename="report.pdf", payload=b"second")

    assert artifact.path.read_bytes() == b"second"
    assert entries(storage) == ["report.pdf"]


# ---------------------------------------------------------------------------
# the service: a failure leaves a row, no file, and no damaged neighbour
# ---------------------------------------------------------------------------


@pytest.fixture
def service(
    db_session: Session, session_factory: Callable[[], Session], tmp_path: Path
) -> tuple[ReportService, ReportEnvironment]:
    """Return a service writing into a temporary directory, and its environment.

    The production service over the test's own session and a temporary storage
    directory, so the state machine under test is the one that runs.
    """
    environment = make_environment(session_factory)
    report_service = make_service(db_session, environment, str(tmp_path / "artifacts"))
    return report_service, environment


def test_a_failure_after_the_directory_exists_removes_the_artifact(
    service: tuple[ReportService, ReportEnvironment],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mid-write failure records the row and leaves the directory empty.

    The existing tests for this reach the service's failure branch through a
    blocker file, so the storage directory is never created and no artifact is ever
    attempted. Here the directory is created and then the write fails, which is the
    order a real disk-full failure produces.
    """
    report_service, _environment = service
    break_fsync(monkeypatch)

    with pytest.raises(ReportGenerationError):
        report_service.generate(custom_request())

    rows = report_service.repository.list_reports()
    assert len(rows) == 1
    assert rows[0].status == ReportStatus.FAILED
    assert rows[0].file_size is None
    assert rows[0].error
    assert entries(report_service.storage) == []


def test_a_failed_row_says_what_happened_without_naming_a_path(
    service: tuple[ReportService, ReportEnvironment],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """What is stored for an operator to read names the situation, not the machine.

    A failure sentence is served through the API, so the row is the last place it
    can be made safe: a path or a traceback recorded here would be published later.
    """
    report_service, _environment = service
    break_fsync(monkeypatch)

    with pytest.raises(ReportGenerationError):
        report_service.generate(custom_request())

    row = report_service.repository.list_reports()[0]
    assert row.error
    for internal in (
        "Traceback",
        'File "',
        "app.",
        str(report_service.storage.directory),
    ):
        assert internal not in row.error


def test_a_failed_generation_does_not_damage_an_earlier_report(
    service: tuple[ReportService, ReportEnvironment],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure must not reach backwards at work that already succeeded.

    An earlier report keeps its artifact, its status and its ability to be
    downloaded, and the failed attempt adds nothing to the directory -- not even a
    temporary file under the name it would have used.
    """
    report_service, _environment = service
    first = report_service.generate(custom_request(title="First"))

    break_fsync(monkeypatch)
    with pytest.raises(ReportGenerationError):
        report_service.generate(custom_request(title="Second"))
    monkeypatch.undo()

    kept = report_service.get_record(first.report_id)
    assert kept is not None
    assert kept.status == ReportStatus.COMPLETED
    assert report_service.artifact_is_available(kept) is True
    assert report_service.read_artifact(kept) == first.path.read_bytes()
    assert entries(report_service.storage) == [first.path.name]

    failed = [
        row
        for row in report_service.repository.list_reports()
        if row.status == ReportStatus.FAILED
    ]
    assert len(failed) == 1
    assert report_service.artifact_is_available(failed[0]) is False


def test_a_generation_succeeds_after_a_failed_one(
    service: tuple[ReportService, ReportEnvironment],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The layer recovers: nothing from the failure obstructs the next attempt."""
    report_service, _environment = service
    break_fsync(monkeypatch)
    with pytest.raises(ReportGenerationError):
        report_service.generate(custom_request(title="Doomed"))
    monkeypatch.undo()

    recovered = report_service.generate(custom_request(title="Recovered"))

    assert recovered.record.status == ReportStatus.COMPLETED
    assert recovered.path.exists()
    assert recovered.record.file_size == recovered.size_bytes
    assert entries(report_service.storage) == [recovered.path.name]


# ---------------------------------------------------------------------------
# the route: the same failure, seen by a caller
# ---------------------------------------------------------------------------


def report_service_override(directory: str) -> Callable[..., ReportService]:
    """Return a ``get_report_service`` override writing into ``directory``.

    The service is built from the *request's* own session and the analytics service
    over it, so everything except the destination of the file is what the
    application builds and the route under test is the real route.
    """

    def override(
        db: Session = Depends(get_db),
        analytics: AnalyticsService = Depends(get_analytics_service),
    ) -> ReportService:
        return ReportService(
            db=db, analytics=analytics, storage=ReportStorage(directory)
        )

    return override


@pytest.fixture
def generating(
    tmp_path: Path, db_engine
) -> Generator[tuple[TestClient, ReportStorage], None, None]:
    """A client whose report artifacts land in a temporary directory.

    Yields the storage alongside the client so a test can inspect what a failed
    request actually left on disk. Nothing here writes to the configured
    ``reports/`` directory.
    """
    storage = ReportStorage(str(tmp_path / "artifacts"))
    overrides = {
        get_db: make_db_override(db_engine),
        get_report_service: report_service_override(str(storage.directory)),
    }
    with api_client(overrides) as test_client:
        yield test_client, storage


def test_a_failed_generation_through_the_route_leaves_no_artifact(
    generating: tuple[TestClient, ReportStorage],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller sees one safe sentence, and the store shows one failed row.

    The whole path is asserted together because the three answers have to agree: a
    500 is only honest if no file was left behind, and the listing is only honest
    if the row it shows is the failed one and its download is refused.
    """
    client, storage = generating
    break_fsync(monkeypatch)

    outcome = client.post(
        GENERATE_URL, json={"report_type": "daily", "format": "CSV"}
    )
    assert outcome.status_code == 500
    body = outcome.json()
    assert body["success"] is False
    assert body["message"]
    for internal in ("Traceback", 'File "', "site-packages"):
        assert internal not in outcome.text

    assert entries(storage) == []

    listed = client.get(REPORTS_URL).json()["data"]
    assert listed["total"] == 1
    failed = listed["reports"][0]
    assert failed["status"] == ReportStatus.FAILED
    download = client.get(f"{REPORTS_URL}/{failed['report_id']}/download")
    assert download.status_code == 404


def test_a_failed_generation_does_not_break_the_next_request(
    generating: tuple[TestClient, ReportStorage],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The service is left usable: the next generation succeeds and downloads.

    A failure that poisoned the session, the storage or the request-scoped service
    would show up here rather than in the next test's setup, which is where an
    operator would meet it.
    """
    client, storage = generating
    break_fsync(monkeypatch)
    failed = client.post(GENERATE_URL, json={"report_type": "daily", "format": "CSV"})
    assert failed.status_code == 500
    monkeypatch.undo()

    outcome = client.post(
        GENERATE_URL, json={"report_type": "daily", "format": "CSV"}
    )
    assert outcome.status_code == 201
    report_id = outcome.json()["data"]["report"]["report_id"]

    download = client.get(f"{REPORTS_URL}/{report_id}/download")
    assert download.status_code == 200
    assert download.content
    assert len(entries(storage)) == 1
