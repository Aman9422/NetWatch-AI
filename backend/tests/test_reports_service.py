"""Tests for the report generation service (M17.12).

The service is the conductor: it resolves a period, writes the metadata row, asks
the assembler for content, asks a renderer for bytes, asks storage to place them,
and records the outcome. So the tests here are about the *state machine over one
row* that conducting produces, and they fall into three groups.

**A success is a row and a file that agree.** Status ``completed``, a recorded
size equal to the file's real size, and an artifact that begins the way its format
must. The period on the row is the request's period, so a report can be found by
the day it covers.

**A failure is recorded, not lost.** A generation that cannot finish leaves a row
that says ``failed`` with a safe sentence and no size, and raises a
:class:`~app.reports.errors.ReportGenerationError`. Nothing claims a file that is
not there. An unanswerable *request* is refused before any row is written, so the
store is untouched.

**Reading a stored report is safe.** A completed row whose file is intact resolves
and reads; the same row after its file is deleted reports the artifact as
unavailable rather than raising out of a listing, and a name that escapes the
storage directory is refused.

The collaborators are the production classes over the test's own session and a
temporary storage directory, so a generation under test is the production one.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.analytics.window import iso_from_epoch
from app.config.settings import settings
from app.models.user import User
from app.reports.assembler import REPORT_ROW_LIMIT, default_title
from app.reports.errors import ReportGenerationError, ReportRequestError
from app.reports.requests import ReportRequest, build_request, resolve_period
from app.reports.service import GENERIC_FAILURE, ReportService, _row_limit
from app.reports.status import ReportStatus
from app.reports.storage import ReportStorage
from tests.analytics_fakes import WINDOW_END, WINDOW_START, seed_packet
from tests.reports_fakes import make_analytics, make_environment, make_service


def iso(epoch: float) -> str:
    """Render a window bound as the ISO-8601 string a request carries."""
    return iso_from_epoch(epoch)


def custom_request(**overrides: object) -> ReportRequest:
    """Return a valid custom-period request over the analytics test window.

    The period is passed explicitly so the generated report covers the instants
    the seeders place their rows in.
    """
    values: dict[str, object] = {
        "report_type": "custom",
        "output_format": "CSV",
        "since": iso(WINDOW_START),
        "until": iso(WINDOW_END),
        "now": WINDOW_END,
    }
    values.update(overrides)
    return build_request(**values)  # type: ignore[arg-type]


@pytest.fixture
def service(
    db_session: Session, session_factory: Callable[[], Session], tmp_path: Path
) -> tuple[ReportService, object]:
    """Return a service writing into a temporary directory, and its environment.

    The environment rides along so a test can drive a runtime service -- the device
    registry, the tracker, the detector -- and so a test can seed the database
    through ``db_session``, which is the same session the service reads.
    """
    environment = make_environment(session_factory)
    report_service = make_service(
        db_session, environment, str(tmp_path / "artifacts")
    )
    return report_service, environment


class BrokenStorage(ReportStorage):
    """A storage whose write fails for a reason the layer did not classify.

    Used to reach the service's generic-failure branch: every classified failure is
    a :class:`ReportError` the service re-raises unchanged, so the branch that
    translates an unclassified exception needs a failure no layer produced.
    """

    def write(self, *, filename: str, payload: bytes):  # type: ignore[override]
        raise RuntimeError("the disk caught fire")


# ---------------------------------------------------------------------------
# a successful generation
# ---------------------------------------------------------------------------


def test_a_generation_stores_a_completed_row_and_an_artifact(service) -> None:
    """The row and the file agree, and the row says the generation finished."""
    report_service, _environment = service

    result = report_service.generate(custom_request())

    assert result.record.status == ReportStatus.COMPLETED
    assert result.record.format == "CSV"
    assert result.record.report_type == "custom"
    assert result.record.error is None
    assert result.record.file_path
    assert result.path.exists()
    assert result.record.file_size == result.size_bytes == result.path.stat().st_size


def test_a_generated_csv_really_is_csv(service) -> None:
    """The bytes on disk are the format the row says they are."""
    report_service, _environment = service

    result = report_service.generate(custom_request(output_format="CSV"))

    assert result.path.read_bytes().startswith(b"###")


def test_a_generated_pdf_really_is_a_pdf(service) -> None:
    """The other renderer is reached through the same request path."""
    report_service, _environment = service

    result = report_service.generate(custom_request(output_format="PDF"))

    payload = result.path.read_bytes()
    assert payload.startswith(b"%PDF")
    assert result.record.format == "PDF"


def test_the_row_records_the_period_the_report_covers(service) -> None:
    """A stored report can be found by the day it covers, not just when it was made."""
    report_service, _environment = service

    result = report_service.generate(custom_request())

    assert result.record.period_start == resolve_period(custom_request()).utc_since()
    assert result.record.period_end == resolve_period(custom_request()).utc_until()


def test_a_generation_records_the_data_the_report_carries(
    service, db_session: Session
) -> None:
    """The content is returned, so a caller need not re-read the file it wrote."""
    report_service, _environment = service
    seed_packet(db_session, offset=0.0)
    seed_packet(db_session, offset=1.0)

    result = report_service.generate(custom_request())

    assert result.content.report_id == result.report_id
    summary = {metric.label: metric.value for metric in result.content.summary}
    assert summary["Packets stored in period"] == "2"


def test_the_derived_name_says_which_period_the_report_covers(service) -> None:
    """The name comes from the period, so two days cannot share one."""
    report_service, _environment = service
    request = custom_request()

    result = report_service.generate(request)

    assert result.record.name == default_title(resolve_period(request), "CSV")


def test_a_requested_title_is_used_as_the_report_name(service) -> None:
    """A caller who names the report gets that name on the stored row."""
    report_service, _environment = service

    result = report_service.generate(custom_request(title="Nightly digest"))

    assert result.record.name == "Nightly digest"


def test_generated_by_is_left_null_when_no_user_is_named(service) -> None:
    """A local deployment with no accounts records no user, rather than guessing."""
    report_service, _environment = service

    result = report_service.generate(custom_request())

    assert result.record.generated_by is None


def test_generated_by_is_recorded_when_the_caller_names_a_user(
    service, db_session: Session
) -> None:
    """The column references the users table, so a real user is recorded."""
    report_service, _environment = service
    db_session.add(User(id=7, username="analyst", role="analyst"))
    db_session.commit()

    result = report_service.generate(custom_request(generated_by=7))

    assert result.record.generated_by == 7


# ---------------------------------------------------------------------------
# a generation that fails
# ---------------------------------------------------------------------------


def test_a_write_failure_marks_the_row_failed_and_raises(
    db_session: Session, session_factory: Callable[[], Session], tmp_path: Path
) -> None:
    """A row is written first, so a failure leaves a record rather than nothing."""
    environment = make_environment(session_factory)
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"i am a file")
    report_service = make_service(db_session, environment, str(blocker))

    with pytest.raises(ReportGenerationError):
        report_service.generate(custom_request())

    rows = report_service.repository.list_reports()
    assert len(rows) == 1
    assert rows[0].status == ReportStatus.FAILED
    assert rows[0].file_size is None
    assert rows[0].error


def test_a_failed_row_carries_a_safe_sentence(service, tmp_path: Path) -> None:
    """The failure sentence names the situation, never a path or a traceback."""
    report_service, _environment = service
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"i am a file")
    report_service.storage = ReportStorage(str(blocker))

    with pytest.raises(ReportGenerationError) as caught:
        report_service.generate(custom_request())

    message = str(caught.value)
    for internal in ("Traceback", "File \"", "app.", str(blocker)):
        assert internal not in message


def test_an_unclassified_failure_becomes_the_generic_sentence(
    db_session: Session, session_factory: Callable[[], Session], tmp_path: Path
) -> None:
    """An exception no layer classified still fails cleanly, with no internals."""
    environment = make_environment(session_factory)
    report_service = ReportService(
        db=db_session,
        analytics=make_analytics(db_session, environment),
        storage=BrokenStorage(str(tmp_path / "artifacts")),
    )

    with pytest.raises(ReportGenerationError) as caught:
        report_service.generate(custom_request())

    assert str(caught.value) == GENERIC_FAILURE
    rows = report_service.repository.list_reports()
    assert rows[0].status == ReportStatus.FAILED
    assert rows[0].error == GENERIC_FAILURE


def test_an_unanswerable_request_is_refused_before_a_row_is_written(service) -> None:
    """Nothing is generated and nothing is stored for a 400 (M17.12)."""
    report_service, _environment = service
    request = build_request(report_type="custom", output_format="CSV", now=WINDOW_END)

    with pytest.raises(ReportRequestError):
        report_service.generate(request)

    assert report_service.repository.count_reports() == 0


# ---------------------------------------------------------------------------
# reading a stored report
# ---------------------------------------------------------------------------


def test_a_completed_report_can_be_looked_up_and_read(service) -> None:
    """The metadata row resolves and the artifact reads back byte-for-byte."""
    report_service, _environment = service
    result = report_service.generate(custom_request())

    record = report_service.get_record(result.report_id)

    assert record is not None
    assert report_service.artifact_path(record) == result.path
    assert report_service.read_artifact(record) == result.path.read_bytes()
    assert report_service.artifact_is_available(record) is True


def test_an_unknown_report_id_resolves_to_nothing(service) -> None:
    """A missing id is the caller's to turn into a 404, not an exception here."""
    report_service, _environment = service

    assert report_service.get_record(999_999) is None


def test_a_report_whose_file_was_removed_reports_itself_unavailable(service) -> None:
    """A listing says a download would fail without attempting one."""
    report_service, _environment = service
    result = report_service.generate(custom_request())
    result.path.unlink()
    record = report_service.get_record(result.report_id)
    assert record is not None

    assert report_service.artifact_is_available(record) is False


def test_a_report_still_generating_has_no_available_artifact(service) -> None:
    """Only a completed row can be served, whatever its name says."""
    report_service, _environment = service
    record = report_service.repository.create_report(
        name="In progress",
        report_type="daily",
        report_format="CSV",
        file_path="",
        generated_at=resolve_period(custom_request()).utc_since(),
        status=ReportStatus.GENERATING,
    )

    assert report_service.artifact_is_available(record) is False


# ---------------------------------------------------------------------------
# the row limit (M17.13)
# ---------------------------------------------------------------------------


def test_the_row_limit_never_exceeds_the_analytics_group_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A report cannot show more groups than the service it reads will produce."""
    monkeypatch.setattr(settings, "report_max_table_rows", 10_000)

    assert _row_limit() == REPORT_ROW_LIMIT


def test_a_lower_setting_lowers_the_report(monkeypatch: pytest.MonkeyPatch) -> None:
    """The configured ceiling is applied when it is the smaller number."""
    monkeypatch.setattr(settings, "report_max_table_rows", 3)

    assert _row_limit() == 3


def test_the_row_limit_is_at_least_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even a nonsensical setting must not produce a report with no rows at all."""
    monkeypatch.setattr(settings, "report_max_table_rows", 0)

    assert _row_limit() == 1
