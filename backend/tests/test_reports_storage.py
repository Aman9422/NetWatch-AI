"""Tests for the report storage layer (M17.9).

Storage is the only part of the reporting layer that touches the filesystem, so
the tests here are the ones that would catch a report escaping its directory, a
half-written artifact being served, or a naming rule that lets one generation
overwrite another's file.

Three properties get the most attention, because each is the sort of thing that is
invisible until it matters:

* **The file name is collision-safe.** It carries the stored id, so two daily
  reports for the same day -- generated twice, or in two formats -- cannot land on
  one another.
* **Writes are atomic.** Bytes go to a temporary file in the same directory and are
  moved onto the final name, so no reader ever sees a partial artifact and no
  failed write leaves debris behind.
* **Reads are confined.** A ``file_path`` is data read from a database row, and a
  database value must never be able to make the process open an arbitrary file.
  Every read re-checks containment rather than trusting a value chosen at write
  time.

Each failure path also asserts that the sentence names no path: an operator reads
it, and a path in an API response is an information leak (M13.30/M17.14).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config.settings import settings
from app.reports.errors import ReportArtifactMissing, ReportGenerationError
from app.reports.storage import (
    FILENAME_PREFIX,
    FORMAT_EXTENSIONS,
    ReportStorage,
    StoredArtifact,
    build_filename,
    extension_for,
    get_report_storage,
    safe_label,
)

PAYLOAD = b"report bytes"


@pytest.fixture
def storage(tmp_path: Path) -> ReportStorage:
    """A storage layer over a directory that does not exist yet.

    The directory is deliberately not created here: creating it is the storage
    layer's own job, on first write, and a test that pre-created it would never
    exercise that.
    """
    return ReportStorage(str(tmp_path / "artifacts"))


# ---------------------------------------------------------------------------
# the naming rule
# ---------------------------------------------------------------------------


def test_a_period_label_is_reduced_to_a_filename_token() -> None:
    """A period label is built from ISO instants, so this is defence in depth."""
    assert safe_label("2026-09-28 to 2026-10-04") == "2026-09-28-to-2026-10-04"
    assert safe_label("2026-10-09") == "2026-10-09"


def test_a_label_can_never_contribute_a_separator() -> None:
    """No run of unsafe characters survives as anything but a single dash."""
    assert safe_label("../../etc/passwd") == "etc-passwd"
    assert safe_label("C:\\Windows\\System32") == "C-Windows-System32"
    assert "/" not in safe_label("2026/10/09")
    assert "\\" not in safe_label("2026\\10\\09")


def test_an_unusable_label_becomes_the_word_period() -> None:
    """A label that reduces to nothing must not leave two adjacent separators."""
    assert safe_label("") == "period"
    assert safe_label("///") == "period"
    assert safe_label("   ") == "period"


def test_each_format_maps_to_its_own_extension() -> None:
    """The extension is derived here, so a request cannot choose one."""
    assert extension_for("CSV") == "csv"
    assert extension_for("PDF") == "pdf"
    assert extension_for("csv") == "csv"


def test_an_unknown_format_still_yields_an_extension() -> None:
    """This function is total: format validation belongs to the service."""
    assert extension_for("DOCX") == "docx"
    assert FORMAT_EXTENSIONS == {"CSV": "csv", "PDF": "pdf"}


def test_a_filename_carries_its_id_its_period_and_its_format() -> None:
    """A human browsing the directory can tell which report each file is."""
    name = build_filename(
        report_id=123, label="2026-10-09", output_format="CSV"
    )

    assert name == f"{FILENAME_PREFIX}-000123-2026-10-09.csv"


def test_a_filename_pads_its_id_so_a_listing_sorts_numerically() -> None:
    """Without padding, report 10 would sort before report 9."""
    ninth = build_filename(report_id=9, label="2026-10-09", output_format="PDF")
    tenth = build_filename(report_id=10, label="2026-10-09", output_format="PDF")

    assert ninth < tenth


def test_two_generations_of_the_same_day_cannot_share_a_name() -> None:
    """The id is what disambiguates; the period and format merely describe."""
    first = build_filename(report_id=1, label="2026-10-09", output_format="PDF")
    second = build_filename(report_id=2, label="2026-10-09", output_format="PDF")
    same_id_other_format = build_filename(
        report_id=1, label="2026-10-09", output_format="CSV"
    )

    assert len({first, second, same_id_other_format}) == 3


def test_the_storage_names_a_file_without_touching_the_filesystem(
    storage: ReportStorage,
) -> None:
    """A listing request that never writes must not create a directory."""
    name = storage.filename_for(
        report_id=7, label="2026-10-09", output_format="PDF"
    )

    assert name == build_filename(
        report_id=7, label="2026-10-09", output_format="PDF"
    )
    assert not storage.directory.exists()


# ---------------------------------------------------------------------------
# the directory
# ---------------------------------------------------------------------------


def test_the_configured_directory_is_resolved_to_an_absolute_path() -> None:
    """A relative setting is resolved against the working directory, once."""
    configured = ReportStorage()

    assert configured.directory.is_absolute()
    assert configured.directory == Path(settings.report_storage_dir).resolve()


def test_get_report_storage_returns_a_layer_over_the_configured_directory() -> None:
    """One factory, used where a request-scoped layer has no directory of its own."""
    assert get_report_storage().directory == ReportStorage().directory


def test_the_directory_is_created_on_first_write(storage: ReportStorage) -> None:
    """Importing the module must never write to disk; writing must."""
    assert not storage.directory.exists()

    storage.write(filename="a.pdf", payload=PAYLOAD)

    assert storage.directory.is_dir()


def test_ensuring_the_directory_twice_is_harmless(storage: ReportStorage) -> None:
    """A second request must not fail because the directory already exists."""
    first = storage.ensure_directory()

    assert storage.ensure_directory() == first


# ---------------------------------------------------------------------------
# writing
# ---------------------------------------------------------------------------


def test_a_write_reports_where_the_bytes_landed(storage: ReportStorage) -> None:
    """The size is recorded on the metadata row, so it is returned here."""
    artifact = storage.write(filename="report.pdf", payload=PAYLOAD)

    assert isinstance(artifact, StoredArtifact)
    assert artifact.path == storage.directory / "report.pdf"
    assert artifact.size_bytes == len(PAYLOAD)
    assert artifact.path.read_bytes() == PAYLOAD


def test_a_write_leaves_no_temporary_file_behind(storage: ReportStorage) -> None:
    """A failed or finished write must not accumulate ``.tmp`` files."""
    storage.write(filename="report.pdf", payload=PAYLOAD)

    names = sorted(entry.name for entry in storage.directory.iterdir())

    assert names == ["report.pdf"]


def test_a_write_replaces_an_existing_artifact_atomically(
    storage: ReportStorage,
) -> None:
    """The second write is the one a reader sees, whole."""
    storage.write(filename="report.pdf", payload=b"first")
    storage.write(filename="report.pdf", payload=b"second")

    assert (storage.directory / "report.pdf").read_bytes() == b"second"


def test_a_write_uses_only_the_final_component_of_a_name(
    storage: ReportStorage,
) -> None:
    """A caller-supplied name is data, and data must not name a directory."""
    outside = storage.directory.parent / "escaped.pdf"

    storage.write(filename="../../escaped.pdf", payload=PAYLOAD)

    assert not outside.exists()
    assert (storage.directory / "escaped.pdf").read_bytes() == PAYLOAD


def test_a_directory_that_cannot_be_created_is_a_generation_failure(
    tmp_path: Path,
) -> None:
    """A path that is a file, not a directory, fails with a safe sentence."""
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"i am a file")
    storage = ReportStorage(str(blocker))

    with pytest.raises(ReportGenerationError) as caught:
        storage.write(filename="report.pdf", payload=PAYLOAD)

    message = str(caught.value)
    assert "storage directory" in message or "could not be written" in message
    assert str(tmp_path) not in message
    assert "Traceback" not in message


# ---------------------------------------------------------------------------
# reading
# ---------------------------------------------------------------------------


def test_a_stored_name_resolves_inside_the_directory(storage: ReportStorage) -> None:
    """A bare file name from a metadata row resolves against the directory."""
    storage.write(filename="report.pdf", payload=PAYLOAD)

    resolved = storage.artifact_path("report.pdf")

    assert resolved == storage.directory / "report.pdf"
    assert storage.read("report.pdf") == PAYLOAD


def test_a_missing_artifact_is_reported_as_missing_not_as_an_error(
    storage: ReportStorage,
) -> None:
    """A row whose file was removed by hand is a 404, not a 500."""
    storage.ensure_directory()

    with pytest.raises(ReportArtifactMissing) as caught:
        storage.artifact_path("absent.pdf")

    assert storage.exists("absent.pdf") is False
    assert "not available" in str(caught.value)


def test_an_empty_stored_location_is_not_a_location(storage: ReportStorage) -> None:
    """A row interrupted before its name was chosen can never be served."""
    storage.write(filename="report.pdf", payload=PAYLOAD)

    assert storage.exists("") is False


def test_a_stored_path_outside_the_directory_is_refused(storage: ReportStorage) -> None:
    """A database value must never make the process open an arbitrary file.

    The value is a real, readable file, so the only thing that refuses it is the
    containment check rather than a missing-file accident.
    """
    storage.ensure_directory()
    outside = storage.directory.parent / "secret.txt"
    outside.write_bytes(b"not a report")

    with pytest.raises(ReportArtifactMissing):
        storage.artifact_path(str(outside))
    with pytest.raises(ReportArtifactMissing):
        storage.artifact_path("../secret.txt")

    assert storage.exists(str(outside)) is False


def test_a_containment_refusal_names_no_path(storage: ReportStorage) -> None:
    """The refusal says the artifact is unavailable, not where it lives (M13.30)."""
    storage.ensure_directory()
    outside = storage.directory.parent / "secret.txt"
    outside.write_bytes(b"not a report")

    with pytest.raises(ReportArtifactMissing) as caught:
        storage.read(str(outside))

    message = str(caught.value)
    assert str(storage.directory) not in message
    assert "secret.txt" not in message


def test_a_directory_is_not_an_artifact(storage: ReportStorage) -> None:
    """Only a file can be served, even when the name resolves inside the layer."""
    storage.ensure_directory()
    (storage.directory / "nested").mkdir()

    assert storage.exists("nested") is False


# ---------------------------------------------------------------------------
# deleting
# ---------------------------------------------------------------------------


def test_deleting_an_artifact_removes_it_and_says_so(storage: ReportStorage) -> None:
    """Cleanup after a failed generation needs to know whether it removed a file."""
    storage.write(filename="report.pdf", payload=PAYLOAD)

    assert storage.delete("report.pdf") is True
    assert storage.exists("report.pdf") is False


def test_deleting_something_that_is_not_there_is_not_an_error(
    storage: ReportStorage,
) -> None:
    """Cleanup runs on the way out of a failure, so it must not raise."""
    storage.ensure_directory()

    assert storage.delete("absent.pdf") is False


def test_deleting_cannot_be_used_to_remove_a_file_outside_the_directory(
    storage: ReportStorage,
) -> None:
    """The containment check applies to deletion exactly as it does to reading."""
    storage.ensure_directory()
    outside = storage.directory.parent / "secret.txt"
    outside.write_bytes(b"not a report")

    assert storage.delete(str(outside)) is False
    assert outside.exists() is True
