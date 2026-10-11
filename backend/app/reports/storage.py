"""Where a generated report's bytes live on disk (M17.9).

One directory, one naming rule, one write path. Everything that touches the
filesystem is here, so "which paths can the reporting layer touch?" has a single
answer that a reviewer can read in one file.

**One directory, configurable.** Artifacts go in ``settings.report_storage_dir``.
A relative value is resolved against the process working directory -- the same
directory the default ``sqlite:///./netwatch.db`` already assumes -- so the
default configuration needs no absolute path and a deployment can point the
directory at a mounted volume by setting one variable. The directory is created on
first use rather than at import: importing a module must never write to disk.

**One naming rule, and it is collision-safe.** A report's file name carries its
stored id, its period and its format::

    netwatch-report-000123-2026-10-09-daily.csv

The id is what makes the name unique. Two daily reports for the same day --
generated twice, or generated with different formats -- get different ids and
therefore different names, so a second generation can never overwrite the first
one's file. The period and format are in the name for a human browsing the
directory, and the id is what actually disambiguates.

**Writes are atomic.** Bytes go to a temporary file in the *same* directory and are
then moved onto the final name with :func:`os.replace`, which is atomic on both
POSIX and Windows. A reader therefore never sees a half-written artifact: it is
either the previous file or the complete new one. A failure removes the temporary
file, so a failed generation leaves no debris behind and no directory slowly
accumulating ``.tmp`` files.

**Downloads are confined.** :meth:`ReportStorage.artifact_path` returns a path only
when it resolves *inside* the storage directory. A stored ``file_path`` is data read
from a database row, and a database value must never be able to make the process
open an arbitrary file: the containment check is what stops it, and it is applied on
every read rather than trusted once at write time.

**Failures are sentences.** A directory that cannot be created, a file that cannot
be written, an artifact that is not there -- each raises
:class:`~app.reports.errors.ReportGenerationError` or
:class:`~app.reports.errors.ReportArtifactMissing` with a message that names no
path (M13.30/M17.14). The real exception is logged beside the report's id.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.config.settings import settings
from app.reports.errors import ReportArtifactMissing, ReportGenerationError

logger = logging.getLogger(__name__)

#: Prefix every artifact name carries, so the storage directory's contents are
#: recognisable at a glance and cannot be confused with another tool's files.
FILENAME_PREFIX = "netwatch-report"

#: Characters removed from a period label before it enters a file name. A period
#: label is built from ISO-8601 instants, so this is defence in depth rather than
#: a routine substitution: it guarantees a label can never contribute a path
#: separator, a drive letter or a wildcard to a name.
_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9]+")

#: The stored format -> the file extension it is written with. The extension is
#: derived here rather than supplied by a caller, so a request cannot choose one.
FORMAT_EXTENSIONS: dict[str, str] = {
    "CSV": "csv",
    "PDF": "pdf",
}


def extension_for(output_format: str) -> str:
    """Return the file extension for a format, defaulting to the format's lower name.

    An unrecognised format is not refused here: format validation belongs to the
    service, which owns the request. This function is total so the storage layer
    never raises for a reason the service has not already reported.
    """
    return FORMAT_EXTENSIONS.get(str(output_format).upper(), str(output_format).lower())


def safe_label(text: str) -> str:
    """Reduce a period label to characters safe in a file name.

    Runs of anything outside ``[A-Za-z0-9]`` collapse to a single ``-`` and the
    result is trimmed, so ``2026-09-28 to 2026-10-04`` becomes
    ``2026-09-28-to-2026-10-04`` and a custom period's two ISO timestamps become
    one readable token. An input that reduces to nothing yields ``period`` rather
    than an empty segment, which would produce a name with two adjacent separators.
    """
    collapsed = _UNSAFE_NAME_CHARS.sub("-", str(text)).strip("-")
    return collapsed or "period"


def build_filename(*, report_id: int, label: str, output_format: str) -> str:
    """Return the file name one report's artifact is written under (M17.9).

    The id is zero-padded to six digits because directory listings sort
    lexicographically: without padding, report 10 would sort before report 9. Six
    digits holds a million reports, which is well past what a local SQLite
    deployment generates, and a seventh digit would still sort correctly.
    """
    return (
        f"{FILENAME_PREFIX}-{int(report_id):06d}-"
        f"{safe_label(label)}.{extension_for(output_format)}"
    )


@dataclass(frozen=True)
class StoredArtifact:
    """The result of writing one artifact to disk.

    Attributes:
        path: Where the bytes were written, absolute.
        size_bytes: The file's size, recorded on the metadata row so a client can
            report it without a second filesystem call.
    """

    path: Path
    size_bytes: int


class ReportStorage:
    """Reads and writes report artifacts inside one directory (M17.9).

    The directory is resolved once, at construction, from the configured value. It
    is deliberately *not* created at construction either: a service may be built
    to answer a listing request that never writes anything, and creating a
    directory to answer a read is a side effect nobody asked for.
    """

    def __init__(self, directory: str | os.PathLike[str] | None = None) -> None:
        """Bind the storage to a directory, defaulting to the configured one.

        Args:
            directory: An explicit directory, used by tests to work inside a
                temporary path. ``None`` means ``settings.report_storage_dir``.
        """
        raw = settings.report_storage_dir if directory is None else str(directory)
        self._directory = Path(raw).expanduser()
        if not self._directory.is_absolute():
            self._directory = (Path.cwd() / self._directory).resolve()
        else:
            self._directory = self._directory.resolve()

    @property
    def directory(self) -> Path:
        """Return the absolute storage directory. Never exposed through the API."""
        return self._directory

    def filename_for(
        self, *, report_id: int, label: str, output_format: str
    ) -> str:
        """Return the file name for a report, without touching the filesystem."""
        return build_filename(
            report_id=report_id, label=label, output_format=output_format
        )

    def ensure_directory(self) -> Path:
        """Create the storage directory if it does not exist, and return it.

        Raises:
            ReportGenerationError: If the directory cannot be created. The
                message names the situation and not the path (M13.30).
        """
        try:
            self._directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.exception(
                "Report storage directory could not be created at %s", self._directory
            )
            raise ReportGenerationError(
                "The report storage directory could not be created"
            ) from exc
        return self._directory

    def write(self, *, filename: str, payload: bytes) -> StoredArtifact:
        """Write one artifact atomically and return where it landed (M17.9).

        Args:
            filename: The name returned by :meth:`filename_for`. Only its final
                component is used, so a name that somehow carried a separator
                cannot escape the directory.
            payload: The rendered file's bytes.

        Returns:
            The written path and its size.

        Raises:
            ReportGenerationError: If the write fails. Any partial file has
                already been removed, so a failed generation leaves no artifact.
        """
        directory = self.ensure_directory()
        # ``Path.name`` on the final component: a caller-supplied name is data,
        # and data must not be able to name a directory.
        target = directory / Path(filename).name
        temporary: str | None = None
        try:
            handle = tempfile.NamedTemporaryFile(
                mode="wb",
                dir=directory,
                prefix=f".{target.name}.",
                suffix=".tmp",
                delete=False,
            )
            temporary = handle.name
            try:
                with handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            except Exception:
                # Close without a second flush, then drop the partial file.
                raise
            os.replace(temporary, target)
            temporary = None
        except OSError as exc:
            logger.exception("Report artifact %s could not be written", filename)
            raise ReportGenerationError(
                "The report file could not be written to the storage directory"
            ) from exc
        finally:
            if temporary is not None:
                self._discard(temporary)

        try:
            size = target.stat().st_size
        except OSError as exc:
            logger.exception("Report artifact %s could not be measured", filename)
            raise ReportGenerationError(
                "The report file was written but could not be read back"
            ) from exc

        logger.info("Report artifact %s written (%d byte(s))", target.name, size)
        return StoredArtifact(path=target, size_bytes=size)

    def artifact_path(self, stored_path: str) -> Path:
        """Resolve a stored ``file_path`` to an existing file inside the directory.

        Args:
            stored_path: The value from the metadata row. A bare file name is
                resolved against the storage directory; an absolute or relative
                path is resolved as given.

        Returns:
            The absolute path of the artifact.

        Raises:
            ReportArtifactMissing: If the stored location is outside the storage
                directory, does not exist, or is not a file. All three are the same
                answer to a client -- the artifact is not available -- and none of
                them names a path (M13.30).
        """
        candidate = Path(stored_path)
        if not candidate.is_absolute():
            candidate = self._directory / candidate
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            logger.info("Report artifact %s is not present", stored_path)
            raise ReportArtifactMissing(
                "The report file is not available in the storage directory"
            ) from exc

        if not self._is_inside(resolved):
            # A stored path pointing outside the directory is either a
            # misconfiguration or an attempt to read an arbitrary file. It is
            # logged loudly and never honoured.
            logger.warning(
                "Refusing to serve a report artifact outside the storage directory"
            )
            raise ReportArtifactMissing(
                "The report file is not available in the storage directory"
            )
        if not resolved.is_file():
            raise ReportArtifactMissing(
                "The report file is not available in the storage directory"
            )
        return resolved

    def read(self, stored_path: str) -> bytes:
        """Return an artifact's bytes, or raise :class:`ReportArtifactMissing`.

        The read goes through :meth:`artifact_path`, so containment is enforced on
        the download path exactly as it is on the resolve path.
        """
        resolved = self.artifact_path(stored_path)
        try:
            return resolved.read_bytes()
        except OSError as exc:
            logger.exception("Report artifact %s could not be read", resolved.name)
            raise ReportArtifactMissing(
                "The report file could not be read from the storage directory"
            ) from exc

    def exists(self, stored_path: str) -> bool:
        """Return True when a stored location resolves to a readable artifact."""
        try:
            self.artifact_path(stored_path)
        except ReportArtifactMissing:
            return False
        return True

    def delete(self, stored_path: str) -> bool:
        """Remove an artifact, returning whether a file was removed.

        Used when generation fails after a row was written: the row is marked
        failed and any partial file is dropped, so the metadata never claims an
        artifact that is not there.
        """
        try:
            resolved = self.artifact_path(stored_path)
        except ReportArtifactMissing:
            return False
        try:
            resolved.unlink()
        except OSError:
            logger.exception("Report artifact %s could not be removed", resolved.name)
            return False
        return True

    def _is_inside(self, resolved: Path) -> bool:
        """Return True when ``resolved`` lies inside the storage directory."""
        try:
            return resolved.is_relative_to(self._directory)
        except ValueError:  # pragma: no cover - defensive; is_relative_to is total
            return False

    @staticmethod
    def _discard(path: str) -> None:
        """Remove a partial file, logging rather than raising on failure.

        Called from a ``finally`` block, so it must not raise: the exception that
        brought it here is the one worth reporting, and a second one raised while
        cleaning up would replace it.
        """
        try:
            os.unlink(path)
        except OSError:
            logger.debug("Partial report artifact could not be removed")


def get_report_storage() -> ReportStorage:
    """Return a storage bound to the configured directory (M13.28)."""
    return ReportStorage()


__all__ = [
    "FILENAME_PREFIX",
    "FORMAT_EXTENSIONS",
    "ReportStorage",
    "StoredArtifact",
    "build_filename",
    "extension_for",
    "get_report_storage",
    "safe_label",
]
