"""The failures the reporting layer raises (M17.14).

Three failure kinds, kept apart because they need three different answers:

:class:`ReportRequestError`
    The caller asked for something that cannot be honoured -- an unsupported
    report type, an unsupported format, a period that is inverted, empty or too
    long. Nothing is generated and nothing is stored, so this maps to a ``400``.
:class:`ReportGenerationError`
    Generation was attempted and did not finish: the renderer failed, the storage
    directory could not be written, disk space ran out, the database write failed.
    The message names what failed in a sentence an operator can act on, and it
    carries **no** traceback, path or SQL text (M13.30/M17.14).
:class:`ReportArtifactMissing`
    A stored report exists but its artifact does not: generation failed, or the
    file was deleted from the storage directory after the fact. The metadata is
    intact, so this maps to a ``404`` rather than to a server error.

Every message is a sentence a local operator can read. None of them names a
table, a column, a filesystem path, a stack frame or a driver exception -- the
real cause is logged, beside a report id, and never returned (M17.14).
"""

from __future__ import annotations


class ReportError(RuntimeError):
    """Base class for every failure the reporting layer raises."""

    def __init__(self, message: str, *, field: str = "request") -> None:
        """Store the safe sentence and the request field it concerns.

        Args:
            message: A sentence safe to show an operator. The real cause belongs
                in the log, not here.
            field: Which request field the failure concerns, so a route can put
                it in the standard error envelope's ``errors`` list.
        """
        super().__init__(message)
        self.message = str(message)
        self.field = str(field)


class ReportRequestError(ReportError):
    """A report request that cannot be honoured (400)."""


class ReportGenerationError(ReportError):
    """Generation was attempted and failed (500)."""

    def __init__(self, message: str, *, field: str = "report_generation") -> None:
        super().__init__(message, field=field)


class ReportArtifactMissing(ReportError):
    """A stored report whose artifact is not available (404)."""

    def __init__(self, message: str, *, field: str = "report_id") -> None:
        super().__init__(message, field=field)


__all__ = [
    "ReportArtifactMissing",
    "ReportError",
    "ReportGenerationError",
    "ReportRequestError",
]
