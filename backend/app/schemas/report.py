"""Wire schemas for stored report metadata and report generation (M13.20/M17).

The ``reports`` table describes a report — its name, type, format, the period it
covers and when it was produced — and records where the file lives. Every model
here exposes the *metadata* and deliberately not the location.

``file_path`` is therefore absent from every model. It is an internal filesystem
location, and M13.30 forbids exposing one: a client has no use for the server's
absolute path, and publishing it would leak the deployment's layout. The choice is
structural rather than a filter applied at the last moment, so no code path can
forget it.

**What M17 added to the view, and why.** Three facts a *generated* report has that
M13's hand-written rows never carried: the ``status`` of generation, the
artifact's ``file_size``, and the half-open ``period`` the report covers. A client
that cannot see the period cannot tell two daily reports apart, and a client that
cannot see the status would offer a download for a file that was never written.
``downloadable`` states that answer directly, computed from the store, so a UI
never has to infer it from a status it may not understand.

**Nothing here is optional-by-guessing.** Fields a pre-M17 row genuinely cannot
answer are ``None`` rather than a plausible default, and the model says so: an
unknown period is not the epoch, and an unknown size is not zero.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from app.schemas.alert import to_iso_timestamp

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.models.report import Report


def _epoch(value: datetime | None) -> float | None:
    """Return a stored naive-UTC datetime as epoch seconds, or ``None``.

    Rows store naive UTC, so the zone is attached rather than assumed: reading a
    naive value in the server's local zone would make the same row report two
    different instants on two machines (M13.26). A ``None`` stays ``None`` --
    an unrecorded instant is not the epoch.
    """
    if not isinstance(value, datetime):
        return None
    aware = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return aware.timestamp()


class ReportView(BaseModel):
    """Serializable snapshot of one stored report's metadata (M13.20/M17.9)."""

    report_id: int
    name: str
    report_type: str = Field(
        default="", description="Report category: daily, weekly or custom"
    )
    format: str = Field(default="", description="Stored output format: CSV or PDF")
    generated_by: int | None = Field(
        default=None, description="User id that produced it, when recorded"
    )
    generated_at: str | None = Field(default=None, description="ISO-8601 UTC")
    generated_at_epoch: float | None = Field(
        default=None, description="The same instant in epoch seconds (M13.26)"
    )
    period_start: str | None = Field(
        default=None,
        description="Inclusive lower bound of the covered period, ISO-8601 UTC",
    )
    period_end: str | None = Field(
        default=None,
        description="Exclusive upper bound of the covered period, ISO-8601 UTC",
    )
    period_start_epoch: float | None = Field(
        default=None, description="The inclusive bound in epoch seconds"
    )
    period_end_epoch: float | None = Field(
        default=None, description="The exclusive bound in epoch seconds"
    )
    status: str = Field(
        default="completed",
        description="Generation state: generating, completed or failed",
    )
    file_size: int | None = Field(
        default=None, description="Artifact size in bytes, once written"
    )
    error: str | None = Field(
        default=None, description="Safe sentence explaining a failed generation"
    )
    downloadable: bool = Field(
        default=False,
        description="Whether the artifact is present and can be downloaded",
    )

    @classmethod
    def from_record(
        cls, record: "Report", *, downloadable: bool | None = None
    ) -> "ReportView":
        """Project a stored report row onto this model.

        The file location is not read here, so it cannot leak through this model
        even by accident.

        Args:
            record: The stored row.
            downloadable: Whether the artifact can be served, as determined by the
                storage layer. Passed in rather than derived here, because
                "does this file exist?" is not a question a wire model can answer
                and a model that guessed from ``status`` alone would be wrong for
                a file removed after the fact. ``None`` means the caller did not
                ask, and the field reports ``False`` -- the honest answer for a
                report nobody has checked.
        """
        return cls(
            report_id=int(record.id),
            name=str(record.name),
            report_type=str(record.report_type),
            format=str(record.format),
            generated_by=record.generated_by,
            generated_at=to_iso_timestamp(record.generated_at),
            generated_at_epoch=_epoch(record.generated_at),
            period_start=to_iso_timestamp(record.period_start),
            period_end=to_iso_timestamp(record.period_end),
            period_start_epoch=_epoch(record.period_start),
            period_end_epoch=_epoch(record.period_end),
            status=str(record.status),
            file_size=record.file_size,
            error=record.error,
            downloadable=bool(downloadable),
        )


class ReportListData(BaseModel):
    """Payload of the report-collection endpoint (M13.20/M13.24)."""

    count: int = 0
    total: int = 0
    limit: int = 100
    offset: int = 0
    has_more: bool = False
    reports: list[ReportView] = Field(default_factory=list)


class ReportGenerationRequest(BaseModel):
    """Body of ``POST /api/v1/reports/generate`` (M17.4).

    Every field is optional, and the defaults are the layer's own: a request with
    an empty body produces the previous completed UTC day as a PDF, which is what
    "generate a report" means when nobody says otherwise.

    The values are declared as plain strings rather than as an enum so the
    *service* owns the vocabulary and answers with the documented ``400`` naming
    the offending field, exactly as it does for a bad timestamp. An enum here
    would answer ``422`` for a bad format and ``400`` for a bad date, which is two
    shapes for one kind of mistake.
    """

    report_type: str | None = Field(
        default=None,
        description="daily, weekly or custom. Defaults to daily.",
        examples=["daily", "weekly", "custom"],
    )
    format: str | None = Field(
        default=None,
        description="CSV or PDF. Defaults to PDF.",
        examples=["PDF", "CSV"],
    )
    title: str | None = Field(
        default=None,
        description=(
            "Optional title. Defaults to a name derived from the period, so two "
            "daily reports cannot share one."
        ),
    )
    generated_by: int | None = Field(
        default=None, description="Optional user id to record against the report"
    )
    since: str | None = Field(
        default=None,
        description=(
            "Inclusive lower bound, ISO-8601 UTC. Required by a custom report and "
            "refused for a preset, which derives its period from the UTC calendar."
        ),
        examples=["2026-10-01T00:00:00+00:00"],
    )
    until: str | None = Field(
        default=None,
        description="Exclusive upper bound, ISO-8601 UTC. Required by a custom report.",
        examples=["2026-10-02T00:00:00+00:00"],
    )


class ReportMetricView(BaseModel):
    """One headline figure from a generated report (M17.3).

    Returned by the generation endpoint so a client can show what a report *says*
    -- its period and its summary figures -- without downloading the file it just
    asked for.
    """

    label: str
    value: str


class GeneratedReportData(BaseModel):
    """Payload of a successful generation (M17.12).

    The stored metadata, plus the summary block the report itself opens with. The
    two come from the same assembly, so the summary a client shows here and the
    summary printed inside the PDF cannot disagree.
    """

    report: ReportView
    summary: list[ReportMetricView] = Field(default_factory=list)


__all__ = [
    "GeneratedReportData",
    "ReportGenerationRequest",
    "ReportListData",
    "ReportMetricView",
    "ReportView",
]
