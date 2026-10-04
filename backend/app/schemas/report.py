"""Read-only wire schemas for stored report metadata (M13.20).

The ``reports`` table describes a report — its name, type, format and when it was
produced — and records where the file lives. M13.20 exposes the *metadata* and
deliberately not the location.

``file_path`` is therefore absent from every model here. It is an internal
filesystem location, and M13.30 forbids exposing one: a client has no use for the
server's absolute path, and publishing it would leak the deployment's layout. The
choice is structural rather than a filter applied at the last moment, so no code
path can forget it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from app.schemas.alert import to_iso_timestamp

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.models.report import Report


class ReportView(BaseModel):
    """Serializable snapshot of one stored report's metadata (M13.20)."""

    report_id: int
    name: str
    report_type: str = Field(
        default="", description="Report category, e.g. daily, weekly, custom"
    )
    format: str = Field(default="", description="Stored output format")
    generated_by: int | None = Field(
        default=None, description="User id that produced it, when recorded"
    )
    generated_at: str | None = Field(default=None, description="ISO-8601 UTC")
    generated_at_epoch: float | None = Field(
        default=None, description="The same instant in epoch seconds (M13.26)"
    )

    @classmethod
    def from_record(cls, record: "Report") -> "ReportView":
        """Project a stored report row onto this model.

        The file location is not read here, so it cannot leak through this model
        even by accident.
        """
        generated = record.generated_at
        epoch: float | None = None
        if isinstance(generated, datetime):
            # Rows store naive UTC, so the zone is attached rather than assumed:
            # reading a naive value in the server's local zone would make the
            # same row report two different instants on two machines (M13.26).
            aware = (
                generated
                if generated.tzinfo is not None
                else generated.replace(tzinfo=timezone.utc)
            )
            epoch = aware.timestamp()
        return cls(
            report_id=int(record.id),
            name=str(record.name),
            report_type=str(record.report_type),
            format=str(record.format),
            generated_by=record.generated_by,
            generated_at=to_iso_timestamp(generated),
            generated_at_epoch=epoch,
        )


class ReportListData(BaseModel):
    """Payload of the report-collection endpoint (M13.20/M13.24)."""

    count: int = 0
    total: int = 0
    limit: int = 100
    offset: int = 0
    has_more: bool = False
    reports: list[ReportView] = Field(default_factory=list)


__all__ = ["ReportListData", "ReportView"]
