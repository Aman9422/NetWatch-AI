"""Turning a report request into a validated period and format (M17.4-M17.6).

A report request arrives as four loose values -- a preset name, a format, an
optional pair of bounds and a title -- and this module is the only place that
decides which combinations of them are answerable. Everything downstream
receives a :class:`ReportRequest` whose fields are already canonical, so no later
stage has to ask "was this validated?".

**Refusal, never adjustment.** A request this module cannot honour is refused
with a sentence naming the field, never quietly reinterpreted. A daily report is
*the previous completed UTC day*, so a caller who also sends ``since`` and
``until`` has asked two contradictory things and is told so rather than having one
of them silently dropped. M17.6's whole point is that the period a report covers
is explicit; guessing which of two periods the caller meant would erase that.

**Bounds follow M13.26.** ``since`` is inclusive, ``until`` is exclusive, and both
arrive as ISO-8601 UTC strings. The parse happens here, at the boundary, so the
period model downstream reasons in epoch seconds only.

The ISO parsing is restated from :mod:`app.api.common.validation` rather than
imported from it, for the reason :mod:`app.analytics.window` restates its own
conversion: the reports layer must not depend on the API layer, because the API
layer's routers depend on the reports layer. A six-line restatement is cheaper
than a dependency cycle, and a test asserts the two agree.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.reports.errors import ReportRequestError
from app.reports.period import (
    CUSTOM,
    DAILY,
    REPORT_TYPES,
    ReportPeriod,
    resolve_custom,
    resolve_daily,
    resolve_weekly,
)

#: The output formats a report may be generated in, canonicalised. Upper case
#: because that is what the ``reports.format`` column already stores and what
#: M13.20's filter folds to, so a stored row and a request name the same thing.
SUPPORTED_FORMATS: tuple[str, ...] = ("CSV", "PDF")

#: The format a request gets when it names none. PDF, because the default reader
#: of a report is a person.
DEFAULT_FORMAT = "PDF"

#: The preset a request gets when it names none. Daily, because it is the shortest
#: period the layer offers and therefore the cheapest question to answer by
#: accident.
DEFAULT_REPORT_TYPE = DAILY


def normalize_format(value: str | None, *, field_name: str = "format") -> str:
    """Return the canonical output format, or raise for an unusable one.

    Case is folded, because ``pdf`` and ``PDF`` are the same format to every
    person, but an unknown value is refused rather than defaulted: generating the
    wrong format for a caller who asked for ``DOCX`` would waste the work and
    hide the mistake.

    Raises:
        ReportRequestError: If ``value`` is present and is not a supported format.
    """
    if value is None:
        return DEFAULT_FORMAT
    text = str(value).strip()
    if not text:
        raise ReportRequestError(
            f"{field_name} must not be empty", field=field_name
        )
    candidate = text.upper()
    if candidate not in SUPPORTED_FORMATS:
        allowed = ", ".join(SUPPORTED_FORMATS)
        raise ReportRequestError(
            f"'{value}' is not a supported format (expected one of: {allowed})",
            field=field_name,
        )
    return candidate


def normalize_report_type(value: str | None, *, field_name: str = "report_type") -> str:
    """Return the canonical report type, or raise for an unusable one.

    Raises:
        ReportRequestError: If ``value`` is present and is not one of
            :data:`~app.reports.period.REPORT_TYPES`.
    """
    if value is None:
        return DEFAULT_REPORT_TYPE
    text = str(value).strip()
    if not text:
        raise ReportRequestError(
            f"{field_name} must not be empty", field=field_name
        )
    candidate = text.lower()
    if candidate not in REPORT_TYPES:
        allowed = ", ".join(REPORT_TYPES)
        raise ReportRequestError(
            f"'{value}' is not a supported report type (expected one of: {allowed})",
            field=field_name,
        )
    return candidate


def parse_instant(value: str | None, field_name: str) -> float | None:
    """Parse an ISO-8601 instant into epoch seconds, reading a naive value as UTC.

    Args:
        value: The raw value, or ``None`` when it was not sent.
        field_name: The request field, echoed in a refusal.

    Returns:
        Epoch seconds, or ``None`` when ``value`` was not sent.

    Raises:
        ReportRequestError: If ``value`` is present but blank or not ISO-8601. A
            typo must fail loudly: silently shifting a report's period to another
            day would produce a file that is wrong in a way nobody would notice.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        raise ReportRequestError(f"{field_name} must not be empty", field=field_name)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReportRequestError(
            f"'{value}' is not a valid ISO-8601 timestamp for {field_name}",
            field=field_name,
        ) from exc
    if parsed.tzinfo is None:
        # A naive value is read as UTC rather than as the server's local time,
        # which is the only reading under which the same request means the same
        # thing on two machines (M13.26).
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).timestamp()


@dataclass(frozen=True)
class ReportRequest:
    """A validated, canonical report request (M17.4).

    Every field is already resolved: the type and the format are canonical
    members of their vocabularies, the bounds are epoch seconds or ``None``, and
    the instant the request was made at is pinned rather than read from the clock
    by whoever needs it.

    Attributes:
        report_type: ``daily``, ``weekly`` or ``custom``.
        output_format: ``CSV`` or ``PDF``.
        title: A caller-supplied title, or ``None`` for the derived one.
        generated_by: The user the report is recorded against, or ``None``.
        since: Inclusive lower bound in epoch seconds, only for ``custom``.
        until: Exclusive upper bound in epoch seconds, only for ``custom``.
        now: The instant the request was made at. Passed in rather than read from
            the clock so a preset's period, the report's own ``generated_at`` and
            a test's expectation are all the same instant.
    """

    report_type: str = DEFAULT_REPORT_TYPE
    output_format: str = DEFAULT_FORMAT
    title: str | None = None
    generated_by: int | None = None
    since: float | None = None
    until: float | None = None
    now: float = field(default_factory=time.time)


def build_request(
    *,
    report_type: str | None = None,
    output_format: str | None = None,
    title: str | None = None,
    generated_by: int | None = None,
    since: str | None = None,
    until: str | None = None,
    now: float | None = None,
) -> ReportRequest:
    """Validate the loose values a route received into one canonical request.

    Args:
        report_type: The requested preset, case-insensitive, or ``None``.
        output_format: The requested format, case-insensitive, or ``None``.
        title: An optional title. A blank one is treated as absent, because a
            report with an empty title would be unnamed rather than default-named.
        generated_by: An optional user id.
        since: The inclusive lower bound as an ISO-8601 string, or ``None``.
        until: The exclusive upper bound as an ISO-8601 string, or ``None``.
        now: The instant to treat as "now", or ``None`` for the wall clock.

    Returns:
        The validated request.

    Raises:
        ReportRequestError: If any value cannot be honoured.
    """
    resolved_type = normalize_report_type(report_type)
    cleaned_title = (title or "").strip() or None
    return ReportRequest(
        report_type=resolved_type,
        output_format=normalize_format(output_format),
        title=cleaned_title,
        generated_by=None if generated_by is None else int(generated_by),
        since=parse_instant(since, "since"),
        until=parse_instant(until, "until"),
        now=time.time() if now is None else float(now),
    )


def resolve_period(request: ReportRequest) -> ReportPeriod:
    """Return the bounded period a request asks about (M17.4-M17.6).

    A preset derives its bounds from the UTC calendar -- the previous completed
    day, or the previous completed Monday-to-Sunday week -- so it takes no
    bounds. A custom report takes both, and a half-supplied one is refused:
    defaulting the missing half would answer a question nobody asked, and the
    period a report covers is the one fact a reader must be able to trust.

    Args:
        request: The validated request.

    Returns:
        The resolved, bounded, half-open period.

    Raises:
        ReportRequestError: If a preset was given bounds, or a custom period is
            half-specified, inverted, empty or longer than the analytics layer's
            own ceiling.
    """
    if request.report_type == CUSTOM:
        if request.since is None or request.until is None:
            raise ReportRequestError(
                "a custom report needs both since and until",
                field="period",
            )
        try:
            return resolve_custom(since=request.since, until=request.until)
        except ValueError as exc:
            raise ReportRequestError(str(exc), field="period") from exc

    if request.since is not None or request.until is not None:
        raise ReportRequestError(
            f"a {request.report_type} report derives its period from the UTC "
            "calendar, so since and until cannot be supplied",
            field="period",
        )
    if request.report_type == DAILY:
        return resolve_daily(now=request.now)
    return resolve_weekly(now=request.now)


__all__ = [
    "DEFAULT_FORMAT",
    "DEFAULT_REPORT_TYPE",
    "SUPPORTED_FORMATS",
    "ReportRequest",
    "build_request",
    "normalize_format",
    "normalize_report_type",
    "parse_instant",
    "resolve_period",
]
