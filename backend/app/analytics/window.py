"""The one analytics time model: windows, buckets and their SQL twin (M16.7).

Every analytics query in M16 is answered over an explicit, bounded window, and
this module is the only place that decides what a window *is*. Four rules, all
documented rather than implied:

**Bounds follow M13.26 exactly.** A window is ``[since, until)``: ``since`` is
inclusive and ``until`` is exclusive, which is the convention M10's finding query,
M11's alert query and M13's HTTP filters already use. The bounds are UTC, and a
naive datetime is read as UTC rather than as local time
(:mod:`app.api.common.validation` does the parsing; this module only reasons
about the result).

**A window is always bounded.** ``until`` defaults to *now* and ``since``
defaults to one hour earlier (:data:`DEFAULT_WINDOW_SECONDS`). A request can never
ask for "all of history": a range longer than :data:`MAX_WINDOW_SECONDS` is
rejected rather than silently clamped, because clamping would answer a different
question than the one asked.

**Buckets are wall-clock aligned.** A bucket begins at an instant that is an
exact multiple of its size since the Unix epoch — :func:`bucket_start` — so the
same trend is comparable across requests instead of shifting with each caller's
``since``. The first and last buckets of a window are frequently *partial*: a
20-minute window with 15-minute buckets holds two whole buckets plus two edges.

**A series is bounded by construction.** :data:`MAX_BUCKETS` caps how many points
a series may hold; :func:`resolve_window` picks the smallest documented bucket
whose resulting point count fits, and refuses an explicitly requested bucket that
would not. There is no path that returns an unbounded time series.

:func:`bucket_expression` is the SQL side of :func:`bucket_start`. They are the
same rule written twice on purpose: one is applied in Python to decide which
buckets a response lists, the other inside SQLite to decide which rows fall in
them, and a test asserts they agree. Splitting them across two modules is how
that agreement would eventually be lost.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import Integer, cast, func

#: Window length used when a request names no bounds: one hour.
DEFAULT_WINDOW_SECONDS = 3600.0

#: Longest window a request may ask for: thirty days. M16 forbids an unbounded
#: scan of SQLite data, so the ceiling is a number rather than "however long the
#: table happens to be".
MAX_WINDOW_SECONDS = 30.0 * 24.0 * 3600.0

#: Most points a time series may hold. A series is a trend, not a dump: past this
#: many points the message is carried by choosing a larger bucket instead.
MAX_BUCKETS = 240

#: Safety ceiling on rows a series *statement* may return. A resolved window's
#: bucket count is already at most :data:`MAX_BUCKETS`, so this can never bite;
#: it exists so that every series query is bounded by its own ``LIMIT`` rather
#: than by reasoning about another module.
MAX_SERIES_POINTS = MAX_BUCKETS + 8

#: The bucket sizes a request may name explicitly, in seconds, smallest first.
#: They are round factors of a minute, an hour and a day so a bucket boundary is
#: also a human-readable clock boundary in UTC.
BUCKET_SIZES: tuple[int, ...] = (10, 30, 60, 300, 900, 1800, 3600, 21600, 43200, 86400)


def iso_from_epoch(epoch_seconds: float) -> str:
    """Render epoch seconds as an ISO-8601 UTC string.

    The API convention (M13.26, and :mod:`app.alerts.timestamps`) is ISO-8601
    with an explicit ``+00:00`` offset, which is what this returns.
    """
    return datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc).isoformat()


def to_utc_datetime(epoch_seconds: float) -> datetime:
    """Convert epoch seconds to the naive UTC datetime the stores persist.

    SQLite keeps a ``DateTime`` column as a UTC wall-clock value with no offset,
    so a stored row round-trips as a *naive* datetime whose wall time is UTC. The
    analytics layer filters against those columns, and this is the conversion
    every bound goes through, so a query cannot be silently shifted by the
    caller's timezone.

    It is the same conversion :mod:`app.alerts.timestamps` performs for the alert
    engine. It is restated here rather than imported so the analytics time model
    depends on nothing but its own definition — the two must agree on the
    *format*, and a test asserts they do.
    """
    return datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc).replace(
        tzinfo=None
    )


def bucket_start(epoch_seconds: float, bucket_seconds: int) -> int:
    """Return the start of the bucket containing an instant (M16.7).

    Buckets are aligned to the Unix epoch, so a boundary depends only on the
    bucket size and never on the request's ``since``. The instant is floored to a
    whole second first: every documented bucket is at least ten seconds, so a
    sub-second remainder can never move an instant across a boundary.

    Raises:
        ValueError: If ``bucket_seconds`` is not positive.
    """
    size = int(bucket_seconds)
    if size < 1:
        raise ValueError("bucket_seconds must be at least 1")
    return (math.floor(float(epoch_seconds)) // size) * size


def bucket_expression(column, bucket_seconds: int):
    """Return the SQL expression that computes :func:`bucket_start` for a column.

    SQLite stores a ``DateTime`` column as a UTC wall-clock string, so
    ``strftime('%s', column)`` yields its epoch seconds as text — verified against
    the values M7, M9 and M11 write. The cast to ``INTEGER`` happens before the
    division as well as after it: SQLAlchemy renders ``Integer / Integer`` as
    **true** division (to match Python's operator), and SQLite truncates a real
    quotient toward zero, which is a floor for the positive epoch values involved.
    The trailing multiplication scales the quotient back to a bucket start.

    Args:
        column: The ``DateTime`` column to bucket.
        bucket_seconds: Bucket size in seconds. Must be one of
            :data:`BUCKET_SIZES` for a response's listed buckets to line up with
            the rows SQLite groups.

    Raises:
        ValueError: If ``bucket_seconds`` is not positive.
    """
    size = int(bucket_seconds)
    if size < 1:
        raise ValueError("bucket_seconds must be at least 1")
    epoch = func.strftime("%s", column)
    quotient = cast(cast(epoch, Integer) / size, Integer)
    return quotient * size


def bucket_count(since: float, until: float, bucket_seconds: int) -> int:
    """Return how many buckets a window would list at ``bucket_seconds``.

    The last bucket is the one holding the last whole second inside the window:
    ``until`` is exclusive, so an ``until`` of exactly ``T`` means the last
    instant included is ``T - 1``.
    """
    first = bucket_start(since, bucket_seconds)
    last = bucket_start(math.ceil(float(until)) - 1, bucket_seconds)
    return (last - first) // int(bucket_seconds) + 1


def choose_bucket_seconds(since: float, until: float) -> int:
    """Return the smallest documented bucket whose series fits :data:`MAX_BUCKETS`.

    A short window gets fine buckets and a long one gets coarse ones, from one
    table rather than an invented rule per endpoint. The answer is total: the
    largest documented bucket spans a day, and the longest allowed window is
    thirty days, so thirty points always fit.
    """
    for size in BUCKET_SIZES:
        if bucket_count(since, until, size) <= MAX_BUCKETS:
            return size
    return BUCKET_SIZES[-1]


@dataclass(frozen=True)
class AnalyticsWindow:
    """A resolved, bounded analytics window (M16.7).

    Attributes:
        since: Inclusive lower bound, epoch seconds.
        until: Exclusive upper bound, epoch seconds.
        bucket_seconds: Bucket size, one of :data:`BUCKET_SIZES`.
        defaulted: True when the caller named no bounds and the default window
            was applied, so a response can say so rather than pretending the
            caller asked for it.
    """

    since: float
    until: float
    bucket_seconds: int
    defaulted: bool = False

    @property
    def seconds(self) -> float:
        """Return the window length in seconds."""
        return self.until - self.since

    @property
    def first_bucket(self) -> int:
        """Return the epoch second the first listed bucket begins at."""
        return bucket_start(self.since, self.bucket_seconds)

    @property
    def last_bucket(self) -> int:
        """Return the epoch second the last listed bucket begins at."""
        return bucket_start(math.ceil(self.until) - 1, self.bucket_seconds)

    @property
    def buckets(self) -> int:
        """Return how many buckets this window lists."""
        return (self.last_bucket - self.first_bucket) // self.bucket_seconds + 1

    def bucket_starts(self) -> list[int]:
        """Return every bucket start in the window, oldest first."""
        return [
            self.first_bucket + index * self.bucket_seconds
            for index in range(self.buckets)
        ]

    def iso_since(self) -> str:
        """Return the inclusive bound as an ISO-8601 UTC string."""
        return iso_from_epoch(self.since)

    def iso_until(self) -> str:
        """Return the exclusive bound as an ISO-8601 UTC string."""
        return iso_from_epoch(self.until)


def resolve_window(
    *,
    since: float | None,
    until: float | None,
    bucket_seconds: int | None,
    now: float,
) -> AnalyticsWindow:
    """Resolve request bounds and a bucket choice into one bounded window.

    Args:
        since: Inclusive lower bound in epoch seconds, or ``None`` for the
            default (one hour before ``until``).
        until: Exclusive upper bound in epoch seconds, or ``None`` for ``now``.
        bucket_seconds: An explicit bucket size, or ``None`` to choose one.
        now: The instant the default window ends at. Passed in rather than read
            from the clock so a test — and a response's own log line — can pin it.

    Returns:
        The resolved :class:`AnalyticsWindow`.

    Raises:
        ValueError: If the window is empty or inverted, longer than
            :data:`MAX_WINDOW_SECONDS`, names a bucket outside
            :data:`BUCKET_SIZES`, or names a bucket that would produce more than
            :data:`MAX_BUCKETS` points. Each of these is a request that cannot be
            honoured, so it is refused rather than silently adjusted: answering a
            narrower or wider question than the caller asked is worse than saying
            no, and the message names what was wrong.
    """
    defaulted = since is None and until is None
    upper = float(now) if until is None else float(until)
    lower = (upper - DEFAULT_WINDOW_SECONDS) if since is None else float(since)

    if lower > upper:
        raise ValueError("since must not be later than until")
    if lower == upper:
        raise ValueError("the analytics window must not be empty")

    span = upper - lower
    if span > MAX_WINDOW_SECONDS:
        raise ValueError(
            "the analytics window must not exceed "
            f"{int(MAX_WINDOW_SECONDS)} seconds"
        )

    if bucket_seconds is None:
        size = choose_bucket_seconds(lower, upper)
    else:
        size = int(bucket_seconds)
        if size not in BUCKET_SIZES:
            allowed = ", ".join(str(value) for value in BUCKET_SIZES)
            raise ValueError(
                f"'{bucket_seconds}' is not a supported bucket size "
                f"(expected one of: {allowed})"
            )
        if bucket_count(lower, upper, size) > MAX_BUCKETS:
            raise ValueError(
                f"a bucket of {size} seconds produces more than "
                f"{MAX_BUCKETS} points for this window"
            )

    return AnalyticsWindow(
        since=lower, until=upper, bucket_seconds=size, defaulted=defaulted
    )


__all__ = [
    "BUCKET_SIZES",
    "DEFAULT_WINDOW_SECONDS",
    "MAX_BUCKETS",
    "MAX_SERIES_POINTS",
    "MAX_WINDOW_SECONDS",
    "AnalyticsWindow",
    "bucket_count",
    "bucket_expression",
    "bucket_start",
    "choose_bucket_seconds",
    "iso_from_epoch",
    "resolve_window",
    "to_utc_datetime",
]
