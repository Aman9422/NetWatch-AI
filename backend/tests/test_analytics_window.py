"""Tests for the M16 analytics time model (M16.7).

The window is the one thing every analytics query depends on, so it is tested on
its own: what a request may ask for, what it gets when it asks for nothing, and
what happens when what it asks for cannot be honoured. Nothing here touches a
database — this is the arithmetic the queries are built on, and it is checked
before any query is written on top of it.
"""

from __future__ import annotations

from datetime import timezone

import pytest

from app.analytics.window import (
    BUCKET_SIZES,
    DEFAULT_WINDOW_SECONDS,
    MAX_BUCKETS,
    MAX_WINDOW_SECONDS,
    AnalyticsWindow,
    bucket_count,
    bucket_start,
    choose_bucket_seconds,
    iso_from_epoch,
    resolve_window,
    to_utc_datetime,
)

#: A fixed "now" so a default window is a constant rather than a moving target.
NOW = 1_700_000_000.0


def test_default_window_is_one_hour_ending_now() -> None:
    window = resolve_window(since=None, until=None, bucket_seconds=None, now=NOW)

    assert window.until == NOW
    assert window.since == NOW - DEFAULT_WINDOW_SECONDS
    assert window.seconds == DEFAULT_WINDOW_SECONDS
    assert window.defaulted is True


def test_named_bounds_are_kept_and_not_marked_default() -> None:
    window = resolve_window(
        since=NOW - 120.0, until=NOW, bucket_seconds=None, now=NOW
    )

    assert window.since == NOW - 120.0
    assert window.until == NOW
    assert window.defaulted is False


def test_only_until_given_leaves_since_one_hour_earlier() -> None:
    window = resolve_window(since=None, until=NOW, bucket_seconds=None, now=0.0)

    assert window.until == NOW
    assert window.since == NOW - DEFAULT_WINDOW_SECONDS
    assert window.defaulted is False


def test_named_since_without_until_ends_now() -> None:
    window = resolve_window(since=NOW - 30.0, until=None, bucket_seconds=None, now=NOW)

    assert window.until == NOW
    assert window.since == NOW - 30.0
    assert window.defaulted is False


def test_inverted_range_is_refused() -> None:
    with pytest.raises(ValueError, match="since must not be later than until"):
        resolve_window(since=NOW, until=NOW - 1.0, bucket_seconds=None, now=NOW)


def test_empty_range_is_refused() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        resolve_window(since=NOW, until=NOW, bucket_seconds=None, now=NOW)


def test_range_longer_than_the_ceiling_is_refused_rather_than_clamped() -> None:
    with pytest.raises(ValueError, match="must not exceed"):
        resolve_window(
            since=NOW - MAX_WINDOW_SECONDS - 1.0,
            until=NOW,
            bucket_seconds=None,
            now=NOW,
        )


def test_the_ceiling_itself_is_allowed() -> None:
    window = resolve_window(
        since=NOW - MAX_WINDOW_SECONDS, until=NOW, bucket_seconds=None, now=NOW
    )

    assert window.seconds == MAX_WINDOW_SECONDS


def test_unknown_bucket_size_is_refused_and_names_the_allowed_values() -> None:
    with pytest.raises(ValueError) as excinfo:
        resolve_window(since=NOW - 60.0, until=NOW, bucket_seconds=45, now=NOW)

    message = str(excinfo.value)
    assert "45" in message
    for size in BUCKET_SIZES:
        assert str(size) in message


def test_explicit_bucket_that_would_exceed_the_point_ceiling_is_refused() -> None:
    # Ten-second buckets over an hour is 361 points, past MAX_BUCKETS.
    with pytest.raises(ValueError, match="more than"):
        resolve_window(
            since=NOW - DEFAULT_WINDOW_SECONDS,
            until=NOW,
            bucket_seconds=BUCKET_SIZES[0],
            now=NOW,
        )


def test_explicit_bucket_within_the_ceiling_is_kept_verbatim() -> None:
    window = resolve_window(
        since=NOW - DEFAULT_WINDOW_SECONDS, until=NOW, bucket_seconds=60, now=NOW
    )

    assert window.bucket_seconds == 60
    assert window.buckets <= MAX_BUCKETS


def test_a_named_bucket_is_never_replaced_by_a_choice() -> None:
    """A caller who names a size gets that size, not a "better" one."""

    fine = resolve_window(since=NOW - 100.0, until=NOW, bucket_seconds=10, now=NOW)

    assert fine.bucket_seconds == 10


@pytest.mark.parametrize(
    ("span", "expected"),
    [
        (60.0, 10),
        (600.0, 10),
        (3600.0, 30),
        (24.0 * 3600.0, 900),
        (7.0 * 24.0 * 3600.0, 3600),
        (MAX_WINDOW_SECONDS, 21600),
    ],
)
def test_chosen_bucket_grows_with_the_window(span: float, expected: int) -> None:
    """Short ranges get fine buckets, long ranges coarse ones (M16.7)."""

    chosen = choose_bucket_seconds(NOW - span, NOW)

    assert chosen == expected
    assert chosen in BUCKET_SIZES


def test_a_chosen_bucket_always_keeps_the_series_bounded() -> None:
    """No window length may produce more than MAX_BUCKETS points."""

    for span in (1.0, 60.0, 3600.0, 86_400.0, 7.0 * 86_400.0, MAX_WINDOW_SECONDS):
        size = choose_bucket_seconds(NOW - span, NOW)
        assert bucket_count(NOW - span, NOW, size) <= MAX_BUCKETS


def test_bucket_count_covers_the_partial_edge_buckets() -> None:
    # A 90-second window starting 15s into a 60s bucket touches three buckets:
    # the partial one it starts in, the one it spans, and the one its last
    # included second falls in.
    since = NOW + 15.0
    assert bucket_count(since, since + 90.0, 60) == 3


def test_buckets_are_aligned_to_the_epoch_and_not_to_since() -> None:
    window = AnalyticsWindow(since=NOW + 17.0, until=NOW + 197.0, bucket_seconds=60)

    assert window.first_bucket % 60 == 0
    assert window.first_bucket <= window.since
    assert window.last_bucket % 60 == 0


def test_two_windows_sharing_a_bucket_size_share_their_boundaries() -> None:
    first = AnalyticsWindow(since=NOW + 3.0, until=NOW + 303.0, bucket_seconds=60)
    second = AnalyticsWindow(since=NOW + 50.0, until=NOW + 250.0, bucket_seconds=60)

    first_starts = set(first.bucket_starts())
    second_starts = set(second.bucket_starts())

    # Every boundary is a multiple of the size, and a boundary one window lists
    # inside the other's range is listed by both.
    assert all(start % 60 == 0 for start in first_starts | second_starts)
    assert second_starts.issubset(first_starts)


def test_bucket_starts_lists_every_bucket_once_in_order() -> None:
    aligned = NOW - (NOW % 60)  # on the bucket grid, so no partial edge bucket
    window = AnalyticsWindow(since=aligned, until=aligned + 600.0, bucket_seconds=60)

    starts = window.bucket_starts()
    assert starts == sorted(starts)
    assert len(starts) == len(set(starts)) == window.buckets == 10
    assert starts[0] == window.first_bucket
    assert starts[-1] == window.last_bucket


def test_an_unaligned_since_adds_the_partial_bucket_it_starts_in() -> None:
    # NOW sits 20 seconds into a 60-second bucket, so a ten-minute window
    # starting there touches the partial bucket it begins in plus ten whole
    # ones. The extra bucket is the documented partial edge (M16.7), not an
    # off-by-one: the listing still holds every bucket the window covers.
    window = AnalyticsWindow(since=NOW, until=NOW + 600.0, bucket_seconds=60)

    assert window.buckets == 11
    assert window.first_bucket < window.since
    assert window.last_bucket < window.until


def test_bucket_start_floors_sub_second_remainders() -> None:
    assert bucket_start(NOW + 0.9, 10) == bucket_start(NOW, 10)


def test_bucket_start_rejects_a_non_positive_size() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        bucket_start(NOW, 0)


def test_iso_from_epoch_is_utc_with_an_explicit_offset() -> None:
    rendered = iso_from_epoch(0.0)

    assert rendered.startswith("1970-01-01T00:00:00")
    assert rendered.endswith("+00:00")


def test_window_renders_its_bounds_as_iso_utc() -> None:
    window = AnalyticsWindow(since=NOW, until=NOW + 60.0, bucket_seconds=10)

    assert window.iso_since() == iso_from_epoch(NOW)
    assert window.iso_until() == iso_from_epoch(NOW + 60.0)
    assert window.iso_since().endswith("+00:00")


def test_to_utc_datetime_is_the_same_instant_read_as_naive_utc() -> None:
    converted = to_utc_datetime(NOW)

    assert converted.tzinfo is None
    assert converted.replace(tzinfo=timezone.utc).timestamp() == NOW


def test_an_explicit_window_still_reports_its_bucket_count() -> None:
    window = resolve_window(
        since=NOW - 3600.0, until=NOW, bucket_seconds=None, now=NOW
    )

    assert window.buckets <= MAX_BUCKETS
    assert len(window.bucket_starts()) == window.buckets
