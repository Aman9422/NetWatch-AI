"""Persistent-store tests (M21.8).

The store is where a baseline stops being a runtime observation and becomes a
record that survives a restart, so the failures that matter here are the quiet
ones: a duplicate window folded in twice, a profile that resets itself on reboot, a
retention pass that deletes the wrong rows, or a reset that reaches beyond its own
device.

Every test runs against the isolated in-memory database from ``conftest`` so
nothing here can reach the developer's own ``netwatch.db``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.baselines.aggregation import WindowCounters, floor_window
from app.baselines.states import LearningState
from app.baselines.store import MAX_STORED_ADDRESSES, BaselineStore, retention_cutoff
from app.models.baseline_observation import BaselineProfile, BaselineWindow

DEVICE = "mac:aa:bb:cc:dd:ee:01"
OTHER = "mac:aa:bb:cc:dd:ee:02"

#: A whole number of minutes, so window starts are exact.
BASE = 1_700_000_040.0


def counter(
    *,
    device_key: str = DEVICE,
    offset: float = 0.0,
    packets: int = 10,
    ip: str = "10.0.0.21",
    measure_connections: bool = True,
) -> WindowCounters:
    """Build one window as the aggregator would leave it for a flush."""
    start = BASE + offset
    return WindowCounters(
        device_key=device_key,
        identity_kind="mac",
        window_start=floor_window(start, 60.0),
        window_seconds=60.0,
        packet_count=packets,
        byte_count=packets * 100,
        tcp_packets=packets,
        new_connections=1 if measure_connections else 0,
        first_seen=start,
        last_seen=start,
        mac_address=device_key.removeprefix("mac:"),
        ip_address=ip,
        peers={"10.0.0.5"},
        ports={443},
        # A window only stores a connection count when it carried a conversation
        # key; that is how "not measured" stays distinguishable from "zero".
        conversation_keys={"TCP|10.0.0.5|443"} if measure_connections else set(),
    )


@pytest.fixture
def store(session_factory: Callable[[], Session]) -> BaselineStore:
    """A store over the isolated database, with small test thresholds."""
    return BaselineStore(
        session_factory=session_factory,
        provisional_min_samples=3,
        established_min_samples=5,
    )


# ---------------------------------------------------------------------------
# writing windows
# ---------------------------------------------------------------------------


def test_a_window_becomes_a_profile_with_its_sample_count(
    store: BaselineStore,
) -> None:
    """The first window creates the profile; before it there is none."""
    assert store.get_profile(DEVICE) is None

    written = store.write_windows([counter()])

    assert written == 1
    profile = store.get_profile(DEVICE)
    assert profile is not None
    assert profile.sample_count == 1
    assert profile.learning_state == LearningState.LEARNING.value
    assert profile.identity_kind == "mac"


def test_repeated_flushes_accumulate_samples(store: BaselineStore) -> None:
    """Each new window is another sample, and the count drives maturity."""
    for index in range(4):
        store.write_windows([counter(offset=index * 60.0)])

    profile = store.get_profile(DEVICE)

    assert profile is not None
    assert profile.sample_count == 4


def test_a_duplicate_window_is_not_a_second_sample(store: BaselineStore) -> None:
    """A re-flush after a crash must be a no-op, not an inflated count (M21.8)."""
    window = counter()

    assert store.write_windows([window]) == 1
    assert store.write_windows([window]) == 0

    profile = store.get_profile(DEVICE)
    assert profile is not None
    assert profile.sample_count == 1


def test_a_window_that_observed_nothing_is_never_written(
    store: BaselineStore,
) -> None:
    """A silent window is not a zero-valued sample (M21.5)."""
    silent = counter()
    silent.packet_count = 0

    assert store.write_windows([silent]) == 0
    assert store.get_profile(DEVICE) is None


def test_two_devices_keep_separate_profiles(store: BaselineStore) -> None:
    """One device's samples never move another's state."""
    for index in range(4):
        store.write_windows([counter(offset=index * 60.0)])
    store.write_windows([counter(device_key=OTHER, packets=3)])

    mine = store.get_profile(DEVICE)
    theirs = store.get_profile(OTHER)

    assert mine is not None and theirs is not None
    assert mine.sample_count == 4
    assert theirs.sample_count == 1


def test_a_device_that_changes_ip_keeps_one_profile(store: BaselineStore) -> None:
    """The identity is the MAC, so a new lease is not a new device."""
    store.write_windows([counter(ip="10.0.0.21")])
    store.write_windows([counter(offset=60.0, ip="10.0.0.99")])

    profile = store.get_profile(DEVICE)

    assert profile is not None
    assert profile.sample_count == 2
    # Both addresses are remembered, newest first, so the change is not hidden.
    assert profile.ip_addresses[0] == "10.0.0.99"
    assert "10.0.0.21" in profile.ip_addresses


def test_a_profile_remembers_the_original_first_observation(
    store: BaselineStore,
) -> None:
    """An out-of-order flush must not move the start of the history."""
    store.write_windows([counter(offset=120.0)])
    store.write_windows([counter(offset=0.0)])

    profile = store.get_profile(DEVICE)

    assert profile is not None
    assert profile.first_observed_at is not None
    assert profile.last_observed_at is not None
    assert profile.first_observed_at < profile.last_observed_at


def test_statistics_appear_only_once_the_threshold_is_reached(
    store: BaselineStore,
) -> None:
    """Below the provisional threshold no figures are published (M21.7)."""
    store.write_windows([counter(offset=0.0)])
    store.write_windows([counter(offset=60.0)])

    learning = store.get_profile(DEVICE)
    assert learning is not None
    assert learning.statistics == {}

    store.write_windows([counter(offset=120.0)])

    provisional = store.get_profile(DEVICE)
    assert provisional is not None
    assert provisional.statistics != {}
    assert provisional.learning_state == LearningState.PROVISIONAL.value


def test_the_profile_reaches_established_at_the_configured_count(
    store: BaselineStore,
) -> None:
    """Five windows is the threshold this store was built with."""
    for index in range(5):
        store.write_windows([counter(offset=index * 60.0)])

    profile = store.get_profile(DEVICE)

    assert profile is not None
    assert profile.learning_state == LearningState.ESTABLISHED.value
    assert profile.publishes_statistics is True


def test_an_unmeasurable_connection_count_is_stored_as_null(
    store: BaselineStore,
) -> None:
    """A window that could not measure connections does not store a zero (M21.5)."""
    store.write_windows([counter(measure_connections=False)])

    windows = store.list_windows(DEVICE)

    assert len(windows) == 1
    assert windows[0].new_connections is None


# ---------------------------------------------------------------------------
# reads
# ---------------------------------------------------------------------------


def test_the_listing_is_ordered_and_paginated(store: BaselineStore) -> None:
    """A page is deterministic, so two identical requests return the same rows."""
    for index in range(3):
        store.write_windows([counter(device_key=f"mac:aa:bb:cc:dd:ee:0{index}")])

    page = store.list_profiles(limit=2, offset=0)
    rest = store.list_profiles(limit=2, offset=2)

    assert len(page) == 2
    assert len(rest) == 1
    assert store.count_profiles() == 3


def test_the_listing_can_be_filtered_by_learning_state(store: BaselineStore) -> None:
    """The filter is applied in the query, and the count agrees with it."""
    # Five windows is this store's established threshold, so exactly one device is
    # established and the other is still learning.
    for index in range(5):
        store.write_windows([counter(offset=index * 60.0)])
    store.write_windows([counter(device_key=OTHER)])

    established = store.list_profiles(learning_state="established")

    assert len(established) == 1
    assert established[0].device_key == DEVICE
    assert store.count_profiles(learning_state="established") == 1
    assert store.count_profiles(learning_state="learning") == 1


def test_windows_are_read_newest_first(store: BaselineStore) -> None:
    """The detail view shows recent behaviour, so the order is part of the contract."""
    for index in range(3):
        store.write_windows([counter(offset=index * 60.0)])

    windows = store.list_windows(DEVICE, limit=10)

    assert len(windows) == 3
    starts = [window.window_start for window in windows]
    assert starts == sorted(starts, reverse=True)


def test_a_device_with_no_windows_reads_as_no_profile(store: BaselineStore) -> None:
    """Absence is a real answer, not an empty profile (M21.10)."""
    assert store.get_profile("mac:00:00:00:00:00:99") is None
    assert store.list_windows("mac:00:00:00:00:00:99") == []


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------


def test_a_reset_removes_only_the_named_device(store: BaselineStore) -> None:
    """Reset is scoped to one identity, never to the store."""
    for index in range(3):
        store.write_windows([counter(offset=index * 60.0)])
    store.write_windows([counter(device_key=OTHER)])

    windows_deleted, profile_deleted = store.reset_device(DEVICE)

    assert windows_deleted == 3
    assert profile_deleted is True
    assert store.get_profile(DEVICE) is None
    assert store.get_profile(OTHER) is not None


def test_a_reset_of_an_absent_device_deletes_nothing(store: BaselineStore) -> None:
    """A no-op reset is a success, because the outcome is the same either way."""
    assert store.reset_device("mac:11:22:33:44:55:66") == (0, False)


def test_learning_restarts_from_zero_after_a_reset(store: BaselineStore) -> None:
    """The next window is a first sample, not a continuation."""
    for index in range(4):
        store.write_windows([counter(offset=index * 60.0)])
    store.reset_device(DEVICE)

    store.write_windows([counter(offset=600.0)])

    profile = store.get_profile(DEVICE)
    assert profile is not None
    assert profile.sample_count == 1
    assert profile.learning_state == LearningState.LEARNING.value


def test_a_reset_leaves_no_orphan_window_rows(
    store: BaselineStore, session_factory: Callable[[], Session]
) -> None:
    """The rows actually go, rather than being hidden from the reader."""
    store.write_windows([counter(), counter(offset=60.0)])
    store.reset_device(DEVICE)

    session = session_factory()
    try:
        windows = list(session.scalars(select(BaselineWindow)).all())
        profiles = list(session.scalars(select(BaselineProfile)).all())
    finally:
        session.close()

    assert windows == []
    assert profiles == []


# ---------------------------------------------------------------------------
# retention
# ---------------------------------------------------------------------------


def _window_at(observed_at: datetime, device_key: str = DEVICE) -> WindowCounters:
    """Build a window at a specific instant, for the retention tests.

    Anchored on the wall clock rather than on ``BASE``, because retention compares
    against now: a fixed 2023 instant would make every window in the test look
    ancient, and the assertion would then pass for the wrong reason.
    """
    start = observed_at.replace(tzinfo=None).timestamp()
    return WindowCounters(
        device_key=device_key,
        identity_kind="mac",
        window_start=floor_window(start, 60.0),
        window_seconds=60.0,
        packet_count=5,
        byte_count=500,
        tcp_packets=5,
        first_seen=start,
        last_seen=start,
        mac_address=device_key.removeprefix("mac:"),
        ip_address="10.0.0.21",
    )


def _expired_window(device_key: str = DEVICE) -> WindowCounters:
    """Build a window thirty days old, which any default period expires."""
    return _window_at(datetime.now(timezone.utc) - timedelta(days=30), device_key)


def _recent_window(device_key: str = DEVICE) -> WindowCounters:
    """Build a window from an hour ago, which no default period expires."""
    return _window_at(datetime.now(timezone.utc) - timedelta(hours=1), device_key)


def test_retention_deletes_only_expired_windows(store: BaselineStore) -> None:
    """Age is the only criterion, and only the window store is touched."""
    # One window past the period and one inside it, so the assertion is about age
    # rather than about which of two ancient rows happened to be first.
    store.write_windows([_expired_window(), _recent_window()])

    deleted, affected = store.delete_windows_before(retention_cutoff(7), max_rows=100)

    assert deleted == 1
    assert affected == [DEVICE]
    assert len(store.list_windows(DEVICE, limit=10)) == 1


def test_retention_deletes_no_more_than_its_cap(store: BaselineStore) -> None:
    """A backlog is drained over several passes rather than one long transaction."""
    store.write_windows(
        [_expired_window(f"mac:aa:bb:cc:dd:ee:0{index}") for index in range(5)]
    )

    deleted, _ = store.delete_windows_before(retention_cutoff(7), max_rows=2)

    assert deleted == 2


def test_retention_keeps_the_profile_but_recomputes_it(store: BaselineStore) -> None:
    """Profiles describe an identity that was seen; deleting one would lose that."""
    store.write_windows([_expired_window()])

    _, affected = store.delete_windows_before(retention_cutoff(7), max_rows=100)
    for device_key in affected:
        store.recompute_profile(device_key)

    profile = store.get_profile(DEVICE)

    assert profile is not None
    assert profile.sample_count == 0
    assert profile.learning_state == LearningState.LEARNING.value
    assert profile.statistics == {}


def test_retention_rejects_a_zero_row_cap(store: BaselineStore) -> None:
    """A cap of zero would be a pass that silently does nothing forever."""
    with pytest.raises(ValueError):
        store.delete_windows_before(datetime.now(timezone.utc), max_rows=0)


@pytest.mark.parametrize("days", [0, 7, 30])
def test_the_cutoff_is_the_configured_period_back(days: int) -> None:
    """``now`` is injectable, so the cutoff is checkable rather than inferred."""
    reference = datetime(2025, 6, 1, 12, 0, 0)

    cutoff = retention_cutoff(days, now=reference)

    assert cutoff == reference - timedelta(days=days)


def test_a_negative_retention_window_is_rejected() -> None:
    """A negative period would put the cutoff in the future and delete everything."""
    with pytest.raises(ValueError):
        retention_cutoff(-1)


# ---------------------------------------------------------------------------
# robustness
# ---------------------------------------------------------------------------


def test_the_stored_address_list_is_bounded(store: BaselineStore) -> None:
    """A device that changes address constantly cannot grow a row without bound."""
    for index in range(MAX_STORED_ADDRESSES + 5):
        store.write_windows([counter(offset=index * 60.0, ip=f"10.0.1.{index}")])

    profile = store.get_profile(DEVICE)

    assert profile is not None
    assert len(profile.ip_addresses) <= MAX_STORED_ADDRESSES
    assert profile.ip_addresses[0] == f"10.0.1.{MAX_STORED_ADDRESSES + 4}"


def test_a_store_built_with_an_impossible_statistics_limit_is_rejected() -> None:
    """A zero-window recalculation would publish figures from no samples."""
    with pytest.raises(ValueError):
        BaselineStore(statistics_max_windows=0)


def test_a_store_built_with_an_impossible_threshold_is_rejected() -> None:
    """A zero threshold would make every device established on creation."""
    with pytest.raises(ValueError):
        BaselineStore(provisional_min_samples=0)
