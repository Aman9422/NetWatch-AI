"""Unit tests for statistics time windows, rankings and bounded counters (M6.18).

Covers M6.8/M6.9 (rate windows and throughput), M6.10 (top talkers),
M6.11 (protocol distribution helpers) and M6.14 (bounded memory).
"""

from __future__ import annotations

import threading
import time

import pytest

from app.statistics.bounded_counter import BoundedCounter
from app.statistics.manager import TrafficStatisticsManager
from app.statistics.rate_window import RateWindow
from tests.fakes import PACKET_BASE_TIME, make_normalized_packet


# ---------------------------------------------------------------------------
# RateWindow (M6.8 / M6.9)
# ---------------------------------------------------------------------------


def test_rate_window_reports_packets_and_bytes_per_second() -> None:
    """Events inside the window are divided by the window length."""
    window = RateWindow(window_seconds=1.0)
    for _ in range(5):
        window.record(1, 10, at=100.0)

    packets_per_second, bytes_per_second = window.rates(now=100.5)

    assert packets_per_second == pytest.approx(5.0)
    assert bytes_per_second == pytest.approx(50.0)


def test_rate_window_prunes_events_older_than_the_window() -> None:
    """Only events inside the window contribute to the rate."""
    window = RateWindow(window_seconds=1.0)
    window.record(1, 10, at=100.0)  # outside the window at t=105
    window.record(1, 10, at=105.0)

    packets_per_second, _ = window.rates(now=105.0)

    assert packets_per_second == pytest.approx(1.0)


def test_rate_window_rolls_over_to_zero() -> None:
    """Once every event ages out, the rate returns to zero (window rollover)."""
    window = RateWindow(window_seconds=1.0)
    window.record(1, 10, at=100.0)

    packets_per_second, bytes_per_second = window.rates(now=200.0)

    assert packets_per_second == 0.0
    assert bytes_per_second == 0.0


def test_rate_window_reset_clears_events() -> None:
    """Reset removes all buffered events."""
    window = RateWindow(window_seconds=1.0)
    window.record(1, 10, at=100.0)
    window.reset()

    assert window.rates(now=100.0) == (0.0, 0.0)


def test_rate_window_rejects_non_positive_seconds() -> None:
    """A window of zero or negative length is invalid."""
    with pytest.raises(ValueError):
        RateWindow(window_seconds=0.0)


def test_rate_window_buffer_stays_bounded_without_reads() -> None:
    """Recording alone keeps the buffer bounded, even with no reads (M6.14).

    A window whose rate is never queried must still drop aged events, otherwise
    its buffer would grow without limit for the lifetime of the process.
    """
    window = RateWindow(window_seconds=10.0)
    for offset in range(1000):
        window.record(1, 10, at=float(offset))

    # Events older than 10s are dropped as new buckets open, so at most ~11
    # buckets (10s window, one bucket per second of the synthetic traffic) are
    # retained out of 1000 records.
    assert len(window._buckets) <= 11


def test_rate_window_memory_does_not_scale_with_packet_count() -> None:
    """A burst of many packets collapses into few buckets (M6.14).

    This is the core memory guarantee: a window holds a number of buckets set by
    its length, not by how many packets pass through it. 100,000 packets inside
    one second must occupy the same handful of buckets as one packet would.
    """
    window = RateWindow(window_seconds=1.0)
    for step in range(100_000):
        window.record(1, 10, at=100.0 + step * 0.00001)

    # 1s window at 100ms buckets → at most 11 buckets, regardless of the 100k
    # packets recorded.
    assert len(window._buckets) <= 11


def test_rate_window_rejects_non_positive_bucket() -> None:
    """A non-positive bucket resolution is invalid."""
    with pytest.raises(ValueError):
        RateWindow(window_seconds=1.0, bucket_seconds=0.0)


# ---------------------------------------------------------------------------
# Manager rate windows (M6.8 / M6.9)
# ---------------------------------------------------------------------------


def test_manager_computes_packets_and_bytes_per_second() -> None:
    """The manager reports rates derived from the observed packets."""
    manager = TrafficStatisticsManager()
    now = time.time()
    for _ in range(10):
        manager.record_packet(make_normalized_packet(timestamp=now, length=20))

    packets_per_second, bytes_per_second = manager.get_rates("1s")

    assert packets_per_second == pytest.approx(10.0)
    assert bytes_per_second == pytest.approx(200.0)


def test_manager_rates_ignore_stale_packets() -> None:
    """Packets older than the window no longer contribute to the rate."""
    manager = TrafficStatisticsManager()
    manager.record_packet(make_normalized_packet(timestamp=time.time() - 10.0))

    packets_per_second, bytes_per_second = manager.get_rates("1s")

    assert packets_per_second == 0.0
    assert bytes_per_second == 0.0


def test_manager_supports_multiple_windows() -> None:
    """The 1s, 10s and 60s windows all report a positive rate for fresh packets."""
    manager = TrafficStatisticsManager()
    now = time.time()
    for _ in range(5):
        manager.record_packet(make_normalized_packet(timestamp=now, length=10))

    for label in ("1s", "10s", "60s"):
        packets_per_second, _ = manager.get_rates(label)
        assert packets_per_second > 0.0


def test_snapshot_bits_per_second_is_bytes_times_eight() -> None:
    """Throughput includes a bits-per-second figure (M6.9)."""
    manager = TrafficStatisticsManager()
    now = time.time()
    for _ in range(10):
        manager.record_packet(make_normalized_packet(timestamp=now, length=100))

    snapshot = manager.get_statistics()

    assert snapshot.bits_per_second == pytest.approx(snapshot.bytes_per_second * 8.0)
    assert snapshot.bits_per_second == pytest.approx(8000.0)


# ---------------------------------------------------------------------------
# Top talkers (M6.10)
# ---------------------------------------------------------------------------


def test_top_talkers_ranked_by_packets() -> None:
    """Top sources are ordered by packet count, busiest first."""
    manager = TrafficStatisticsManager()
    for _ in range(3):
        manager.record_packet(make_normalized_packet(source_ip="10.0.0.1"))
    manager.record_packet(make_normalized_packet(source_ip="10.0.0.2"))

    talkers = manager.get_top_talkers()

    assert [entry.key for entry in talkers["sources"]] == ["10.0.0.1", "10.0.0.2"]


def test_top_talkers_ranked_by_bytes() -> None:
    """Ranking by bytes reorders entries when byte volume differs."""
    manager = TrafficStatisticsManager()
    manager.record_packet(make_normalized_packet(source_ip="10.0.0.1", length=10))
    manager.record_packet(make_normalized_packet(source_ip="10.0.0.2", length=900))

    talkers = manager.get_top_talkers(by="bytes")

    assert talkers["sources"][0].key == "10.0.0.2"


def test_top_talkers_equal_values_are_deterministic() -> None:
    """Equal counts are ordered by key so results are stable."""
    manager = TrafficStatisticsManager()
    manager.record_packet(make_normalized_packet(source_ip="10.0.0.20"))
    manager.record_packet(make_normalized_packet(source_ip="10.0.0.10"))

    talkers = manager.get_top_talkers()

    assert [entry.key for entry in talkers["sources"]] == ["10.0.0.10", "10.0.0.20"]


def test_top_talkers_respects_limit() -> None:
    """The limit caps how many ranked entries are returned."""
    manager = TrafficStatisticsManager()
    for index in range(20):
        manager.record_packet(make_normalized_packet(source_ip=f"10.0.0.{index}"))

    talkers = manager.get_top_talkers(limit=5)

    assert len(talkers["sources"]) == 5


def test_top_talkers_empty_state() -> None:
    """A fresh manager has no talkers in any category."""
    manager = TrafficStatisticsManager()

    assert manager.get_top_talkers() == {
        "sources": [],
        "destinations": [],
        "conversations": [],
    }


def test_conversations_are_tracked() -> None:
    """Repeated packets between the same endpoints form one conversation."""
    manager = TrafficStatisticsManager()
    for _ in range(3):
        manager.record_packet(
            make_normalized_packet(
                source_ip="10.0.0.1",
                source_port=1000,
                destination_ip="10.0.0.2",
                destination_port=80,
            )
        )

    conversations = manager.get_top_talkers()["conversations"]

    assert conversations[0].key == "10.0.0.1:1000->10.0.0.2:80"
    assert conversations[0].packets == 3


# ---------------------------------------------------------------------------
# BoundedCounter (M6.14)
# ---------------------------------------------------------------------------


def test_bounded_counter_accumulates_packets_and_bytes() -> None:
    """Repeated adds accumulate both packet and byte totals."""
    counter = BoundedCounter(max_keys=10)
    counter.add("a", 1, 100)
    counter.add("a", 1, 50)

    assert counter.items() == {"a": (2, 150)}


def test_bounded_counter_evicts_least_active_when_full() -> None:
    """When full, the least active key is evicted to admit a new one."""
    counter = BoundedCounter(max_keys=2)
    counter.add("busy", 10, 0)
    counter.add("quiet", 1, 0)
    counter.add("newcomer", 5, 0)

    keys = set(counter.items())

    assert "busy" in keys
    assert "newcomer" in keys
    assert "quiet" not in keys


def test_bounded_counter_stays_bounded() -> None:
    """Inserting far more keys than capacity never exceeds the bound (M6.14)."""
    counter = BoundedCounter(max_keys=3)
    for index in range(100):
        counter.add(f"key-{index}", index + 1, 0)

    assert len(counter) == 3


def test_bounded_counter_top_by_bytes() -> None:
    """The ``top`` ranking can sort by bytes instead of packets."""
    counter = BoundedCounter(max_keys=10)
    counter.add("a", 1, 10)
    counter.add("b", 5, 1)

    assert counter.top(limit=2, by="bytes")[0][0] == "a"


def test_bounded_counter_requires_positive_capacity() -> None:
    """A capacity below one is rejected."""
    with pytest.raises(ValueError):
        BoundedCounter(max_keys=0)


def test_bounded_counter_reset() -> None:
    """Reset empties the counter."""
    counter = BoundedCounter(max_keys=4)
    counter.add("a", 1, 1)
    counter.reset()

    assert counter.items() == {}
    assert len(counter) == 0


def test_bounded_counter_keeps_the_most_active_keys() -> None:
    """Under high cardinality the busiest keys survive eviction (M6.14)."""
    counter = BoundedCounter(max_keys=3)
    for index in range(50):
        for _ in range(index + 1):  # each key is more active than the last
            counter.add(f"key-{index}", 1, 0)

    survived = {key for key, _, _ in counter.top(limit=3)}

    assert survived == {"key-47", "key-48", "key-49"}


def test_bounded_counter_heap_does_not_grow_without_bound() -> None:
    """The eviction index is rebuilt so it cannot grow without bound (M6.14)."""
    counter = BoundedCounter(max_keys=4)
    for _ in range(10_000):
        counter.add("hot", 1, 0)
        counter.add("cold", 1, 0)

    assert len(counter._heap) <= counter._heap_rebuild_threshold


def test_snapshot_totals_cover_ranked_entries_under_concurrency() -> None:
    """Ranked lists are never larger than the totals they accompany (NIT-4).

    ``get_statistics`` snapshots the ranked counters before the aggregate totals,
    so a live snapshot must never claim more per-source activity than the total
    packet count that is reported alongside it.
    """
    manager = TrafficStatisticsManager()
    stop = threading.Event()

    def writer() -> None:
        while not stop.is_set():
            manager.record_packet(make_normalized_packet(source_ip="10.0.0.1"))

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        for _ in range(200):
            snapshot = manager.get_statistics()
            ranked = sum(entry.packets for entry in snapshot.top_sources)
            assert ranked <= snapshot.total_packets
    finally:
        stop.set()
        thread.join()


def test_manager_bounds_high_cardinality_sources() -> None:
    """The manager keeps source tracking bounded even under many distinct IPs."""
    manager = TrafficStatisticsManager(max_tracked_keys=16)
    for index in range(200):
        manager.record_packet(make_normalized_packet(source_ip=f"10.0.{index // 256}.{index % 256}"))

    snapshot = manager.get_statistics()

    assert len(snapshot.top_sources) <= 16
