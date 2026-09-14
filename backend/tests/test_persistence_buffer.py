"""Unit tests for the bounded packet buffer (M7.9/M7.19).

The buffer is the memory-safety boundary between capture and the database, so
these tests focus on its two contracts: FIFO ordering on the way out, and a hard
cap on how much can be held — with evictions counted rather than silent.
"""

from __future__ import annotations

import threading
import time

import pytest

from app.persistence.buffer import BoundedPacketBuffer


def _row(index: int) -> dict[str, object]:
    """Return a minimal packet row carrying an identifiable index."""
    return {"source_ip": f"10.0.0.{index}", "packet_length": index}


# ---------------------------------------------------------------------------
# Basic enqueue / dequeue
# ---------------------------------------------------------------------------


def test_put_increases_the_depth() -> None:
    """Enqueuing a row makes the buffer non-empty."""
    buffer = BoundedPacketBuffer(10)
    assert buffer.is_empty() is True

    accepted = buffer.put(_row(1))

    assert accepted is True
    assert buffer.size() == 1
    assert buffer.is_empty() is False


def test_get_batch_returns_rows_in_fifo_order() -> None:
    """Rows come back oldest-first."""
    buffer = BoundedPacketBuffer(10)
    for index in range(3):
        buffer.put(_row(index))

    batch = buffer.get_batch(3)

    assert [row["source_ip"] for row in batch] == ["10.0.0.0", "10.0.0.1", "10.0.0.2"]
    assert buffer.size() == 0


def test_get_batch_respects_the_requested_size() -> None:
    """Only ``max_items`` rows are returned per drain step."""
    buffer = BoundedPacketBuffer(10)
    for index in range(5):
        buffer.put(_row(index))

    batch = buffer.get_batch(2)

    assert len(batch) == 2
    assert buffer.size() == 3


def test_get_batch_on_an_empty_buffer_returns_nothing() -> None:
    """Draining an empty buffer is a no-op, not an error."""
    assert BoundedPacketBuffer(4).get_batch(4) == []


def test_drain_returns_every_pending_row() -> None:
    """``drain`` empties the buffer and returns all buffered rows."""
    buffer = BoundedPacketBuffer(10)
    for index in range(4):
        buffer.put(_row(index))

    rows = buffer.drain()

    assert len(rows) == 4
    assert buffer.size() == 0


def test_put_many_returns_the_eviction_count() -> None:
    """``put_many`` reports how many rows it had to evict (here: none)."""
    buffer = BoundedPacketBuffer(10)

    evicted = buffer.put_many(_row(index) for index in range(4))

    assert evicted == 0
    assert buffer.size() == 4


# ---------------------------------------------------------------------------
# Bounded behaviour
# ---------------------------------------------------------------------------


def test_buffer_never_exceeds_its_capacity() -> None:
    """The hard cap holds no matter how many rows are pushed in."""
    buffer = BoundedPacketBuffer(3)
    for index in range(10):
        buffer.put(_row(index))

    assert buffer.size() == 3


def test_full_buffer_evicts_the_oldest_row_and_counts_it() -> None:
    """A full buffer drops the *oldest* row and records the eviction."""
    buffer = BoundedPacketBuffer(2)
    buffer.put(_row(0))
    buffer.put(_row(1))

    accepted = buffer.put(_row(2))

    assert accepted is False
    assert buffer.dropped_count() == 1
    # The two most recent rows survive; the oldest was evicted.
    assert [row["source_ip"] for row in buffer.drain()] == ["10.0.0.1", "10.0.0.2"]


def test_clear_resets_rows_and_drop_counter() -> None:
    """``clear`` discards pending rows and resets the eviction counter."""
    buffer = BoundedPacketBuffer(1)
    buffer.put(_row(0))
    buffer.put(_row(1))  # evicts row 0

    buffer.clear()

    assert buffer.size() == 0
    assert buffer.dropped_count() == 0


def test_capacity_must_be_positive() -> None:
    """A non-positive capacity is rejected up front."""
    with pytest.raises(ValueError):
        BoundedPacketBuffer(0)


def test_max_size_is_exposed() -> None:
    """The capacity is readable so diagnostics can report queue utilisation."""
    assert BoundedPacketBuffer(7).max_size == 7


# ---------------------------------------------------------------------------
# Blocking / shutdown behaviour
# ---------------------------------------------------------------------------


def test_wait_for_item_returns_immediately_when_rows_exist() -> None:
    """A consumer with pending rows never waits."""
    buffer = BoundedPacketBuffer(4)
    buffer.put(_row(0))

    assert buffer.wait_for_item(0.5) is True


def test_wait_for_item_times_out_when_empty() -> None:
    """A consumer with an empty buffer gives up after the timeout."""
    buffer = BoundedPacketBuffer(4)

    start = time.perf_counter()
    available = buffer.wait_for_item(0.05)
    elapsed = time.perf_counter() - start

    assert available is False
    assert elapsed >= 0.04


def test_wake_releases_a_blocked_consumer() -> None:
    """``wake`` releases a thread blocked in ``wait_for_item`` (shutdown)."""
    buffer = BoundedPacketBuffer(4)
    released = threading.Event()

    def consumer() -> None:
        buffer.wait_for_item(5.0)
        released.set()

    thread = threading.Thread(target=consumer, daemon=True)
    thread.start()
    time.sleep(0.05)  # let the consumer block
    buffer.wake()
    thread.join(timeout=1.0)

    assert released.is_set() is True
