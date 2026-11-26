"""Shared helpers for the M22 anomaly-detection tests.

Two things every M22 test needs and neither of which belongs in a test file:

* **A window that looks like a real one.** ``BaselineWindow`` has eleven
  attributes; a helper that fills them from a small set of knobs keeps each test
  about the behaviour it asserts rather than about the column list.
* **An engine wired to a throwaway database.** The stores take a session
  *factory*, so pointing one at the fixture's in-memory engine is a two-line
  helper that every engine-level test would otherwise repeat.

**The synthetic data is deliberately noisy.** An earlier exploratory run fitted a
forest on windows that varied by a handful of packets and discovered that *both*
the test's "normal" and its "unusual" window scored below zero: with contamination
0.02 and almost no variance, the fitted threshold sits inside the ordinary data,
so ordinary windows are flagged too. That is a real property of Isolation Forest on
low-variance input, not a bug, and it is the reason every dataset here draws from a
seeded generator with meaningful spread. A deterministic seed is used throughout so
the figures the tests assert are reproducible.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any

from app.anomaly_detection import (
    AnomalyEngine,
    EvaluationStore,
    ModelCache,
    ModelConfig,
    ModelLifecycle,
    ModelStore,
    TrainingDatasetReader,
)

#: A stable device identity for the whole suite.
DEVICE_MAC = "mac:aa:bb:cc:dd:ee:01"
DEVICE_IP = "ip:10.0.0.7"

#: The instant the synthetic history starts, so window arithmetic is readable.
BASE_TIME = datetime(2026, 11, 20, 0, 0, 0)

#: Default random seed. Fixed so every assertion is reproducible (M22.16).
SEED = 42


def make_window(
    *,
    device_key: str = DEVICE_MAC,
    index: int = 0,
    packet_count: int = 200,
    byte_count: int = 24_000,
    tcp_packets: int = 140,
    udp_packets: int = 50,
    icmp_packets: int = 1,
    dns_packets: int = 5,
    unique_peers: int = 6,
    unique_destination_ports: int = 9,
    new_connections: int | None = 4,
    peers_truncated: bool = False,
    ports_truncated: bool = False,
    window_seconds: float = 60.0,
) -> Any:
    """Build one synthetic observation window.

    Deliberately a plain object rather than a ``BaselineWindow``: the feature
    extraction is structural, so a test can exercise it without a database, and
    the fields it does not care about stay out of the way.

    Args:
        index: Minute offset from :data:`BASE_TIME`.
    """
    return type(
        "SyntheticWindow",
        (),
        {
            "device_key": device_key,
            "window_start": BASE_TIME + timedelta(minutes=index),
            "window_seconds": window_seconds,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "tcp_packets": tcp_packets,
            "udp_packets": udp_packets,
            "icmp_packets": icmp_packets,
            "dns_packets": dns_packets,
            "unique_peers": unique_peers,
            "unique_destination_ports": unique_destination_ports,
            "new_connections": new_connections,
            "peers_truncated": peers_truncated,
            "ports_truncated": ports_truncated,
        },
    )()


def normal_windows(
    count: int, *, device_key: str = DEVICE_MAC, seed: int = SEED
) -> list[Any]:
    """Return ``count`` plausible, noisy windows for one device.

    The spread is what makes the fitted forest meaningful: roughly ±30% on the
    volume features and a genuinely varying peer/port count, which is what a real
    device produces over a couple of hours.
    """
    rng = random.Random(seed)
    windows: list[Any] = []
    for index in range(count):
        packets = rng.randint(140, 280)
        windows.append(
            make_window(
                device_key=device_key,
                index=index,
                packet_count=packets,
                byte_count=packets * rng.randint(90, 130),
                tcp_packets=int(packets * rng.uniform(0.55, 0.8)),
                udp_packets=int(packets * rng.uniform(0.15, 0.35)),
                icmp_packets=rng.randint(0, 4),
                dns_packets=rng.randint(2, 12),
                unique_peers=rng.randint(4, 9),
                unique_destination_ports=rng.randint(6, 14),
                new_connections=rng.randint(2, 7),
            )
        )
    return windows


def unusual_window(*, device_key: str = DEVICE_MAC, index: int = 500) -> Any:
    """Return one window that is wildly unlike :func:`normal_windows`.

    A flood to many peers and ports: an order of magnitude more packets, hundreds
    of peers and more than a thousand destination ports.
    """
    return make_window(
        device_key=device_key,
        index=index,
        packet_count=24_000,
        byte_count=24_000 * 1400,
        tcp_packets=23_000,
        udp_packets=900,
        icmp_packets=400,
        dns_packets=800,
        unique_peers=900,
        unique_destination_ports=1500,
        new_connections=1200,
    )


def window_before(index: int) -> datetime:
    """Return the start of a synthetic window, for a cutoff argument."""
    return BASE_TIME + timedelta(minutes=index)


def make_engine(
    session_factory: Any,
    *,
    min_training_windows: int = 20,
    max_training_windows: int = 500,
    refresh_interval: int = 30,
    cache_size: int = 4,
    alert_sink: Any = None,
    enabled: bool = True,
) -> AnomalyEngine:
    """Build an engine over the caller's database, not started.

    ``min_training_windows`` defaults to 20 rather than the production 100 so a
    test seeds a dataset in milliseconds instead of a hundred rows.

    Args:
        session_factory: The fixture's factory over the in-memory engine.
        alert_sink: Optional stand-in for the M11 alert engine's entry point.
    """
    model_store = ModelStore(session_factory=session_factory)
    dataset_reader = TrainingDatasetReader(session_factory=session_factory)
    lifecycle = ModelLifecycle(
        model_store=model_store,
        dataset_reader=dataset_reader,
        config=ModelConfig(),
        min_training_windows=min_training_windows,
        max_training_windows=max_training_windows,
        refresh_interval=refresh_interval,
        cache=ModelCache(max_size=cache_size),
        enabled=enabled,
    )
    return AnomalyEngine(
        lifecycle=lifecycle,
        evaluation_store=EvaluationStore(session_factory=session_factory),
        dataset_reader=dataset_reader,
        model_store=model_store,
        alert_sink=alert_sink,
        max_queue=64,
        autostart=False,
    )


def persist_windows(session_factory: Any, windows: list[Any]) -> None:
    """Write synthetic windows into ``baseline_windows``.

    The rows are real, so the dataset reader's own query — including its strict
    ``window_start < before`` cutoff — is what the tests exercise.
    """
    from app.models.baseline_observation import BaselineWindow

    session = session_factory()
    try:
        for window in windows:
            session.add(
                BaselineWindow(
                    device_key=window.device_key,
                    window_start=window.window_start,
                    window_seconds=window.window_seconds,
                    packet_count=window.packet_count,
                    byte_count=window.byte_count,
                    tcp_packets=window.tcp_packets,
                    udp_packets=window.udp_packets,
                    icmp_packets=window.icmp_packets,
                    dns_packets=window.dns_packets,
                    unique_peers=window.unique_peers,
                    unique_destination_ports=window.unique_destination_ports,
                    new_connections=window.new_connections,
                    peers_truncated=window.peers_truncated,
                    ports_truncated=window.ports_truncated,
                )
            )
        session.commit()
    finally:
        session.close()


class RecordingAlertSink:
    """A stand-in for the M11 alert engine that records what it was handed."""

    def __init__(self) -> None:
        self.findings: list[Any] = []

    def __call__(self, findings: list) -> list:
        self.findings.extend(findings)
        return []

    @property
    def rule_ids(self) -> list[str]:
        """Return the rule id of every finding, in order."""
        return [finding.rule_id for finding in self.findings]


__all__ = [
    "BASE_TIME",
    "DEVICE_IP",
    "DEVICE_MAC",
    "SEED",
    "RecordingAlertSink",
    "make_engine",
    "make_window",
    "normal_windows",
    "persist_windows",
    "unusual_window",
    "window_before",
]
