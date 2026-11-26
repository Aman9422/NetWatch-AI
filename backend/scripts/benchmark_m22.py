"""Performance baseline for M22 (ML anomaly detection).

Measures only what M22 adds — fitting one Isolation Forest and scoring one
completed observation window — on a deterministic synthetic dataset. It touches
no database, starts no capture and reaches no network, so two runs are
comparable.

What this is **not**: an accuracy evaluation. The project has no labelled
production dataset, so this script reports how long the work takes, and how far
apart the decision scores of a synthetic "normal" population and a synthetic
"unusual" population fall. That separation is a wiring check, not a precision,
recall or false-positive figure — those need labels this project does not have.

Everything is seeded, so a reported number is reproducible:

    cd backend
    .venv\\Scripts\\python.exe scripts\\benchmark_m22.py

Usage:
    python scripts/benchmark_m22.py [--windows 1440] [--rows 200]
"""

from __future__ import annotations

import argparse
import random
import statistics
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.anomaly_detection.features import FEATURE_NAMES, FeatureVector  # noqa: E402
from app.anomaly_detection.model import (  # noqa: E402
    DEFAULT_CONTAMINATION,
    DEFAULT_N_ESTIMATORS,
    DEFAULT_RANDOM_STATE,
    FittedModel,
    ModelConfig,
    build_model,
)
from app.anomaly_detection.preprocessing import (  # noqa: E402
    PreprocessingPlan,
    build_plan,
    to_matrix,
    to_row,
)

#: Seed for the data generator, kept separate from the forest's own seed so the
#: two are never accidentally coupled.
DATA_SEED = 20260101

#: The shape of a "normal" window: one device's steady minute.
NORMAL: dict[str, tuple[float, float]] = {
    "packet_count": (500.0, 40.0),
    "byte_count": (300_000.0, 20_000.0),
    "tcp_packets": (400.0, 35.0),
    "udp_packets": (80.0, 12.0),
    "icmp_packets": (2.0, 1.0),
    "dns_packets": (15.0, 4.0),
    "unique_peers": (12.0, 2.0),
    "unique_destination_ports": (20.0, 3.0),
}

#: How an "unusual" window differs: more volume, many more peers and ports.
UNUSUAL: dict[str, tuple[float, float]] = {
    "packet_count": (4_000.0, 200.0),
    "byte_count": (2_400_000.0, 120_000.0),
    "tcp_packets": (3_600.0, 180.0),
    "udp_packets": (300.0, 40.0),
    "icmp_packets": (2.0, 1.0),
    "dns_packets": (15.0, 4.0),
    "unique_peers": (90.0, 6.0),
    "unique_destination_ports": (260.0, 15.0),
}


def build_windows(
    count: int, profile: dict[str, tuple[float, float]]
) -> list[FeatureVector]:
    """Build a deterministic synthetic set from a behavioural profile."""
    rng = random.Random(DATA_SEED)
    started = datetime(2026, 1, 1)
    windows: list[FeatureVector] = []
    for index in range(count):
        values = {
            name: float(max(0.0, rng.gauss(centre, spread)))
            for name, (centre, spread) in profile.items()
        }
        windows.append(
            FeatureVector(
                device_key="mac:synthetic",
                window_start=started + timedelta(minutes=index),
                window_seconds=60.0,
                values=values,
            )
        )
    return windows


def measure(
    training: list[FeatureVector],
    plan: PreprocessingPlan,
    *,
    normal_rows: list[FeatureVector],
    unusual_rows: list[FeatureVector],
) -> int:
    """Fit one model, score it, and print the report."""
    matrix = to_matrix(training, plan)
    model: FittedModel = build_model(config=ModelConfig(), plan=plan)

    started = time.perf_counter()
    model.fit(matrix)
    fit_seconds = time.perf_counter() - started

    row = to_row(training[0], plan)
    started = time.perf_counter()
    for _ in range(2000):
        model.score(row)
    score_seconds = (time.perf_counter() - started) / 2000.0

    normal_scores = [model.score(to_row(v, plan)).decision_score for v in normal_rows]
    unusual_scores = [
        model.score(to_row(v, plan)).decision_score for v in unusual_rows
    ]
    normal_flagged = sum(
        1 for v in normal_rows if model.score(to_row(v, plan)).is_anomaly
    )
    unusual_flagged = sum(
        1 for v in unusual_rows if model.score(to_row(v, plan)).is_anomaly
    )

    print("M22 anomaly detection — performance baseline")
    print("=" * 64)
    print(
        f"configuration   : n_estimators={DEFAULT_N_ESTIMATORS},"
        f" contamination={DEFAULT_CONTAMINATION},"
        f" random_state={DEFAULT_RANDOM_STATE}"
    )
    print(f"data seed       : {DATA_SEED}")
    print(f"features used   : {len(plan.feature_names)} of {len(FEATURE_NAMES)}")
    if plan.excluded:
        print(f"excluded        : {plan.excluded}")
    print(f"training rows   : {len(matrix)}")
    print(f"fit             : {fit_seconds * 1000:.1f} ms")
    print(f"score (one row) : {score_seconds * 1_000_000:.0f} us")
    print()
    print("synthetic separation — a wiring check, NOT an accuracy figure")
    print(
        f"normal          : n={len(normal_scores)},"
        f" median score {statistics.median(normal_scores):+.4f},"
        f" flagged {normal_flagged}"
    )
    print(
        f"unusual         : n={len(unusual_scores)},"
        f" median score {statistics.median(unusual_scores):+.4f},"
        f" flagged {unusual_flagged}"
    )
    print()
    print(
        "A flagged row means 'differs from the learned pattern'. It is not a\n"
        "maliciousness verdict, and these scores are not probabilities."
    )
    return 0


def main() -> int:
    """Run the measurement."""
    parser = argparse.ArgumentParser(description="M22 performance baseline")
    parser.add_argument("--windows", type=int, default=1440)
    parser.add_argument("--rows", type=int, default=200)
    args = parser.parse_args()
    if args.windows < 100:
        parser.error("--windows must be at least 100 (M22's training minimum)")
    if args.rows < 1:
        parser.error("--rows must be at least 1")

    training = build_windows(args.windows, NORMAL)
    plan = build_plan(training)
    return measure(
        training,
        plan,
        normal_rows=build_windows(args.rows, NORMAL),
        unusual_rows=build_windows(args.rows, UNUSUAL),
    )


if __name__ == "__main__":
    raise SystemExit(main())
