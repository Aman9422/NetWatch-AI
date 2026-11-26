"""Behavioural baseline engine (M21).

The package's public surface, and the reason it is a package rather than one
module: M21 has six separable responsibilities and the milestone asks for them to
be separated. Each lives in one file:

* :mod:`app.baselines.features` — what one packet contributes (M21.4).
* :mod:`app.baselines.aggregation` — the bounded in-memory window (M21.5).
* :mod:`app.baselines.statistics` — the robust statistical profile (M21.6).
* :mod:`app.baselines.states` — the learning lifecycle (M21.7).
* :mod:`app.baselines.store` — persistence, reads, reset and retention queries
  (M21.8).
* :mod:`app.baselines.engine` — the runtime component the pipeline feeds (M21.9).
* :mod:`app.baselines.retention` — the retention policy the M19 sweep drives
  (M21.8).

**What this package does not do.** It does not detect anomalies, score a
deviation, raise an alert or block a device. It learns what normal looks like and
describes it. Comparing a window against a profile is M22's work, and M21 must not
pretend to have done it.
"""

from app.baselines.aggregation import (
    WindowAggregator,
    WindowCounters,
    floor_window,
    window_start_datetime,
)
from app.baselines.engine import (
    BaselineEngine,
    get_baseline_engine,
    reset_baseline_engine,
)
from app.baselines.features import PacketObservation, observe
from app.baselines.retention import (
    BaselineRetentionOutcome,
    BaselineRetentionService,
    get_baseline_retention_service,
    reset_baseline_retention_service,
)
from app.baselines.states import (
    LEARNING_STATES,
    LearningState,
    describe_state,
    is_mature,
    normalize_state,
    publishes_statistics,
    state_for_samples,
)
from app.baselines.statistics import (
    FEATURE_NAMES,
    FeatureStatistics,
    summarise_samples,
)
from app.baselines.store import BaselineStore, ProfileSnapshot, retention_cutoff

__all__ = [
    "BaselineEngine",
    "BaselineRetentionOutcome",
    "BaselineRetentionService",
    "BaselineStore",
    "FEATURE_NAMES",
    "FeatureStatistics",
    "LEARNING_STATES",
    "LearningState",
    "PacketObservation",
    "ProfileSnapshot",
    "WindowAggregator",
    "WindowCounters",
    "describe_state",
    "floor_window",
    "get_baseline_engine",
    "get_baseline_retention_service",
    "is_mature",
    "normalize_state",
    "observe",
    "publishes_statistics",
    "reset_baseline_engine",
    "reset_baseline_retention_service",
    "retention_cutoff",
    "state_for_samples",
    "summarise_samples",
    "window_start_datetime",
]
