"""The bounded model cache (M22.7).

One fitted model per device identity, held in a least-recently-used map with a hard
capacity. The cap is not advisory: a flood of spoofed identities would otherwise
grow the cache without limit, which is exactly the unbounded growth M22.7 forbids.
Eviction is deterministic — least recently used first, with insertion order as the
tie-break — so two runs over the same access sequence evict the same entries.

The lock is held for the dictionary operation only, never across training. A
caller holding it while fitting a forest would block every other device's
evaluation for the duration of that fit.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime

from app.anomaly_detection.features import FeatureVector
from app.anomaly_detection.model import FittedModel
from app.anomaly_detection.states import ModelState

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CachedModel:
    """One fitted model plus the data an evaluation needs to describe it.

    Attributes:
        device_key: The identity the model belongs to.
        model: The fitted forest.
        model_version: The version this model corresponds to.
        trained_at: When it was fitted.
        training_sample_count: How many windows were fitted.
        training_vectors: The vectors the model was fitted on. Retained so an
            evaluation can describe *what it was compared with* without a second
            database read. Bounded because the training set is bounded.
        windows_since_training: New usable windows since the last fit, which is
            what the refresh interval is measured against.
        state: The lifecycle state at the moment it was cached.
    """

    device_key: str
    model: FittedModel
    model_version: int
    trained_at: datetime | None
    training_sample_count: int
    training_vectors: list[FeatureVector] = field(default_factory=list)
    windows_since_training: int = 0
    state: str = ModelState.READY.value


class ModelCache:
    """A bounded, thread-safe, least-recently-used cache of fitted models (M22.7)."""

    def __init__(self, max_size: int = 64) -> None:
        """Create the cache.

        Args:
            max_size: Hard cap on held models.

        Raises:
            ValueError: If ``max_size`` is below one, which would make every
                evaluation retrain from scratch.
        """
        if max_size < 1:
            raise ValueError("max_size must be at least 1")
        self._max_size = max_size
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, CachedModel] = OrderedDict()
        self._eviction_count = 0

    @property
    def max_size(self) -> int:
        """Return the configured capacity."""
        return self._max_size

    def __len__(self) -> int:
        """Return how many models are currently held."""
        with self._lock:
            return len(self._entries)

    def get(self, device_key: str) -> CachedModel | None:
        """Return a cached model and mark it most recently used."""
        with self._lock:
            entry = self._entries.get(device_key)
            if entry is None:
                return None
            self._entries.move_to_end(device_key)
            return entry

    def put(self, entry: CachedModel) -> None:
        """Insert or replace a model, evicting the least recently used."""
        with self._lock:
            self._entries[entry.device_key] = entry
            self._entries.move_to_end(entry.device_key)
            while len(self._entries) > self._max_size:
                evicted_key, _ = self._entries.popitem(last=False)
                self._eviction_count += 1
                logger.debug("Evicted cached anomaly model for %s", evicted_key)

    def forget(self, device_key: str) -> None:
        """Drop one device's model, if held."""
        with self._lock:
            self._entries.pop(device_key, None)

    def clear(self) -> None:
        """Drop every cached model. For tests and reloads."""
        with self._lock:
            self._entries.clear()

    def keys(self) -> tuple[str, ...]:
        """Return the cached device keys, least recently used first."""
        with self._lock:
            return tuple(self._entries)

    def get_eviction_count(self) -> int:
        """Return how many models have been evicted by the capacity cap."""
        with self._lock:
            return self._eviction_count


__all__ = ["CachedModel", "ModelCache"]
