"""The bounded, thread-safe store of correlated incidents (M12.22/M12.23/M12.26).

Correlation needs somewhere to keep the incidents it is building, and that
somewhere has three jobs M12 is explicit about:

* **Be bounded** (M12.22). Incidents accumulate on a busy network, so the store
  has a hard cap on how many it holds and a retention age after which an
  incident with no recent activity is dropped. The alerts themselves are never
  dropped — they live in their own table (M11.16) — so expiring correlation
  context loses a *relationship*, never a record.
* **Be safe under concurrency** (M12.23). Correlation runs on the capture thread
  while the read API answers questions from a thread pool, so the store is
  protected by one lock around its mutation, and reading hands back an immutable
  snapshot.
* **Answer queries** (M12.26). Recent, open, by device, by source, by rule, by
  risk and by time range, all bounded and all deterministically ordered.

**Where the lock is, and where it deliberately is not.** A correlation step is
read-decide-write: find the incident this event belongs to, then fold it in. If
the lock covered only the write, two threads could both decide to fold an event
into the same incident and the second write would silently discard the first.
The whole step therefore runs inside one lock, which is what :meth:`ingest`
exists to do.

The lock does **not** cover anything that touches a database or any other
injected callable that might. Scoring is pure arithmetic and is allowed inside;
persistence is not, and runs outside, on the incident :meth:`ingest` returns.
That keeps a slow disk from stalling correlation for every other thread, and it
keeps the failure-isolation boundary (M12.25) outside the critical section.

Incidents are immutable, so a reader is never handed a half-updated object: it
receives the incident as it stood at one instant, and a later join produces a new
instance rather than mutating that one.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum

from app.correlation.incident import (
    DEFAULT_MAX_MEMBERS,
    DEFAULT_MAX_REASONS,
    CorrelatedIncident,
)
from app.correlation.event import CorrelationEvent
from app.correlation.relationship import Relationship
from app.correlation.status import (
    ACTIVE_STATUSES,
    IncidentStatus,
    validate_transition,
)
from app.correlation.window import CorrelationWindow
from app.risk.bands import RiskBand
from app.risk.engine import RiskResult

#: Cap on incidents held in runtime state. Mirrors
#: ``settings.correlation_max_incidents``. On overflow the least recently active
#: incident is evicted, so a burst cannot grow the store without limit (M12.22).
DEFAULT_MAX_INCIDENTS = 1024

#: Seconds an incident may go untouched before expiration may drop it. Mirrors
#: ``settings.correlation_retention_seconds``.
DEFAULT_RETENTION_SECONDS = 3600.0

#: How many recently processed event identities are remembered for
#: deduplication (M12.11). Bounded so the cost of deduplication cannot grow with
#: uptime; a FIFO evicts the oldest, so the guarantee is exact for the most
#: recent N events and best-effort beyond it.
DEFAULT_SEEN_EVENT_CAPACITY = 4096

#: Default page size for an incident query (M12.26).
DEFAULT_PAGE_SIZE = 100

#: Hard ceiling on a page size, so a caller cannot ask for an unbounded read.
DEFAULT_MAX_PAGE_SIZE = 500


logger = logging.getLogger(__name__)


class IncidentOrder(str, Enum):
    """Deterministic orderings for incident queries (M12.26).

    Every option is total — ties break on ``incident_id`` — so a query returns
    the same sequence whatever order the incidents happen to sit in the store.
    """

    RECENT = "recent"
    OLDEST = "oldest"
    RISK = "risk"
    CONFIDENCE = "confidence"


def _normalized_statuses(values: Sequence[IncidentStatus | str]) -> tuple[str, ...]:
    """Return validated, deduplicated, sorted status values.

    Raises:
        ValueError: If a value is not one of the four incident states, so a typo
            in a filter cannot silently select nothing.
    """
    resolved = {IncidentStatus(str(value).strip().lower()) for value in values}
    return tuple(sorted(status.value for status in resolved))


#: The verdict of one rule evaluation: which M12.12 rule matched, the
#: relationships that justified it, and the reason trail they produce. ``None``
#: — the absence of a verdict — means no rule applies and the events are not the
#: same activity.
IncidentVerdict = tuple[str, tuple[Relationship, ...], tuple[str, ...]]

#: Signature of the rule evaluator the engine injects into
#: :meth:`IncidentRegistry.ingest`. For one candidate incident it returns either
#: ``None`` — no rule applies, these are not the same activity — or an
#: :data:`IncidentVerdict`.
#:
#: The registry deliberately does not know the M12.12 rules. Rule sets are
#: *policy*, and a bounded store is not the place for policy; injecting the
#: evaluator keeps rule decisions in :mod:`app.correlation.engine` while letting
#: the store hold its lock across the whole read-decide-write step.
IncidentEvaluator = Callable[[CorrelatedIncident], IncidentVerdict | None]

#: Signature of the risk scorer the engine injects into
#: :meth:`IncidentRegistry.ingest`. It maps an incident to a
#: :class:`~app.risk.engine.RiskResult`; the registry reads only ``score`` and
#: ``band`` from it, so the scoring model stays free to grow fields the store
#: neither knows nor needs.
IncidentScorer = Callable[[CorrelatedIncident], RiskResult]


@dataclass(frozen=True)
class CorrelationOutcome:
    """What happened to one correlated event (M12.25).

    The same shape as M11's ``AlertOutcome``, for the same reason: correlation is
    reached from the capture path, and M12.25 requires that a correlation failure
    must not stop alert processing. An outcome is therefore always *returned*
    rather than raised, and exactly one of the flags describes the result.

    Attributes:
        event_id: The event this outcome concerns.
        rule_id: The detector rule that produced it.
        incident: The incident as it stood after the step, or ``None`` when the
            event was skipped. Returned so the caller can persist its risk score
            *outside* the registry lock (M12.24).
        incident_id: Convenience copy of ``incident.incident_id``.
        created: True when a new incident was opened.
        joined: True when the event folded into an existing incident.
        duplicate: True when the event had already been ingested (M12.11).
        correlation_rule_id: The M12.12 rule that matched, when one did.
        correlation_confidence: How strongly the event was judged related.
        risk_score: The incident's score after the step.
        expired_incidents: How many incidents this step's expiration swept away.
        error: ``None`` on success, or why the step failed.
    """

    event_id: str
    rule_id: str
    incident: CorrelatedIncident | None = None
    incident_id: str | None = None
    created: bool = False
    joined: bool = False
    duplicate: bool = False
    correlation_rule_id: str | None = None
    correlation_confidence: float = 0.0
    risk_score: int = 0
    expired_incidents: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        """Return True when the step completed without error."""
        return self.error is None

    def as_dict(self) -> dict[str, object]:
        """Return the outcome as a JSON-friendly mapping, for diagnostics."""
        return {
            "event_id": self.event_id,
            "rule_id": self.rule_id,
            "incident_id": self.incident_id,
            "created": self.created,
            "joined": self.joined,
            "duplicate": self.duplicate,
            "correlation_rule_id": self.correlation_rule_id,
            "correlation_confidence": round(float(self.correlation_confidence), 6),
            "risk_score": int(self.risk_score),
            "expired_incidents": int(self.expired_incidents),
            "error": self.error,
        }


@dataclass
class CorrelationCounters:
    """Execution counters for the correlation store and engine (M12.34)."""

    events_seen: int = 0
    incidents_created: int = 0
    incidents_updated: int = 0
    correlations_matched: int = 0
    duplicates_skipped: int = 0
    expired_incidents: int = 0
    evicted_incidents: int = 0
    scored: int = 0
    score_errors: int = 0
    errors: int = 0


class IncidentRegistry:
    """The bounded, lock-protected store of correlated incidents (M12.22).

    Args:
        max_incidents: Hard cap on held incidents. On overflow the least recently
            active incident is evicted, so memory is bounded even under a
            spoofed flood.
        retention_seconds: Age after which an incident with no recent activity is
            dropped. Must be positive; ``None`` is not accepted, because
            unbounded retention is exactly what M12.22 forbids.
        seen_event_capacity: How many recent event identities are remembered for
            deduplication (M12.11).
        max_members / max_reasons: Caps applied when an incident grows.
        clock: Time source in epoch seconds. Injectable so a test can pin
            expiration exactly instead of sleeping.

    Raises:
        ValueError: If a bound is not positive. A zero cap or a zero retention
            would make the store unusable, so it is rejected at construction
            rather than at the first event.
    """

    def __init__(
        self,
        *,
        max_incidents: int = DEFAULT_MAX_INCIDENTS,
        retention_seconds: float = DEFAULT_RETENTION_SECONDS,
        seen_event_capacity: int = DEFAULT_SEEN_EVENT_CAPACITY,
        max_members: int = DEFAULT_MAX_MEMBERS,
        max_reasons: int = DEFAULT_MAX_REASONS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        for name, value in (
            ("max_incidents", max_incidents),
            ("seen_event_capacity", seen_event_capacity),
            ("max_members", max_members),
            ("max_reasons", max_reasons),
        ):
            if int(value) < 1:
                raise ValueError(f"{name} must be at least 1")
        if float(retention_seconds) <= 0:
            raise ValueError("retention_seconds must be positive")

        self._max_incidents = int(max_incidents)
        self._retention_seconds = float(retention_seconds)
        self._seen_event_capacity = int(seen_event_capacity)
        self._max_members = int(max_members)
        self._max_reasons = int(max_reasons)
        self._clock = clock

        self._incidents: dict[str, CorrelatedIncident] = {}
        # Event identity mapped to the incident that absorbed it, plus a FIFO of
        # insertion order so both can be trimmed together. The mapping is what
        # makes deduplication O(1) *and* lets a repeated event report *which*
        # incident already holds it — a bare set could only answer "seen" (M12.11).
        self._seen_events: dict[str, str] = {}
        self._seen_order: deque[str] = deque()
        self._counters = CorrelationCounters()
        # Sweep at most ten times per retention period rather than on every
        # event: expiration is O(n) and correlation is on the capture path, so
        # its cost has to be bounded independently of the event rate (M12.22).
        self._sweep_interval = max(float(retention_seconds) / 10.0, 1.0)
        self._next_sweep = 0.0
        # An RLock rather than a Lock: the public methods compose (a lifecycle
        # change reads, validates and writes), and re-entrancy keeps that
        # composition readable instead of forcing private unlocked variants.
        self._lock = threading.RLock()

    # -- introspection ------------------------------------------------------

    @property
    def max_incidents(self) -> int:
        """Return the configured cap on held incidents (M12.22)."""
        return self._max_incidents

    @property
    def retention_seconds(self) -> float:
        """Return the configured retention age in seconds (M12.22)."""
        return self._retention_seconds

    def get(self, incident_id: str) -> CorrelatedIncident | None:
        """Return one incident by identifier, or ``None`` when unknown."""
        with self._lock:
            return self._incidents.get(str(incident_id))

    def incidents(self) -> list[CorrelatedIncident]:
        """Return a snapshot of every held incident, newest first.

        A snapshot rather than a live view: incidents are immutable, so the list
        stays internally consistent while the capture thread keeps folding events
        into the store (M12.23).
        """
        with self._lock:
            return sorted(
                self._incidents.values(),
                key=lambda incident: (
                    -float(incident.last_seen),
                    incident.incident_id,
                ),
            )

    def incident_count(self) -> int:
        """Return how many incidents are held."""
        with self._lock:
            return len(self._incidents)

    def active_count(self) -> int:
        """Return how many held incidents still need attention (M12.26)."""
        with self._lock:
            return sum(
                1
                for incident in self._incidents.values()
                if incident.normalized_status.value in ACTIVE_STATUSES
            )

    def has_seen_event(self, event_id: str) -> bool:
        """Return True when this event identity was already ingested (M12.11)."""
        with self._lock:
            return str(event_id) in self._seen_events

    def incident_for_event(self, event_id: str) -> str | None:
        """Return the incident that absorbed ``event_id``, if still held."""
        with self._lock:
            return self._seen_events.get(str(event_id))

    def seen_event_count(self) -> int:
        """Return how many recent event identities are remembered."""
        with self._lock:
            return len(self._seen_events)

    # -- ingestion (M12.2/M12.25) ------------------------------------------

    def ingest(
        self,
        event: CorrelationEvent,
        *,
        window: CorrelationWindow,
        evaluator: IncidentEvaluator,
        title_factory: Callable[[CorrelationEvent], str] | None = None,
        scorer: IncidentScorer | None = None,
    ) -> CorrelationOutcome:
        """Fold one event into the store, opening an incident when needed.

        This is the whole critical section — deduplicate, sweep, find the
        incident the event belongs to, fold it in, score it, store it, and bound
        the store — under one lock, so two threads cannot both fold an event into
        the same incident and lose one of the folds (M12.23).

        Never raises (M12.25): a correlation failure must not stop alert
        processing, so an unexpected failure is counted and returned as an error
        outcome.

        Args:
            event: The normalized event to correlate.
            window: The bounded correlation window (M12.5). Passed in rather than
                held, so a reconfiguration takes effect on the next event.
            evaluator: The injected rule check (M12.12). It is called once per
                candidate, most recently active first, and the first candidate it
                accepts wins — which is what makes attribution deterministic.
            title_factory: Composes the title for a newly opened incident.
                Defaults to the event's own title, then its rule id.
            scorer: Optional risk scorer applied to the incident before it is
                stored, so the stored score always matches the stored membership
                (M12.13).

        Returns:
            The outcome. Exactly one of ``created``, ``joined`` or ``duplicate``
            is set, unless ``error`` is.
        """
        try:
            with self._lock:
                return self._ingest_locked(
                    event,
                    window=window,
                    evaluator=evaluator,
                    title_factory=title_factory,
                    scorer=scorer,
                )
        except Exception:  # noqa: BLE001 - correlation must never stop capture
            with self._lock:
                self._counters.errors += 1
            logger.exception(
                "Correlation failed for event %s; alert processing continues",
                event.event_id,
            )
            return CorrelationOutcome(
                event_id=str(event.event_id),
                rule_id=str(event.rule_id),
                error="Correlation failed",
            )

    def _ingest_locked(
        self,
        event: CorrelationEvent,
        *,
        window: CorrelationWindow,
        evaluator: IncidentEvaluator,
        title_factory: Callable[[CorrelationEvent], str] | None,
        scorer: IncidentScorer | None,
    ) -> CorrelationOutcome:
        """The critical section of :meth:`ingest`, with the lock already held."""
        key = str(event.event_id)
        now = float(self._clock())
        expired = self._weep(now)
        self._counters.events_seen += 1

        known = self._seen_events.get(key)
        if known is not None:
            # The same event observed twice. This is M12.11's deduplication, and
            # its purpose is deliberately narrower than M11's: M11 asks "is this
            # the same alert?", this asks "has this event already been folded
            # into an incident?" — so a repeated observation does not inflate an
            # incident's membership or its score.
            self._counters.duplicates_skipped += 1
            incident = self._incidents.get(known)
            return CorrelationOutcome(
                event_id=key,
                rule_id=str(event.rule_id),
                incident=incident,
                incident_id=incident.incident_id if incident else known,
                duplicate=True,
                correlation_confidence=(
                    float(incident.correlation_confidence) if incident else 0.0
                ),
                risk_score=int(incident.risk_score) if incident else 0,
                expired_incidents=expired,
            )

        match = self._find_match(event, window=window, evaluator=evaluator)
        if match is not None:
            candidate, rule_id, relationships, reasons = match
            grown = candidate.merged_with_event(
                event,
                relationships=relationships,
                correlation_rule_id=rule_id,
                reasons=reasons,
                max_members=self._max_members,
                max_reasons=self._max_reasons,
            )
            stored = self._score(grown, scorer)
            self._store(stored)
            self._remember(key, stored.incident_id)
            self._counters.incidents_updated += 1
            self._counters.correlations_matched += 1
            return CorrelationOutcome(
                event_id=key,
                rule_id=str(event.rule_id),
                incident=stored,
                incident_id=stored.incident_id,
                joined=True,
                correlation_rule_id=rule_id,
                correlation_confidence=float(stored.correlation_confidence),
                risk_score=int(stored.risk_score),
                expired_incidents=expired,
            )

        opened = CorrelatedIncident.opened_by(
            event,
            title=self._title_for(event, title_factory),
            max_members=self._max_members,
            max_reasons=self._max_reasons,
        )
        stored = self._score(opened, scorer)
        self._store(stored)
        self._remember(key, stored.incident_id)
        self._counters.incidents_created += 1
        return CorrelationOutcome(
            event_id=key,
            rule_id=str(event.rule_id),
            incident=stored,
            incident_id=stored.incident_id,
            created=True,
            risk_score=int(stored.risk_score),
            expired_incidents=expired,
        )

    def _find_match(
        self,
        event: CorrelationEvent,
        *,
        window: CorrelationWindow,
        evaluator: IncidentEvaluator,
    ) -> tuple[CorrelatedIncident, str, list, tuple[str, ...]] | None:
        """Return the incident this event belongs to, or ``None``.

        Candidates are considered most recently active first, so when several
        incidents could accept an event, the one that was active most recently
        wins and the choice does not depend on dictionary order. Only incidents
        still open or under investigation are considered: an event must not
        reopen a relationship someone has already resolved (M12.9).
        """
        candidates = sorted(
            (
                incident
                for incident in self._incidents.values()
                if incident.normalized_status.value in ACTIVE_STATUSES
            ),
            key=lambda incident: (
                -float(incident.last_seen),
                incident.incident_id,
            ),
        )
        for candidate in candidates:
            if candidate.has_event(event.event_id):
                continue
            if not window.incident_accepts(
                start_time=candidate.start_time,
                last_seen=candidate.last_seen,
                timestamp=event.timestamp,
            ):
                continue
            # The evaluator owns the M12.12 rule set *and* re-checks that the
            # match carries an anchoring relationship, which is where M12.4's
            # "not merely close in time" is enforced. Asking it twice would put
            # policy in two places that could disagree.
            result = evaluator(candidate)
            if result is None:
                continue
            rule_id, relationships, reasons = result
            return candidate, str(rule_id), list(relationships), tuple(reasons)
        return None

    def _title_for(
        self,
        event: CorrelationEvent,
        factory: Callable[[CorrelationEvent], str] | None,
    ) -> str:
        """Return the title for an incident opened by ``event``."""
        if factory is not None:
            try:
                composed = str(factory(event)).strip()
            except Exception:  # noqa: BLE001 - a title is never worth failing over
                composed = ""
            if composed:
                return composed
        return str(event.title or event.rule_id)

    def _score(
        self, incident: CorrelatedIncident, scorer: IncidentScorer | None
    ) -> CorrelatedIncident:
        """Return ``incident`` with a computed score, or unchanged on failure.

        Called with the lock held, and deliberately confined to arithmetic: the
        scorer is the risk engine, which holds no per-incident state and takes no
        lock of its own. A scorer that raised would be contained here, because a
        risk-scoring failure must not destroy the incident it was scoring
        (M12.25) — the incident is stored unmodified and the failure is counted.
        """
        if scorer is None:
            return incident
        try:
            result = scorer(incident)
        except Exception:  # noqa: BLE001 - scoring must never lose the incident
            self._counters.score_errors += 1
            logger.exception(
                "Risk scoring failed for incident %s; the incident is kept",
                incident.incident_id,
            )
            return incident
        score = getattr(result, "score", None)
        if score is None:
            self._counters.score_errors += 1
            return incident
        band = getattr(result, "band", None)
        self._counters.scored += 1
        return incident.with_risk(
            score=int(score), band=band if isinstance(band, RiskBand) else None
        )

    def _remember(self, event_id: str, incident_id: str) -> None:
        """Record that ``event_id`` was absorbed by ``incident_id`` (M12.11)."""
        if event_id in self._seen_events:
            return
        self._seen_events[event_id] = incident_id
        self._seen_order.append(event_id)
        while len(self._seen_order) > self._seen_event_capacity:
            oldest = self._seen_order.popleft()
            self._seen_events.pop(oldest, None)

    def _store(self, incident: CorrelatedIncident) -> None:
        """Store ``incident`` and keep the store inside its cap (M12.22)."""
        self._incidents[incident.incident_id] = incident
        self._enforce_capacity()

    def _enforce_capacity(self) -> int:
        """Evict least-recently-active incidents until the cap is met (M12.22).

        Eviction is by ``last_seen``, so the incident given up is the one with
        the least recent activity — the one an operator is least likely to still
        be looking at. Returns how many were evicted.
        """
        evicted = 0
        while len(self._incidents) > self._max_incidents:
            oldest = min(
                self._incidents.values(),
                key=lambda incident: (float(incident.last_seen), incident.incident_id),
            )
            del self._incidents[oldest.incident_id]
            evicted += 1
        if evicted:
            self._counters.evicted_incidents += evicted
        return evicted

    def _weep(self, now: float) -> int:
        """Run expiration if the sweep interval has elapsed (M12.22)."""
        if self._next_sweep > 0 and now < self._next_sweep:
            return 0
        self._next_sweep = now + self._sweep_interval
        return self._drop_older_than(now - self._retention_seconds)

    def _drop_older_than(self, cutoff: float) -> int:
        """Drop incidents whose ``last_seen`` predates ``cutoff``.

        Only correlation context is dropped. The alerts that were grouped remain
        in the ``alerts`` table, so what is lost is the relationship, not the
        record (M12.22).
        """
        stale = [
            incident_id
            for incident_id, incident in self._incidents.items()
            if float(incident.last_seen) < float(cutoff)
        ]
        for incident_id in stale:
            del self._incidents[incident_id]
        if stale:
            self._counters.expired_incidents += len(stale)
        return len(stale)

    def expire_old_context(
        self, *, now: float | None = None, retention_seconds: float | None = None
    ) -> int:
        """Drop incidents with no activity inside the retention age (M12.22).

        Exposed so an operator or a background task can force a sweep rather than
        waiting for the next event to trigger one.

        Args:
            now: Current time in epoch seconds. Defaults to the clock.
            retention_seconds: Override the configured age for this sweep.
                Must be positive when supplied.

        Returns:
            How many incidents were dropped.

        Raises:
            ValueError: If ``retention_seconds`` is supplied and is not positive,
                because an unbounded retention would defeat the whole method.
        """
        with self._lock:
            stamp = float(self._clock() if now is None else now)
            if retention_seconds is None:
                cutoff = stamp - self._retention_seconds
            else:
                retention = float(retention_seconds)
                if retention <= 0:
                    raise ValueError("retention_seconds must be positive")
                cutoff = stamp - retention
            return self._drop_older_than(cutoff)

    # -- lifecycle (M12.9) --------------------------------------------------

    def set_status(
        self,
        incident_id: str,
        status: IncidentStatus | str,
        *,
        updated_at: float | None = None,
    ) -> CorrelatedIncident | None:
        """Move an incident to a new lifecycle state (M12.9).

        The move is validated against the transition table *before* anything is
        written, so an illegal transition leaves the store untouched rather than
        half-updated.

        Args:
            incident_id: The incident to change.
            status: The target state.
            updated_at: Epoch seconds to record. Defaults to the clock.

        Returns:
            The updated incident, or ``None`` when the id is unknown. A move to
            the state the incident is already in returns it unchanged.

        Raises:
            ValueError: If ``status`` is not one of the four states.
            InvalidIncidentTransition: If the move is not allowed. ``resolved``
                and ``dismissed`` are terminal, and M12 asks for no reopen.
        """
        with self._lock:
            incident = self._incidents.get(str(incident_id))
            if incident is None:
                return None
            if not validate_transition(incident.normalized_status, status):
                return incident
            stamp = float(self._clock() if updated_at is None else updated_at)
            updated = incident.with_status(status, updated_at=stamp)
            self._incidents[updated.incident_id] = updated
            return updated

    def apply_risk(
        self,
        incident_id: str,
        *,
        score: int,
        band: RiskBand | None = None,
    ) -> CorrelatedIncident | None:
        """Write a risk score onto a stored incident (M12.13).

        Used when a score is recomputed outside ingestion — after a lifecycle
        change, or in a backfill — while :meth:`ingest` writes scores inline. The
        band is derived from the score unless one is supplied, so a stored band
        can never disagree with the score beside it (M12.27).

        Returns:
            The updated incident, or ``None`` when the id is unknown.
        """
        with self._lock:
            incident = self._incidents.get(str(incident_id))
            if incident is None:
                return None
            updated = incident.with_risk(score=score, band=band)
            self._incidents[updated.incident_id] = updated
            return updated

    # -- queries (M12.26) ---------------------------------------------------

    def list_incidents(
        self, query: IncidentQuery | None = None
    ) -> list[CorrelatedIncident]:
        """Return one bounded page of incidents matching ``query`` (M12.26).

        Filtering happens under the lock; the sort happens outside it, on a
        snapshot. The store must not be sorted while the capture thread is
        writing to it, and the snapshot is immutable, so reading it unlocked is
        safe (M12.23).
        """
        resolved = query if query is not None else IncidentQuery()
        with self._lock:
            matched = [
                incident
                for incident in self._incidents.values()
                if resolved.matches(incident)
            ]
        matched.sort(key=resolved.sort_key)
        start = resolved.offset
        return matched[start : start + resolved.limit]

    def count_incidents(self, query: IncidentQuery | None = None) -> int:
        """Return how many incidents match ``query`` (M12.26).

        Applies exactly the filters :meth:`list_incidents` applies — both go
        through :meth:`IncidentQuery.matches` — so a count can never disagree
        with the listing it accompanies.
        """
        resolved = query if query is not None else IncidentQuery()
        with self._lock:
            return sum(
                1
                for incident in self._incidents.values()
                if resolved.matches(incident)
            )

    def recent_incidents(
        self, *, limit: int = DEFAULT_PAGE_SIZE
    ) -> list[CorrelatedIncident]:
        """Return the most recently active incidents (M12.26)."""
        return self.list_incidents(IncidentQuery(limit=limit))

    def open_incidents(
        self, *, limit: int = DEFAULT_PAGE_SIZE
    ) -> list[CorrelatedIncident]:
        """Return incidents still open or under investigation, riskiest first.

        Ordered by risk rather than by recency, because the question this answers
        is "what still needs attention?" rather than "what happened last"
        (M12.26).
        """
        return self.list_incidents(
            IncidentQuery(
                active_only=True,
                limit=limit,
                order=IncidentOrder.RISK,
            )
        )

    def incidents_for_device(
        self,
        device_id: str,
        *,
        limit: int = DEFAULT_PAGE_SIZE,
        active_only: bool = False,
    ) -> list[CorrelatedIncident]:
        """Return incidents involving one M8 device identity, at either end."""
        return self.list_incidents(
            IncidentQuery(device_id=device_id, limit=limit, active_only=active_only)
        )

    def incidents_for_source(
        self,
        source_ip: str,
        *,
        limit: int = DEFAULT_PAGE_SIZE,
        active_only: bool = False,
    ) -> list[CorrelatedIncident]:
        """Return incidents with ``source_ip`` among their source addresses."""
        return self.list_incidents(
            IncidentQuery(source_ip=source_ip, limit=limit, active_only=active_only)
        )

    def incidents_for_connection(
        self,
        connection_id: str,
        *,
        limit: int = DEFAULT_PAGE_SIZE,
        active_only: bool = False,
    ) -> list[CorrelatedIncident]:
        """Return incidents involving one M9 conversation."""
        return self.list_incidents(
            IncidentQuery(
                connection_id=connection_id,
                limit=limit,
                active_only=active_only,
            )
        )

    def incidents_for_rule(
        self,
        rule_id: str,
        *,
        correlation: bool = False,
        limit: int = DEFAULT_PAGE_SIZE,
        active_only: bool = False,
    ) -> list[CorrelatedIncident]:
        """Return incidents a rule contributed to (M12.26).

        Args:
            rule_id: The rule to match.
            correlation: When True, match the *correlation* rule that grouped the
                incident (M12.12) rather than a detector rule.
        """
        if correlation:
            return self.list_incidents(
                IncidentQuery(
                    correlation_rule_id=rule_id,
                    limit=limit,
                    active_only=active_only,
                )
            )
        return self.list_incidents(
            IncidentQuery(rule_id=rule_id, limit=limit, active_only=active_only)
        )

    def incidents_by_risk(
        self,
        *,
        min_risk_score: int = 0,
        max_risk_score: int | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        active_only: bool = False,
    ) -> list[CorrelatedIncident]:
        """Return incidents inside a risk-score range, highest score first."""
        return self.list_incidents(
            IncidentQuery(
                min_risk_score=min_risk_score,
                max_risk_score=max_risk_score,
                limit=limit,
                active_only=active_only,
                order=IncidentOrder.RISK,
            )
        )

    def incidents_in_range(
        self,
        *,
        since: float,
        until: float | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        active_only: bool = False,
    ) -> list[CorrelatedIncident]:
        """Return incidents whose extent overlaps a time range (M12.26)."""
        return self.list_incidents(
            IncidentQuery(
                since=since,
                until=until,
                limit=limit,
                active_only=active_only,
            )
        )

    # -- diagnostics (M12.34) ----------------------------------------------

    def stats(self) -> dict[str, object]:
        """Return the store's counters and its configured bounds (M12.34).

        Read under the lock so the numbers describe one instant rather than a
        mixture of two. Counters are diagnostics only: nothing here can affect a
        correlation decision or a score.
        """
        with self._lock:
            return {
                "incidents": len(self._incidents),
                "active_incidents": sum(
                    1
                    for incident in self._incidents.values()
                    if incident.normalized_status.value in ACTIVE_STATUSES
                ),
                "seen_events": len(self._seen_events),
                "max_incidents": self._max_incidents,
                "retention_seconds": self._retention_seconds,
                "seen_event_capacity": self._seen_event_capacity,
                "max_members": self._max_members,
                "max_reasons": self._max_reasons,
                "events_seen": self._counters.events_seen,
                "incidents_created": self._counters.incidents_created,
                "incidents_updated": self._counters.incidents_updated,
                "correlations_matched": self._counters.correlations_matched,
                "duplicates_skipped": self._counters.duplicates_skipped,
                "expired_incidents": self._counters.expired_incidents,
                "evicted_incidents": self._counters.evicted_incidents,
                "scored": self._counters.scored,
                "score_errors": self._counters.score_errors,
                "errors": self._counters.errors,
            }

    def reset(self) -> None:
        """Clear every held incident, the deduplication index and the counters.

        Runtime state only: nothing here touches the database, so the alerts an
        incident referred to are unaffected (M12.22).
        """
        with self._lock:
            self._incidents.clear()
            self._seen_events.clear()
            self._seen_order.clear()
            self._next_sweep = 0.0
            self._counters = CorrelationCounters()


@dataclass(frozen=True)
class IncidentQuery:
    """A bounded, deterministic incident query (M12.26).

    One value object rather than a dozen keyword arguments, because the read
    paths (:meth:`IncidentRegistry.list_incidents` and
    :meth:`IncidentRegistry.count_incidents`) must apply *identical* filters — a
    count that disagreed with its listing would make paging a lie.

    Every filter is optional and the filters combine conjunctively. ``limit`` and
    ``offset`` are validated at construction, so an unusable query is rejected
    before it reaches the store.

    Attributes:
        statuses: Restrict to these lifecycle states.
        active_only: Restrict to ``open``/``investigating`` (M12.9). Combines
            with ``statuses`` by intersection: asking for an active ``resolved``
            incident correctly returns nothing.
        device_id: Incidents involving this M8 device identity at either end.
        connection_id: Incidents involving this M9 conversation.
        source_ip: Incidents with this source address among their members.
        destination_ip: Incidents with this destination address.
        rule_id: Incidents a given *detector* rule contributed to.
        correlation_rule_id: Incidents a given M12.12 correlation rule grouped.
        min_risk_score / max_risk_score: Inclusive bounds on ``risk_score``.
        min_confidence: Inclusive lower bound on the correlation confidence.
        since / until: A time range over the incident's extent. An incident is
            selected when its ``[start_time, last_seen]`` **overlaps**
            ``[since, until)`` — a query about a span, so an incident that began
            before ``since`` but was still active inside it is included.
        limit: Page size, ``1..DEFAULT_MAX_PAGE_SIZE``.
        offset: Rows to skip.
        order: One of :class:`IncidentOrder`.
    """

    statuses: tuple[str, ...] = ()
    active_only: bool = False
    device_id: str | None = None
    connection_id: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    rule_id: str | None = None
    correlation_rule_id: str | None = None
    min_risk_score: int | None = None
    max_risk_score: int | None = None
    min_confidence: float | None = None
    since: float | None = None
    until: float | None = None
    limit: int = DEFAULT_PAGE_SIZE
    offset: int = 0
    order: IncidentOrder = IncidentOrder.RECENT

    def __post_init__(self) -> None:
        """Normalize the status filter and validate the page bounds.

        Raises:
            ValueError: If the page bounds are unusable, a risk bound is outside
                ``0..100``, the risk bounds are inverted, or the time range is
                inverted. Rejecting an inverted range rather than returning an
                empty page is deliberate: an empty result would look like "no
                incidents" when the query was simply wrong.
        """
        object.__setattr__(self, "statuses", _normalized_statuses(self.statuses))
        if not isinstance(self.order, IncidentOrder):
            # Accept the string form too. A query reaches this store from an
            # HTTP parameter as text, and normalising it here means the ``is``
            # comparisons in :meth:`sort_key` cannot silently fall through to
            # the default ordering and report a result in the wrong order.
            object.__setattr__(
                self, "order", IncidentOrder(str(self.order).strip().lower())
            )
        if self.limit < 1:
            raise ValueError("limit must be at least 1")
        if self.limit > DEFAULT_MAX_PAGE_SIZE:
            raise ValueError(f"limit must not exceed {DEFAULT_MAX_PAGE_SIZE}")
        if self.offset < 0:
            raise ValueError("offset must not be negative")
        for value in (self.min_risk_score, self.max_risk_score):
            if value is not None and not 0 <= int(value) <= 100:
                raise ValueError("risk score bounds must be within 0..100")
        if (
            self.min_risk_score is not None
            and self.max_risk_score is not None
            and int(self.min_risk_score) > int(self.max_risk_score)
        ):
            raise ValueError("min_risk_score must not exceed max_risk_score")
        if (
            self.since is not None
            and self.until is not None
            and float(self.since) > float(self.until)
        ):
            raise ValueError("since must not be after until")

    def allowed_statuses(self) -> frozenset[str] | None:
        """Return the effective status set, or ``None`` when unrestricted.

        Combining the explicit filter with ``active_only`` by intersection is
        what makes the two filters composable instead of ambiguous.
        """
        if self.active_only:
            requested = set(self.statuses) if self.statuses else set(ACTIVE_STATUSES)
            return frozenset(requested & ACTIVE_STATUSES)
        if self.statuses:
            return frozenset(self.statuses)
        return None

    def matches(self, incident: CorrelatedIncident) -> bool:
        """Return True when ``incident`` satisfies every supplied filter."""
        allowed = self.allowed_statuses()
        if allowed is not None and incident.normalized_status.value not in allowed:
            return False
        identity = incident.identity
        if self.device_id is not None and self.device_id not in identity.devices:
            return False
        if (
            self.connection_id is not None
            and self.connection_id not in identity.connections
        ):
            return False
        if (
            self.source_ip is not None
            and self.source_ip not in identity.source_addresses
        ):
            return False
        if (
            self.destination_ip is not None
            and self.destination_ip not in identity.destination_addresses
        ):
            return False
        if self.rule_id is not None and self.rule_id not in incident.rule_ids:
            return False
        if (
            self.correlation_rule_id is not None
            and self.correlation_rule_id not in incident.correlation_rule_ids
        ):
            return False
        if (
            self.min_risk_score is not None
            and incident.risk_score < int(self.min_risk_score)
        ):
            return False
        if (
            self.max_risk_score is not None
            and incident.risk_score > int(self.max_risk_score)
        ):
            return False
        if (
            self.min_confidence is not None
            and float(incident.correlation_confidence) < float(self.min_confidence)
        ):
            return False
        if self.since is not None and float(incident.last_seen) < float(self.since):
            return False
        if self.until is not None and float(incident.start_time) >= float(self.until):
            return False
        return True

    def sort_key(self, incident: CorrelatedIncident) -> tuple[object, ...]:
        """Return a total ordering key for this query's ordering.

        Total because every option ends in ``incident_id``: two incidents with
        the same timestamp still have a defined relative order, so a page of
        results is stable across identical queries (M12.26).
        """
        if self.order is IncidentOrder.OLDEST:
            return (float(incident.last_seen), incident.incident_id)
        if self.order is IncidentOrder.RISK:
            return (
                -int(incident.risk_score),
                -float(incident.last_seen),
                incident.incident_id,
            )
        if self.order is IncidentOrder.CONFIDENCE:
            return (
                -float(incident.correlation_confidence),
                -float(incident.last_seen),
                incident.incident_id,
            )
        return (-float(incident.last_seen), incident.incident_id)


__all__ = [
    "CorrelationCounters",
    "CorrelationOutcome",
    "DEFAULT_MAX_INCIDENTS",
    "DEFAULT_MAX_PAGE_SIZE",
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_RETENTION_SECONDS",
    "DEFAULT_SEEN_EVENT_CAPACITY",
    "IncidentEvaluator",
    "IncidentOrder",
    "IncidentQuery",
    "IncidentRegistry",
    "IncidentScorer",
    "IncidentVerdict",
]
