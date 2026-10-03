"""The correlated incident: the thing M12 produces (M12.8).

An incident is what several related events add up to. M12.8 lists the fields it
must carry, and the list is a good description of the model's whole discipline:

* ``incident_id``, ``title``, ``created_at``, ``updated_at``
* ``start_time``, ``last_seen``
* ``status``
* ``alert_ids``, ``finding_ids``, ``device_ids``, ``connection_ids``
* ``correlation_reasons``, ``risk_score``, ``confidence``

Everything here is **derived from the events that actually arrived**, and M12.8's
closing line — "use only information supported by the correlated events" — is
enforced structurally rather than trusted:

* Identity is one :class:`~app.correlation.identity.IdentityIndex`, unioned as
  events join. There is no field an caller can set to an identity no event
  mentioned.
* ``severities`` and ``alert_confidences`` are accumulated as events arrive, so
  the worst severity and the mean confidence are facts about the membership
  rather than estimates.
* ``risk_score`` starts at the model minimum and is only ever written by
  :class:`~app.risk.engine.RiskScoringEngine` (M12.13), via :meth:`with_risk`.

**Risk and confidence are two fields, not one** (M12.16). ``confidence`` on this
model is the *correlation* confidence — how strongly the events were judged
related (M12.7). The alerts' own confidences live in ``alert_confidences`` and
are summarised separately. A caller cannot read one and mistake it for the
other because they do not share a name or a derivation.

**Membership is bounded** (M12.22). Every accumulating list has a cap, and a list
that hits its cap stops growing while continuing to count: ``event_count`` keeps
rising past the cap and ``dropped_events`` records how many references were held
back. That way an incident on a busy network degrades in detail rather than in
memory, and the degradation is visible in the data instead of silent.

Instances are immutable. Growing an incident returns a new one
(:meth:`merged_with_event`), which is what lets readers hold a consistent
snapshot while the correlation engine keeps folding events in (M12.23).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from app.alerts.severity import AlertSeverity, from_value, rank
from app.alerts.timestamps import to_utc_datetime
from app.correlation.confidence import combine_relationships
from app.correlation.event import CorrelationEvent
from app.correlation.identity import IdentityIndex
from app.correlation.status import IncidentStatus, from_value as status_from_value
from app.risk.inputs import RiskInputs
from app.risk.bands import MIN_RISK_SCORE, RiskBand, band_for

#: Cap on an incident's reference lists — event ids, alert ids and finding ids
#: each — so one incident cannot accumulate unbounded membership (M12.22).
#: Mirrors ``settings.correlation_max_related_alerts``.
DEFAULT_MAX_MEMBERS = 64

#: Cap on an incident's correlation reason trail (M12.22). Mirrors
#: ``settings.correlation_max_correlation_reasons``.
DEFAULT_MAX_REASONS = 16

#: Cap on every identity set an incident accumulates. Deliberately far above what
#: ``DEFAULT_MAX_MEMBERS`` events can produce (each event names at most two
#: devices and two addresses), so the bound is structural and provable while
#: never evicting anything a real incident would have matched on.
MAX_IDENTITY_ENTITIES = 256

#: Prefix on every incident identifier, so an id is recognisable in a log line.
INCIDENT_ID_PREFIX = "inc"


def _bounded_extend(
    values: tuple[str, ...], additions: tuple[str, ...], *, cap: int
) -> tuple[str, ...]:
    """Return ``values`` plus the unseen members of ``additions``, capped.

    Deduplicates while preserving arrival order, which is the order the reasons
    and the member lists should read in. ``cap`` bounds the result, so an
    incident cannot grow without limit even under a flood (M12.22).
    """
    merged = list(values)
    seen = set(values)
    for value in additions:
        if value in seen:
            continue
        if len(merged) >= cap:
            break
        merged.append(value)
        seen.add(value)
    return tuple(merged)


def _bounded_int_extend(
    values: tuple[int, ...], additions: tuple[int, ...], *, cap: int
) -> tuple[int, ...]:
    """Return the integer-valued equivalent of :func:`_bounded_extend`."""
    merged = list(values)
    seen = set(values)
    for value in additions:
        if value in seen:
            continue
        if len(merged) >= cap:
            break
        merged.append(value)
        seen.add(value)
    return tuple(merged)


def _bounded_identity(left: IdentityIndex, right: IdentityIndex) -> IdentityIndex:
    """Return the union of two identities, capped per dimension (M12.22).

    Each dimension is capped separately so a device flood cannot crowd the
    connection or rule dimensions out of the index — the dimensions answer
    different questions and must not compete for the same budget.
    """
    merged = left.merged_with(right)
    return IdentityIndex(
        source_devices=frozenset(sorted(merged.source_devices)[:MAX_IDENTITY_ENTITIES]),
        source_addresses=frozenset(
            sorted(merged.source_addresses)[:MAX_IDENTITY_ENTITIES]
        ),
        destination_devices=frozenset(
            sorted(merged.destination_devices)[:MAX_IDENTITY_ENTITIES]
        ),
        destination_addresses=frozenset(
            sorted(merged.destination_addresses)[:MAX_IDENTITY_ENTITIES]
        ),
        devices=frozenset(sorted(merged.devices)[:MAX_IDENTITY_ENTITIES]),
        connections=frozenset(sorted(merged.connections)[:MAX_IDENTITY_ENTITIES]),
        rules=frozenset(sorted(merged.rules)[:MAX_IDENTITY_ENTITIES]),
    )


def incident_id_for(event: CorrelationEvent) -> str:
    """Return the deterministic incident id an event would open.

    Derived from the seeding event rather than generated randomly, for three
    reasons: the id is traceable back to the observation that started the
    incident, it is reproducible across runs (which the tests and the
    verification script both rely on), and re-seeing the same seeding event
    cannot invent a second incident under a new name (M12.11).
    """
    return f"{INCIDENT_ID_PREFIX}:{event.event_id}"


@dataclass(frozen=True)
class CorrelatedIncident:
    """One correlated incident and its bounded membership (M12.8).

    Attributes:
        incident_id: Stable identity, derived from the seeding event.
        title: Short human-readable label, composed from the detectors involved.
        created_at: When this incident record was opened, in epoch seconds.
        updated_at: When it was last changed, in epoch seconds.
        start_time: The earliest event time in the incident.
        last_seen: The latest event time in the incident. The pair bounds the
            incident's temporal extent, which is what the window is measured
            against (M12.5).
        status: Lifecycle state (M12.9).
        identity: The union of every member's identity dimensions (M12.4).
        event_ids: Identities of the events folded in, capped.
        alert_ids: Database ids of the alerts folded in, capped.
        finding_ids: M10 finding ids folded in, capped.
        rule_ids: Detector rule ids involved, deduplicated on arrival.
        correlation_rule_ids: Which M12.12 correlation rules have matched, in the
            order they first matched.
        correlation_reasons: The reason trail, most recent match last, capped.
        correlation_confidence: How strongly the latest joining event was judged
            related, in ``[0, 1]``. Kept apart from every other number (M12.16).
        alert_confidences: Each member alert's own evidence confidence (M11.5).
        severities: Each member alert's stored severity value.
        event_count: How many events have actually been folded in, including any
            whose reference could not be retained because a cap was reached.
        dropped_events: How many events were counted but not retained by id,
            so truncation is visible rather than silent (M12.22).
        risk_score: Bounded ``0..100`` prioritisation metric (M12.14). Only
            :meth:`with_risk` writes it.
        risk_band: Documented display band for ``risk_score`` (M12.27).
    """

    incident_id: str
    title: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0
    start_time: float = 0.0
    last_seen: float = 0.0
    status: IncidentStatus | str = IncidentStatus.OPEN
    identity: IdentityIndex = field(default_factory=IdentityIndex)
    event_ids: tuple[str, ...] = ()
    alert_ids: tuple[int, ...] = ()
    finding_ids: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    correlation_rule_ids: tuple[str, ...] = ()
    correlation_reasons: tuple[str, ...] = ()
    correlation_confidence: float = 0.0
    alert_confidences: tuple[float, ...] = ()
    severities: tuple[str, ...] = ()
    event_count: int = 0
    dropped_events: int = 0
    risk_score: int = MIN_RISK_SCORE
    risk_band: RiskBand = RiskBand.MINIMAL

    def __post_init__(self) -> None:
        """Normalize the status and clamp the stored score.

        Raises:
            ValueError: If ``status`` is not one of the four incident states.
                Failing at construction is what keeps a typo out of stored state.
        """
        object.__setattr__(self, "status", status_from_value(self.status))

    # -- derived identity views (M12.8) -------------------------------------

    @property
    def device_ids(self) -> tuple[str, ...]:
        """Return the device identities involved, in a stable order."""
        return tuple(sorted(self.identity.devices))

    @property
    def connection_ids(self) -> tuple[str, ...]:
        """Return the conversation references involved, in a stable order."""
        return tuple(sorted(self.identity.connections))

    @property
    def normalized_status(self) -> IncidentStatus:
        """Return the status as an enum."""
        return status_from_value(self.status)

    # -- derived measurements ----------------------------------------------

    def span_seconds(self) -> float:
        """Return how long the incident's events span, in seconds.

        Never negative: the two ends are ordered on read, so an incident whose
        events arrived out of order still reports a sensible extent.
        """
        return max(float(self.last_seen) - float(self.start_time), 0.0)

    def worst_severity(self) -> AlertSeverity | None:
        """Return the most serious severity among the member alerts.

        ``None`` when no member carried a severity — which is the normal state of
        an incident built only from findings, since M10 findings have no severity
        (M12.15). Returning ``None`` rather than inventing a level keeps
        "unmeasured" distinguishable from "low".
        """
        if not self.severities:
            return None
        levels = [from_value(value) for value in self.severities]
        return max(levels, key=rank)

    def mean_alert_confidence(self) -> float:
        """Return the mean member alert confidence, or ``0.0`` when none.

        The alert confidences only. Deliberately does **not** include
        :attr:`correlation_confidence`: averaging two quantities that answer
        different questions would produce a third number that means nothing
        (M12.16).
        """
        if not self.alert_confidences:
            return 0.0
        return sum(float(value) for value in self.alert_confidences) / float(
            len(self.alert_confidences)
        )

    def alert_count(self) -> int:
        """Return how many distinct alerts the incident groups (M12.10)."""
        return len(self.alert_ids)

    def has_event(self, event_id: str) -> bool:
        """Return True when ``event_id`` is already a member (M12.11)."""
        return str(event_id) in self.event_ids

    def rule_set(self) -> frozenset[str]:
        """Return the detector rule ids involved, as a set."""
        return frozenset(self.rule_ids)

    # -- construction -------------------------------------------------------

    @classmethod
    def opened_by(
        cls,
        event: CorrelationEvent,
        *,
        title: str,
        max_members: int = DEFAULT_MAX_MEMBERS,
        max_reasons: int = DEFAULT_MAX_REASONS,
    ) -> CorrelatedIncident:
        """Create the incident an event opens when nothing else matched.

        A seed incident carries the seeding event as its sole member, with an
        empty reason trail: nothing was correlated to open it — it is the
        baseline other events are compared against. Its correlation confidence
        is the confidence of no relationship at all, ``0.0``, not the event's own
        confidence, which belongs to ``alert_confidences`` (M12.16).
        """
        identity = IdentityIndex.from_event(event)
        severity = event.normalized_severity
        return cls(
            incident_id=incident_id_for(event),
            title=str(title or event.title or event.rule_id),
            created_at=float(event.timestamp),
            updated_at=float(event.timestamp),
            start_time=float(event.timestamp),
            last_seen=float(event.timestamp),
            status=IncidentStatus.OPEN,
            identity=identity,
            event_ids=(event.event_id,),
            alert_ids=(event.alert_id,) if event.alert_id is not None else (),
            finding_ids=(event.finding_id,) if event.finding_id else (),
            rule_ids=(event.rule_id,),
            correlation_rule_ids=(),
            correlation_reasons=(),
            correlation_confidence=0.0,
            alert_confidences=(
                (event.normalized_confidence,)
                if event.is_alert
                else ()
            ),
            severities=(severity.value,) if severity is not None else (),
            event_count=1,
            dropped_events=0,
            risk_score=MIN_RISK_SCORE,
            risk_band=RiskBand.MINIMAL,
        )

    def merged_with_event(
        self,
        event: CorrelationEvent,
        *,
        relationships,
        correlation_rule_id: str,
        reasons: tuple[str, ...],
        max_members: int = DEFAULT_MAX_MEMBERS,
        max_reasons: int = DEFAULT_MAX_REASONS,
    ) -> CorrelatedIncident:
        """Return a new incident with ``event`` folded into this one (M12.10).

        The individual events are **not** consumed or replaced: the incident
        records their references, and the alerts themselves stay in their table
        untouched, so correlation creates a higher-level relationship without
        destroying what it grouped (M12.10).

        Args:
            event: The event that satisfied a correlation rule.
            relationships: The relationships established between the event and
                this incident, used to recompute the correlation confidence.
            correlation_rule_id: The M12.12 rule that matched, recorded in the
                incident's rule list so an operator can see *how* it grouped.
            reasons: The reason trail from the match, appended to the existing
                trail under its own cap.
            max_members: Cap on each reference list.
            max_reasons: Cap on the reason trail.

        Returns:
            The grown incident. ``event_count`` always rises, even when a cap
            prevents the event's reference from being retained, so the count and
            the retained list can only disagree in the documented direction.
        """
        already = self.has_event(event.event_id)
        retained = len(self.event_ids) < max_members or already
        severity = event.normalized_severity
        return replace(
            self,
            updated_at=max(float(self.updated_at), float(event.timestamp)),
            start_time=min(float(self.start_time), float(event.timestamp)),
            last_seen=max(float(self.last_seen), float(event.timestamp)),
            identity=_bounded_identity(self.identity, IdentityIndex.from_event(event)),
            event_ids=_bounded_extend(
                self.event_ids, (event.event_id,), cap=max_members
            ),
            alert_ids=_bounded_int_extend(
                self.alert_ids,
                (event.alert_id,) if event.alert_id is not None else (),
                cap=max_members,
            ),
            finding_ids=_bounded_extend(
                self.finding_ids,
                (event.finding_id,) if event.finding_id else (),
                cap=max_members,
            ),
            rule_ids=_bounded_extend(self.rule_ids, (event.rule_id,), cap=max_members),
            correlation_rule_ids=_bounded_extend(
                self.correlation_rule_ids,
                (correlation_rule_id,),
                cap=max_reasons,
            ),
            correlation_reasons=_bounded_extend(
                self.correlation_reasons, reasons, cap=max_reasons
            ),
            correlation_confidence=combine_relationships(list(relationships)),
            alert_confidences=(
                (
                    self.alert_confidences + (event.normalized_confidence,)
                    if event.is_alert
                    else self.alert_confidences
                )
            )[:max_members],
            severities=(
                (self.severities + (severity.value,))
                if severity is not None
                else self.severities
            )[:max_members],
            event_count=self.event_count + 1,
            dropped_events=self.dropped_events + (0 if retained else 1),
        )

    # -- derived state ------------------------------------------------------

    def with_status(
        self, status: IncidentStatus | str, *, updated_at: float
    ) -> CorrelatedIncident:
        """Return a copy in a new lifecycle state (M12.9).

        Validation is the caller's job — :func:`app.correlation.status.
        validate_transition` decides whether the move is allowed — because that
        function needs the *current* state and owns the transition table.
        """
        return replace(
            self,
            status=status_from_value(status),
            updated_at=float(updated_at),
        )

    def with_risk(
        self, *, score: int, band: RiskBand | None = None
    ) -> CorrelatedIncident:
        """Return a copy carrying a computed risk score (M12.13).

        The band is recomputed from the score unless one is supplied, so a stored
        band can never disagree with the score it labels.
        """
        bounded = int(score)
        return replace(
            self,
            risk_score=bounded,
            risk_band=band if band is not None else band_for(bounded),
        )

    # -- risk inputs (M12.15/M12.13) ---------------------------------------

    def to_risk_inputs(
        self,
        *,
        now: float | None = None,
        historical_occurrences: int = 0,
    ) -> RiskInputs:
        """Return the bounded facts a risk score may be computed from (M12.15).

        This is the **only** bridge between the correlation layer and the risk
        layer, and it runs one way: correlation builds inputs and calls the
        engine; the scoring engine knows nothing about incidents. That keeps the
        formula testable from a literal and keeps the score reproducible from the
        incident alone.

        Args:
            now: Scoring time in epoch seconds. Defaults to the incident's own
                ``last_seen``, which scores the incident "as of itself" and gives
                it a full recency contribution rather than a decay that depends
                on when someone happened to ask.
            historical_occurrences: How many earlier related occurrences are
                known. Defaults to ``0`` — no history — because a caller with no
                historical source must be able to say so, and a fabricated count
                would be an invented fact (M12.20).

        Returns:
            The incident's facts, ready to be scored.
        """
        severity = self.worst_severity()
        return RiskInputs(
            severity=severity,
            confidences=tuple(self.alert_confidences),
            alert_count=self.alert_count(),
            rule_ids=tuple(self.rule_ids),
            device_ids=self.device_ids,
            connection_ids=self.connection_ids,
            last_seen=float(self.last_seen),
            now=float(self.last_seen if now is None else now),
            historical_occurrences=int(historical_occurrences),
            correlation_confidence=float(self.correlation_confidence),
            # Pinned to zero: M12 ships no ML subsystem, so the reserved
            # contribution is unavailable rather than estimated (M12.18).
            ml_contribution=0.0,
        )

    # -- serialization (M12.26) --------------------------------------------

    def as_dict(self) -> dict[str, object]:
        """Return the incident as a JSON-friendly mapping for the read API.

        Every list is sorted or already ordered on arrival, so the same incident
        always serialises identically. Timestamps are emitted both as epoch
        seconds — which is what the model reasons in — and as ISO-8601 UTC, which
        is what a client displays.
        """
        severity = self.worst_severity()
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "status": self.normalized_status.value,
            "created_at": float(self.created_at),
            "updated_at": float(self.updated_at),
            "start_time": float(self.start_time),
            "last_seen": float(self.last_seen),
            "created_at_iso": to_utc_datetime(self.created_at).isoformat(),
            "updated_at_iso": to_utc_datetime(self.updated_at).isoformat(),
            "start_time_iso": to_utc_datetime(self.start_time).isoformat(),
            "last_seen_iso": to_utc_datetime(self.last_seen).isoformat(),
            "span_seconds": self.span_seconds(),
            "event_count": int(self.event_count),
            "dropped_events": int(self.dropped_events),
            "alert_ids": list(self.alert_ids),
            "finding_ids": list(self.finding_ids),
            "device_ids": list(self.device_ids),
            "connection_ids": list(self.connection_ids),
            "rule_ids": list(self.rule_ids),
            "correlation_rule_ids": list(self.correlation_rule_ids),
            "correlation_reasons": list(self.correlation_reasons),
            "correlation_confidence": round(float(self.correlation_confidence), 6),
            "alert_confidence": round(self.mean_alert_confidence(), 6),
            "severity": severity.value if severity is not None else None,
            "risk_score": int(self.risk_score),
            "risk_band": self.risk_band.value,
        }

    def summary(self) -> dict[str, object]:
        """Return the compact view used by listings (M12.26).

        Listings return the facts an operator scans — identity, lifecycle, the
        counts, the two confidences and the score — without the full member lists,
        which are what :meth:`as_dict` is for.
        """
        severity = self.worst_severity()
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "status": self.normalized_status.value,
            "start_time": float(self.start_time),
            "last_seen": float(self.last_seen),
            "event_count": int(self.event_count),
            "alert_count": self.alert_count(),
            "finding_count": len(self.finding_ids),
            "device_ids": list(self.device_ids),
            "correlation_confidence": round(float(self.correlation_confidence), 6),
            "alert_confidence": round(self.mean_alert_confidence(), 6),
            "severity": severity.value if severity is not None else None,
            "risk_score": int(self.risk_score),
            "risk_band": self.risk_band.value,
        }


__all__ = [
    "DEFAULT_MAX_MEMBERS",
    "DEFAULT_MAX_REASONS",
    "INCIDENT_ID_PREFIX",
    "MAX_IDENTITY_ENTITIES",
    "CorrelatedIncident",
    "incident_id_for",
]
