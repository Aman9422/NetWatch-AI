"""Correlation identity: what makes two events related (M12.4).

M12.4 requires that "correlation rules must be explicit" and that events are not
merged "simply because they occurred close together". This module makes that
concrete by reducing each event to a small set of *identity dimensions* and then
answering a narrow question: which dimensions do these two things share?

The dimensions are the ones M12.4 lists — source, destination, device,
connection, rule, and time — and each maps onto exactly one
:class:`~app.correlation.relationship.RelationshipKind`. Nothing here decides
whether a relationship is *enough*; that is the anchor rule in
:mod:`app.correlation.relationship` and the rule set in
:mod:`app.correlation.rules`.

**Identity is a set, not a single value, and that matters.** An event may know
both a device identity (M8) and the address it resolved to. If one event knows
the device and another only knows the address, they are still the same actor, so
the comparison is between *sets* of known identities rather than between two
chosen representatives. A comparison that picked one value per side would miss
exactly the case where enrichment succeeded on one observation and not the other
— which is the common case, not the edge case.

Each comparison therefore keeps devices and addresses apart and prefers the
device when both overlap. A device identity is the stronger, and reporting
``same_source:dev-7`` is more useful to an operator than
``same_source:10.0.0.5`` for the same relationship.

Every result is deterministic: overlaps are reported as the lowest element of a
sorted set, so the same pair of events always produces the same reasons in the
same order (M12.17's determinism requirement applies to correlation too).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.correlation.event import CorrelationEvent
from app.correlation.relationship import Relationship, RelationshipKind
from app.correlation.window import CorrelationWindow


def _clean(values: tuple[str | None, ...]) -> frozenset[str]:
    """Return the non-empty, trimmed members of ``values`` as a set."""
    return frozenset(
        text for text in (str(value).strip() if value else "" for value in values) if text
    )


def _first_shared(left: frozenset[str], right: frozenset[str]) -> str | None:
    """Return the lowest shared member of two sets, or ``None``.

    "Lowest of the sorted overlap" rather than "any member" is what makes a
    correlation reason reproducible: an unordered set membership test would let
    the reported detail vary between runs, and an incident's reasons are stored.
    """
    shared = left & right
    return min(shared) if shared else None


@dataclass(frozen=True)
class IdentityIndex:
    """The identity dimensions one event — or one incident — can match on.

    Devices and addresses are held apart so a comparison can prefer a device
    match and fall back to an address match, which is the only way to relate an
    enriched event to an unenriched one.

    Attributes:
        source_devices: Source device identities (M8).
        source_addresses: Source addresses.
        destination_devices: Destination device identities (M8).
        destination_addresses: Destination addresses.
        devices: Every device identity involved, at either end.
        connections: M9 conversation references.
        rules: Detector rule ids.
    """

    source_devices: frozenset[str] = field(default_factory=frozenset)
    source_addresses: frozenset[str] = field(default_factory=frozenset)
    destination_devices: frozenset[str] = field(default_factory=frozenset)
    destination_addresses: frozenset[str] = field(default_factory=frozenset)
    devices: frozenset[str] = field(default_factory=frozenset)
    connections: frozenset[str] = field(default_factory=frozenset)
    rules: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_event(cls, event: CorrelationEvent) -> IdentityIndex:
        """Build the identity index of a normalized event (M12.4)."""
        return cls(
            source_devices=_clean((event.source_device_id,)),
            source_addresses=_clean((event.source_ip,)),
            destination_devices=_clean((event.destination_device_id,)),
            destination_addresses=_clean((event.destination_ip,)),
            devices=event.device_ids(),
            connections=_clean((event.connection_id,)),
            rules=_clean((event.rule_id,)),
        )

    @classmethod
    def from_sets(
        cls,
        *,
        source_devices: tuple[str, ...] = (),
        source_addresses: tuple[str, ...] = (),
        destination_devices: tuple[str, ...] = (),
        destination_addresses: tuple[str, ...] = (),
        connections: tuple[str, ...] = (),
        rules: tuple[str, ...] = (),
    ) -> IdentityIndex:
        """Build an index from aggregate sets, for an incident.

        The ``devices`` union is derived rather than passed, so a caller cannot
        supply an index whose device set contradicts its source and destination
        device sets — a state that would make ``same_device`` and
        ``same_source`` disagree about the same fact.
        """
        source_device_set = _clean(source_devices)
        destination_device_set = _clean(destination_devices)
        return cls(
            source_devices=source_device_set,
            source_addresses=_clean(source_addresses),
            destination_devices=destination_device_set,
            destination_addresses=_clean(destination_addresses),
            devices=source_device_set | destination_device_set,
            connections=_clean(connections),
            rules=_clean(rules),
        )

    def merged_with(self, other: IdentityIndex) -> IdentityIndex:
        """Return the union of two indexes, for growing an incident's identity."""
        return IdentityIndex(
            source_devices=self.source_devices | other.source_devices,
            source_addresses=self.source_addresses | other.source_addresses,
            destination_devices=(
                self.destination_devices | other.destination_devices
            ),
            destination_addresses=(
                self.destination_addresses | other.destination_addresses
            ),
            devices=self.devices | other.devices,
            connections=self.connections | other.connections,
            rules=self.rules | other.rules,
        )

    def is_empty(self) -> bool:
        """Return True when the index carries no identity at all."""
        return not any(
            (
                self.source_devices,
                self.source_addresses,
                self.destination_devices,
                self.destination_addresses,
                self.connections,
                self.rules,
            )
        )


def identity_relationships(
    left: IdentityIndex, right: IdentityIndex
) -> list[Relationship]:
    """Return every identity relationship two indexes share (M12.4/M12.6).

    Time is deliberately absent: proximity is added by the caller, because an
    event-to-event comparison and an event-to-incident comparison measure it
    against different references. Keeping it out of here is what stops the two
    paths from drifting apart.

    The returned list is in the fixed order of :class:`RelationshipKind`, and
    each relationship is reported at most once.
    """
    relationships: list[Relationship] = []

    connection = _first_shared(left.connections, right.connections)
    if connection is not None:
        relationships.append(
            Relationship(RelationshipKind.SAME_CONNECTION, connection)
        )

    device = _first_shared(left.devices, right.devices)
    if device is not None:
        relationships.append(Relationship(RelationshipKind.SAME_DEVICE, device))

    source = _first_shared(left.source_devices, right.source_devices) or _first_shared(
        left.source_addresses, right.source_addresses
    )
    if source is not None:
        relationships.append(Relationship(RelationshipKind.SAME_SOURCE, source))

    destination = _first_shared(
        left.destination_devices, right.destination_devices
    ) or _first_shared(left.destination_addresses, right.destination_addresses)
    if destination is not None:
        relationships.append(
            Relationship(RelationshipKind.SAME_DESTINATION, destination)
        )

    rule = _first_shared(left.rules, right.rules)
    if rule is not None:
        relationships.append(Relationship(RelationshipKind.SAME_RULE, rule))

    return relationships


def relationships_between(
    first: CorrelationEvent,
    second: CorrelationEvent,
    *,
    window: CorrelationWindow,
) -> list[Relationship]:
    """Return every relationship between two events (M12.4/M12.6).

    This is the pairwise question: *may these two be related at all?* The answer
    includes :data:`~app.correlation.relationship.RelationshipKind.TIME_PROXIMITY`
    when they are close in time, but proximity is only ever a *strengthening*
    relationship — it never anchors, so a pair that share nothing but a timestamp
    still produces no justification for correlation (M12.4).
    """
    relationships = identity_relationships(
        IdentityIndex.from_event(first), IdentityIndex.from_event(second)
    )
    if window.are_proximal(first.timestamp, second.timestamp):
        relationships.append(Relationship(RelationshipKind.TIME_PROXIMITY))
    return relationships


def relationships_with_identity(
    event: CorrelationEvent,
    identity: IdentityIndex,
    *,
    reference_time: float,
    window: CorrelationWindow,
) -> list[Relationship]:
    """Return every relationship between an event and an incident's identity.

    Args:
        event: The incoming event.
        identity: The incident's aggregate identity, from
            :meth:`IdentityIndex.from_sets`.
        reference_time: The incident's ``last_seen`` in epoch seconds. Proximity
            is measured against the incident's most recent activity, not against
            an arbitrary member.
        window: The bounded correlation window.

    Returns:
        The identity relationships plus ``time_proximity`` when the event is
        close to the incident's latest activity.
    """
    relationships = identity_relationships(IdentityIndex.from_event(event), identity)
    if window.are_proximal(event.timestamp, reference_time):
        relationships.append(Relationship(RelationshipKind.TIME_PROXIMITY))
    return relationships


def anchor_relationships(
    relationships: list[Relationship], *, threshold: float
) -> list[Relationship]:
    """Return only the relationships strong enough to anchor (M12.4/M12.6).

    An anchor is what justifies correlating at all. With the default threshold
    these are the four identity relationships; rule identity and time proximity
    are excluded by weight, which is precisely M12.4's "do not merge events
    simply because they occurred close together".
    """
    return [item for item in relationships if item.is_anchor(threshold)]


def has_anchor(relationships: list[Relationship], *, threshold: float) -> bool:
    """Return True when at least one relationship may anchor correlation."""
    return any(item.is_anchor(threshold) for item in relationships)


__all__ = [
    "IdentityIndex",
    "anchor_relationships",
    "has_anchor",
    "identity_relationships",
    "relationships_between",
    "relationships_with_identity",
]
