"""The explicit correlation rules (M12.12).

M12.12 asks for "a small initial set of explicit correlation rules" and warns
against creating "dozens". This module therefore defines five, each of which
corresponds to a named rule in the milestone, and each of which is expressed as
data rather than as control flow so it can be read, tested and printed.

The five rules, in the order they are evaluated — most specific first, so a pair
that satisfies two rules is attributed to the more informative one:

1. **``scan_sequence``** (M12.12 Rule 2) — an internal scan *and* a port scan from
   the same source, close in time. The most specific rule: it names two detectors
   as well as the shared source.
2. **``same_connection``** (M12.12 Rule 3) — both events reference the same M9
   conversation. A "strong relationship" in the milestone's own words.
3. **``same_source_activity``** (M12.12 Rule 1) — multiple alerts from the same
   source device or address inside the window.
4. **``device_centric_activity``** (M12.12 Rule 4) — multiple alerts concerning
   the same affected device inside the window.
5. **``same_destination_activity``** (M12.6 "Same Destination") — related events
   aimed at the same destination address or device inside the window.

Rule 5 exists because M12.6 defines ``same_destination`` as an *anchoring*
relationship — its weight is exactly the default anchor threshold, and it is a
member of :data:`~app.correlation.relationship.ANCHOR_RELATIONSHIPS` — while the
milestone's four *example* rules (M12.12) happen to reference only source,
connection and device. M12's completion criteria require same-destination
correlation to work, so without a rule consuming it an anchor-capable
relationship would exist that nothing could ever match on. That is the case that
matters in practice: when an address does **not** resolve to an M8 device, a
shared destination can only be expressed as ``same_destination``, and two events
sharing only it would otherwise be uncorrelatable. It is placed last because its
weight is the lowest of the four anchors, so any stronger shared dimension wins
the attribution.

Every rule requires an **anchoring** relationship, and the anchor threshold is
configuration rather than a literal. That is the structural guarantee behind
M12.4's "do not merge events simply because they occurred close together": the
rules can only be satisfied by identity overlap, because the only non-identity
relationship — time proximity — is below the anchor threshold and no rule lists
it as an anchor. Time proximity appears in reasons and raises the correlation
confidence; it can never, by itself, cause a correlation.

A rule that matched produces a :class:`CorrelationMatch` carrying the rule's
identifier and the full reason trail, which the incident records. An incident
therefore says not only "these alerts were grouped" but which rule grouped them
and which shared values justified it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.correlation.relationship import (
    Relationship,
    RelationshipKind,
)

#: Detector rule ids whose co-occurrence from one source is a scan sequence
#: (M12.12 Rule 2). Both must be present.
SCAN_SEQUENCE_RULES: frozenset[str] = frozenset({"internal_scan", "port_scan"})

#: Prefix marking a reason as "this rule matched", so an incident's reason trail
#: distinguishes the rule that grouped the events from the relationships that
#: justified it.
RULE_REASON_PREFIX = "matched:"


@dataclass(frozen=True)
class CorrelationRule:
    """One explicit correlation rule (M12.12).

    Attributes:
        rule_id: Stable identifier, stored in an incident's reason trail.
        title: Short human-readable name.
        description: What the rule says, in words.
        anchors: Relationship kinds, at least one of which must be present *and*
            strong enough to anchor. This is the rule's identity requirement.
        requires_all: Relationship kinds that must *all* be present in addition
            to the anchor. Used where a rule needs more than one dimension.
        detector_pair: Detector rule ids that must both appear across the two
            sides of the comparison for this rule to apply.
        min_incident_events: How many events the incident must already hold. The
            volume rules ask for at least one, so they describe the joining of
            two or more events rather than a lone event with itself.
    """

    rule_id: str
    title: str
    description: str
    anchors: frozenset[RelationshipKind]
    requires_all: frozenset[RelationshipKind] = field(default_factory=frozenset)
    detector_pair: frozenset[str] = field(default_factory=frozenset)
    min_incident_events: int = 1

    def matched_anchors(
        self, relationships: list[Relationship], *, anchor_threshold: float
    ) -> list[Relationship]:
        """Return the relationships satisfying this rule's anchor requirement."""
        return [
            item
            for item in relationships
            if item.kind in self.anchors and item.kind.is_anchor(anchor_threshold)
        ]

    def is_satisfied(
        self,
        relationships: list[Relationship],
        *,
        event_rule_id: str,
        incident_rules: frozenset[str],
        incident_event_count: int,
        anchor_threshold: float,
    ) -> bool:
        """Return True when this rule's conditions all hold.

        Args:
            relationships: The relationships established between the incoming
                event and the incident.
            event_rule_id: The incoming event's detector rule id.
            incident_rules: The detector rule ids already present in the
                incident.
            incident_event_count: How many events the incident already holds.
            anchor_threshold: The configured anchor strength.
        """
        if incident_event_count < self.min_incident_events:
            return False
        if not self.matched_anchors(relationships, anchor_threshold=anchor_threshold):
            return False
        present_kinds = {item.kind for item in relationships}
        if not self.requires_all.issubset(present_kinds):
            return False
        if self.detector_pair:
            combined = set(incident_rules) | {event_rule_id}
            if not self.detector_pair.issubset(combined):
                return False
        return True


@dataclass(frozen=True)
class CorrelationMatch:
    """The rule that grouped an event, and the reasons it did (M12.12).

    Attributes:
        rule_id: Identifier of the rule that matched.
        title: Human-readable name of the matched rule.
        reasons: The full reason trail, deterministically ordered: the matched
            rule first, then every established relationship as
            ``kind:detail``.
    """

    rule_id: str
    title: str
    reasons: tuple[str, ...]


def _ordered_reasons(
    rule_id: str, relationships: list[Relationship]
) -> tuple[str, ...]:
    """Return the reason trail for a match, in a stable order.

    Sorted by ``(kind, detail)`` so the same set of relationships always
    produces the same trail, whatever order the comparison happened to build it
    in. Reasons are stored on an incident, so they must not vary between runs.
    """
    reasons = [f"{RULE_REASON_PREFIX}{rule_id}"]
    reasons.extend(
        item.reason()
        for item in sorted(
            relationships, key=lambda item: (item.kind.value, item.detail or "")
        )
    )
    return tuple(reasons)


#: The rule set, in evaluation order (M12.12). Most specific first, so a pair
#: matching several rules is attributed to the most informative one.
DEFAULT_RULES: tuple[CorrelationRule, ...] = (
    CorrelationRule(
        rule_id="scan_sequence",
        title="Scan sequence",
        description=(
            "An internal scan and a port scan observed from the same source "
            "close together, which is a scan followed by follow-up activity "
            "rather than two unrelated detections."
        ),
        anchors=frozenset({RelationshipKind.SAME_SOURCE}),
        detector_pair=SCAN_SEQUENCE_RULES,
    ),
    CorrelationRule(
        rule_id="same_connection",
        title="Same connection",
        description=(
            "Both events reference the same tracked conversation, the strongest "
            "available evidence that they describe one piece of activity."
        ),
        anchors=frozenset({RelationshipKind.SAME_CONNECTION}),
    ),
    CorrelationRule(
        rule_id="same_source_activity",
        title="Same source activity",
        description=(
            "Related events emitted by the same source device or address within "
            "the correlation window."
        ),
        anchors=frozenset({RelationshipKind.SAME_SOURCE}),
    ),
    CorrelationRule(
        rule_id="device_centric_activity",
        title="Device-centric activity",
        description=(
            "Related events concerning the same affected device within the "
            "correlation window."
        ),
        anchors=frozenset({RelationshipKind.SAME_DEVICE}),
    ),
    CorrelationRule(
        rule_id="same_destination_activity",
        title="Same destination activity",
        description=(
            "Related events aimed at the same destination address or device "
            "within the correlation window."
        ),
        anchors=frozenset({RelationshipKind.SAME_DESTINATION}),
    ),
)


def rule_ids() -> tuple[str, ...]:
    """Return every rule identifier, in evaluation order."""
    return tuple(rule.rule_id for rule in DEFAULT_RULES)


def rule_by_id(rule_id: str) -> CorrelationRule | None:
    """Return the rule with ``rule_id``, or ``None`` when there is no such rule."""
    for rule in DEFAULT_RULES:
        if rule.rule_id == rule_id:
            return rule
    return None


def evaluate_rules(
    relationships: list[Relationship],
    *,
    event_rule_id: str,
    incident_rules: frozenset[str],
    incident_event_count: int,
    anchor_threshold: float,
    rules: tuple[CorrelationRule, ...] | None = None,
) -> CorrelationMatch | None:
    """Return the first rule satisfied by a comparison, or ``None`` (M12.12).

    Evaluation is in :data:`DEFAULT_RULES` order — most specific first — and stops
    at the first match, which keeps the attribution deterministic when several
    rules would apply.

    Returns:
        A :class:`CorrelationMatch` naming the rule and carrying the reason
        trail, or ``None`` when no rule is satisfied. ``None`` is a normal
        answer: it means the events are not related under the explicit rule set,
        and the engine starts a new incident instead of forcing a merge.
    """
    candidates = DEFAULT_RULES if rules is None else rules
    for rule in candidates:
        if rule.is_satisfied(
            relationships,
            event_rule_id=event_rule_id,
            incident_rules=incident_rules,
            incident_event_count=incident_event_count,
            anchor_threshold=anchor_threshold,
        ):
            return CorrelationMatch(
                rule_id=rule.rule_id,
                title=rule.title,
                reasons=_ordered_reasons(rule.rule_id, relationships),
            )
    return None


def describe_rules() -> list[dict[str, object]]:
    """Return the rule set as data, for docs and verification output (M12.12)."""
    return [
        {
            "rule_id": rule.rule_id,
            "title": rule.title,
            "description": rule.description,
            "anchors": sorted(kind.value for kind in rule.anchors),
            "requires_all": sorted(kind.value for kind in rule.requires_all),
            "detector_pair": sorted(rule.detector_pair),
            "min_incident_events": rule.min_incident_events,
        }
        for rule in DEFAULT_RULES
    ]


__all__ = [
    "CorrelationMatch",
    "CorrelationRule",
    "DEFAULT_RULES",
    "RULE_REASON_PREFIX",
    "SCAN_SEQUENCE_RULES",
    "describe_rules",
    "evaluate_rules",
    "rule_by_id",
    "rule_ids",
]
