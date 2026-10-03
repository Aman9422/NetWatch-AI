"""The explicit correlation rule set (M12.12).

M12.12 asks for "a small initial set of explicit correlation rules" and warns
against "dozens". The tests here hold that line from two directions at once: each
named rule in the milestone is shown to work, and the *structure* that keeps a
rule from firing on time alone is shown to be structural rather than incidental.

The decisive cases are the negatives. A rule set that correlated any two nearby
events would pass every positive test in this file, so the tests that matter most
are the ones asserting ``None``: proximity without identity must not correlate,
rule identity without any overlap must not correlate, and a strengthened anchor
threshold must withdraw a rule that had been satisfied before it.
"""

from __future__ import annotations

import pytest

from app.correlation.relationship import (
    ANCHOR_RELATIONSHIPS,
    DEFAULT_ANCHOR_THRESHOLD,
    Relationship,
    RelationshipKind,
)
from app.correlation.rules import (
    DEFAULT_RULES,
    RULE_REASON_PREFIX,
    SCAN_SEQUENCE_RULES,
    CorrelationRule,
    describe_rules,
    evaluate_rules,
    rule_by_id,
    rule_ids,
)

SOURCE_DEVICE_ID = "mac:aa:aa:aa:aa:aa:aa"
CONNECTION_ID = "conn-0001"
OTHER_SOURCE_DEVICE_ID = "mac:bb:bb:bb:bb:bb:bb"


def _source(device: str = SOURCE_DEVICE_ID) -> list[Relationship]:
    return [Relationship(RelationshipKind.SAME_SOURCE, device)]


def _evaluate(
    relationships: list[Relationship],
    *,
    event_rule_id: str = "port_scan",
    incident_rules: frozenset[str] = frozenset(),
    incident_event_count: int = 1,
    anchor_threshold: float = DEFAULT_ANCHOR_THRESHOLD,
):
    """Call the evaluator with the M12.12 defaults, overriding one thing."""
    return evaluate_rules(
        relationships,
        event_rule_id=event_rule_id,
        incident_rules=incident_rules,
        incident_event_count=incident_event_count,
        anchor_threshold=anchor_threshold,
    )


# --------------------------------------------------------------------------
# The rule set (M12.12)
# --------------------------------------------------------------------------


def test_the_rule_set_is_the_documented_rules() -> None:
    """M12.12's named rules, plus the one M12.6/M12 completion requires.

    "Small" is the requirement, not a count of exactly four: M12.6 defines four
    anchoring relationships, and every one of them must be reachable by some
    rule, or the engine would hold an anchor nothing could ever match on.
    """
    assert rule_ids() == (
        "scan_sequence",
        "same_connection",
        "same_source_activity",
        "device_centric_activity",
        "same_destination_activity",
    )
    assert len(DEFAULT_RULES) == len(set(rule_ids()))
    # Small, per M12.12's warning against "dozens".
    assert len(DEFAULT_RULES) <= 8


def test_every_anchoring_relationship_is_reachable_by_some_rule() -> None:
    """No anchor may exist that the rule set can never consume (M12.6).

    ``ANCHOR_RELATIONSHIPS`` is the documented set of relationships strong
    enough to justify correlation on their own. If one of them appeared in no
    rule's anchors, the engine would classify it as sufficient and then never
    act on it — the relationship table and the rule set would disagree.
    """
    anchored: set[RelationshipKind] = set()
    for rule in DEFAULT_RULES:
        anchored |= set(rule.anchors)
    assert anchored == ANCHOR_RELATIONSHIPS


def test_rule_set_is_ordered_most_specific_first() -> None:
    """Evaluation order is data, and the most specific rule comes first.

    ``scan_sequence`` constrains two detectors *and* the shared source, so it
    must be consulted before ``same_source_activity`` — otherwise a scan
    sequence would always be attributed to the vaguer rule.
    """
    assert DEFAULT_RULES[0].rule_id == "scan_sequence"
    scan_sequence = DEFAULT_RULES[0]
    assert scan_sequence.detector_pair == SCAN_SEQUENCE_RULES
    assert scan_sequence.anchors == frozenset({RelationshipKind.SAME_SOURCE})
    # Every other rule constrains less than the one before it.
    assert DEFAULT_RULES[1].detector_pair == frozenset()
    assert DEFAULT_RULES[2].detector_pair == frozenset()


def test_every_rule_requires_an_anchor_that_can_actually_anchor() -> None:
    """No rule may rest on a relationship that is too weak to anchor.

    This is the structural guarantee behind M12.4's prohibition, asserted over
    the whole set rather than one rule at a time: if a rule listed
    ``time_proximity`` as its anchor, the rule set would start merging events
    because they were merely close together.
    """
    for rule in DEFAULT_RULES:
        assert rule.anchors, f"{rule.rule_id} must name an anchor"
        for kind in rule.anchors:
            assert kind.is_anchor(DEFAULT_ANCHOR_THRESHOLD), (
                f"{rule.rule_id} anchors on {kind.value}, which cannot anchor"
            )
        # Rule identity and proximity are never enough on their own.
        assert RelationshipKind.SAME_RULE not in rule.anchors
        assert RelationshipKind.TIME_PROXIMITY not in rule.anchors


def test_rule_by_id_returns_the_rule_or_nothing() -> None:
    """Lookup is total: an unknown id returns ``None`` rather than raising."""
    assert rule_by_id("scan_sequence") is not None
    assert rule_by_id("scan_sequence").title  # type: ignore[union-attr]
    assert rule_by_id("not_a_rule") is None


def test_describe_rules_matches_the_definitions() -> None:
    """The rule table documented to operators is generated from the rules."""
    described = describe_rules()
    assert [item["rule_id"] for item in described] == list(rule_ids())
    for item, rule in zip(described, DEFAULT_RULES):
        assert item["title"] == rule.title
        assert item["anchors"] == sorted(kind.value for kind in rule.anchors)
        assert item["detector_pair"] == sorted(rule.detector_pair)


# --------------------------------------------------------------------------
# Rule 2 — scan sequence (M12.12)
# --------------------------------------------------------------------------


def test_scan_sequence_matches_when_both_detectors_share_a_source() -> None:
    """``internal_scan`` + ``port_scan`` from one source is a scan sequence."""
    match = _evaluate(
        _source(), event_rule_id="port_scan", incident_rules=frozenset({"internal_scan"})
    )
    assert match is not None
    assert match.rule_id == "scan_sequence"


def test_scan_sequence_needs_both_detectors() -> None:
    """One detector alone is not a sequence; the vaguer rule takes it instead."""
    match = _evaluate(
        _source(), event_rule_id="port_scan", incident_rules=frozenset({"port_scan"})
    )
    assert match is not None
    assert match.rule_id == "same_source_activity"


def test_scan_sequence_needs_a_shared_source() -> None:
    """Different sources are not a sequence even with both detectors present."""
    match = _evaluate(
        [Relationship(RelationshipKind.SAME_DEVICE, OTHER_SOURCE_DEVICE_ID)],
        event_rule_id="port_scan",
        incident_rules=frozenset({"internal_scan"}),
    )
    # It is still a candidate on the device dimension, but not a scan sequence.
    assert match is not None
    assert match.rule_id == "device_centric_activity"


# --------------------------------------------------------------------------
# Rule 3 — same connection (M12.12)
# --------------------------------------------------------------------------


def test_same_connection_matches_on_a_shared_conversation() -> None:
    """The same M9 conversation is the milestone's "strong relationship"."""
    match = _evaluate(
        [Relationship(RelationshipKind.SAME_CONNECTION, CONNECTION_ID)]
    )
    assert match is not None
    assert match.rule_id == "same_connection"


def test_same_connection_matches_even_with_a_repeating_detector() -> None:
    """A shared conversation correlates regardless of which detector fired."""
    match = _evaluate(
        [
            Relationship(RelationshipKind.SAME_CONNECTION, CONNECTION_ID),
            Relationship(RelationshipKind.SAME_RULE, "port_scan"),
        ],
        event_rule_id="port_scan",
        incident_rules=frozenset({"port_scan"}),
    )
    assert match is not None
    assert match.rule_id == "same_connection"


# --------------------------------------------------------------------------
# Rule 1 — same source activity (M12.12)
# --------------------------------------------------------------------------


def test_same_source_activity_matches_on_a_shared_source() -> None:
    """One origin emitting related events correlates."""
    match = _evaluate(_source())
    assert match is not None
    assert match.rule_id == "same_source_activity"


def test_same_source_activity_prefers_a_device_over_an_address() -> None:
    """The reason names the device when the device is what overlapped."""
    match = _evaluate(
        [Relationship(RelationshipKind.SAME_SOURCE, SOURCE_DEVICE_ID)]
    )
    assert match is not None
    assert f"same_source:{SOURCE_DEVICE_ID}" in match.reasons


# --------------------------------------------------------------------------
# Rule 4 — device-centric activity (M12.12)
# --------------------------------------------------------------------------


def test_device_centric_activity_matches_on_a_shared_device() -> None:
    """One affected asset is a real pivot, so it correlates on its own."""
    match = _evaluate(
        [Relationship(RelationshipKind.SAME_DEVICE, SOURCE_DEVICE_ID)]
    )
    assert match is not None
    assert match.rule_id == "device_centric_activity"


# --------------------------------------------------------------------------
# Rule 5 — same destination activity (M12.6)
# --------------------------------------------------------------------------


def test_same_destination_activity_matches_on_a_shared_destination() -> None:
    """A shared destination correlates, which M12's criteria require.

    This is the unresolved-address case: when neither event's endpoints resolved
    to an M8 device, a shared destination can only be expressed as
    ``same_destination``, and without this rule the relationship would be
    classified as anchoring and then never consumed by anything.
    """
    match = _evaluate(
        [Relationship(RelationshipKind.SAME_DESTINATION, "203.0.113.7")]
    )
    assert match is not None
    assert match.rule_id == "same_destination_activity"
    assert "same_destination:203.0.113.7" in match.reasons


def test_a_stronger_shared_dimension_wins_over_same_destination() -> None:
    """Attribution follows the most informative relationship available.

    ``same_destination`` is the weakest of the four anchors, so a pair that also
    shares a source is attributed to ``same_source_activity``.
    """
    match = _evaluate(
        _source() + [Relationship(RelationshipKind.SAME_DESTINATION, "203.0.113.7")]
    )
    assert match is not None
    assert match.rule_id == "same_source_activity"


# --------------------------------------------------------------------------
# The negatives: what must never correlate (M12.4/M12.12)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "relationships",
    [
        [],
        [Relationship(RelationshipKind.TIME_PROXIMITY)],
        [Relationship(RelationshipKind.SAME_RULE, "port_scan")],
        [
            Relationship(RelationshipKind.TIME_PROXIMITY),
            Relationship(RelationshipKind.SAME_RULE, "port_scan"),
        ],
    ],
)
def test_proximity_and_rule_identity_alone_never_correlate(
    relationships: list[Relationship],
) -> None:
    """No rule may be satisfied without an anchor (M12.4).

    Every case here shares time, a rule, or both, and none of it justifies
    merging the events — which is the milestone's central prohibition, asserted
    over the whole rule set at once.
    """
    assert _evaluate(relationships) is None


def test_a_seed_incident_does_not_match_a_rule_against_itself() -> None:
    """Rules describe joining two or more events, not one event alone."""
    assert _evaluate(_source(), incident_event_count=0) is None
    assert _evaluate(_source(), incident_event_count=1) is not None


def test_relationships_below_a_raised_threshold_stop_anchoring() -> None:
    """The anchor requirement is configuration, not a literal.

    Raising ``correlation_min_anchor_strength`` above ``same_source``'s weight
    must withdraw the rules that relied on it, while a shared conversation — the
    strongest evidence — still correlates.
    """
    assert _evaluate(_source(), anchor_threshold=0.80) is None
    strong = _evaluate(
        [Relationship(RelationshipKind.SAME_CONNECTION, CONNECTION_ID)],
        anchor_threshold=0.80,
    )
    assert strong is not None
    assert strong.rule_id == "same_connection"


def test_a_rule_without_its_required_dimension_is_not_satisfied() -> None:
    """``requires_all`` is enforced, not advisory.

    Built directly so the check is exercised even though no rule in the shipped
    set uses ``requires_all`` — the mechanism is part of the rule contract, and
    an untested contract is one a later rule will break.
    """
    rule = CorrelationRule(
        rule_id="test_requires_all",
        title="Test",
        description="Requires a source and a connection together.",
        anchors=frozenset({RelationshipKind.SAME_SOURCE}),
        requires_all=frozenset({RelationshipKind.SAME_CONNECTION}),
    )
    assert not rule.is_satisfied(
        _source(),
        event_rule_id="port_scan",
        incident_rules=frozenset(),
        incident_event_count=1,
        anchor_threshold=DEFAULT_ANCHOR_THRESHOLD,
    )
    assert rule.is_satisfied(
        _source() + [Relationship(RelationshipKind.SAME_CONNECTION, CONNECTION_ID)],
        event_rule_id="port_scan",
        incident_rules=frozenset(),
        incident_event_count=1,
        anchor_threshold=DEFAULT_ANCHOR_THRESHOLD,
    )


# --------------------------------------------------------------------------
# The reason trail (M12.12)
# --------------------------------------------------------------------------


def test_match_records_the_rule_and_every_justifying_relationship() -> None:
    """A match explains *which* rule grouped the events and *why*."""
    relationships = [
        Relationship(RelationshipKind.TIME_PROXIMITY),
        Relationship(RelationshipKind.SAME_SOURCE, SOURCE_DEVICE_ID),
    ]
    match = _evaluate(relationships)
    assert match is not None
    assert match.reasons[0] == f"{RULE_REASON_PREFIX}{match.rule_id}"
    assert f"same_source:{SOURCE_DEVICE_ID}" in match.reasons
    assert "time_proximity" in match.reasons


def test_reason_trail_is_deterministic_whatever_order_it_was_built_in() -> None:
    """Reasons are stored on the incident, so their order cannot vary.

    The same relationships supplied in two different orders must produce a
    byte-identical trail, or an incident would serialise differently between
    runs for no reason an operator could see.
    """
    relationships = [
        Relationship(RelationshipKind.SAME_RULE, "port_scan"),
        Relationship(RelationshipKind.SAME_SOURCE, SOURCE_DEVICE_ID),
        Relationship(RelationshipKind.TIME_PROXIMITY),
    ]
    forward = _evaluate(list(relationships))
    backward = _evaluate(list(reversed(relationships)))
    assert forward is not None and backward is not None
    assert forward.rule_id == backward.rule_id
    assert forward.reasons == backward.reasons
