"""How two events can be related, and how strong each relationship is (M12.6/M12.7).

M12.4 is explicit: "correlation rules must be explicit" and events must not be
merged "simply because they occurred close together". This module is where that
requirement becomes data rather than intent.

Two separate ideas live here, and keeping them apart is the whole point:

**Relationship strength** — how much a *relationship* says that two events belong
to the same activity. It is a property of the shared dimension, not of how
serious anything is.

**Anchor vs. strengthening** — whether a relationship is strong enough, *on its
own*, to justify correlating two events at all. Only anchoring kinds may do
that. Every other kind may only make an already-justified relationship
stronger.

The table (M12.6), which is normative::

    relationship       weight   anchors?   why
    ----------------   ------   --------   ----------------------------------
    same_connection     0.90      yes      the same conversation (M9 id) is the
                                          strongest evidence of one activity
    same_device         0.75      yes      one affected asset is a real pivot
    same_source         0.70      yes      one origin emitting related events
    same_destination    0.55      yes      one target being contacted
    same_rule           0.35      no       the same detector firing twice is
                                          expected and says little on its own
    time_proximity      0.25      no       merely happening at the same time

The default anchor threshold is 0.55, which is exactly ``same_destination``'s
weight. That is deliberate: it makes the boundary of "anchor" legible — the four
identity relationships anchor, rule identity and time proximity do not — instead
of resting on a number someone has to look up. An operator may raise or lower it
via ``settings.correlation_min_anchor_strength``, and the classification follows
the configured value rather than being hard-coded.

**These weights are not a risk score and must never be reported as one.**
Correlation strength answers "are these the same incident?"; risk answers "how
much does this deserve attention?" (M12.16). A pair of perfectly correlated
low-severity events is strongly correlated and barely risky, and the model has to
be able to say both at once.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

#: Weight of each relationship, in ``[0, 1]`` (M12.6). See the module docstring
#: for the reasoning behind each value.
RELATIONSHIP_WEIGHTS: dict[str, float] = {
    "same_connection": 0.90,
    "same_device": 0.75,
    "same_source": 0.70,
    "same_destination": 0.55,
    "same_rule": 0.35,
    "time_proximity": 0.25,
}

#: The default strength a relationship must reach on its own to justify
#: correlating two events (M12.4/M12.6). Equal to ``same_destination``'s weight,
#: so the four identity relationships anchor and nothing else does.
DEFAULT_ANCHOR_THRESHOLD = 0.55


class RelationshipKind(str, Enum):
    """Every way two events can be related (M12.6)."""

    SAME_CONNECTION = "same_connection"
    SAME_DEVICE = "same_device"
    SAME_SOURCE = "same_source"
    SAME_DESTINATION = "same_destination"
    SAME_RULE = "same_rule"
    TIME_PROXIMITY = "time_proximity"

    @property
    def weight(self) -> float:
        """Return this relationship's strength, in ``[0, 1]`` (M12.6)."""
        return RELATIONSHIP_WEIGHTS[self.value]

    @property
    def label(self) -> str:
        """Return a short human-readable name for reports and reasons."""
        return _LABELS[self.value]

    @property
    def description(self) -> str:
        """Return the documented meaning of this relationship."""
        return _DESCRIPTIONS[self.value]

    def is_anchor(self, threshold: float = DEFAULT_ANCHOR_THRESHOLD) -> bool:
        """Return True when this relationship may justify correlation alone.

        Args:
            threshold: The configured anchor strength
                (``settings.correlation_min_anchor_strength``). A relationship
                anchors when its own weight reaches it.
        """
        return self.weight >= float(threshold)


_LABELS: dict[str, str] = {
    "same_connection": "same connection",
    "same_device": "same device",
    "same_source": "same source",
    "same_destination": "same destination",
    "same_rule": "same detection rule",
    "time_proximity": "time proximity",
}

_DESCRIPTIONS: dict[str, str] = {
    "same_connection": (
        "Both events reference the same M9 conversation, which is the strongest "
        "evidence that they describe one piece of activity."
    ),
    "same_device": (
        "Both events concern the same M8 device identity, so one asset is "
        "involved at both ends of the relationship."
    ),
    "same_source": (
        "Both events originate from the same source address or source device."
    ),
    "same_destination": (
        "Both events are directed at the same destination address or device."
    ),
    "same_rule": (
        "Both events were produced by the same detection rule. Expected for a "
        "repeating detector, so it strengthens but never anchors."
    ),
    "time_proximity": (
        "The two events occurred close together. Necessary for a relationship "
        "to be plausible and never sufficient on its own (M12.4)."
    ),
}

#: Every relationship that anchors at the default threshold. Exported so tests
#: and documentation read the same set the engine applies.
ANCHOR_RELATIONSHIPS: frozenset[RelationshipKind] = frozenset(
    kind for kind in RelationshipKind if kind.is_anchor(DEFAULT_ANCHOR_THRESHOLD)
)


@dataclass(frozen=True)
class Relationship:
    """One established relationship between two correlation events (M12.6).

    Attributes:
        kind: Which relationship was established.
        detail: The shared value that established it — the connection id, the
            device id, the rule id — or ``None`` when the relationship carries no
            single value (time proximity). Recorded so a correlation reason can
            name *why*, not merely *that*, which is what makes an incident
            explainable rather than asserted.
    """

    kind: RelationshipKind
    detail: str | None = None

    @property
    def strength(self) -> float:
        """Return the relationship's documented weight (M12.6)."""
        return self.kind.weight

    @property
    def label(self) -> str:
        """Return the short human-readable name of the relationship."""
        return self.kind.label

    def is_anchor(self, threshold: float = DEFAULT_ANCHOR_THRESHOLD) -> bool:
        """Return True when this relationship may justify correlation alone."""
        return self.kind.is_anchor(threshold)

    def reason(self) -> str:
        """Return a stable ``kind:detail`` string for an incident's reasons.

        Deliberately machine-readable and stable: reasons are stored on the
        incident and read by tests and by the API, so they must not depend on
        punctuation changes or on a locale.
        """
        if self.detail is None:
            return self.kind.value
        return f"{self.kind.value}:{self.detail}"


def describe_relationships() -> list[dict[str, object]]:
    """Return the relationship table as data, for docs and verification output.

    This exists so the documented table and the applied table cannot drift: the
    design doc and ``scripts/verify_m12.py`` both render what this returns.
    """
    return [
        {
            "kind": kind.value,
            "label": kind.label,
            "weight": kind.weight,
            "anchors": kind.is_anchor(),
            "description": kind.description,
        }
        for kind in RelationshipKind
    ]


__all__ = [
    "ANCHOR_RELATIONSHIPS",
    "DEFAULT_ANCHOR_THRESHOLD",
    "RELATIONSHIP_WEIGHTS",
    "Relationship",
    "RelationshipKind",
    "describe_relationships",
]
