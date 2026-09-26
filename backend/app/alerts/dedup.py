"""Alert deduplication: the key and the window (M11.9/M11.10).

A detector is allowed to report the same behaviour repeatedly — M10 findings are
observations, and a port scan is observed once per packet burst. Turning every
observation into its own alert would flood the alert store with near-identical
rows, so an alert is raised once per distinct incident and later observations
within the window are folded into it.

**The deduplication key** (M11.9) is, exactly::

    rule_id | source_ip | destination_ip | protocol | device_id | connection_id

with ``-`` standing in for every component that is absent. The components are
joined in that fixed order, so the key is stable, greppable and safe to store in
``alerts.correlation_key`` — which is the column M2 documents as "optional key
used to deduplicate related alerts".

Three deliberate properties of that key:

* **Time is not a component.** Time is expressed by the *window* instead, so the
  key describes the incident and the window describes how long it lasts.
* **The connection is present only when the caller supplies one.** A detection
  finding carries no connection reference — M10 anchors findings to addresses,
  not to M9 records — so the engine's own path leaves the component as ``-``.
  Supplying a connection id therefore distinguishes incidents that share a rule
  and endpoints, which is what M11.27's "different connection" case asks for.
* **The device component is a single value.** When both ends resolve, the source
  device wins, because every M10 detector reports a source-initiated behaviour.
  The destination device is then redundant: the same source and destination
  address already imply the same destination device.

**The window** (M11.10) is bounded and configurable, never unlimited: an existing
alert is a duplicate candidate only while the observation falls inside a window
of at most :data:`MAX_DEDUP_WINDOW_SECONDS`. Once the window has expired a new
alert is created, so a source that keeps scanning all day produces one alert per
window rather than one alert forever.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from app.detection.finding import DetectionFinding

#: Rendered in place of a component the finding did not provide.
ABSENT_COMPONENT = "-"

#: Separator between key components. ``|`` cannot occur in an IP address, a
#: protocol label, a device id or a connection id, so the key cannot be forged by
#: a crafted value.
KEY_SEPARATOR = "|"

#: Upper bound on the deduplication window. M11.10 forbids an unlimited window;
#: a day is the ceiling, so a misconfigured value cannot silently swallow every
#: future incident of the same rule between the same endpoints.
MAX_DEDUP_WINDOW_SECONDS = 86_400.0

#: Default window, in step with ``settings.alert_dedup_window_seconds``.
DEFAULT_DEDUP_WINDOW_SECONDS = 300.0


def _component(value: str | None) -> str:
    """Render one key component, using ``-`` for an absent value."""
    if value is None:
        return ABSENT_COMPONENT
    text = str(value).strip()
    return text if text else ABSENT_COMPONENT


@dataclass(frozen=True)
class DeduplicationKey:
    """The identity of an incident a repeated observation belongs to (M11.9)."""

    rule_id: str
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None
    device_id: str | None = None
    connection_id: str | None = None

    @classmethod
    def from_finding(
        cls,
        finding: "DetectionFinding",
        *,
        connection_id: str | None = None,
    ) -> "DeduplicationKey":
        """Build the key for a detection finding (M11.9).

        Args:
            finding: The M10 finding the alert would be created from.
            connection_id: An optional M9 connection reference. M10 findings do
                not carry one, so this is supplied only when the caller resolved
                a conversation for the finding.

        Raises:
            ValueError: If the finding names no rule. A finding without a rule id
                is not alertable, so building a key for it is a programming
                error rather than something to paper over.
        """
        if not finding.rule_id:
            raise ValueError("A detection finding must name a rule to be deduplicated")
        return cls(
            rule_id=str(finding.rule_id).strip(),
            source_ip=finding.source_ip,
            destination_ip=finding.destination_ip,
            protocol=finding.protocol,
            device_id=_device_component(finding),
            connection_id=connection_id,
        )

    def components(self) -> dict[str, str]:
        """Return the rendered components, in key order, for diagnostics."""
        return {
            "rule_id": _component(self.rule_id),
            "source_ip": _component(self.source_ip),
            "destination_ip": _component(self.destination_ip),
            "protocol": _component(self.protocol),
            "device_id": _component(self.device_id),
            "connection_id": _component(self.connection_id),
        }

    def value(self) -> str:
        """Return the storable key string (M11.9)."""
        return KEY_SEPARATOR.join(self.components().values())


def _device_component(finding: "DetectionFinding") -> str | None:
    """Return the single device component for a finding (M11.9).

    The source device is preferred; the destination device is the fallback, so an
    alert from a detector that only identified the target is still groupable by
    device. An unresolved address contributes nothing rather than a placeholder
    device (M11.15).
    """
    return finding.source_device_id or finding.destination_device_id


@dataclass(frozen=True)
class DeduplicationWindow:
    """The bounded interval inside which a repeated observation is a duplicate.

    Attributes:
        seconds: Window length. Must be positive and at most
            :data:`MAX_DEDUP_WINDOW_SECONDS` (M11.10).
    """

    seconds: float = DEFAULT_DEDUP_WINDOW_SECONDS

    def __post_init__(self) -> None:
        """Reject a window M11.10 forbids.

        Raises:
            ValueError: If the window is not positive or exceeds the ceiling. An
                unlimited window would merge genuinely separate incidents, which
                M11.9 explicitly forbids.
        """
        value = float(self.seconds)
        if value <= 0:
            raise ValueError("The deduplication window must be positive")
        if value > MAX_DEDUP_WINDOW_SECONDS:
            raise ValueError(
                "The deduplication window must not exceed "
                f"{MAX_DEDUP_WINDOW_SECONDS:.0f} seconds"
            )

    def cutoff(self, at: float) -> float:
        """Return the earliest creation time still inside the window at ``at``.

        An alert created exactly at the cutoff is *inside* the window: the
        boundary is inclusive, so the window is closed at both ends and a test
        can pin the edge exactly.
        """
        return float(at) - float(self.seconds)

    def contains(self, created_at: float, at: float) -> bool:
        """Return True when an alert created at ``created_at`` is a duplicate at ``at``.

        A candidate created *after* ``at`` — which can only happen if a clock
        moved backwards — is treated as inside the window. Deduplicating is the
        safe direction: the alternative would be creating a second alert for an
        observation already recorded.
        """
        return (float(at) - float(created_at)) <= float(self.seconds)
