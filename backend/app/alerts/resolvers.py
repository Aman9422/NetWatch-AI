"""Resolve a detection finding into the M7/M9/M8 records that support its alert (M11.13-M11.15).

A finding is deliberately thin: M10 anchors it to addresses and to the devices
those addresses resolved to, never to a packet row or a conversation. Attaching
evidence therefore means *looking the related records up*, and this module is the
one place that does it.

Three properties are deliberate:

* **Every source is injected and optional.** A resolver is a narrow callable, so
  the alert service can be built without a database (unit tests) or with the real
  repositories (runtime) and nothing else changes. A source that is missing is
  simply not consulted.
* **Resolution never fails an alert (M11.26).** Each lookup is an enrichment: a
  database error, an unparseable address or an unexpected source object produces
  no evidence rather than an exception. The alert is worth more than its
  supporting detail.
* **Resolution is bounded (M11.12/M11.13).** Packets are looked for inside a
  window around the observation and capped, conversations are capped, so an
  alert's evidence set is decided by a rule and not by how busy the network was.

An address that resolves to nothing is left unresolved. M11 never invents a
device, a packet or a conversation to fill a gap (M11.15).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from app.alerts.timestamps import to_utc_datetime
from app.persistence.session_factory import SessionFactory

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.detection.finding import DetectionFinding

logger = logging.getLogger(__name__)

# Default bounds. The service passes configured values (M11.23).
DEFAULT_MAX_PACKETS = 5
DEFAULT_PACKET_WINDOW_SECONDS = 5.0
DEFAULT_MAX_CONNECTIONS = 5


@dataclass(frozen=True)
class ResolutionLimits:
    """Bounds on how much related evidence one alert may gather (M11.12).

    Attributes:
        max_packets: Most packet references to attach per alert.
        packet_window_seconds: Half-width of the window searched around the
            observation, so only packets close to the behaviour are considered.
        max_connections: Most conversation references to attach per alert.
    """

    max_packets: int = DEFAULT_MAX_PACKETS
    packet_window_seconds: float = DEFAULT_PACKET_WINDOW_SECONDS
    max_connections: int = DEFAULT_MAX_CONNECTIONS


class FindingResolvers:
    """Looks up the records a finding's alert can reference (M11.13/M11.14).

    The three sources are duck-typed rather than fixed types, because each is a
    different milestone's query surface:

    * ``packet_source`` exposes ``list(...)`` (M7's
      :class:`~app.repositories.packet.PacketRepository`);
    * ``connection_source`` exposes ``list_connections(...)`` (M9's
      :class:`~app.connections.manager.ConnectionTracker`);
    * ``rule_source`` exposes ``get_by_rule_key(...)`` (M2's
      :class:`~app.repositories.detection_rule.DetectionRuleRepository`).
    """

    def __init__(
        self,
        *,
        packet_source: Any | None = None,
        connection_source: Any | None = None,
        rule_source: Any | None = None,
        limits: ResolutionLimits | None = None,
    ) -> None:
        self._packet_source = packet_source
        self._connection_source = connection_source
        self._rule_source = rule_source
        self._limits = limits or ResolutionLimits()

    @property
    def limits(self) -> ResolutionLimits:
        """Return the bounds this resolver applies."""
        return self._limits

    def packets(self, finding: "DetectionFinding") -> list[Any]:
        """Return the persisted packets that support ``finding`` (M11.13).

        The search is bounded by address, protocol and a window around the
        observation, so the packets returned are the traffic the detector was
        looking at rather than whatever happened to be newest.

        Returns an empty list — never an error — when no packet source is wired,
        when the finding names no address to match on, or when the lookup fails.
        A finding with no address has no packet to point at: volume detectors
        report a rate, not a frame, and inventing a "recent packet" would be
        evidence the detector never saw.
        """
        source = self._packet_source
        if source is None:
            return []
        if not finding.source_ip and not finding.destination_ip:
            return []
        at = float(finding.timestamp)
        half_window = float(self._limits.packet_window_seconds)
        try:
            return list(
                source.list(
                    source_ip=finding.source_ip,
                    destination_ip=finding.destination_ip,
                    protocol=finding.protocol,
                    since=to_utc_datetime(at - half_window),
                    until=to_utc_datetime(at + half_window),
                    limit=max(int(self._limits.max_packets), 1),
                )
            )
        except Exception:  # noqa: BLE001 - evidence is enrichment (M11.26)
            logger.debug("Packet evidence lookup failed for finding %s", finding.finding_id)
            return []

    def packets_within(
        self, finding: "DetectionFinding"
    ) -> tuple[list[Any], bool]:
        """Return matching packets and whether the window was truncated.

        Returns:
            The packets (at most the configured cap), and ``True`` when more
            packets matched than the cap allowed. The flag is carried so the
            alert can state that its packet evidence is a sample rather than
            pretending it is complete.
        """
        packets = self.packets(finding)
        return packets, len(packets) >= max(int(self._limits.max_packets), 1)

    def connections(self, finding: "DetectionFinding") -> list[Any]:
        """Return the tracked conversations related to ``finding`` (M11.14).

        The match is by the finding's addresses and protocol, which is how a
        conversation is identified without the finding carrying an M9 reference.
        Like packet resolution it is bounded, and it is enrichment: a missing
        tracker or a failed lookup yields no conversation rather than an error.
        """
        source = self._connection_source
        if source is None or not finding.source_ip:
            return []
        try:
            return list(
                source.list_connections(
                    protocol=_protocol_label(finding.protocol),
                    source_ip=finding.source_ip,
                    destination_ip=finding.destination_ip,
                    limit=max(int(self._limits.max_connections), 1),
                )
            )
        except Exception:  # noqa: BLE001 - evidence is enrichment (M11.26)
            logger.debug(
                "Connection evidence lookup failed for finding %s", finding.finding_id
            )
            return []

    def rule_row_id(self, rule_key: str | None) -> int | None:
        """Return the ``detection_rules.id`` for a detector rule key, or ``None``.

        The ``alerts.rule_id`` column is a foreign key into the rule catalogue, so
        persisting an alert through it requires the catalogue row. Resolution is
        best-effort and its failure is *visible*, not hidden: a detector with no
        catalogue row still produces an alert, and that alert carries its string
        rule id in the deduplication key (M11.9) — only the foreign key is left
        empty.
        """
        source = self._rule_source
        if source is None or not rule_key:
            return None
        try:
            rule = source.get_by_rule_key(str(rule_key).strip())
        except Exception:  # noqa: BLE001 - linkage is best-effort
            logger.debug("Detection rule lookup failed for rule %r", rule_key)
            return None
        if rule is None:
            return None
        row_id = getattr(rule, "id", None)
        return int(row_id) if isinstance(row_id, int) else None


def _protocol_label(protocol: str | None) -> str | None:
    """Return the protocol label the M9 tracker matches on, or ``None``.

    The connection tracker validates its protocol filter and rejects an unknown
    value, so a finding whose protocol is not tracked must not be passed through
    as-is: doing so would turn a legitimate finding into a failed lookup. The
    label is upper-cased because that is the form M9 stores.
    """
    if not protocol:
        return None
    text = str(protocol).strip().upper()
    return text or None


class SessionPacketSource:
    """Adapts :class:`~app.repositories.packet.PacketRepository` to the resolver.

    The repository needs an open session, but the resolver is a long-lived object
    built once at startup. This adapter opens a session **per lookup** and closes
    it again, so packet resolution runs on a fresh session and the resolver holds
    no database state — which is what makes it safe to call from the capture
    thread and the API's thread pool alike.

    A failed read yields no packets rather than an exception: a missing packet
    reference must not cost the alert (M11.26).
    """

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def list(self, **filters: Any) -> list[Any]:
        """Return packets matching ``filters``, or an empty list on failure."""
        from app.repositories.packet import PacketRepository

        session = self._session_factory()
        try:
            return PacketRepository(session).list(**filters)
        except Exception:  # noqa: BLE001 - evidence is enrichment (M11.26)
            logger.debug("Packet source lookup failed; continuing without it")
            return []
        finally:
            session.close()


class SessionRuleSource:
    """Adapts :class:`~app.repositories.detection_rule.DetectionRuleRepository`.

    Like :class:`SessionPacketSource`, it opens a session per lookup and never
    raises: a rule catalogue that cannot be read leaves the alert's foreign key
    ``NULL`` rather than failing the alert (M11.18).
    """

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def get_by_rule_key(self, rule_key: str) -> Any | None:
        """Return the catalogue row for ``rule_key``, or ``None``."""
        from app.repositories.detection_rule import DetectionRuleRepository

        session = self._session_factory()
        try:
            return DetectionRuleRepository(session).get_by_rule_key(rule_key)
        except Exception:  # noqa: BLE001 - linkage is best-effort
            logger.debug("Detection rule source lookup failed for %r", rule_key)
            return None
        finally:
            session.close()


#: Builds the resolver set from the running application's layers (M11.23).
#: Injected into the service factory so nothing here is imported at module scope
#: (which would construct registries as an import side effect).
ResolverFactory = Callable[[], FindingResolvers]


__all__ = [
    "DEFAULT_MAX_CONNECTIONS",
    "DEFAULT_MAX_PACKETS",
    "DEFAULT_PACKET_WINDOW_SECONDS",
    "FindingResolvers",
    "ResolutionLimits",
    "ResolverFactory",
    "SessionPacketSource",
    "SessionRuleSource",
]
