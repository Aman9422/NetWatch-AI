"""Build an alert's evidence set from a finding and the records behind it (M11.11-M11.15).

This sits between the pure evidence *descriptors* in :mod:`app.alerts.evidence`
(which know how to render one record) and the *resolvers* in
:mod:`app.alerts.resolvers` (which know how to find related records). Its job is
the one decision neither of the others should make: **what evidence an alert
carries, and in what order it is added when there is more than the cap allows.**

The order is priority, because :class:`~app.alerts.evidence.EvidenceCollection`
drops whatever arrives after the cap:

1. the rule record — the detector and the finding that raised the alert;
2. the behavioural record — the numbers the detector measured;
3. device records — which hosts were involved (M11.15);
4. connection records — the conversations carrying the behaviour (M11.14);
5. packet records — the individual frames, last because they are the most
   numerous and the least irreplaceable (M11.13).

So a cap that bites discards packet references first and the justification for
the alert never. That is the correct trade: an alert with no evidence of *why* it
exists is worthless, while an alert whose packet sample is partial is still fully
explainable.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.alerts.evidence import (
    AlertEvidenceRecord,
    EvidenceCollection,
    EvidenceRole,
    behavioral_evidence,
    connection_evidence,
    device_evidence,
    packet_evidence,
    rule_evidence,
)
from app.alerts.resolvers import FindingResolvers
from app.alerts.timestamps import to_epoch_seconds

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.alerts.mapping import RuleAlertMapping
    from app.detection.finding import DetectionFinding

logger = logging.getLogger(__name__)


def build_evidence(
    finding: "DetectionFinding",
    mapping: "RuleAlertMapping",
    *,
    resolvers: FindingResolvers | None,
    max_records: int,
    packet_evidence_enabled: bool = True,
) -> EvidenceCollection:
    """Assemble the bounded evidence set for the alert a finding produces.

    Args:
        finding: The M10 finding the alert is being raised from. It is always the
            primary evidence source; nothing here invents a fact the detector did
            not observe.
        mapping: The rule's alert mapping (M11.8), for the title and severity the
            rule record carries.
        resolvers: Where related packets, conversations and rule rows come from.
            ``None`` means "no resolution", which yields the finding's own
            evidence only — a perfectly valid alert.
        max_records: Hard cap on the records the collection will hold (M11.12).
        packet_evidence_enabled: Whether to resolve packet references at all
            (M11.13). Packet lookup is the only one that searches an unbounded
            table, so it is separately switchable.

    Returns:
        The evidence collection. It is never empty: the rule and behavioural
        records are always added first and the cap is at least 1.
    """
    collection = EvidenceCollection(max_records)
    at = float(finding.timestamp)

    _add_finding_evidence(collection, finding, mapping)
    _add_device_evidence(collection, finding, at=at)

    if resolvers is not None:
        _add_connection_evidence(collection, finding, resolvers, at=at)
        if packet_evidence_enabled:
            _add_packet_evidence(collection, finding, resolvers, at=at)

    if collection.dropped():
        # Counted, not hidden: the alert was supported by more evidence than the
        # configured bound allows, and that is worth seeing in the logs.
        logger.info(
            "Alert evidence for finding %s capped at %d record(s); %d dropped",
            finding.finding_id,
            max_records,
            collection.dropped(),
        )
    return collection


def _add_finding_evidence(
    collection: EvidenceCollection,
    finding: "DetectionFinding",
    mapping: "RuleAlertMapping",
) -> None:
    """Add the always-present rule and behavioural records (M11.7/M11.8)."""
    at = float(finding.timestamp)
    collection.add(
        rule_evidence(
            finding_id=finding.finding_id,
            rule_id=mapping.rule_id,
            rule_name=finding.rule_name,
            severity=mapping.severity.value,
            confidence=finding.confidence,
            at=at,
        )
    )
    collection.add(
        behavioral_evidence(
            description=finding.description,
            confidence=finding.confidence,
            measured=dict(finding.evidence),
            at=at,
        )
    )


def _add_device_evidence(
    collection: EvidenceCollection,
    finding: "DetectionFinding",
    *,
    at: float,
) -> None:
    """Add one record per resolved M8 device association (M11.15).

    Only devices the finding actually resolved are recorded — an unresolved
    address is left out rather than being written as a placeholder device, which
    is what M11.15 requires.
    """
    if finding.source_device_id:
        collection.add(
            device_evidence(
                device_id=finding.source_device_id,
                role=EvidenceRole.SOURCE,
                ip_address=finding.source_ip,
                at=at,
            )
        )
    if finding.destination_device_id:
        collection.add(
            device_evidence(
                device_id=finding.destination_device_id,
                role=EvidenceRole.DESTINATION,
                ip_address=finding.destination_ip,
                at=at,
            )
        )


def _add_connection_evidence(
    collection: EvidenceCollection,
    finding: "DetectionFinding",
    resolvers: FindingResolvers,
    *,
    at: float,
) -> None:
    """Add one record per related tracked conversation (M11.14).

    A connection source object is read defensively: resolving evidence is
    enrichment, and an unexpected object must yield no evidence rather than an
    exception that costs the whole alert (M11.26).
    """
    for connection in resolvers.connections(finding):
        try:
            collection.add(
                connection_evidence(
                    connection_id=str(connection.connection_id),
                    role=_connection_role(connection, finding),
                    protocol=str(connection.protocol),
                    source_ip=str(connection.source_ip),
                    source_port=connection.source_port,
                    destination_ip=str(connection.destination_ip),
                    destination_port=connection.destination_port,
                    packet_count=int(connection.packet_count),
                    byte_count=int(connection.byte_count),
                    state=_state_value(connection.state),
                    first_seen=connection.first_seen or None,
                    last_seen=connection.last_seen or None,
                    at=at,
                )
            )
        except Exception:  # noqa: BLE001 - evidence is enrichment (M11.26)
            logger.debug(
                "Skipped a connection evidence record for finding %s",
                finding.finding_id,
            )


def _add_packet_evidence(
    collection: EvidenceCollection,
    finding: "DetectionFinding",
    resolvers: FindingResolvers,
    *,
    at: float,
) -> None:
    """Add one reference per persisted packet supporting the finding (M11.13).

    Each record points at a real ``packets.id``. A packet without one is skipped:
    evidence that cannot be looked up is not evidence, and M11 never stores a
    dangling reference.
    """
    for packet in resolvers.packets(finding):
        packet_id = _packet_row_id(packet)
        if packet_id is None:
            continue
        try:
            collection.add(
                packet_evidence(
                    packet_id=packet_id,
                    role=EvidenceRole.RELATED,
                    timestamp=to_epoch_seconds(getattr(packet, "timestamp", None)),
                    source_ip=_optional_str(getattr(packet, "source_ip", None)),
                    destination_ip=_optional_str(
                        getattr(packet, "destination_ip", None)
                    ),
                    protocol=_optional_str(getattr(packet, "protocol", None)),
                    length=_optional_int(getattr(packet, "packet_length", None)),
                    at=at,
                )
            )
        except Exception:  # noqa: BLE001 - evidence is enrichment (M11.26)
            logger.debug(
                "Skipped a packet evidence record for finding %s", finding.finding_id
            )


def _connection_role(connection: object, finding: "DetectionFinding") -> EvidenceRole:
    """Return the role a conversation plays relative to the finding.

    A conversation whose recorded source is the finding's source describes the
    behaviour directly; anything else was matched by address or protocol and is
    recorded as related. The distinction is descriptive, not a judgement.
    """
    source_ip = getattr(connection, "source_ip", None)
    if source_ip is not None and source_ip == finding.source_ip:
        return EvidenceRole.SOURCE
    return EvidenceRole.RELATED


def _state_value(state: object) -> str:
    """Render a connection state, tolerating an enum or a plain string."""
    value = getattr(state, "value", state)
    return str(value)


def _packet_row_id(packet: object) -> int | None:
    """Return a packet row's primary key, or ``None`` when it has none.

    An id that is missing or not an integer means the object cannot be
    referenced, so it is skipped instead of producing a bad foreign key.
    """
    row_id = getattr(packet, "id", None)
    return int(row_id) if isinstance(row_id, int) else None


def _optional_str(value: object) -> str | None:
    """Return ``value`` as a string, or ``None`` when it is absent."""
    return None if value is None else str(value)


def _optional_int(value: object) -> int | None:
    """Return ``value`` as an int, or ``None`` when it is absent or unusable.

    ``isinstance`` is used rather than a bare ``int(value)`` inside a ``try``
    because it lets the type checker *see* the narrowing: after the check the
    value is provably an int, a float or a str, which are the only types
    ``int()`` accepts for this purpose.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float, str)):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return None


# Re-exported so the service imports the collection type from one place.
__all__ = ["AlertEvidenceRecord", "EvidenceCollection", "build_evidence"]
