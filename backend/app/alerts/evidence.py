"""Alert evidence: the bounded, referenced record of what supports an alert (M11.11–M11.15).

Evidence is *supporting information*, not a second copy of the data. Two rules
shape everything here:

* **References, never copies (M11.13).** A packet evidence record stores the
  ``packets.id`` it points at plus a small readable digest. Rewriting a packet's
  fields into the alert would create a second, divergent record of the same
  observation, and a retention sweep that deletes the packet would leave a
  convincing-looking ghost behind. The foreign key is the link; the digest only
  makes a row legible when read on its own.
* **Bounded (M11.12).** An alert carries at most
  ``settings.alert_max_evidence_per_alert`` records. A flood that touches a
  thousand conversations must not turn one alert into a thousand rows, so
  :class:`EvidenceCollection` stops at the cap and *counts* what it dropped
  rather than silently truncating.

The ``evidence_type`` values are exactly the ones the M2 ``alert_evidence``
column already documents — ``packet``, ``connection``, ``behavioral``, ``rule``
and ``device``. ``ml`` is documented there too but nothing in M11 writes it:
model-based evidence belongs to a later milestone and M11 does not invent a
producer for it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum

from app.alerts.timestamps import to_utc_datetime

#: A JSON value an evidence document may hold. Scalars are the norm; nested
#: objects are allowed because ``alert_evidence.evidence_data`` is a JSON
#: document, and the serialiser below is what makes that safe.
EvidenceValue = int | float | str | bool | None | dict[str, object] | list[object]


class EvidenceType(str, Enum):
    """The kinds of evidence an alert may carry (M11.11)."""

    RULE = "rule"
    BEHAVIORAL = "behavioral"
    PACKET = "packet"
    CONNECTION = "connection"
    DEVICE = "device"


class EvidenceRole(str, Enum):
    """Which part of the alert an evidence record describes (M11.14/M11.15)."""

    SOURCE = "source"
    DESTINATION = "destination"
    RELATED = "related"


@dataclass(frozen=True)
class AlertEvidenceRecord:
    """One piece of evidence to attach to an alert (M11.11).

    Attributes:
        evidence_type: The kind of evidence, from :class:`EvidenceType`.
        evidence_data: The JSON document describing the evidence. Top-level keys
            are stable and greppable, so evidence stays queryable.
        packet_id: The ``packets.id`` this record references, for packet
            evidence only (M11.13). ``None`` for every other kind.
        created_at: Observation time in epoch seconds. Always the time of the
            underlying observation — the finding's timestamp — never the moment
            the row happened to be written, so evidence and alert agree.

    Raises:
        ValueError: If ``evidence_data`` is empty. A record that says nothing is
            not evidence, and storing one would inflate the evidence count that
            M11.3 derives from it.
    """

    evidence_type: EvidenceType
    evidence_data: dict[str, EvidenceValue] = field(default_factory=dict)
    packet_id: int | None = None
    created_at: float = 0.0

    def __post_init__(self) -> None:
        """Reject an empty evidence document."""
        if not self.evidence_data:
            raise ValueError(
                f"A {self.evidence_type.value} evidence record must carry data"
            )
        if self.packet_id is not None and self.evidence_type is not EvidenceType.PACKET:
            raise ValueError("Only packet evidence may reference a packet row")

    def to_row_values(self, *, alert_id: int) -> dict[str, object]:
        """Return the ``alert_evidence`` column values for this record.

        Args:
            alert_id: Primary key of the alert the evidence belongs to.

        Returns:
            Keyword arguments for the ``AlertEvidence`` model. ``evidence_data``
            is a deterministic JSON string: keys sorted, no incidental
            whitespace, so the same evidence always serialises identically and a
            test can compare it byte for byte.
        """
        return {
            "alert_id": alert_id,
            "packet_id": self.packet_id,
            "evidence_type": self.evidence_type.value,
            "evidence_data": serialize_evidence_data(self.evidence_data),
            "created_at": to_utc_datetime(self.created_at),
        }


def serialize_evidence_data(data: dict[str, EvidenceValue]) -> str:
    """Serialise an evidence document to the JSON text the column stores.

    ``default=str`` is a deliberate last resort: a detector value that is not a
    JSON scalar is rendered rather than raised, because a malformed evidence
    value must never be the reason an alert is lost (M11.26).
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


class EvidenceCollection:
    """Accumulates the bounded evidence set for one alert (M11.12).

    Records are held in the order they were added, so the caller controls
    priority: the service adds the mandatory finding-linked records first and the
    resolved, optional ones after, which means a cap that bites drops the least
    important evidence.
    """

    def __init__(self, max_records: int) -> None:
        """Create a collection holding at most ``max_records`` records.

        Raises:
            ValueError: If ``max_records`` is below 1. A cap of zero would
                silently produce alerts with no evidence at all, which M11.12
                does not allow.
        """
        if max_records < 1:
            raise ValueError("max_records must be at least 1")
        self._max_records = int(max_records)
        self._records: list[AlertEvidenceRecord] = []
        self._dropped = 0

    def add(self, record: AlertEvidenceRecord) -> bool:
        """Add one record, returning False when the cap rejected it."""
        if len(self._records) >= self._max_records:
            self._dropped += 1
            return False
        self._records.append(record)
        return True

    def extend(self, records: list[AlertEvidenceRecord]) -> int:
        """Add several records; return how many the cap accepted."""
        return sum(1 for record in records if self.add(record))

    def records(self) -> tuple[AlertEvidenceRecord, ...]:
        """Return the accepted records, in the order they were added."""
        return tuple(self._records)

    def count(self) -> int:
        """Return how many records were accepted."""
        return len(self._records)

    def dropped(self) -> int:
        """Return how many records the cap rejected (M11.12).

        Counted, never hidden: a non-zero value means the alert was supported by
        more evidence than the bound allows, which is worth knowing.
        """
        return self._dropped

    @property
    def full(self) -> bool:
        """Return True once the cap has been reached."""
        return len(self._records) >= self._max_records


def rule_evidence(
    *,
    finding_id: str,
    rule_id: str,
    rule_name: str,
    severity: str,
    confidence: float,
    at: float,
) -> AlertEvidenceRecord:
    """Describe the detector and finding that raised the alert (M11.8).

    This is the record that keeps the original finding identifiable (M11.7): it
    names the detector, the finding it produced and the severity the mapping
    assigned, so the alert's own justification is stored with it.
    """
    return AlertEvidenceRecord(
        evidence_type=EvidenceType.RULE,
        created_at=at,
        evidence_data={
            "finding_id": finding_id,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity": severity,
            "confidence": round(float(confidence), 6),
        },
    )


def behavioral_evidence(
    *,
    description: str,
    confidence: float,
    measured: dict[str, EvidenceValue],
    at: float,
) -> AlertEvidenceRecord:
    """Describe the observed behaviour behind the finding (M11.11).

    ``measured`` is the detector's own evidence dictionary, nested verbatim
    under ``measured`` so the alert can be explained with the exact numbers M10
    compared against its threshold — no re-derivation, no rounding that could
    disagree with the finding.
    """
    return AlertEvidenceRecord(
        evidence_type=EvidenceType.BEHAVIORAL,
        created_at=at,
        evidence_data={
            "description": description,
            "confidence": round(float(confidence), 6),
            "measured": dict(measured),
        },
    )


def packet_evidence(
    *,
    packet_id: int,
    role: EvidenceRole,
    timestamp: float | None,
    source_ip: str | None,
    destination_ip: str | None,
    protocol: str | None,
    length: int | None,
    at: float,
) -> AlertEvidenceRecord:
    """Reference one persisted packet that supports the alert (M11.13).

    The packet is identified by its row id; the remaining fields are a digest
    for readability only and never replace the row itself.
    """
    return AlertEvidenceRecord(
        evidence_type=EvidenceType.PACKET,
        packet_id=int(packet_id),
        created_at=at,
        evidence_data={
            "role": role.value,
            "packet_id": int(packet_id),
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "length": length,
        },
    )


def connection_evidence(
    *,
    connection_id: str,
    role: EvidenceRole,
    protocol: str,
    source_ip: str,
    source_port: int | None,
    destination_ip: str,
    destination_port: int | None,
    packet_count: int,
    byte_count: int,
    state: str,
    first_seen: float | None,
    last_seen: float | None,
    at: float,
) -> AlertEvidenceRecord:
    """Reference one tracked conversation related to the alert (M11.14).

    A connection is identified by its M9 ``connection_id``, which is stable for
    the life of the conversation and lets a reader fetch the live aggregate.
    """
    return AlertEvidenceRecord(
        evidence_type=EvidenceType.CONNECTION,
        created_at=at,
        evidence_data={
            "role": role.value,
            "connection_id": connection_id,
            "protocol": protocol,
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "packet_count": int(packet_count),
            "byte_count": int(byte_count),
            "state": state,
            "first_seen": first_seen,
            "last_seen": last_seen,
        },
    )


def device_evidence(
    *,
    device_id: str,
    role: EvidenceRole,
    ip_address: str | None,
    at: float,
) -> AlertEvidenceRecord:
    """Associate one M8 device with the alert (M11.15).

    ``device_id`` is the M8 registry's opaque identity, not a ``devices`` table
    row: M8 is the authority on what a device is, and M11 must not invent a
    database device to hold an alert reference.
    """
    return AlertEvidenceRecord(
        evidence_type=EvidenceType.DEVICE,
        created_at=at,
        evidence_data={
            "role": role.value,
            "device_id": device_id,
            "ip_address": ip_address,
        },
    )
