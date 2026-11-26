"""Persistent behavioural-baseline models (M21.8).

Two tables, and the split between them is the design:

``baseline_profiles``
    One row per observed device identity. It carries the learning state, the
    sample count the state is derived from, the first and latest observation
    timestamps, and the statistical profile as JSON. This is the row the API and
    the frontend read.

``baseline_windows``
    One row per ``(device_key, window_start)`` — an aggregated behavioural
    sample. These are the inputs the statistical profile is calculated from, and
    they are what retention deletes.

**Why not the M2 ``behavioral_baselines`` table?** That table keys on
``devices.id``, a foreign key into ``devices``. M21 requires the engine to work
without the ``devices`` table being populated — M20 documents that the live
device registry is held in memory and that table is development seed data — and a
baseline has to survive a device changing its IP address. Both requirements are
satisfied by keying on the M8 *string* identity (``mac:...`` / ``ip:...``), which
is stable across an IP change and exists whether or not any row was ever written
to ``devices``. The M2 table is left exactly as it is: it is seed data, nothing
writes to it at runtime, and rewriting it would be a schema change to a table no
milestone after M2 has used.

**Nothing here stores a packet or a payload.** A window holds counters and set
cardinalities — how many packets, how many distinct peers — never an address, and
never a byte of a frame. That is what makes an unbounded retention window
tolerable in the first place.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.mixins import TimestampMixin, utcnow


class BaselineProfile(TimestampMixin, Base):
    """The learnt behavioural profile of one device identity (M21.7/M21.8).

    Attributes:
        id: Primary key.
        device_key: Stable M8 identity — ``mac:aa:bb:...`` or ``ip:1.2.3.4``.
            Unique, so one identity has exactly one profile.
        identity_kind: ``mac`` or ``ip``, recorded rather than re-derived, so a
            reader can tell a hardware identity from a fallback one without
            parsing the key.
        learning_state: ``learning``, ``provisional`` or ``established`` (M21.7).
        sample_count: How many observation *windows* shaped this profile. This is
            the number maturity is decided from — never elapsed time.
        first_observed_at / last_observed_at: UTC bounds of the observations
            that produced this profile.
        statistics_json: The statistical profile, one entry per supported
            feature, serialised as JSON. It is a document rather than seventy
            columns because a feature set is a design decision (M21.4) and a
            column per statistic would make adding a feature a migration.
        last_mac_address / last_ip_addresses: The most recent identity detail seen
            for this device, so the frontend can show *which* device this is
            without joining the in-memory registry (which may have evicted it).
    """

    __tablename__ = "baseline_profiles"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_key: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    identity_kind: Mapped[str] = mapped_column(String(8), nullable=False, default="ip")
    learning_state: Mapped[str] = mapped_column(
        String(16), nullable=False, default="learning"
    )
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    last_observed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    statistics_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    last_ip_addresses: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: How many windows this profile's statistics were calculated from. Kept
    #: beside ``sample_count`` because they answer different questions: the
    #: sample count is the whole history, the calculation count is the bounded
    #: recent slice (M21.6) the figures actually describe.
    statistics_sample_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    #: The window length, in seconds, the samples were aggregated over. Stored so
    #: a profile learnt at 60 s is never silently compared with one learnt at 10 s
    #: after an operator changes the setting.
    window_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=60.0)

    __table_args__ = (
        Index("idx_baseline_profiles_state", "learning_state"),
        Index("idx_baseline_profiles_last_observed", "last_observed_at"),
    )


class BaselineWindow(Base):
    """One aggregated behavioural observation window (M21.5/M21.8).

    A row exists only when the window actually observed something: the engine
    never writes a zero-valued window for a device it did not see, because a
    missing observation and a silent device are different facts (M21.5).

    Attributes:
        id: Primary key.
        device_key: Stable M8 identity of the observing device.
        window_start: UTC start of the window. With ``device_key`` it is unique,
            which is what makes a re-flush of the same window a no-op instead of
            a duplicate sample (M21.8).
        window_seconds: Length of the window the counters cover.
        packet_count / byte_count: Totals over the window.
        tcp_packets / udp_packets / icmp_packets / dns_packets: Protocol counts.
        unique_peers / unique_destination_ports: Set cardinalities over the
            window. Cardinalities, not the sets: no address is stored.
        new_connections: How many conversation keys were seen for the first time
            by this device. ``NULL`` when the feature could not be measured.
        peers_truncated / ports_truncated: True when the in-memory set hit its
            configured cap, so a consumer knows the cardinality is a floor rather
            than an exact count (M21.5).
    """

    __tablename__ = "baseline_windows"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_key: Mapped[str] = mapped_column(String(80), nullable=False)
    window_start: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow
    )
    window_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=60.0)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    byte_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tcp_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    udp_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    icmp_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dns_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unique_peers: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unique_destination_ports: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    new_connections: Mapped[int | None] = mapped_column(Integer, nullable=True)
    peers_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    ports_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow
    )

    __table_args__ = (
        # One row per device per window. This is the constraint that makes a
        # duplicate flush safe (M21.8 "safe handling of duplicate windows").
        UniqueConstraint(
            "device_key", "window_start", name="uq_baseline_windows_device_window"
        ),
        # Retention deletes by age, so the age column is indexed on its own.
        Index("idx_baseline_windows_start", "window_start"),
        # The statistics query reads the newest N windows of one device.
        Index("idx_baseline_windows_device_start", "device_key", "window_start"),
    )


__all__ = ["BaselineProfile", "BaselineWindow"]
