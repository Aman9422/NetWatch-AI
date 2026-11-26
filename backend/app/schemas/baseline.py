"""Wire schemas for behavioural baselines (M21.10/M21.11).

These models describe how a learnt baseline is exposed over the API. The runtime
representation is :class:`app.baselines.store.ProfileSnapshot`; this module is its
serialisable projection, and it is where the statement M21.7 requires — *an
established baseline describes previous behaviour and is not an anomaly verdict* —
travels to the client.

Two deliberate absences:

* **No score.** There is no "risk", "confidence" or "suspicion" field anywhere in
  this module. M21 does not judge behaviour; a number here would be an anomaly
  score M22 has not produced yet.
* **No raw peers or addresses.** A profile reports *how many* distinct peers and
  ports a device normally uses, never which ones. Storing an address set would be
  storing traffic content the baseline never needs (M21.8).
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from app.baselines.statistics import FeatureStatistics
from app.baselines.store import ProfileSnapshot

#: Human labels for the statistical features, so the frontend does not have to
#: invent a presentation for a field name (M21.11).
FEATURE_LABELS: dict[str, str] = {
    "packet_count": "Packets per window",
    "byte_count": "Bytes per window",
    "tcp_packets": "TCP packets per window",
    "udp_packets": "UDP packets per window",
    "icmp_packets": "ICMP packets per window",
    "dns_packets": "DNS packets per window",
    "unique_peers": "Distinct peers per window",
    "unique_destination_ports": "Distinct destination ports per window",
    "new_connections": "New conversations per window",
}

#: The sentence every baseline response carries about what a baseline is (M21.7).
#: Stated once so the API, the page and the documentation cannot drift apart.
BASELINE_DISCLAIMER = (
    "A behavioural baseline describes network activity this device has already "
    "been observed producing. It is not an anomaly verdict, a risk score or a "
    "statement that the device is safe."
)


def to_iso(value: datetime | None) -> str | None:
    """Render a stored naive-UTC datetime as an ISO-8601 UTC string.

    Stored timestamps are naive UTC. Serialising one without a timezone would let
    a browser interpret it as local time, so the offset is attached here — at the
    API boundary, once — rather than in every consumer (M13.26).
    """
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


class FeatureStatisticsView(BaseModel):
    """The statistical summary of one behavioural feature (M21.6/M21.10).

    Attributes:
        feature: Stable feature name, e.g. ``packet_count``.
        label: A human label for the feature.
        count: How many observation windows carried a value for this feature.
        mean / median / mad / mad_scaled / stdev / p95: The statistics.
        min / max: The observed range.
        truncated: True when a contributing window hit a peer or port cap, so
            the central figures are floors rather than exact numbers.
    """

    feature: str
    label: str
    count: int
    mean: float
    median: float
    mad: float = Field(description="Median absolute deviation (unscaled)")
    mad_scaled: float = Field(description="MAD * 1.4826, a robust sigma estimate")
    stdev: float
    p95: float
    min: float
    max: float
    truncated: bool = False

    @classmethod
    def from_summary(cls, summary: FeatureStatistics) -> "FeatureStatisticsView":
        """Project one calculated summary onto the wire shape."""
        return cls(
            feature=summary.feature,
            label=FEATURE_LABELS.get(summary.feature, summary.feature),
            count=summary.count,
            mean=summary.mean,
            median=summary.median,
            mad=summary.mad,
            mad_scaled=summary.mad_scaled,
            stdev=summary.stdev,
            p95=summary.p95,
            min=summary.minimum,
            max=summary.maximum,
            truncated=summary.truncated,
        )


class BaselineView(BaseModel):
    """One device's learnt baseline as the API exposes it (M21.10).

    Attributes:
        device_key: Stable identity — ``mac:...`` or ``ip:...``.
        identity_kind: ``mac`` (hardware, survives an IP change) or ``ip`` (the
            weaker fallback used when no usable MAC was observed).
        mac_address / ip_addresses: The identity detail most recently observed.
        learning_state: ``learning``, ``provisional`` or ``established``.
        state_description: One sentence explaining the state (M21.7).
        sample_count: How many observation windows shaped this profile. This is
            the number maturity is decided from, never elapsed time.
        statistics_sample_count: How many recent windows the figures describe.
        window_seconds: The aggregation interval the samples cover.
        first_observed_at / last_observed_at: UTC bounds of the observations.
        statistics: One entry per feature with at least one sample. Empty while
            still ``learning``, because no profile is published yet.
        window_count / recent_windows: How many of this device's most recent
            observation windows are included in the detail response.
        disclaimer: The sentence stating what a baseline is and is not.
    """

    device_key: str
    identity_kind: str
    mac_address: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    learning_state: str
    state_description: str
    sample_count: int
    statistics_sample_count: int
    window_seconds: float
    first_observed_at: str | None = None
    last_observed_at: str | None = None
    statistics: list[FeatureStatisticsView] = Field(default_factory=list)
    recent_windows: list["BaselineWindowView"] = Field(default_factory=list)
    disclaimer: str = BASELINE_DISCLAIMER

    @classmethod
    def from_snapshot(
        cls,
        snapshot: ProfileSnapshot,
        *,
        state_description: str,
        recent_windows: list["BaselineWindowView"] | None = None,
    ) -> "BaselineView":
        """Project a stored profile onto the wire shape.

        Args:
            snapshot: The profile as the store read it.
            state_description: The sentence explaining the learning state, from
                :func:`app.baselines.states.describe_state`.
            recent_windows: The device's most recent observation windows, for the
                detail response. Omitted from the listing, which carries neither.
        """
        statistics = [
            FeatureStatisticsView.from_summary(summary)
            for summary in snapshot.statistics.values()
        ]
        # Ordered by the feature vocabulary rather than by dict order, so two
        # responses for the same profile present the same order (M13.24).
        statistics.sort(key=lambda view: _feature_rank(view.feature))
        return cls(
            device_key=snapshot.device_key,
            identity_kind=snapshot.identity_kind,
            mac_address=snapshot.mac_address,
            ip_addresses=list(snapshot.ip_addresses),
            learning_state=snapshot.learning_state,
            state_description=state_description,
            sample_count=snapshot.sample_count,
            statistics_sample_count=snapshot.statistics_sample_count,
            window_seconds=snapshot.window_seconds,
            first_observed_at=to_iso(snapshot.first_observed_at),
            last_observed_at=to_iso(snapshot.last_observed_at),
            statistics=statistics,
            recent_windows=recent_windows or [],
        )


class BaselineWindowView(BaseModel):
    """One aggregated observation window (M21.10).

    Exposed on the detail response so an operator can see the samples the profile
    was calculated from. It carries counters only — never a peer address, a port
    number or a payload (M21.8).

    Attributes:
        window_start: UTC start of the window.
        window_seconds: The aggregation interval this window covers.
        packet_count / byte_count: Totals observed in the window.
        tcp_packets / udp_packets / icmp_packets / dns_packets: Protocol counts.
        unique_peers / unique_destination_ports: Set cardinalities.
        new_connections: Conversations seen for the first time, or ``None`` when
            the feature could not be measured for this window.
        peers_truncated / ports_truncated: True when a cardinality hit its cap and
            is therefore a floor rather than an exact count.
    """

    window_start: str
    window_seconds: float
    packet_count: int
    byte_count: int
    tcp_packets: int
    udp_packets: int
    icmp_packets: int
    dns_packets: int
    unique_peers: int
    unique_destination_ports: int
    new_connections: int | None = None
    peers_truncated: bool = False
    ports_truncated: bool = False


class BaselineListData(BaseModel):
    """Payload of the baseline-collection endpoint (M21.10/M13.24).

    ``count`` is the size of this page and ``total`` is the real match count, so a
    client can page without a second request.
    """

    count: int = 0
    limit: int | None = None
    offset: int = 0
    total: int | None = None
    has_more: bool | None = None
    baselines: list[BaselineView] = Field(default_factory=list)


class BaselineResetData(BaseModel):
    """Payload of the reset endpoint (M21.10).

    Attributes:
        device_key: The device whose learning was reset.
        windows_deleted: How many observation windows were removed.
        profile_deleted: Whether a profile row existed and was removed.
        learning_restarted: Always True — a reset always returns the device to
            ``learning``, whether or not it had ever been observed.
        message: A sentence explaining what was and was not touched.
    """

    device_key: str
    windows_deleted: int
    profile_deleted: bool
    learning_restarted: bool = True
    message: str = (
        "The behavioural baseline for this device was deleted and learning will "
        "restart from the next observed packet. No packet, device, alert, "
        "incident, connection or report record was affected."
    )


def _feature_rank(feature: str) -> int:
    """Return the presentation rank of a feature name.

    An unknown feature sorts last rather than raising, so a profile written by a
    later version that added a feature is still renderable here.
    """
    order = list(FEATURE_LABELS)
    try:
        return order.index(feature)
    except ValueError:
        return len(order)


__all__ = [
    "BASELINE_DISCLAIMER",
    "FEATURE_LABELS",
    "BaselineListData",
    "BaselineResetData",
    "BaselineView",
    "BaselineWindowView",
    "FeatureStatisticsView",
    "to_iso",
]
