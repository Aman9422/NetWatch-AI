"""Devices observed inside an analytics window, from the M8 registry (M16.4).

M8 keeps a registry of *current* device records, not a history of sightings, and
M16.4 does not ask for one to be built. So this builder answers a narrower
question than a fabricated time series would: **which devices M8 observed at
least once inside the period, and what did each of them carry?** That is a fact
the registry can support, because every record carries the ``last_seen`` M8 wrote
when it last saw the device.

What is deliberately absent, and why:

**No second identity mechanism.** A device is whatever M8 says it is — a
``device_id``, its MAC, its addresses. Nothing here re-derives an identity from
an address, which would be a second answer to a question M8 already owns (M16.4).

**No risk.** M8 computes none and M16 adds none, so a ranked device carries
traffic totals and nothing that reads as a verdict (M13.10/M16.4).

**No filtering of the M8 limitation.** On a routed path the next hop's MAC can
stand for several remote addresses, and M8 records that as one device with many
IPs. The window does not try to untangle it: the ranked entry carries the
addresses M8 attributed, including all of them, so the limitation is visible in
the response rather than hidden by it (M16.4).

**A device with no ``last_seen`` is not in any window.** The M8 record is undated
only before its first observation is stamped, and placing an undated record in a
window would mean choosing which window it belongs to. It is excluded, and the
total is the count of records that were actually placed.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.analytics.metrics import RankMetric
from app.analytics.window import AnalyticsWindow
from app.schemas.analytics import DeviceWindowData, RankedDevice
from app.schemas.device import DeviceStatus, DeviceView


def build_device_window(
    views: list[DeviceView],
    window: AnalyticsWindow,
    *,
    limit: int,
    by: RankMetric,
) -> DeviceWindowData:
    """Return the devices M8 last observed inside one window (M16.4).

    Args:
        views: Every current M8 device view, as the registry holds them.
        window: The resolved, bounded window. A device is included when its
            ``last_seen`` falls inside ``[since, until)``.
        limit: How many devices the ranking carries.
        by: The metric the ranking is ordered by.
    """
    seen = [view for view in views if _observed_in_window(view, window)]
    counts = {status.value: 0 for status in DeviceStatus}
    for view in seen:
        counts[view.status.value] = counts.get(view.status.value, 0) + 1
    ranked = sorted(seen, key=lambda view: _rank_key(view, by))
    return DeviceWindowData(
        total=len(seen),
        by_status=counts,
        rank_by=by,
        top=[ranked_device(view) for view in ranked[:limit]],
    )


def ranked_device(view: DeviceView) -> RankedDevice:
    """Project one M8 device view onto the analytics ranking entry (M16.4).

    Used for both the whole-registry ranking and the windowed one, so a client
    reads the same shape whichever it asked for. ``first_seen`` and ``last_seen``
    are copied as M8 rendered them, and stay ``None`` when M8 has not dated the
    record rather than being replaced by an epoch zero.
    """
    return RankedDevice(
        device_id=view.device_id,
        mac_address=view.mac_address,
        ip_addresses=list(view.ip_addresses),
        hostname=view.hostname,
        status=view.status.value,
        first_seen=view.first_seen,
        last_seen=view.last_seen,
        packets=view.packet_count,
        bytes=view.byte_count,
    )


def _rank_key(view: DeviceView, by: RankMetric) -> tuple[float, str]:
    """Return the sort key a ranked device orders by.

    Descending on the metric, then ascending on the device id so equal traffic
    always orders the same way and a ranking is stable across requests (M13.24).
    """
    metric = view.byte_count if by == "bytes" else view.packet_count
    return (-float(metric), view.device_id)


def _observed_in_window(view: DeviceView, window: AnalyticsWindow) -> bool:
    """Return True when M8 last saw ``view`` inside ``[since, until)``."""
    observed = iso_to_epoch(view.last_seen)
    if observed is None:
        return False
    return window.since <= observed < window.until


def iso_to_epoch(value: str | None) -> float | None:
    """Parse an ISO-8601 timestamp into epoch seconds, or ``None``.

    An unparseable or absent value returns ``None`` rather than raising: the
    timestamp comes from a record this layer does not own, and a single malformed
    one must not take the whole block down. ``Z`` is accepted as UTC, matching
    :func:`app.api.common.validation.parse_epoch_filter`.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return float(parsed.timestamp())


__all__ = [
    "build_device_window",
    "iso_to_epoch",
    "ranked_device",
]
