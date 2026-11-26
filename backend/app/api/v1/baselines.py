"""Behavioural baseline API (M21.10).

Three surfaces over the M21 engine:

* ``GET /baselines`` — a page of learnt per-device baselines.
* ``GET /baselines/{device_key}`` — one device's baseline, with its statistical
  profile and the observation windows it was calculated from.
* ``POST /baselines/{device_key}/reset`` — delete one device's baseline and let
  learning restart.

**Before M21 this module refused with 501**, deliberately: no baseline engine
existed, and serving the M2 development seed rows would have presented a
placeholder as an analysed profile. M21 implements the engine, so the routes now
do real work — and they say plainly what a baseline is (M21.7): a description of
behaviour that has already been observed, never an anomaly verdict.

**What these routes cannot do.** There is no field, filter or body that scores a
device, classifies a deviation or raises an alert. M21 must not claim to detect
anomalies; that is M22.

**Every response is bounded.** The listing pages through the M13 contract, so a
response can never be a dump of every device ever seen, and the detail carries a
bounded number of recent windows rather than the whole history.
"""

from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, Depends, Query

from app.api.common import (
    ErrorCode,
    NotFoundError,
    PageWindow,
    page_meta,
    pagination_params,
    success_payload,
)
from app.baselines.engine import BaselineEngine, get_baseline_engine
from app.baselines.states import describe_state
from app.schemas.baseline import (
    BaselineListData,
    BaselineResetData,
    BaselineView,
    BaselineWindowView,
    to_iso,
)

logger = logging.getLogger(__name__)

router = APIRouter()

#: The closed learning-state vocabulary, mirrored from ``LearningState``. Using a
#: Literal lets FastAPI document it and reject an unknown value with a 422 before
#: the handler runs (M13.25).
LearningStateParam = Literal["learning", "provisional", "established"]

#: Most observation windows the detail response carries (M21.10).
#:
#: Bounded on purpose: the samples exist to show *what the profile was calculated
#: from*, and twenty windows is enough to see the shape of a device's behaviour
#: without turning a detail response into a table dump.
MAX_DETAIL_WINDOWS = 20


def _to_window_view(window: object) -> BaselineWindowView:
    """Project a stored window row onto the wire shape.

    The row is read through explicit attribute access rather than
    ``vars()``/``__dict__``, so a column renamed or removed fails at the type
    checker instead of silently vanishing from a response.
    """
    return BaselineWindowView(
        window_start=to_iso(getattr(window, "window_start", None)) or "",
        window_seconds=float(getattr(window, "window_seconds", 0.0)),
        packet_count=int(getattr(window, "packet_count", 0)),
        byte_count=int(getattr(window, "byte_count", 0)),
        tcp_packets=int(getattr(window, "tcp_packets", 0)),
        udp_packets=int(getattr(window, "udp_packets", 0)),
        icmp_packets=int(getattr(window, "icmp_packets", 0)),
        dns_packets=int(getattr(window, "dns_packets", 0)),
        unique_peers=int(getattr(window, "unique_peers", 0)),
        unique_destination_ports=int(getattr(window, "unique_destination_ports", 0)),
        new_connections=getattr(window, "new_connections", None),
        peers_truncated=bool(getattr(window, "peers_truncated", False)),
        ports_truncated=bool(getattr(window, "ports_truncated", False)),
    )


@router.get("", response_model=None)
def list_baselines(
    learning_state: LearningStateParam | None = Query(
        default=None, description="Keep only baselines in this learning state"
    ),
    window: PageWindow = Depends(pagination_params),
    engine: BaselineEngine = Depends(get_baseline_engine),
) -> dict:
    """Return a page of learnt behavioural baselines (M21.10).

    Ordering is ``last_observed_at DESC, device_key`` — the most recently observed
    device first, with the identity as a tie-break, so the order is total and two
    identical requests return the same page (M13.24).

    A device that has been discovered but has produced no observation window yet
    has no baseline at all and therefore does not appear here. That is the honest
    answer: there is nothing to report until something has been observed.
    """
    rows = engine.list_profiles(
        learning_state=learning_state, limit=window.limit, offset=window.offset
    )
    total = engine.count_profiles(learning_state=learning_state)
    payload = BaselineListData(
        **page_meta(len(rows), window, total=total),
        baselines=[
            BaselineView.from_snapshot(
                row, state_description=describe_state(row.learning_state)
            )
            for row in rows
        ],
    )
    logger.info("Returning %d of %d baseline(s) via API", payload.count, total)
    return success_payload("Baselines retrieved", payload.model_dump(mode="json"))


@router.get("/{device_key}", response_model=None)
def get_baseline(
    device_key: str,
    engine: BaselineEngine = Depends(get_baseline_engine),
) -> dict:
    """Return one device's learnt baseline (M21.10).

    Args:
        device_key: The stable M8 identity — ``mac:aa:bb:...`` or ``ip:1.2.3.4``.
            A colon is legal in a path segment, so the id is used as sent.
        engine: The baseline engine.

    Raises:
        NotFoundError: If no baseline exists for this identity. That is a real
            answer rather than a fault: a device that has been discovered but has
            produced no complete observation window yet has nothing to report.
    """
    snapshot = engine.get_profile(device_key)
    if snapshot is None:
        logger.info("Baseline lookup found no profile for %r", device_key)
        raise NotFoundError(
            "No behavioural baseline has been learnt for this device yet",
            code=ErrorCode.NOT_FOUND,
            field="device_key",
        )

    windows = engine.store.list_windows(device_key, limit=MAX_DETAIL_WINDOWS)
    view = BaselineView.from_snapshot(
        snapshot,
        state_description=describe_state(snapshot.learning_state),
        recent_windows=[_to_window_view(row) for row in windows],
    )
    return success_payload("Baseline retrieved", view.model_dump(mode="json"))


@router.post("/{device_key}/reset", response_model=None)
def reset_baseline(
    device_key: str,
    engine: BaselineEngine = Depends(get_baseline_engine),
) -> dict:
    """Delete one device's baseline and let learning restart (M21.10).

    Deletes only this device's observation windows and its profile. No packet,
    device, alert, incident, connection or report row is touched — the reset is
    confined to the two M21 tables, which is what makes it safe to run against a
    device an operator wants to re-learn.

    The in-memory window and the remembered conversation keys are cleared too, so
    the next packet genuinely starts a new window rather than resuming a partial
    one that survived the delete.

    Answers ``200`` even when there was nothing to delete: "this device now has no
    baseline" is true either way, and a ``404`` would force a caller to distinguish
    "already absent" from "reset failed" for an operation whose outcome is the
    same.
    """
    windows_deleted, profile_deleted = engine.reset_device(device_key)
    payload = BaselineResetData(
        device_key=device_key,
        windows_deleted=windows_deleted,
        profile_deleted=profile_deleted,
    )
    logger.info(
        "Reset baseline for %r (%d window(s) deleted, profile %s)",
        device_key,
        windows_deleted,
        "deleted" if profile_deleted else "absent",
    )
    return success_payload("Baseline reset", payload.model_dump(mode="json"))


__all__ = ["MAX_DETAIL_WINDOWS", "router"]
