"""The dashboard tick: a sampled, bounded dashboard update (M14.9).

A dashboard is not a change log. It wants "here is the state, refreshed", not one
message per counter movement — a busy capture session moves the packet count
thousands of times a second, and streaming each movement is the flood M14.15
forbids. So this module samples at ``websocket_dashboard_interval_seconds``
(default 1 s) and publishes one ``dashboard.updated`` per tick carrying only the
numbers M14.9 names.

Two rules make it safe to run on a timer:

* **It reads the services that own each fact** — the same reads
  ``GET /api/v1/dashboard/summary`` performs — and derives nothing. The packet
  count comes from the capture manager, the rates from the M6 snapshot, the device
  count from the M8 registry, active connections from the M9 tracker, open alerts
  from the M11 aggregation, active incidents from the M12 engine. There is no
  second aggregation anywhere in M14 (M13.19's rule, kept).
* **One unavailable service does not lose the tick.** Each read is individually
  contained and falls back to a zero, so a database that is briefly unhappy
  degrades one number rather than silencing the dashboard (M14.14). A failed read
  is logged, because a permanently zero field would otherwise be invisible.

The services are imported *inside* the sampling functions rather than at module
level. That is deliberate: this module is reached from the WebSocket package's
import, and importing the capture pipeline from there would make every WebSocket
import pull the whole M4→M12 stack into the process. Deferring the import to first
use keeps the layering one-way and matches how the capture manager already
resolves its own collaborators.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import TypeVar

from app.websockets import builders
from app.websockets.channels import Channel
from app.websockets.manager import WebSocketManager

logger = logging.getLogger(__name__)

#: Floor on the configured interval. A tick of a fraction of a second would make
#: the dashboard channel the flood the design exists to prevent.
MIN_INTERVAL_SECONDS = 0.1

#: Task name, so a debugger or a heap dump shows what the task is.
DASHBOARD_TASK_NAME = "ws-dashboard"

T = TypeVar("T")


def _safe(name: str, reader: Callable[[], T], default: T) -> T:
    """Run one service read, returning ``default`` when it fails (M14.14).

    A dashboard is a *view* of six services, and a view that disappears because
    one of them hiccuped is worse than a view with one stale zero in it. The
    failure is logged at warning level once per tick rather than at error level,
    because a persistently broken service would otherwise write a line a second.
    """
    try:
        return reader()
    except Exception:  # noqa: BLE001 - a sample must never break the tick
        logger.warning("Dashboard sample %r is unavailable", name, exc_info=True)
        return default


# -- one read per fact -------------------------------------------------------


def _capture_sample() -> tuple[bool, str | None, int]:
    """Return ``(running, interface, packet_count)`` from the capture manager."""
    from app.services.capture_manager import get_capture_manager

    manager = get_capture_manager()
    status = manager.get_status()
    return manager.is_running(), status.interface, int(status.packet_count)


def _traffic_sample() -> tuple[float, float]:
    """Return ``(packets_per_second, bytes_per_second)`` from the M6 snapshot.

    The snapshot is read once and both rates taken from it, so the two numbers
    describe the same instant rather than two instants a few reads apart.
    """
    from app.statistics.manager import get_statistics_manager

    snapshot = get_statistics_manager().get_statistics()
    return float(snapshot.packets_per_second), float(snapshot.bytes_per_second)


def _device_count() -> int:
    """Return how many devices the M8 registry currently holds."""
    from app.devices.manager import get_device_manager

    return len(get_device_manager().list_device_views())


def _active_connection_count() -> int:
    """Return the M9 tracker's own active count."""
    from app.connections.manager import get_connection_tracker

    return int(get_connection_tracker().get_active_count())


def _open_alert_count() -> int:
    """Return how many alerts are still in an M11 active state.

    The aggregation is the M11 query service's, and the set of states that counts
    as "open" is :data:`app.alerts.status.ACTIVE_STATUSES` rather than a list
    written here, so the live number and the REST number cannot drift (M14.9).
    """
    from app.alerts.queries import AlertQueries
    from app.alerts.status import ACTIVE_STATUSES
    from app.persistence.session_factory import app_session_factory

    queries = AlertQueries(session_factory=app_session_factory)
    by_status = queries.summary()["by_status"]
    return int(
        sum(count for status, count in by_status.items() if status in ACTIVE_STATUSES)
    )


def _active_incident_count() -> int:
    """Return how many incidents the M12 engine considers active.

    ``active_only`` is the engine's own filter, so "active" means whatever M12
    says it means (M12.13) and M14 does not restate the status list.
    """
    from app.correlation import get_correlation_engine
    from app.correlation.registry import IncidentQuery

    return int(
        get_correlation_engine().count_incidents(IncidentQuery(active_only=True))
    )


def sample_dashboard() -> dict[str, object]:
    """Read every dashboard fact once and return the payload arguments (M14.9).

    Returns a dictionary of keyword arguments for
    :func:`app.websockets.builders.dashboard_event`, each read contained
    individually so one unavailable service costs one number rather than the
    whole update.
    """
    running, interface, packet_count = _safe(
        "capture", _capture_sample, (False, None, 0)
    )
    packets_per_second, bytes_per_second = _safe(
        "traffic", _traffic_sample, (0.0, 0.0)
    )
    return {
        "capture_running": bool(running),
        "interface": interface,
        "packet_count": int(packet_count),
        "packets_per_second": float(packets_per_second),
        "bytes_per_second": float(bytes_per_second),
        "device_count": _safe("devices", _device_count, 0),
        "active_connections": _safe(
            "connections", _active_connection_count, 0
        ),
        "open_alerts": _safe("alerts", _open_alert_count, 0),
        "active_incidents": _safe(
            "incidents", _active_incident_count, 0
        ),
    }


def publish_dashboard(manager: WebSocketManager) -> bool:
    """Sample the services and broadcast one dashboard event (M14.9).

    Called on the event loop, so the fan-out is invoked directly rather than
    handed over with ``call_soon_threadsafe`` — there is no thread boundary to
    cross and going through one would only add a turn of latency.

    Returns False without doing work when no dashboard client is connected: the
    sampling touches six services, and paying for it to fill a queue nobody is
    draining would be a real cost with no observer (M14.9's "bounded" requirement
    applied to the work as well as the payload).
    """
    if manager.get_connection_count(Channel.DASHBOARD) == 0:
        return False
    values = sample_dashboard()
    event = builders.dashboard_event(timestamp=time.time(), **values)  # type: ignore[arg-type]
    return manager.broadcast(event) >= 0


async def run_dashboard_tick(
    manager: WebSocketManager, *, interval_seconds: float
) -> None:
    """Publish a dashboard update once per interval until cancelled (M14.9).

    The sleep comes first, so an application that starts and stops inside one
    interval never samples anything.
    """
    interval = max(float(interval_seconds), MIN_INTERVAL_SECONDS)
    while True:
        await asyncio.sleep(interval)
        try:
            publish_dashboard(manager)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - one bad tick must not end the tick
            logger.warning("A dashboard tick failed", exc_info=True)


def start_dashboard_tick(
    manager: WebSocketManager, *, interval_seconds: float
) -> asyncio.Task[None] | None:
    """Start the dashboard tick, or return ``None`` when there is nothing to do.

    ``None`` for a disabled manager, a non-positive interval, or a packet channel
    that has been switched off with ``packet_ws_enabled`` — the dashboard channel
    is part of the same "live telemetry" budget, and an operator who turned the
    telemetry stream off did not ask for a once-a-second sample instead.
    """
    if not manager.enabled:
        return None
    if not manager.policies.is_enabled(Channel.DASHBOARD):
        return None
    if float(interval_seconds) <= 0.0:
        return None
    return asyncio.create_task(
        run_dashboard_tick(manager, interval_seconds=interval_seconds),
        name=DASHBOARD_TASK_NAME,
    )


__all__ = [
    "DASHBOARD_TASK_NAME",
    "MIN_INTERVAL_SECONDS",
    "publish_dashboard",
    "run_dashboard_tick",
    "sample_dashboard",
    "start_dashboard_tick",
]
