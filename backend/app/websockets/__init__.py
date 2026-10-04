"""The WebSocket layer for NetWatch AI (M14).

M14 is a *transport* layer: it carries, in real time, facts that M4–M12 already
produce and M13 already serves over HTTP. Nothing here detects, correlates, scores
or decides anything, and nothing here is a source of truth — every event describes
something the producing service still owns (design §1).

This module holds the process-wide singletons and the two lifecycle entry points
the application's lifespan calls:

* :func:`get_websocket_manager` — the one :class:`WebSocketManager` per process;
* :func:`get_event_publisher` — the one publisher the services are given;
* :func:`start_websockets` — bind the loop and start the heartbeat and dashboard
  ticks (M14.20);
* :func:`shutdown_websockets` — announce, close every client, cancel every task
  (M14.20);
* :func:`reset_websockets` — drop the singletons, for tests that want a fresh
  manager under different settings.

**Why singletons rather than dependency injection here.** M13.28 asks that a route
not build a *new* instance inside a handler, and M14.28 leaves the existing
architecture in place. The application already holds its process-wide collaborators
this way (``get_capture_manager``, ``get_correlation_engine``, ...), and a
WebSocket manager *must* be process-wide for a different and stronger reason: the
registry, the per-channel rate buckets and the queues are per-process state, so a
second manager would mean two disjoint sets of subscribers that each believe they
see everything (M14.5).

Every import in this module is either a WebSocket module or configuration. Nothing
here reaches into a service at import time, so a service may import the publisher
without the WebSocket package importing the service back.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence

from app.config.settings import settings
from app.websockets import builders, dashboard, heartbeat
from app.websockets.channels import CHANNELS, CHANNEL_PATHS, Channel
from app.websockets.event import EventType, WebSocketEvent
from app.websockets.manager import WebSocketManager
from app.websockets.policy import build_policy_set
from app.websockets.publisher import EventPublisher, build_publisher
from app.websockets.routes import router as websocket_router

logger = logging.getLogger(__name__)

_manager: WebSocketManager | None = None
_publisher: EventPublisher | None = None
_tasks: list[asyncio.Task[None]] = []


def get_websocket_manager() -> WebSocketManager:
    """Return the process-wide manager, creating it on first use (M14.2).

    The caps and the per-channel policy come from settings, so the configuration
    is read once per process rather than per connection, and a connection cannot
    be admitted under one policy and served under another.
    """
    global _manager
    if _manager is None:
        _manager = WebSocketManager(
            policies=build_policy_set(settings),
            max_connections=settings.websocket_max_connections,
            max_connections_per_channel=settings.websocket_max_connections_per_channel,
            max_event_bytes=settings.websocket_max_event_bytes,
            send_timeout_seconds=settings.websocket_send_timeout_seconds,
            enabled=bool(settings.websockets_enabled),
        )
        logger.info(
            "WebSocket layer configured (enabled=%s, max_connections=%d)",
            _manager.enabled,
            settings.websocket_max_connections,
        )
    return _manager


def get_event_publisher() -> EventPublisher:
    """Return the publisher the services publish through (M14.13).

    Built over the manager, so switching ``websockets_enabled`` off produces a
    publisher whose ``enabled`` is False and whose ``publish`` returns False
    without the pipeline taking a branch.
    """
    global _publisher
    if _publisher is None:
        _publisher = build_publisher(get_websocket_manager())
    return _publisher


def websocket_tasks() -> Sequence[asyncio.Task[None]]:
    """Return the background tasks M14 started, for diagnostics and tests."""
    return tuple(_tasks)


def describe_channels() -> list[dict[str, object]]:
    """Return the channel table, so a caller can list the surface without probing.

    Used by the verification script and available to any diagnostics that want to
    state which channels exist, their paths and their configured depths.
    """
    manager = get_websocket_manager()
    stats = manager.channel_stats()
    return [
        {
            "channel": channel.value,
            "path": CHANNEL_PATHS[channel],
            **stats.get(channel.value, {}),
        }
        for channel in CHANNELS
    ]


async def start_websockets() -> WebSocketManager:
    """Bind the loop and start the M14 background tasks (M14.20).

    Called from the application lifespan before the app accepts traffic. Returns
    the manager so a caller that wants to log or inspect it does not have to fetch
    it again. Idempotent with respect to the tasks: starting twice cancels the
    previous set first, so a reloaded application cannot accumulate heartbeat
    loops that each ping every client.
    """
    manager = get_websocket_manager()
    await manager.start()
    await _cancel_tasks()
    started: list[asyncio.Task[None]] = []
    keepalive = heartbeat.start_heartbeat(
        manager, interval_seconds=settings.websocket_heartbeat_interval_seconds
    )
    if keepalive is not None:
        started.append(keepalive)
    tick = dashboard.start_dashboard_tick(
        manager, interval_seconds=settings.websocket_dashboard_interval_seconds
    )
    if tick is not None:
        started.append(tick)
    _tasks.extend(started)
    logger.info("WebSocket layer started with %d background task(s)", len(started))
    return manager


async def shutdown_websockets() -> None:
    """Announce the shutdown, close every client and cancel every task (M14.20).

    The order matters and is deliberate:

    1. a final ``service.status`` event naming ``shutting_down`` is published
       *before* anything closes, so a connected client learns why its socket is
       about to end rather than seeing a bare close frame;
    2. the background tasks are cancelled and awaited, so nothing ticks against a
       registry that is being cleared;
    3. the manager closes every connection with code 1001 ("going away"), which
       tells a client to reconnect rather than treat the close as an error.

    Idempotent and safe when startup never ran: a test that builds the application
    without its lifespan gets a no-op rather than an error.
    """
    manager = _manager
    if manager is None:
        return
    _announce_shutdown(manager)
    await _cancel_tasks()
    await manager.shutdown()
    logger.info("WebSocket layer shut down")


def _announce_shutdown(manager: WebSocketManager) -> None:
    """Publish the final system event, containing any failure (M14.20)."""
    try:
        manager.publish(
            builders.service_event("websockets", "shutting_down")
        )
    except Exception:  # noqa: BLE001 - a farewell must not fail a shutdown
        logger.debug("Could not publish the shutdown notice", exc_info=True)


async def _cancel_tasks() -> None:
    """Cancel every background task and wait for it to finish.

    Cancellation is the *expected* end of these tasks, so a ``CancelledError``
    here is a success rather than a failure and is not logged. The tasks are
    collected before awaiting, because awaiting one lets the others run to their
    side effects.
    """
    global _tasks
    pending = list(_tasks)
    _tasks = []
    for task in pending:
        task.cancel()
    for task in pending:
        try:
            await task
        except asyncio.CancelledError:
            continue
        except Exception:  # noqa: BLE001 - a task dying during teardown is contained
            logger.warning("A WebSocket task failed during shutdown", exc_info=True)


def reset_websockets() -> None:
    """Drop the manager and publisher singletons (test support).

    Never called by the application. It exists so a test can build a manager under
    different settings without the previous one's registry and rate buckets
    leaking into it. It does **not** await the background tasks: a test that has
    started them calls :func:`shutdown_websockets` first, which is why the two are
    documented together.
    """
    global _manager, _publisher, _tasks
    _manager = None
    _publisher = None
    _tasks = []


__all__ = [
    "CHANNELS",
    "CHANNEL_PATHS",
    "Channel",
    "EventType",
    "WebSocketEvent",
    "WebSocketManager",
    "describe_channels",
    "get_event_publisher",
    "get_websocket_manager",
    "reset_websockets",
    "shutdown_websockets",
    "start_websockets",
    "websocket_router",
    "websocket_tasks",
]
