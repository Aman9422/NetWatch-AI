"""The keepalive task (M14.24).

One `asyncio` task per application, started by the lifespan and cancelled at
shutdown, that asks :meth:`WebSocketManager.heartbeat_tick` to ping every
connection on a fixed interval. Keeping the loop here rather than on the manager
means the manager is a plain object with no timers of its own — a unit test can
call ``heartbeat_tick()`` directly and observe exactly one tick, with no sleep and
no background task to leak.

Why a heartbeat at all (M14.24): a half-open socket — a client that was killed, or
a network that vanished — stays "connected" from the server's point of view
forever, holding a registry slot and a queue. The ping/pong exchange bounds that
lifetime to roughly two intervals.

Why it is slow: the default interval is 20 seconds, so a client receives one
message per 20 seconds while idle. M14.24 explicitly asks for a heartbeat that
avoids unnecessary high-frequency traffic, and a protocol that already has
application-level events on every active channel does not need a per-second ping.
"""

from __future__ import annotations

import asyncio
import logging

from app.websockets.manager import WebSocketManager

logger = logging.getLogger(__name__)

#: Floor on the configured interval. A tick of a fraction of a second would turn
#: the keepalive into the very flood M14.24 warns about, so a misconfigured value
#: is clamped rather than obeyed.
MIN_INTERVAL_SECONDS = 1.0

#: Task name, so a heap dump or a debugger shows what the task is.
HEARTBEAT_TASK_NAME = "ws-heartbeat"


async def run_heartbeat(
    manager: WebSocketManager, *, interval_seconds: float
) -> None:
    """Ping every connection once per interval until cancelled (M14.24).

    A failure inside a tick is logged and the loop continues: the heartbeat is a
    maintenance task, and one bad tick must not silently end keepalive for the rest
    of the process's life (M14.14).

    The sleep happens *before* the first tick, so an application that starts and
    stops within one interval never sends a ping at all.
    """
    interval = max(float(interval_seconds), MIN_INTERVAL_SECONDS)
    while True:
        await asyncio.sleep(interval)
        try:
            await manager.heartbeat_tick()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - the heartbeat must survive a bad tick
            logger.warning("A WebSocket heartbeat tick failed", exc_info=True)


def start_heartbeat(
    manager: WebSocketManager, *, interval_seconds: float
) -> asyncio.Task[None] | None:
    """Start the keepalive task, or return ``None`` when there is nothing to do.

    Returns ``None`` — rather than a task that immediately exits — for a disabled
    manager or a non-positive interval, so a caller can tell "started" from "not
    started" without inspecting a finished task.
    """
    if not manager.enabled:
        return None
    if float(interval_seconds) <= 0.0:
        return None
    return asyncio.create_task(
        run_heartbeat(manager, interval_seconds=interval_seconds),
        name=HEARTBEAT_TASK_NAME,
    )


__all__ = [
    "HEARTBEAT_TASK_NAME",
    "MIN_INTERVAL_SECONDS",
    "run_heartbeat",
    "start_heartbeat",
]
