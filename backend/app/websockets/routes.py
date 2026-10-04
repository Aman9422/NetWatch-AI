"""The four WebSocket endpoints (M14.3).

One route per channel, all mounted under ``/ws`` (M13.3 keeps ``/api/v1``
versioned and allows an unversioned operational route; a socket is not a resource
path). Each is four lines long because every decision lives elsewhere: the channel
vocabulary in :mod:`app.websockets.channels`, admission and lifecycle in
:class:`~app.websockets.manager.WebSocketManager`, input policy in
:mod:`app.websockets.messages`, event shapes in :mod:`app.websockets.builders`.

The receive loop is the only place in M14 that touches a client frame, and it does
exactly three things with one (M14.23):

* an accepted ``ping`` is answered with a ``pong`` carrying the same nonce;
* an accepted ``pong`` clears the keepalive's outstanding-ping mark;
* anything else is refused with an ``error`` event naming the rule that was
  broken, and a client that keeps doing it is disconnected after
  ``websocket_max_invalid_messages`` refusals.

Nothing a client sends reaches a service, a channel, a filter or a command: the
loop's only outputs are those three. That is what "server-push-only" means as a
property of the code rather than a claim in a document.

Two details that are easy to get wrong and are therefore explicit:

* The loop uses ``websocket.receive()`` rather than ``receive_text()``. A binary
  frame is a frame a client can send, and ``receive_text`` on a binary frame either
  raises or yields nothing depending on the Starlette version — inspecting the ASGI
  message makes the refusal ours and the behaviour version-independent.
* A disconnect is the *ordinary* end of a session, not an error. It ends the loop
  quietly; the ``finally`` block unregisters the connection either way.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter
from starlette.websockets import WebSocket, WebSocketDisconnect

from app.config.settings import settings
from app.websockets import builders
from app.websockets.channels import CHANNEL_PATHS, Channel
from app.websockets.connection import ClientConnection
from app.websockets.manager import CLOSE_INVALID_MESSAGE, WebSocketManager
from app.websockets.messages import (
    REFUSAL_NOT_TEXT,
    parse_client_message,
    refuse_binary_frame,
)

logger = logging.getLogger(__name__)

router = APIRouter()

#: Reason sent with the close frame for a client that floods invalid messages.
CLOSE_INVALID_REASON = "Too many invalid messages"

#: ASGI message type a client disconnect arrives as.
_MESSAGE_DISCONNECT = "websocket.disconnect"


def get_manager() -> WebSocketManager:
    """Return the process-wide manager (M14.2/M14.28).

    Imported here rather than at module level because the package's
    ``__init__`` imports this module to publish its router: resolving the
    singleton lazily is what keeps that a one-directional import instead of a
    cycle.
    """
    from app.websockets import get_websocket_manager

    return get_websocket_manager()


async def _serve(websocket: WebSocket, channel: Channel) -> None:
    """Accept, admit, register and then serve one socket (M14.3/M14.4).

    Refusal happens *after* ``accept()`` and *before* registration: a close frame
    with a status code is how a client learns why it was refused, and it cannot be
    sent before the handshake completes. Registering first and closing after would
    let a broadcast reach a socket that was never admitted (M14.22).
    """
    manager = get_manager()
    await websocket.accept()

    reason = manager.check_admission(channel)
    if reason is not None:
        await manager.refuse(websocket, reason)
        return

    connection = await manager.connect(websocket, channel)
    try:
        await _receive_loop(websocket, manager, connection)
    except WebSocketDisconnect:
        # The client closed, or vanished mid-session: the normal end of a session.
        logger.info("WebSocket client %s disconnected", connection.client_id)
    except Exception:  # noqa: BLE001 - a socket fault must not reach the API (M14.29)
        logger.warning(
            "WebSocket client %s failed unexpectedly", connection.client_id,
            exc_info=True,
        )
    finally:
        # Idempotent: if the sender task already retired this client after a
        # failed write, this is a no-op rather than a double cleanup (M14.18).
        await manager.disconnect(connection.client_id)


async def _receive_loop(
    websocket: WebSocket, manager: WebSocketManager, connection: ClientConnection
) -> None:
    """Read client frames until the socket ends, enforcing the input policy.

    Returns when the client disconnects, when it is disconnected for flooding
    invalid messages, or when its sender task has already retired it after a failed
    write; raises :class:`WebSocketDisconnect` when the socket ends underneath us,
    which the caller treats as an ordinary disconnect.
    """
    maximum_invalid = max(int(settings.websocket_max_invalid_messages), 1)
    maximum_bytes = max(int(settings.websocket_max_client_message_bytes), 1)

    while True:
        message = await websocket.receive()
        if message.get("type") == _MESSAGE_DISCONNECT:
            return
        if manager.get_connection(connection.client_id) is None:
            # The sender task retired this client — a write failed, or the server
            # is shutting down — while this loop was waiting for a frame. There is
            # nobody left to answer, so the loop ends rather than queueing replies
            # for a connection that is gone.
            return

        text = message.get("text")
        result = (
            parse_client_message(text, max_bytes=maximum_bytes)
            if text is not None
            else refuse_binary_frame()
        )

        if not result.accepted:
            connection.note_refused()
            manager.send(
                connection.client_id,
                builders.error_event(
                    connection.channel, result.refusal or REFUSAL_NOT_TEXT
                ),
            )
            if connection.counters.refused >= maximum_invalid:
                logger.info(
                    "WebSocket client %s sent %d invalid messages; closing it",
                    connection.client_id,
                    connection.counters.refused,
                )
                await websocket.close(
                    code=CLOSE_INVALID_MESSAGE, reason=CLOSE_INVALID_REASON
                )
                return
            continue

        connection.note_received()
        # A client ping or pong both prove the client is alive, so both clear the
        # outstanding-ping mark; only a ping earns a reply (M14.23/M14.24).
        connection.note_pong()
        if result.is_ping:
            manager.send(
                connection.client_id,
                builders.pong_event(
                    connection.channel,
                    nonce=result.message.nonce if result.message else None,
                ),
            )


# -- one route per channel (M14.3/M14.6) ------------------------------------
#
# The paths come from :data:`app.websockets.channels.CHANNEL_PATHS`, so a URL
# appears once in the codebase and the route, the tests and the verification
# script cannot drift apart. Each handler is the same one-liner: which channel a
# route serves is a constant, not a lookup, because a socket that could change
# channel would make the per-channel policy meaningless.


@router.websocket(CHANNEL_PATHS[Channel.DASHBOARD])
async def dashboard_socket(websocket: WebSocket) -> None:
    """Serve the live dashboard channel (M14.9)."""
    await _serve(websocket, Channel.DASHBOARD)


@router.websocket(CHANNEL_PATHS[Channel.PACKETS])
async def packets_socket(websocket: WebSocket) -> None:
    """Serve the live packet channel (M14.8)."""
    await _serve(websocket, Channel.PACKETS)


@router.websocket(CHANNEL_PATHS[Channel.ALERTS])
async def alerts_socket(websocket: WebSocket) -> None:
    """Serve the alert and incident channel (M14.10/M14.12)."""
    await _serve(websocket, Channel.ALERTS)


@router.websocket(CHANNEL_PATHS[Channel.SYSTEM])
async def system_socket(websocket: WebSocket) -> None:
    """Serve the application state channel (M14.11)."""
    await _serve(websocket, Channel.SYSTEM)


__all__ = [
    "CLOSE_INVALID_REASON",
    "get_manager",
    "router",
]
