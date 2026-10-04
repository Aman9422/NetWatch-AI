"""The transport-agnostic publish seam (M14.13).

The services that produce events must not know that a socket exists. They are
handed an :class:`EventPublisher`, call ``publish(event)`` on it, and move on.
That is the whole contract, and it is what makes M14 additive: the M4→M12 pipeline
gains one optional constructor argument, and every existing test keeps working
with ``None`` — which is a :class:`NullEventPublisher`.

Three implementations, and the reason each exists:

* :class:`EventPublisher` — a :class:`~typing.Protocol`, not a base class, so a
  service can be typed against it and a test can pass anything with the right
  method. There is no import from the pipeline to this module and back.
* :class:`WebSocketEventPublisher` — forwards to a manager. It holds nothing else:
  no socket, no queue, no loop. It is therefore safe to construct on any thread,
  and it is never the thing that fails when a client misbehaves, because the
  manager's :meth:`~app.websockets.manager.WebSocketManager.publish` already
  contains its own failures (M14.14).
* :class:`NullEventPublisher` — accepts everything, does nothing, returns
  ``False``. This is the default for every service, so "no publisher configured"
  and "publisher configured but disabled" behave identically from a caller's point
  of view: no branch in a service ever has to ask whether events are on.

Every method is total: none of the three raises for any argument. A publisher that
could raise would make publishing a thing that can fail on the capture thread,
which M14.14 forbids.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from app.websockets.event import WebSocketEvent

logger = logging.getLogger(__name__)


@runtime_checkable
class EventPublisher(Protocol):
    """What a service needs from an event sink (M14.13).

    Exactly two methods, both synchronous and both booleans. Synchronous matters:
    the callers are the capture worker thread and FastAPI's thread pool, neither of
    which has an event loop to await on, so an ``async def`` here would be a
    signature the capture path could not use.
    """

    def publish(self, event: WebSocketEvent) -> bool:
        """Hand one event to the sink, returning whether it was accepted."""
        ...  # pragma: no cover - protocol

    def publish_many(self, events: Iterable[WebSocketEvent]) -> int:
        """Hand several events over, returning how many were accepted."""
        ...  # pragma: no cover - protocol


class NullEventPublisher:
    """A publisher that keeps nothing and never fails (M14.13).

    The default collaborator for every service. Returning ``False`` — rather than
    pretending success — keeps the meaning of the boolean identical across
    implementations: True means a subscriber may see this event.
    """

    __slots__ = ()

    @property
    def enabled(self) -> bool:
        """Return False: this publisher has no subscribers by definition."""
        return False

    def publish(self, event: WebSocketEvent) -> bool:
        """Accept ``event`` and discard it."""
        return False

    def publish_many(self, events: Iterable[WebSocketEvent]) -> int:
        """Accept every event and discard it, reporting zero accepted."""
        return 0


class _DispatchTarget(Protocol):
    """The part of the manager this publisher uses."""

    @property
    def enabled(self) -> bool:  # pragma: no cover - protocol
        """Whether the WebSocket layer is switched on."""
        ...

    def publish(self, event: WebSocketEvent) -> bool:  # pragma: no cover - protocol
        """Hand an event to the manager's thread-safe entry point."""
        ...


class WebSocketEventPublisher:
    """Forwards events to a :class:`WebSocketManager` (M14.13).

    A thin adapter with no state beyond the manager reference, because every
    decision it could make — is the channel enabled, is the event too large, is
    there a loop — belongs to the manager, and a second place making them could
    disagree with the first.
    """

    __slots__ = ("_manager",)

    def __init__(self, manager: _DispatchTarget) -> None:
        """Create a publisher forwarding to ``manager``."""
        self._manager = manager

    @property
    def manager(self) -> _DispatchTarget:
        """Return the manager events are forwarded to."""
        return self._manager

    @property
    def enabled(self) -> bool:
        """Return whether the underlying layer is switched on."""
        return bool(self._manager.enabled)

    def publish(self, event: WebSocketEvent) -> bool:
        """Forward ``event``, containing any failure (M14.14).

        The manager already contains its own failures, and this wrapper contains a
        second layer of them — a manager replaced by a test double, or an attribute
        that no longer exists — so a bug in the transport cannot surface on the
        capture thread. A failure is logged at debug level, not error level: it is
        counted by the manager and would otherwise flood the log at packet rate.
        """
        try:
            return bool(self._manager.publish(event))
        except Exception:  # noqa: BLE001 - publishing must never raise (M14.14)
            logger.debug(
                "The event publisher could not hand over an event", exc_info=True
            )
            return False

    def publish_many(self, events: Iterable[WebSocketEvent]) -> int:
        """Forward several events, returning how many were accepted."""
        accepted = 0
        for event in events:
            if self.publish(event):
                accepted += 1
        return accepted


def build_publisher(manager: _DispatchTarget | None) -> EventPublisher:
    """Return a publisher for ``manager``, or a null one when there is none.

    The single place the "no manager means a null publisher" decision is made, so
    every service can take the publisher it is given and never test it for ``None``
    itself.
    """
    if manager is None:
        return NullEventPublisher()
    return WebSocketEventPublisher(manager)


def ensure_publisher(publisher: EventPublisher | None) -> EventPublisher:
    """Return ``publisher``, or a :class:`NullEventPublisher` when it is ``None``.

    Used by every service that accepts an *optional* publisher. The alternative —
    a service checking ``if self._events is not None`` at each publish site — is
    the same branch written three or four times per service, and the copies drift.
    Here the decision is made once, when the service is constructed.
    """
    return publisher if publisher is not None else NullEventPublisher()


__all__ = [
    "EventPublisher",
    "NullEventPublisher",
    "WebSocketEventPublisher",
    "build_publisher",
    "ensure_publisher",
]
