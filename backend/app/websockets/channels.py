"""The four WebSocket channels (M14.6).

A channel is the unit of separation: it decides which endpoint a client dialled,
which events that client is entitled to, and — through
:mod:`app.websockets.policy` — how much buffering and rate budget it gets. Keeping
the vocabulary in one importable, dependency-free module is what lets the manager,
the policy table, the routes and the tests agree on the four names without a
string literal appearing twice.

The module is deliberately pure: no FastAPI, no asyncio, no settings. A channel is
a name and a sentence describing what travels on it.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum

#: URL prefix every channel is mounted under. M13.3 keeps ``/api/v1`` versioned
#: and allows an unversioned operational route; a WebSocket endpoint is neither a
#: resource path nor a versioned API, so it lives beside the API rather than
#: inside it, and this is the one place the prefix is written down.
WEBSOCKET_PREFIX = "/ws"


class Channel(str, Enum):
    """One of the four documented real-time streams (M14.3).

    Inheriting from :class:`str` means the value is used directly as the
    ``channel`` field of an event and in JSON, with no conversion step that could
    disagree with the enum.
    """

    DASHBOARD = "dashboard"
    PACKETS = "packets"
    ALERTS = "alerts"
    SYSTEM = "system"


#: What each channel is for, in the wording M14.6 uses. Exposed so diagnostics
#: and the design can describe a channel without restating the milestone.
CHANNEL_PURPOSES: Mapping[Channel, str] = {
    Channel.DASHBOARD: "General real-time dashboard updates",
    Channel.PACKETS: "Live normalized packet events",
    Channel.ALERTS: "New and updated security alerts and incident changes",
    Channel.SYSTEM: "Application and system state changes",
}

#: The path each channel answers on, so the routes and the tests cannot disagree
#: about a URL.
CHANNEL_PATHS: Mapping[Channel, str] = {
    Channel.DASHBOARD: f"{WEBSOCKET_PREFIX}/dashboard",
    Channel.PACKETS: f"{WEBSOCKET_PREFIX}/packets",
    Channel.ALERTS: f"{WEBSOCKET_PREFIX}/alerts",
    Channel.SYSTEM: f"{WEBSOCKET_PREFIX}/system",
}

#: Every channel, in the order the milestone lists them.
CHANNELS: tuple[Channel, ...] = (
    Channel.DASHBOARD,
    Channel.PACKETS,
    Channel.ALERTS,
    Channel.SYSTEM,
)

#: Reverse lookup. Built once so a route can resolve its own path to a channel
#: instead of hard-coding which one it serves.
_PATH_TO_CHANNEL: Mapping[str, Channel] = {
    path: channel for channel, path in CHANNEL_PATHS.items()
}


def channel_for_path(path: str) -> Channel | None:
    """Return the channel a path serves, or ``None`` when it serves none.

    ``None`` rather than an exception: an unknown path is the ordinary outcome for
    a caller asking about a route that is not a WebSocket channel, and the route
    that uses this treats it as a refusal.
    """
    return _PATH_TO_CHANNEL.get(str(path))


def parse_channel(value: Channel | str) -> Channel:
    """Return ``value`` as a :class:`Channel`.

    Raises:
        ValueError: If the value is not one of the four channels. Raising is right
            here — unlike :func:`channel_for_path`, this is called on a value the
            application itself produced, so an unknown name is a bug rather than
            a client's mistake.
    """
    if isinstance(value, Channel):
        return value
    return Channel(str(value))


__all__ = [
    "CHANNELS",
    "CHANNEL_PATHS",
    "CHANNEL_PURPOSES",
    "WEBSOCKET_PREFIX",
    "Channel",
    "channel_for_path",
    "parse_channel",
]
