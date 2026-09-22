"""Connection state vocabulary and TCP flag parsing (M9.10/M9.11).

``ConnectionState`` itself lives in :mod:`app.schemas.connection`, because it is
part of the wire contract. This module holds the *rules* around it: parsing the
compact TCP flag form M5 records (``S``, ``SA``, ``PA``, ``FA`` …), the state a
conversation starts in, the state it takes when it expires, and which states
mean the conversation is over.

It holds no state and performs no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.connections.identity import PROTOCOL_ICMP, PROTOCOL_TCP, PROTOCOL_UDP
from app.schemas.connection import ConnectionState

# Flag letters used by the compact Scapy form.
_FLAG_FIN = "F"
_FLAG_SYN = "S"
_FLAG_RST = "R"
_FLAG_PSH = "P"
_FLAG_ACK = "A"
_FLAG_URG = "U"

# States that mean "this conversation is over".
_TERMINAL_STATES = frozenset({ConnectionState.CLOSED, ConnectionState.INACTIVE})

# Protocols whose state is a simple activity state rather than a TCP state.
_ACTIVITY_PROTOCOLS = frozenset({PROTOCOL_UDP, PROTOCOL_ICMP})


@dataclass(frozen=True)
class TcpFlags:
    """The TCP control flags observed in one packet."""

    fin: bool = False
    syn: bool = False
    rst: bool = False
    psh: bool = False
    ack: bool = False
    urg: bool = False

    @property
    def is_empty(self) -> bool:
        """Return True when no flag at all was observed."""
        return not any((self.fin, self.syn, self.rst, self.psh, self.ack, self.urg))

    @property
    def text(self) -> str:
        """Render the flags in Scapy's compact order (``""`` when empty)."""
        letters = (
            (_FLAG_FIN, self.fin),
            (_FLAG_SYN, self.syn),
            (_FLAG_RST, self.rst),
            (_FLAG_PSH, self.psh),
            (_FLAG_ACK, self.ack),
            (_FLAG_URG, self.urg),
        )
        return "".join(letter for letter, present in letters if present)

    @property
    def is_handshake_open(self) -> bool:
        """Return True for a pure ``SYN``: the start of a fresh handshake.

        A ``SYN+ACK`` is *not* a handshake open — it is a reply, and belongs to
        the reverse direction.
        """
        return self.syn and not self.ack

    @classmethod
    def parse(cls, value: str | None) -> "TcpFlags":
        """Parse a compact flag string, never raising.

        Any form that cannot be read — ``None``, an empty string, or a value
        that is not a set of flag letters — yields "no flags observed" rather
        than a guess.
        """
        if not value:
            return cls()
        text = str(value).strip().upper()
        if not text:
            return cls()
        return cls(
            fin=_FLAG_FIN in text,
            syn=_FLAG_SYN in text,
            rst=_FLAG_RST in text,
            psh=_FLAG_PSH in text,
            ack=_FLAG_ACK in text,
            urg=_FLAG_URG in text,
        )


# Flags used when a packet carried no readable flag string.
NO_FLAGS = TcpFlags()


def initial_state(protocol: str) -> ConnectionState:
    """Return the state a newly created connection starts in.

    A TCP conversation starts as ``observed`` — a single packet never proves the
    handshake completed (M9.10). UDP and ICMP have no handshake, so they start
    ``active`` (M9.11). Anything else is ``unknown``.
    """
    if protocol == PROTOCOL_TCP:
        return ConnectionState.OBSERVED
    if protocol in _ACTIVITY_PROTOCOLS:
        return ConnectionState.ACTIVE
    return ConnectionState.UNKNOWN


def state_after_expiry(protocol: str, current: ConnectionState) -> ConnectionState:
    """Return the state a connection takes when it expires (M9.15).

    A TCP conversation keeps its observed TCP state, because that state is real
    evidence — a packet-less timeout proves nothing about the handshake. A UDP or
    ICMP conversation has no such evidence, so it becomes ``inactive``.
    """
    if protocol in _ACTIVITY_PROTOCOLS:
        if current in (ConnectionState.ACTIVE, ConnectionState.UNKNOWN):
            return ConnectionState.INACTIVE
    return current


def is_terminal(state: ConnectionState) -> bool:
    """Return True when ``state`` means the conversation is over."""
    return state in _TERMINAL_STATES
