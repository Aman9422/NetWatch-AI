"""Client input policy: the only messages a socket may send (M14.23).

M14 is server-push-only (M14.23). This module is what makes that a property of the
code rather than a promise in a document: :func:`parse_client_message` is the only
function that reads a client frame, it accepts exactly two types — ``ping`` and
``pong`` — and it produces a :class:`MessageResult` for everything else, including
a refusal sentence drawn from the closed set below.

Three rules it enforces, all from M14.22/M14.23:

* **Size first.** A frame longer than ``max_bytes`` is refused before it is parsed,
  so an attacker cannot spend the server's JSON parser by sending a large frame.
* **Nothing is echoed.** A refusal names *which* rule was broken, never the bytes
  that broke it: echoing a client's input back is how a payload becomes a log
  line, an error message, or a second injection.
* **Nothing is executed.** A message is a name and an optional nonce. There is no
  field that selects a channel, a topic, a filter or a command, so no client frame
  can widen what a client receives or reach a service.

The module has no dependency on a socket, a manager or a service — it takes the
text a frame carried and returns a value — which is what lets the tests drive it
from literals.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

#: The two accepted client message types (M14.23).
MESSAGE_PING = "ping"
MESSAGE_PONG = "pong"

#: The closed set of accepted types.
ACCEPTED_MESSAGE_TYPES: frozenset[str] = frozenset({MESSAGE_PING, MESSAGE_PONG})

#: Longest nonce the server will mirror back. A nonce is an opaque pairing token,
#: so a longer one carries no information the server needs, and truncating keeps a
#: legal-sized frame from producing a legal-but-large reply.
MAX_NONCE_LENGTH = 64

#: Refusal sentences, one per way a frame can be rejected (M14.23). They are
#: constants rather than formatted strings so no refusal can accidentally embed a
#: client-supplied value (M14.22).
REFUSAL_EMPTY = "The message was empty"
REFUSAL_TOO_LARGE = "The message is larger than the allowed limit"
REFUSAL_NOT_TEXT = "The message must be a text frame"
REFUSAL_NOT_JSON = "The message was not valid JSON"
REFUSAL_NOT_OBJECT = "The message must be a JSON object"
REFUSAL_MISSING_TYPE = "The message has no 'type' field"
REFUSAL_UNKNOWN_TYPE = "The message type is not supported"
REFUSAL_INVALID_NONCE = "The message 'nonce' must be a string"


@dataclass(frozen=True)
class ClientMessage:
    """One accepted client message.

    Attributes:
        type: Either ``ping`` or ``pong``.
        nonce: An optional opaque token a client may send to pair a pong with the
            ping that caused it. Truncated to :data:`MAX_NONCE_LENGTH`.
    """

    type: str
    nonce: str | None = None

    @property
    def is_ping(self) -> bool:
        """Return True for a client ping, which the server answers."""
        return self.type == MESSAGE_PING

    @property
    def is_pong(self) -> bool:
        """Return True for a client pong, which clears the keepalive mark."""
        return self.type == MESSAGE_PONG


@dataclass(frozen=True)
class MessageResult:
    """The outcome of reading one client frame.

    Attributes:
        message: The accepted message, or ``None`` when the frame was refused.
        refusal: A sentence from the constant set above, or ``None`` when the
            frame was accepted. Exactly one of the two is set.
    """

    message: ClientMessage | None = None
    refusal: str | None = None

    @property
    def accepted(self) -> bool:
        """Return True when the frame may be acted on."""
        return self.message is not None

    @property
    def is_ping(self) -> bool:
        """Return True for an accepted client ping."""
        return self.message is not None and self.message.is_ping

    @property
    def is_pong(self) -> bool:
        """Return True for an accepted client pong."""
        return self.message is not None and self.message.is_pong


def _refuse(reason: str) -> MessageResult:
    """Return a refused result naming ``reason``."""
    return MessageResult(message=None, refusal=reason)


def _read_nonce(payload: dict[str, object]) -> tuple[str | None, MessageResult | None]:
    """Return the payload's nonce, or a refusal when it is not a string.

    A non-string nonce is refused rather than ignored: a client that sends an
    object where a token belongs is confused about the protocol, and silently
    answering with an empty nonce would hide its bug.
    """
    if "nonce" not in payload or payload["nonce"] is None:
        return None, None
    raw_nonce = payload["nonce"]
    if not isinstance(raw_nonce, str):
        return None, _refuse(REFUSAL_INVALID_NONCE)
    return raw_nonce[:MAX_NONCE_LENGTH], None


def parse_client_message(raw: str, *, max_bytes: int) -> MessageResult:
    """Validate one client frame against the M14.23 input policy.

    Args:
        raw: The text the socket received, exactly as it arrived.
        max_bytes: The largest frame the server accepts, in UTF-8 bytes
            (``websocket_max_client_message_bytes``).

    Returns:
        An accepted :class:`ClientMessage`, or a refusal whose sentence is one of
        this module's constants. Never raises: a frame is untrusted input, and an
        exception here would be a client-controlled failure.

    The checks run cheapest-and-most-decisive first — length, then JSON, then
    shape, then type — so the common refusal (garbage from something that is not a
    client) costs a length comparison rather than a parse.
    """
    if not isinstance(raw, str) or not raw:
        return _refuse(REFUSAL_EMPTY)
    if len(raw.encode("utf-8")) > int(max_bytes):
        return _refuse(REFUSAL_TOO_LARGE)
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError):
        return _refuse(REFUSAL_NOT_JSON)
    if not isinstance(payload, dict):
        return _refuse(REFUSAL_NOT_OBJECT)
    if "type" not in payload:
        return _refuse(REFUSAL_MISSING_TYPE)
    message_type = payload["type"]
    if not isinstance(message_type, str) or message_type not in ACCEPTED_MESSAGE_TYPES:
        return _refuse(REFUSAL_UNKNOWN_TYPE)
    nonce, refusal = _read_nonce(payload)
    if refusal is not None:
        return refusal
    return MessageResult(message=ClientMessage(type=message_type, nonce=nonce))


def refuse_binary_frame() -> MessageResult:
    """Return the refusal for a non-text frame (M14.23).

    A binary frame is legal at the WebSocket transport and is not one of the two
    documented client messages. It gets its own sentence rather than the
    "malformed JSON" one, because a client that sent bytes and a client that sent
    broken JSON need different fixes, and a refusal that names the wrong rule
    sends the reader to the wrong place.
    """
    return _refuse(REFUSAL_NOT_TEXT)


__all__ = [
    "ACCEPTED_MESSAGE_TYPES",
    "MAX_NONCE_LENGTH",
    "MESSAGE_PING",
    "MESSAGE_PONG",
    "REFUSAL_EMPTY",
    "REFUSAL_INVALID_NONCE",
    "REFUSAL_MISSING_TYPE",
    "REFUSAL_NOT_JSON",
    "REFUSAL_NOT_OBJECT",
    "REFUSAL_NOT_TEXT",
    "REFUSAL_TOO_LARGE",
    "REFUSAL_UNKNOWN_TYPE",
    "ClientMessage",
    "MessageResult",
    "parse_client_message",
]
