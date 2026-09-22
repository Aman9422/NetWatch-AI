"""TCP evidence tracking for a conversation (M9.9, M9.10).

M9 is not a TCP stack. It records the *control flags it actually observed* and
projects a coarse connection state from them:

    observed     a TCP flow was seen; no handshake evidence yet
    established  a SYN+ACK was seen, or a SYN plus ACKs in both directions
    closing      a FIN was seen in one direction
    closed       a RST was seen, or FINs were seen in both directions

The state is a **property** of the accumulated evidence rather than a
transition table. Evidence only ever accumulates, so the projected state can
only ever move forwards (``observed → established → closing → closed``) and a
later packet can never silently downgrade it. That property is exactly what
makes M9.10's rule — *a single SYN never proves the handshake completed* — fall
out of the design instead of needing a special case.

The observation belongs to one :class:`~app.connections.connection.Connection`
and is only touched while the registry lock is held, so it carries no lock of
its own, like ``ObservedDevice``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.connections.identity import Direction
from app.connections.state import TcpFlags
from app.schemas.connection import ConnectionState

# Upper bound on the distinct flag strings remembered per conversation. The
# compact flag form has at most 2**6 = 64 combinations, so this is reached only
# by pathological traffic and never grows without bound.
_MAX_OBSERVED_FLAG_VARIANTS = 64


@dataclass
class TcpObservation:
    """The TCP control evidence observed for one conversation (M9.9)."""

    source_syn: bool = False
    source_syn_ack: bool = False
    source_ack: bool = False
    source_fin: bool = False
    source_rst: bool = False

    destination_syn: bool = False
    destination_syn_ack: bool = False
    destination_ack: bool = False
    destination_fin: bool = False
    destination_rst: bool = False

    #: Distinct compact flag strings seen, bounded by
    #: :data:`_MAX_OBSERVED_FLAG_VARIANTS`.
    observed_flags: set[str] = field(default_factory=set)

    # -- ingestion --------------------------------------------------------

    def observe(self, direction: Direction, flags: TcpFlags) -> None:
        """Record one packet's flags for its direction.

        A packet whose direction cannot be established relative to the
        conversation is not attributed to either side — the counters would
        otherwise be a guess.
        """
        text = flags.text
        if text and len(self.observed_flags) < _MAX_OBSERVED_FLAG_VARIANTS:
            self.observed_flags.add(text)

        if direction is Direction.SOURCE:
            self.source_syn = self.source_syn or flags.syn
            self.source_ack = self.source_ack or flags.ack
            self.source_syn_ack = self.source_syn_ack or (
                flags.syn and flags.ack
            )
            self.source_fin = self.source_fin or flags.fin
            self.source_rst = self.source_rst or flags.rst
        elif direction is Direction.DESTINATION:
            self.destination_syn = self.destination_syn or flags.syn
            self.destination_ack = self.destination_ack or flags.ack
            self.destination_syn_ack = self.destination_syn_ack or (
                flags.syn and flags.ack
            )
            self.destination_fin = self.destination_fin or flags.fin
            self.destination_rst = self.destination_rst or flags.rst

    # -- derived evidence -------------------------------------------------

    @property
    def syn_ack_seen(self) -> bool:
        """Return True when a SYN+ACK was seen in either direction.

        A SYN+ACK is conclusive on its own: a peer only ever answers a SYN, so
        observing the reply proves the handshake happened even when the opening
        SYN was missed.
        """
        return self.source_syn_ack or self.destination_syn_ack

    @property
    def ack_both_directions(self) -> bool:
        """Return True when data flowed with ACK in both directions."""
        return self.source_ack and self.destination_ack

    @property
    def fin_both_directions(self) -> bool:
        """Return True when both peers sent a FIN."""
        return self.source_fin and self.destination_fin

    @property
    def rst_seen(self) -> bool:
        """Return True when either peer reset the connection."""
        return self.source_rst or self.destination_rst

    @property
    def state(self) -> ConnectionState:
        """Project the observed evidence onto a connection state (M9.10)."""
        if self.rst_seen or self.fin_both_directions:
            return ConnectionState.CLOSED
        if self.source_fin or self.destination_fin:
            return ConnectionState.CLOSING
        if self.syn_ack_seen:
            return ConnectionState.ESTABLISHED
        # The SYN was seen and both peers are talking with ACK but the SYN+ACK
        # itself was missed — the handshake still demonstrably completed.
        if self.source_syn and self.ack_both_directions:
            return ConnectionState.ESTABLISHED
        return ConnectionState.OBSERVED

    def flags_seen(self) -> list[str]:
        """Return the distinct observed flag strings in a stable order (M9.9)."""
        return sorted(self.observed_flags)
