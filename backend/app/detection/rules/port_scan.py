"""Port scan detector (M10.8).

A host that opens contact with an unusually large number of **distinct
destination ports** inside a short window has the shape of a port scan. This
detector observes exactly that: per source, the distinct destination ports it
contacted within a configurable window, compared against a configurable
threshold.

Two deliberate choices keep it honest:

* **Only genuine connection attempts count.** Counting every packet that names
  a destination port would flag a busy server, because each reply it sends
  carries a fresh ephemeral destination port — a server answering many clients
  could reach any port threshold without ever scanning. Attempts are narrowed
  in :mod:`app.detection.rules.signals`: a TCP pure ``SYN``, or a datagram sent
  from an ephemeral source port.
* **``PORT_SCAN_SYN_RATIO_THRESHOLD`` characterises, it does not gate.** The
  SYN share of a source's attempts separates a SYN scan (all attempts are SYNs)
  from a UDP or mixed scan. Using it as a *hard* gate would have to miss
  connect-style scans, which open with a SYN but continue with data — so the
  ratio selects the wording and the reported scan type, and the finding is
  raised either way once the port threshold is met.

The finding names only the source: a scan spans many destinations, so
``destination_ip`` is deliberately left empty rather than naming whichever
destination happened to complete the window (M10.14).

When a source crosses the threshold, its state is discarded so the same window
cannot emit a stream of identical findings — the only suppression M10
implements (M10.18).
"""

from __future__ import annotations

import threading

from app.detection.base import DetectionRule
from app.detection.context import DetectionContext
from app.detection.finding import DetectionFinding, threshold_confidence
from app.detection.rules.signals import is_connection_attempt, is_handshake_open
from app.detection.state import WindowedCounter, WindowedDistinct
from app.connections.identity import transport_of

# Default window and threshold, kept in step with the settings defaults (M10.7).
DEFAULT_WINDOW_SECONDS = 10.0
DEFAULT_UNIQUE_PORT_THRESHOLD = 20
DEFAULT_SYN_RATIO_THRESHOLD = 0.5
# Default bound on how many sources / ports one rule instance tracks (M10.19).
DEFAULT_MAX_KEYS = 4096
DEFAULT_MAX_PORTS_PER_SOURCE = 4096


class PortScanRule(DetectionRule):
    """Report a source contacting many distinct destination ports (M10.8)."""

    rule_id = "port_scan"
    rule_name = "Port Scan"
    description = "One source contacting many distinct destination ports in a window"

    def __init__(
        self,
        *,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        unique_port_threshold: int = DEFAULT_UNIQUE_PORT_THRESHOLD,
        syn_ratio_threshold: float = DEFAULT_SYN_RATIO_THRESHOLD,
        max_keys: int = DEFAULT_MAX_KEYS,
        max_values_per_key: int = DEFAULT_MAX_PORTS_PER_SOURCE,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled, window_seconds=window_seconds)
        if unique_port_threshold < 1:
            raise ValueError("unique_port_threshold must be at least 1")
        if not 0.0 <= syn_ratio_threshold <= 1.0:
            raise ValueError("syn_ratio_threshold must be between 0 and 1")

        self._unique_port_threshold = int(unique_port_threshold)
        self._syn_ratio_threshold = float(syn_ratio_threshold)
        self._ports: WindowedDistinct[int] = WindowedDistinct(
            window_seconds, max_keys, max_values_per_key
        )
        self._attempts = WindowedCounter(window_seconds, max_keys)
        self._syn_attempts = WindowedCounter(window_seconds, max_keys)
        # Guards the read-then-clear decision so two concurrent evaluations for
        # the same source cannot both emit a finding for one window (M10.18).
        self._lock = threading.Lock()

    def evaluate(self, context: DetectionContext) -> DetectionFinding | None:
        """Return a finding when one source contacts too many ports (M10.8)."""
        packet = context.packet
        if packet is None or packet.source_ip is None:
            return None
        if not is_connection_attempt(packet):
            return None
        destination_port = packet.destination_port
        if destination_port is None:
            return None

        source_ip = packet.source_ip
        at = context.timestamp
        syn = is_handshake_open(packet)

        with self._lock:
            self._attempts.record(source_ip, at)
            if syn:
                self._syn_attempts.record(source_ip, at)
            unique_ports = self._ports.record(source_ip, destination_port, at)
            if unique_ports < self._unique_port_threshold:
                return None

            attempts = self._attempts.count(source_ip, at)
            syn_attempts = self._syn_attempts.count(source_ip, at)
            window_start = self._ports.window_start(source_ip, at)
            # Minimal rule-level suppression (M10.18): forget this source so the
            # window that just produced a finding starts again from empty.
            self._forget(source_ip)

        syn_ratio = (syn_attempts / attempts) if attempts else 0.0
        is_syn_scan = syn_ratio >= self._syn_ratio_threshold
        window_seconds = self._window_seconds or 0.0

        evidence: dict[str, int | float | str | bool] = {
            "unique_destination_ports": unique_ports,
            "unique_port_threshold": self._unique_port_threshold,
            "connection_attempts": attempts,
            "syn_attempts": syn_attempts,
            "syn_ratio": round(syn_ratio, 4),
            "syn_ratio_threshold": self._syn_ratio_threshold,
            "observation_window_seconds": window_seconds,
        }
        if window_start is not None:
            evidence["window_start"] = window_start

        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            timestamp=at,
            source_ip=source_ip,
            # A scan spans destinations, so no single destination is claimed.
            destination_ip=None,
            protocol=transport_of(packet),
            description=(
                f"Possible SYN port scan detected from {source_ip}"
                if is_syn_scan
                else f"Possible port scan detected from {source_ip}"
            ),
            evidence=evidence,
            confidence=threshold_confidence(
                float(unique_ports), float(self._unique_port_threshold)
            ),
            metadata={
                "unique_destination_ports": unique_ports,
                "scan_characterisation": "syn" if is_syn_scan else "multi_port",
            },
        )

    def state_size(self) -> int:
        """Return how many sources the rule currently tracks (M10.19)."""
        return len(self._ports)

    def reset(self) -> None:
        """Discard every accumulated observation."""
        self._ports.reset()
        self._attempts.reset()
        self._syn_attempts.reset()

    def _forget(self, source_ip: str) -> None:
        """Drop all state for one source (caller holds the rule lock)."""
        self._ports.clear(source_ip)
        self._attempts.clear(source_ip)
        self._syn_attempts.clear(source_ip)
