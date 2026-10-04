"""Detection engine: the orchestrator every detector plugs into (M10.6).

The engine owns *what* is evaluated and *how a failure is contained*; it owns no
detection logic of its own. Concretely it:

* holds the registered rules and their enabled/disabled state,
* builds one :class:`~app.detection.context.DetectionContext` per evaluation,
* evaluates every enabled rule against it,
* **isolates per-rule failures** — a rule that raises is counted and logged, and
  the remaining rules still run (M10.17),
* enriches findings with M8 device associations,
* retains findings in a bounded history for querying (M10.22),
* tracks execution diagnostics.

It never raises into its caller. The capture pipeline calls
:meth:`DetectionEngine.process_packet` on the hot path, and M10.21 requires that
no detection failure may stop capture, processing, statistics, persistence,
device discovery or connection tracking. Every failure path here is therefore
counted and logged, never propagated.

The engine is thread-safe: the rule table is guarded while it is read or
changed, counters are guarded, and rules are evaluated *outside* the table lock
so a slow rule cannot block an enable or disable call (M10.20).
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from app.detection.base import DetectionRule
from app.detection.context import DetectionContext, DeviceResolver
from app.detection.finding import DetectionFinding
from app.detection.history import DEFAULT_MAX_FINDINGS, FindingHistory
from app.detection.rates import (
    DEFAULT_RATES_TTL_SECONDS,
    DEFAULT_RATES_WINDOW,
    RatesFeed,
    TrafficRatesSource,
)
from app.schemas.detection import DetectionDiagnostics
from app.schemas.packet import NormalizedPacket

logger = logging.getLogger(__name__)


@dataclass
class RuleCounters:
    """Per-rule execution counters, for diagnostics (M10.17/M10.31)."""

    evaluations: int = 0
    findings: int = 0
    errors: int = 0
    last_error_at: float | None = None


@dataclass
class _EngineState:
    """Mutable engine state, all of it guarded by the engine lock."""

    rules: dict[str, DetectionRule] = field(default_factory=dict)
    counters: dict[str, RuleCounters] = field(default_factory=dict)
    evaluations: int = 0
    findings: int = 0
    errors: int = 0


class DetectionEngine:
    """Registers detection rules and evaluates them against a context (M10.6)."""

    def __init__(
        self,
        rules: Iterable[DetectionRule] | None = None,
        *,
        rates_source: TrafficRatesSource | None = None,
        rates_window: str = DEFAULT_RATES_WINDOW,
        rates_ttl_seconds: float = DEFAULT_RATES_TTL_SECONDS,
        device_resolver: DeviceResolver | None = None,
        max_findings: int = DEFAULT_MAX_FINDINGS,
        clock: Callable[[], float] = time.time,
        enabled: bool = True,
    ) -> None:
        self._lock = threading.Lock()
        self._state = _EngineState()
        self._history = FindingHistory(max_findings)
        self._enabled = bool(enabled)
        self._device_resolver = device_resolver
        self._clock = clock
        self._rates = (
            RatesFeed(rates_source, rates_window, rates_ttl_seconds)
            if rates_source is not None
            else None
        )

        if rules is not None:
            self.register_many(rules)

    # -- registration -----------------------------------------------------

    def register(self, rule: DetectionRule) -> None:
        """Register one rule.

        Raises:
            ValueError: If the rule declares no id, or a rule with the same
                ``rule_id`` is already registered. Rule ids are the stable name
                used by configuration, diagnostics and the API, so a collision is
                a programming error rather than something to resolve silently.
        """
        if not rule.rule_id:
            raise ValueError("A detection rule must declare a rule_id")
        with self._lock:
            if rule.rule_id in self._state.rules:
                raise ValueError(f"Duplicate detection rule id: {rule.rule_id}")
            self._state.rules[rule.rule_id] = rule
            self._state.counters[rule.rule_id] = RuleCounters()

    def register_many(self, rules: Iterable[DetectionRule]) -> None:
        """Register several rules, in order."""
        for rule in rules:
            self.register(rule)

    def unregister(self, rule_id: str) -> None:
        """Remove a rule and its counters.

        Raises:
            KeyError: If no rule with that id is registered.
        """
        with self._lock:
            if rule_id not in self._state.rules:
                raise KeyError(f"Unknown detection rule: {rule_id}")
            del self._state.rules[rule_id]
            del self._state.counters[rule_id]

    def get_rule(self, rule_id: str) -> DetectionRule | None:
        """Return the registered rule with ``rule_id``, or ``None``."""
        with self._lock:
            return self._state.rules.get(rule_id)

    def get_rules(self) -> list[DetectionRule]:
        """Return the registered rules, in registration order."""
        with self._lock:
            return list(self._state.rules.values())

    def enable(self, rule_id: str) -> None:
        """Include a registered rule in evaluation.

        Raises:
            KeyError: If no rule with that id is registered.
        """
        self._require_rule(rule_id).enable()

    def disable(self, rule_id: str) -> None:
        """Exclude a registered rule from evaluation without removing it.

        Raises:
            KeyError: If no rule with that id is registered.
        """
        self._require_rule(rule_id).disable()

    @property
    def enabled(self) -> bool:
        """Return True while the engine evaluates rules at all (M10.21)."""
        return self._enabled

    def set_enabled(self, enabled: bool) -> None:
        """Turn evaluation on or off without discarding rules or findings."""
        self._enabled = bool(enabled)

    # -- evaluation -------------------------------------------------------

    def build_context(
        self, packet: NormalizedPacket | None = None
    ) -> DetectionContext:
        """Build the context one evaluation will see (M10.4).

        The observation time comes from the packet when it carries one, so a
        finding is timestamped with the capture time rather than with the moment
        detection happened to run. Rates come from the throttled feed (M10.12)
        and are reported as unknown when no source is wired or the source failed.
        """
        timestamp = self._clock()
        if packet is not None and packet.timestamp and packet.timestamp > 0:
            timestamp = float(packet.timestamp)

        packets_per_second: float | None = None
        bytes_per_second: float | None = None
        rate_window_seconds: float | None = None
        if self._rates is not None:
            packets_per_second, bytes_per_second = self._rates.current()
            if bytes_per_second is not None:
                rate_window_seconds = self._rates.window_seconds

        return DetectionContext(
            timestamp=timestamp,
            packet=packet,
            packets_per_second=packets_per_second,
            bytes_per_second=bytes_per_second,
            rate_window_seconds=rate_window_seconds,
            device_resolver=self._device_resolver,
        )

    def process_packet(self, packet: NormalizedPacket) -> list[DetectionFinding]:
        """Turn one pipeline packet into detection findings (M10.21).

        Never raises: any unexpected failure is counted and logged so the
        capture pipeline is unaffected (M10.21).
        """
        if not self._enabled:
            return []
        try:
            return self.evaluate(self.build_context(packet))
        except Exception:  # noqa: BLE001 - detection must not stop capture
            self._record_engine_error()
            logger.exception("Detection evaluation failed; capture continues")
            return []

    def evaluate(self, context: DetectionContext) -> list[DetectionFinding]:
        """Evaluate every enabled rule and return the findings they produced.

        Each rule is evaluated in isolation: a rule that raises is counted and
        logged, and the remaining rules still run (M10.17). Rules are evaluated
        outside the rule-table lock, so a slow detector cannot block an API call
        that enables or disables a rule.
        """
        findings: list[DetectionFinding] = []
        for rule in self._enabled_rules():
            try:
                finding = rule.evaluate(context)
            except Exception:  # noqa: BLE001 - one bad rule must not stop others
                self._record_rule_error(rule.rule_id)
                logger.exception(
                    "Detection rule %r failed; remaining rules continue",
                    rule.rule_id,
                )
                continue

            self._record_rule_evaluation(rule.rule_id)
            if finding is None:
                continue
            findings.append(self._enrich(finding, context))
            self._record_rule_finding(rule.rule_id)

        if findings:
            self._history.add_many(findings)
        return findings

    # -- findings ---------------------------------------------------------

    def get_findings(
        self,
        *,
        rule_id: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        device_id: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int | None = None,
    ) -> list[DetectionFinding]:
        """Return retained findings matching the supplied filters (M10.22).

        Filters combine with AND and the result is newest first. ``since`` is
        inclusive and ``until`` exclusive, so a query window has an explicit
        start and end (M10.13).
        """
        return self._history.query(
            rule_id=rule_id,
            source_ip=source_ip,
            destination_ip=destination_ip,
            device_id=device_id,
            since=since,
            until=until,
            limit=limit,
        )

    def get_finding(self, finding_id: str) -> DetectionFinding | None:
        """Return one retained finding by identifier, or ``None`` (M13.12).

        A read method on the bounded history rather than a new store: a finding
        is an observation that M10 retains in memory and never persists, so the
        only honest answer for an id that has aged out of the cap is that it is
        no longer retained. The API maps that to a ``404``.
        """
        return self._history.get_finding(finding_id)

    def count_findings(
        self,
        *,
        rule_id: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        device_id: str | None = None,
        since: float | None = None,
        until: float | None = None,
    ) -> int:
        """Return how many retained findings match the supplied filters.

        The total a listing reports alongside its page. It uses the same filter
        predicate as :meth:`get_findings`, so a count can never disagree with the
        page it accompanies (M13.24).
        """
        return self._history.count_matching(
            rule_id=rule_id,
            source_ip=source_ip,
            destination_ip=destination_ip,
            device_id=device_id,
            since=since,
            until=until,
        )

    def get_retained_finding_count(self) -> int:
        """Return how many findings the bounded history currently holds."""
        return self._history.count()

    def get_diagnostics(self) -> DetectionDiagnostics:
        """Return execution diagnostics for the engine (M10.6/M10.17)."""
        with self._lock:
            rules = list(self._state.rules.values())
            return DetectionDiagnostics(
                evaluations=self._state.evaluations,
                findings=self._state.findings,
                errors=self._state.errors,
                enabled_rules=sum(1 for rule in rules if rule.enabled),
                registered_rules=len(rules),
                retained_findings=self._history.count(),
            )

    def get_rule_counters(self) -> dict[str, RuleCounters]:
        """Return a copy of the per-rule counters, for diagnostics (M10.31)."""
        with self._lock:
            return {
                rule_id: RuleCounters(
                    evaluations=counters.evaluations,
                    findings=counters.findings,
                    errors=counters.errors,
                    last_error_at=counters.last_error_at,
                )
                for rule_id, counters in self._state.counters.items()
            }

    def reset(self) -> None:
        """Discard every finding, counter and accumulated rule observation."""
        self._history.clear()
        with self._lock:
            for rule in self._state.rules.values():
                rule.reset()
            self._state.counters = {
                rule_id: RuleCounters() for rule_id in self._state.rules
            }
            self._state.evaluations = 0
            self._state.findings = 0
            self._state.errors = 0
        if self._rates is not None:
            self._rates.reset()

    # -- internals --------------------------------------------------------

    def _enabled_rules(self) -> list[DetectionRule]:
        """Return the enabled rules, read under the rule-table lock."""
        with self._lock:
            return [rule for rule in self._state.rules.values() if rule.enabled]

    def _require_rule(self, rule_id: str) -> DetectionRule:
        """Return a registered rule, raising when the id is unknown."""
        with self._lock:
            rule = self._state.rules.get(rule_id)
        if rule is None:
            raise KeyError(f"Unknown detection rule: {rule_id}")
        return rule

    def _enrich(
        self, finding: DetectionFinding, context: DetectionContext
    ) -> DetectionFinding:
        """Attach M8 device associations to a finding (M10.4).

        Association is enrichment: an unresolved address stays ``None`` rather
        than being invented, and a resolver failure degrades the finding instead
        of dropping it.
        """
        if context.device_resolver is None:
            return finding
        source_device_id = context.resolve_device(finding.source_ip)
        destination_device_id = context.resolve_device(finding.destination_ip)
        if source_device_id is None and destination_device_id is None:
            return finding
        return finding.with_devices(
            source_device_id=source_device_id,
            destination_device_id=destination_device_id,
        )

    def _record_rule_evaluation(self, rule_id: str) -> None:
        """Count one successful rule evaluation."""
        with self._lock:
            self._state.evaluations += 1
            counters = self._state.counters.get(rule_id)
            if counters is not None:
                counters.evaluations += 1

    def _record_rule_finding(self, rule_id: str) -> None:
        """Count one finding produced by a rule."""
        with self._lock:
            self._state.findings += 1
            counters = self._state.counters.get(rule_id)
            if counters is not None:
                counters.findings += 1

    def _record_rule_error(self, rule_id: str) -> None:
        """Count one isolated rule failure (M10.17)."""
        with self._lock:
            self._state.errors += 1
            counters = self._state.counters.get(rule_id)
            if counters is not None:
                counters.errors += 1
                counters.last_error_at = self._clock()

    def _record_engine_error(self) -> None:
        """Count one failure of the engine itself."""
        with self._lock:
            self._state.errors += 1
