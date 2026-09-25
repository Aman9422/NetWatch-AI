"""Framework tests for the M10 detection layer (M10.23).

These tests exercise the pieces every detector depends on and none of the
detectors themselves: the rule interface, the detection context, the finding
model, the engine's registration and evaluation cycle, failure isolation and
diagnostics.

The detectors are covered behaviourally in their own files; what is asserted
here is the *contract* they all rely on.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.detection import (
    DetectionEngine,
    DetectionFinding,
    DetectionWindow,
    RatesFeed,
    threshold_confidence,
)
from app.detection.finding import MIN_CONFIDENCE, new_finding_id
from tests.detection_fakes import (
    DETECTION_BASE_TIME,
    DEFAULT_DESTINATION_IP,
    DEFAULT_SOURCE_IP,
    FakeRatesSource,
    FixedRule,
    RecordingRule,
    RaisingRule,
    make_context,
    make_device_resolver,
    make_syn_packet,
)
from tests.fakes import FakeClock


# ---------------------------------------------------------------------------
# The rule interface (M10.3)
# ---------------------------------------------------------------------------


def test_every_detector_declares_an_identity() -> None:
    """Each M10 rule exposes a stable id, a name and a description (M10.3)."""
    from app.config.settings import settings
    from app.detection import build_default_rules

    rules = build_default_rules(settings)

    assert [rule.rule_id for rule in rules] == [
        "port_scan",
        "syn_flood",
        "icmp_flood",
        "internal_scan",
        "high_bandwidth",
    ]
    for rule in rules:
        assert rule.rule_id
        assert rule.rule_name
        assert rule.description
        assert rule.enabled is True
        assert rule.window_seconds is not None
        assert rule.window_seconds > 0


def test_rules_are_enabled_by_default_and_can_be_toggled() -> None:
    """A rule starts enabled and enable/disable change only its own flag."""
    rule = FixedRule()

    assert rule.enabled is True
    rule.disable()
    assert rule.enabled is False
    rule.enable()
    assert rule.enabled is True


def test_a_disabled_rule_still_evaluates_when_called_directly() -> None:
    """``enabled`` is the engine's concern; it never mutates ``evaluate`` (M10.3)."""
    rule = FixedRule(fires=True, enabled=False)

    assert rule.evaluate(make_context()) is not None


def test_rule_repr_names_the_rule_and_its_state() -> None:
    """The diagnostic representation is usable in a log line (M10.3)."""
    rule = FixedRule(rule_id="demo", fires=False)

    text = repr(rule)

    assert "demo" in text
    assert "FixedRule" in text


# ---------------------------------------------------------------------------
# The detection context (M10.4/M10.13)
# ---------------------------------------------------------------------------


def test_context_exposes_the_packet_it_carries() -> None:
    """Convenience accessors read through to the packet (M10.4)."""
    packet = make_syn_packet(source_ip="10.0.0.1", destination_port=8080)
    context = make_context(packet=packet)

    assert context.source_ip == "10.0.0.1"
    assert context.destination_port == 8080
    assert context.protocol == "TCP"
    assert context.packet_length == packet.length


def test_context_without_a_packet_reports_nothing() -> None:
    """A snapshot-only context answers ``None`` rather than inventing a packet."""
    context = make_context()

    assert context.packet is None
    assert context.source_ip is None
    assert context.destination_ip is None
    assert context.destination_port is None
    assert context.protocol is None
    assert context.packet_length == 0


def test_context_window_is_bounded_and_start_inclusive() -> None:
    """A window has an explicit start and end (M10.13)."""
    context = make_context(timestamp=100.0)

    window = context.window(10.0)

    assert window.start == 90.0
    assert window.end == 100.0
    assert window.duration == 10.0
    assert window.contains(90.0) is True
    assert window.contains(99.999) is True
    assert window.contains(100.0) is False
    assert window.contains(89.999) is False


def test_windows_never_both_claim_the_same_instant() -> None:
    """Adjacent windows tile the timeline without overlap (M10.13)."""
    first = DetectionWindow(start=0.0, end=10.0)
    second = DetectionWindow(start=10.0, end=20.0)

    assert first.contains(10.0) is False
    assert second.contains(10.0) is True


def test_context_resolves_device_ids_through_the_injected_resolver() -> None:
    """Device attribution is delegated, never guessed (M10.4)."""
    resolver = make_device_resolver({DEFAULT_SOURCE_IP: "dev-1"})
    context = make_context(device_resolver=resolver)

    assert context.resolve_device(DEFAULT_SOURCE_IP) == "dev-1"
    assert context.resolve_device("10.9.9.9") is None
    assert context.resolve_device(None) is None


def test_context_swallows_a_resolver_failure() -> None:
    """A resolver outage degrades association instead of raising (M10.4)."""

    def broken_resolver(_address: str) -> str | None:
        raise RuntimeError("simulated registry failure")

    context = make_context(device_resolver=broken_resolver)

    assert context.resolve_device(DEFAULT_SOURCE_IP) is None


# ---------------------------------------------------------------------------
# The finding model (M10.5/M10.14/M10.15)
# ---------------------------------------------------------------------------


def test_finding_ids_are_unique_and_prefixed() -> None:
    """A finding is an observation, so each one gets its own id (M10.5)."""
    first = new_finding_id()
    second = new_finding_id()

    assert first != second
    assert first.startswith("fnd-")


def test_finding_requires_the_fields_a_reader_needs() -> None:
    """A finding cannot be built without its rule identity and wording (M10.5)."""
    with pytest.raises(ValidationError):
        # A deliberate call the model must reject (M10.5).
        DetectionFinding(  # type: ignore[call-arg]
            timestamp=1.0, description="missing rule identity"
        )


def test_finding_rejects_a_negative_timestamp() -> None:
    """Observation times are epoch seconds and never negative (M10.5)."""
    with pytest.raises(ValidationError):
        DetectionFinding(
            rule_id="r",
            rule_name="R",
            timestamp=-1.0,
            description="bad time",
        )


def test_finding_confidence_is_bounded() -> None:
    """Confidence is a probability-like value in ``[0, 1]`` (M10.15)."""
    with pytest.raises(ValidationError):
        DetectionFinding(
            rule_id="r",
            rule_name="R",
            timestamp=1.0,
            description="bad confidence",
            confidence=1.5,
        )


def test_finding_defaults_describe_an_unscored_observation() -> None:
    """A finding carries no severity or risk field at all (M10.5/M10.15)."""
    finding = DetectionFinding(
        rule_id="r",
        rule_name="R",
        timestamp=1.0,
        description="Possible port scan detected",
    )

    assert finding.confidence == MIN_CONFIDENCE
    assert finding.evidence == {}
    assert finding.metadata == {}
    assert finding.source_ip is None
    payload = finding.model_dump()
    assert "severity" not in payload
    assert "risk_score" not in payload
    assert "status" not in payload


def test_finding_device_enrichment_never_overwrites_a_known_value() -> None:
    """Enrichment fills gaps; it does not replace what a detector claimed."""
    finding = DetectionFinding(
        rule_id="r",
        rule_name="R",
        timestamp=1.0,
        description="observed",
        source_device_id="detector-value",
    )

    enriched = finding.with_devices(
        source_device_id="resolver-value", destination_device_id="dev-2"
    )

    assert enriched.source_device_id == "detector-value"
    assert enriched.destination_device_id == "dev-2"
    assert finding.destination_device_id is None


def test_finding_projects_onto_the_wire_model() -> None:
    """A finding serializes with an ISO-8601 timestamp (M10.22)."""
    finding = DetectionFinding(
        rule_id="port_scan",
        rule_name="Port Scan",
        timestamp=DETECTION_BASE_TIME,
        description="Possible port scan detected",
        evidence={"unique_destination_ports": 37},
        confidence=0.9,
    )

    view = finding.to_view()

    assert view.finding_id == finding.finding_id
    assert view.rule_id == "port_scan"
    assert view.timestamp is not None
    assert "T" in view.timestamp
    assert view.evidence["unique_destination_ports"] == 37


def test_confidence_scores_the_evidence_not_a_risk() -> None:
    """Confidence grows with how far past the threshold the measurement is."""
    assert threshold_confidence(10.0, 10.0) == MIN_CONFIDENCE
    assert threshold_confidence(15.0, 10.0) == pytest.approx(0.75)
    assert threshold_confidence(20.0, 10.0) == pytest.approx(1.0)
    assert threshold_confidence(1000.0, 10.0) == pytest.approx(1.0)


def test_confidence_never_divides_by_a_zero_threshold() -> None:
    """A non-positive threshold is treated as fully satisfied, not a crash."""
    assert threshold_confidence(0.0, 0.0) == 1.0


# ---------------------------------------------------------------------------
# Engine registration (M10.6)
# ---------------------------------------------------------------------------


def test_engine_registers_rules_in_order() -> None:
    """Registered rules are reported in registration order (M10.6)."""
    engine = DetectionEngine(
        [FixedRule(rule_id="first"), FixedRule(rule_id="second")]
    )

    assert [rule.rule_id for rule in engine.get_rules()] == ["first", "second"]
    assert engine.get_rule("first") is not None
    assert engine.get_rule("missing") is None


def test_engine_rejects_a_duplicate_rule_id() -> None:
    """A rule id is a stable name, so a collision is a programming error."""
    engine = DetectionEngine([FixedRule(rule_id="dup")])

    with pytest.raises(ValueError):
        engine.register(FixedRule(rule_id="dup"))


def test_a_rule_without_an_id_is_rejected() -> None:
    """A rule must be nameable before it can be registered (M10.3)."""
    engine = DetectionEngine()

    with pytest.raises(ValueError):
        engine.register(FixedRule(rule_id=""))


def test_engine_unregisters_a_rule() -> None:
    """An unregistered rule is no longer evaluated (M10.6)."""
    rule = FixedRule()
    engine = DetectionEngine([rule])
    engine.unregister("fixed")

    assert engine.get_rules() == []
    assert engine.evaluate(make_context()) == []


def test_engine_rejects_unknown_rule_operations() -> None:
    """Unregister, enable and disable all refuse an unknown id (M10.6)."""
    engine = DetectionEngine()

    with pytest.raises(KeyError):
        engine.unregister("missing")
    with pytest.raises(KeyError):
        engine.enable("missing")
    with pytest.raises(KeyError):
        engine.disable("missing")


def test_engine_enable_and_disable_control_evaluation() -> None:
    """A disabled rule is skipped without being removed (M10.6)."""
    rule = FixedRule()
    engine = DetectionEngine([rule])

    assert len(engine.evaluate(make_context())) == 1

    engine.disable("fixed")
    assert engine.evaluate(make_context()) == []
    assert rule.evaluations == 1
    assert engine.get_rules() == [rule]

    engine.enable("fixed")
    assert len(engine.evaluate(make_context())) == 1


# ---------------------------------------------------------------------------
# Engine evaluation (M10.6)
# ---------------------------------------------------------------------------


def test_engine_returns_every_rule_finding() -> None:
    """All enabled rules are evaluated against one context (M10.6)."""
    engine = DetectionEngine(
        [
            FixedRule(rule_id="a"),
            FixedRule(rule_id="b", fires=False),
            FixedRule(rule_id="c"),
        ]
    )

    findings = engine.evaluate(make_context())

    assert [finding.rule_id for finding in findings] == ["a", "c"]


def test_engine_enriches_findings_with_device_ids() -> None:
    """The engine attaches M8 device ids to a rule's finding (M10.4)."""
    resolver = make_device_resolver(
        {DEFAULT_SOURCE_IP: "src-device", DEFAULT_DESTINATION_IP: "dst-device"}
    )
    engine = DetectionEngine([FixedRule()], device_resolver=resolver)

    # process_packet builds the context, so the engine's resolver is applied.
    finding = engine.process_packet(make_syn_packet())[0]

    assert finding.source_device_id == "src-device"
    assert finding.destination_device_id == "dst-device"


def test_engine_enriches_using_the_context_resolver() -> None:
    """Association comes from the context, so a supplied resolver is honoured."""
    resolver = make_device_resolver({DEFAULT_SOURCE_IP: "src-device"})
    engine = DetectionEngine([FixedRule()])

    finding = engine.evaluate(make_context(device_resolver=resolver))[0]

    assert finding.source_device_id == "src-device"


def test_engine_without_a_resolver_leaves_association_unknown() -> None:
    """No resolver means unknown devices, not invented ones (M10.4)."""
    engine = DetectionEngine([FixedRule()])

    finding = engine.evaluate(make_context())[0]

    assert finding.source_device_id is None
    assert finding.destination_device_id is None


def test_engine_handles_an_empty_context() -> None:
    """An empty context is evaluated without raising (M10.23)."""
    rule = RecordingRule()
    engine = DetectionEngine([rule])

    assert engine.evaluate(make_context()) == []
    assert len(rule.contexts) == 1
    assert rule.contexts[0].packet is None


def test_engine_handles_a_context_a_rule_cannot_use() -> None:
    """A packet a rule cannot reason about yields nothing, not an error."""
    from app.detection.rules.port_scan import PortScanRule

    engine = DetectionEngine([PortScanRule()])
    # No addresses at all: not a connection attempt from anywhere.
    packet = make_syn_packet(source_ip=None, destination_ip=None)

    assert engine.evaluate(make_context(packet=packet)) == []
    assert engine.get_diagnostics().errors == 0


def test_engine_retains_findings_for_querying() -> None:
    """Produced findings land in the bounded history (M10.22)."""
    engine = DetectionEngine([FixedRule()])

    engine.evaluate(make_context())

    assert engine.get_retained_finding_count() == 1
    assert len(engine.get_findings()) == 1


def test_engine_tracks_per_rule_counters() -> None:
    """Diagnostics distinguish a silent rule from a firing one (M10.6)."""
    engine = DetectionEngine(
        [FixedRule(rule_id="noisy"), FixedRule(rule_id="quiet", fires=False)]
    )
    engine.evaluate(make_context())

    counters = engine.get_rule_counters()

    assert counters["noisy"].evaluations == 1
    assert counters["noisy"].findings == 1
    assert counters["noisy"].errors == 0
    assert counters["quiet"].evaluations == 1
    assert counters["quiet"].findings == 0


# ---------------------------------------------------------------------------
# Failure isolation (M10.17)
# ---------------------------------------------------------------------------


def test_a_failing_rule_does_not_stop_the_others() -> None:
    """One bad detector is isolated and the rest still run (M10.17)."""
    engine = DetectionEngine(
        [
            FixedRule(rule_id="first"),
            RaisingRule(rule_id="broken"),
            FixedRule(rule_id="last"),
        ]
    )

    findings = engine.evaluate(make_context())

    assert [finding.rule_id for finding in findings] == ["first", "last"]


def test_a_failing_rule_is_counted_for_diagnostics() -> None:
    """The isolated failure is recorded rather than swallowed (M10.17)."""
    engine = DetectionEngine([RaisingRule(rule_id="broken")])

    engine.evaluate(make_context())

    diagnostics = engine.get_diagnostics()
    counters = engine.get_rule_counters()

    assert diagnostics.errors == 1
    assert counters["broken"].errors == 1
    assert counters["broken"].last_error_at is not None
    # A rule that failed did not successfully evaluate.
    assert counters["broken"].evaluations == 0


def test_a_failing_rule_is_retried_on_the_next_evaluation() -> None:
    """Isolation is per evaluation, not a permanent disable (M10.17)."""
    rule = RaisingRule(rule_id="broken")
    engine = DetectionEngine([rule, FixedRule(rule_id="healthy")])

    engine.evaluate(make_context())
    findings = engine.evaluate(make_context())

    assert rule.evaluations == 2
    assert [finding.rule_id for finding in findings] == ["healthy"]


def test_engine_diagnostics_start_empty() -> None:
    """A fresh engine reports zero of everything (M10.6)."""
    diagnostics = DetectionEngine([FixedRule()]).get_diagnostics()

    assert diagnostics.evaluations == 0
    assert diagnostics.findings == 0
    assert diagnostics.errors == 0
    assert diagnostics.enabled_rules == 1
    assert diagnostics.registered_rules == 1
    assert diagnostics.retained_findings == 0


def test_engine_diagnostics_report_rule_and_finding_counts() -> None:
    """Diagnostics aggregate the engine's own execution (M10.6)."""
    engine = DetectionEngine(
        [FixedRule(rule_id="a"), FixedRule(rule_id="b", fires=False)]
    )
    engine.disable("b")

    engine.evaluate(make_context())

    diagnostics = engine.get_diagnostics()

    assert diagnostics.evaluations == 1
    assert diagnostics.findings == 1
    assert diagnostics.enabled_rules == 1
    assert diagnostics.registered_rules == 2
    assert diagnostics.retained_findings == 1


# ---------------------------------------------------------------------------
# Engine state management (M10.19)
# ---------------------------------------------------------------------------


def test_engine_reset_discards_findings_and_counters() -> None:
    """Reset returns the engine to its initial observable state (M10.6)."""
    engine = DetectionEngine([FixedRule()])
    engine.evaluate(make_context())

    engine.reset()

    assert engine.get_findings() == []
    assert engine.get_retained_finding_count() == 0
    diagnostics = engine.get_diagnostics()
    assert diagnostics.evaluations == 0
    assert diagnostics.findings == 0
    assert diagnostics.errors == 0


def test_engine_reset_clears_accumulated_detector_state() -> None:
    """Reset also empties the bounded state a detector accumulated (M10.19)."""
    from app.detection.rules.port_scan import PortScanRule

    rule = PortScanRule(window_seconds=60.0, unique_port_threshold=50)
    engine = DetectionEngine([rule])
    for port in range(5):
        engine.process_packet(make_syn_packet(destination_port=port))
    assert rule.state_size() > 0

    engine.reset()

    assert rule.state_size() == 0


def test_engine_can_be_switched_off_entirely() -> None:
    """A disabled engine evaluates nothing and returns no findings (M10.21)."""
    rule = FixedRule()
    engine = DetectionEngine([rule])

    engine.set_enabled(False)

    assert engine.enabled is False
    assert engine.process_packet(make_syn_packet()) == []
    assert rule.evaluations == 0

    engine.set_enabled(True)
    assert len(engine.process_packet(make_syn_packet())) == 1


# ---------------------------------------------------------------------------
# Context building and packet processing (M10.4/M10.21)
# ---------------------------------------------------------------------------


def test_build_context_timestamps_with_the_packet() -> None:
    """An observation is timed at capture, not at evaluation (M10.4)."""
    clock = FakeClock(DETECTION_BASE_TIME + 500.0)
    engine = DetectionEngine([RecordingRule()], clock=clock)
    packet = make_syn_packet(timestamp=DETECTION_BASE_TIME)

    context = engine.build_context(packet)

    assert context.timestamp == DETECTION_BASE_TIME
    assert context.packet is packet


def test_build_context_falls_back_to_the_clock_without_a_packet() -> None:
    """A snapshot evaluation is timed by the clock (M10.4)."""
    clock = FakeClock(DETECTION_BASE_TIME + 500.0)
    engine = DetectionEngine([], clock=clock)

    context = engine.build_context()

    assert context.timestamp == DETECTION_BASE_TIME + 500.0
    assert context.packet is None


def test_build_context_carries_the_traffic_rates() -> None:
    """M6 rates are read into the context for the bandwidth detector (M10.12)."""
    source = FakeRatesSource(
        packets_per_second=250.0, bytes_per_second=2_000_000.0
    )
    engine = DetectionEngine(
        [], rates_source=source, rates_window="1s", rates_ttl_seconds=0.0
    )

    context = engine.build_context()

    assert context.packets_per_second == 250.0
    assert context.bytes_per_second == 2_000_000.0
    assert context.rate_window_seconds == 1.0
    assert source.calls == ["1s"]


def test_build_context_reports_no_rates_without_a_source() -> None:
    """No statistics source means the rate is unknown, not zero (M10.12)."""
    engine = DetectionEngine([])

    context = engine.build_context()

    assert context.packets_per_second is None
    assert context.bytes_per_second is None
    assert context.rate_window_seconds is None


def test_build_context_reports_no_rates_when_the_source_fails() -> None:
    """A statistics outage degrades to unknown rather than raising (M10.17)."""
    source = FakeRatesSource(fail=True)
    engine = DetectionEngine(
        [], rates_source=source, rates_ttl_seconds=0.0
    )

    context = engine.build_context()

    assert context.bytes_per_second is None
    assert context.rate_window_seconds is None


def test_process_packet_evaluates_the_packet() -> None:
    """The pipeline entry point turns one packet into findings (M10.21)."""
    engine = DetectionEngine([FixedRule()])

    findings = engine.process_packet(make_syn_packet())

    assert len(findings) == 1
    assert engine.get_diagnostics().evaluations == 1


def test_process_packet_never_raises_into_the_capture_path() -> None:
    """A detector failure is contained so capture continues (M10.21)."""
    engine = DetectionEngine([RaisingRule()])

    assert engine.process_packet(make_syn_packet()) == []
    assert engine.get_diagnostics().errors == 1


# ---------------------------------------------------------------------------
# The traffic-rate feed (M10.12)
# ---------------------------------------------------------------------------


def test_rates_feed_reads_the_configured_window() -> None:
    """The feed asks M6 for exactly the window it was configured with."""
    source = FakeRatesSource(packets_per_second=10.0, bytes_per_second=20.0)
    feed = RatesFeed(source, window="10s")

    assert feed.window == "10s"
    assert feed.window_seconds == 10.0
    assert feed.current() == (10.0, 20.0)
    assert source.calls == ["10s"]


def test_rates_feed_serves_a_cached_rate_inside_the_ttl() -> None:
    """A rate is recomputed at most once per TTL (M10.12)."""
    source = FakeRatesSource(bytes_per_second=100.0)
    feed = RatesFeed(source, ttl_seconds=5.0)

    feed.current()
    feed.current()
    feed.current()

    assert len(source.calls) == 1


def test_rates_feed_refreshes_once_the_ttl_has_passed() -> None:
    """A stale rate is recomputed rather than reused forever (M10.12)."""
    clock = FakeClock(0.0)
    source = FakeRatesSource(bytes_per_second=100.0)
    feed = RatesFeed(source, ttl_seconds=1.0, clock=clock)

    feed.current()
    clock.advance(2.0)
    feed.current()

    assert len(source.calls) == 2


def test_rates_feed_with_a_zero_ttl_always_reads_fresh() -> None:
    """A zero TTL disables caching, for deterministic callers."""
    source = FakeRatesSource(bytes_per_second=100.0)
    feed = RatesFeed(source, ttl_seconds=0.0)

    feed.current()
    feed.current()

    assert len(source.calls) == 2


def test_rates_feed_reports_unknown_when_the_source_fails() -> None:
    """A failing source yields an unknown rate and is counted (M10.17)."""
    source = FakeRatesSource(fail=True)
    feed = RatesFeed(source, ttl_seconds=0.0)

    assert feed.current() == (None, None)
    assert feed.error_count == 1


def test_rates_feed_rejects_an_unknown_window() -> None:
    """An unsupported M6 window is a programming error, not a silent default."""
    with pytest.raises(ValueError):
        RatesFeed(FakeRatesSource(), window="7s")


def test_rates_feed_reset_clears_the_cache_and_errors() -> None:
    """Reset drops the cached rate and the failure count."""
    source = FakeRatesSource(fail=True)
    feed = RatesFeed(source, ttl_seconds=60.0)
    feed.current()

    feed.reset()

    assert feed.error_count == 0
    source.fail = False
    assert feed.current() == (0.0, 0.0)
