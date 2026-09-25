"""Behavioural tests for the high bandwidth detector (M10.28).

The detector consumes the traffic rate M6 already measures and compares it with a
configured bytes-per-second threshold. It keeps no byte history of its own, so
these tests drive it with contexts rather than packets. They cover the threshold
boundary, the minimum interval between findings, and the statistics-outage case
where no rate is available at all.
"""

from __future__ import annotations

import pytest

from app.detection import HighBandwidthRule
from app.detection.finding import MIN_CONFIDENCE
from tests.detection_fakes import DETECTION_BASE_TIME, make_context

# A one-megabyte-per-second threshold, the application default.
THRESHOLD = 1_000_000.0


def bandwidth_rule(**overrides: object) -> HighBandwidthRule:
    """Build a high bandwidth rule at the test's threshold."""
    values: dict[str, object] = {"bytes_per_second_threshold": THRESHOLD}
    values.update(overrides)
    return HighBandwidthRule(**values)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The rate boundary (M10.28)
# ---------------------------------------------------------------------------


def test_a_rate_below_the_threshold_stays_silent() -> None:
    """Traffic below the configured rate is not a spike (M10.28)."""
    rule = bandwidth_rule()

    finding = rule.evaluate(
        make_context(bytes_per_second=THRESHOLD - 1.0, rate_window_seconds=1.0)
    )

    assert finding is None


def test_a_rate_exactly_at_the_threshold_fires() -> None:
    """The condition is met at the configured rate (M10.28)."""
    rule = bandwidth_rule()

    finding = rule.evaluate(
        make_context(bytes_per_second=THRESHOLD, rate_window_seconds=1.0)
    )

    assert finding is not None
    assert finding.rule_id == "high_bandwidth"
    assert finding.rule_name == "High Bandwidth"
    assert finding.evidence["bytes_per_second"] == THRESHOLD
    assert finding.evidence["bytes_per_second_threshold"] == THRESHOLD
    assert finding.confidence == MIN_CONFIDENCE


def test_a_rate_above_the_threshold_fires() -> None:
    """A rate well above the threshold produces a spike finding (M10.28)."""
    rule = bandwidth_rule()

    finding = rule.evaluate(
        make_context(bytes_per_second=5_000_000.0, rate_window_seconds=1.0)
    )

    assert finding is not None
    assert finding.confidence == 1.0
    assert "5.00 MB/s" in finding.description


def test_the_finding_names_no_endpoint() -> None:
    """Volume is a whole-capture observation, so no host is blamed (M10.14)."""
    rule = bandwidth_rule()

    finding = rule.evaluate(
        make_context(bytes_per_second=THRESHOLD, rate_window_seconds=1.0)
    )

    assert finding is not None
    assert finding.source_ip is None
    assert finding.destination_ip is None
    assert finding.protocol is None


# ---------------------------------------------------------------------------
# Statistics input (M10.28)
# ---------------------------------------------------------------------------


def test_missing_statistics_produce_no_finding() -> None:
    """A context without a rate yields nothing rather than a guess (M10.12)."""
    rule = bandwidth_rule()

    finding = rule.evaluate(make_context(bytes_per_second=None))

    assert finding is None


def test_the_finding_reports_the_measurement_window() -> None:
    """Evidence states which M6 window the rate came from (M10.14)."""
    rule = bandwidth_rule()

    finding = rule.evaluate(
        make_context(
            bytes_per_second=THRESHOLD,
            packets_per_second=1234.0,
            rate_window_seconds=1.0,
        )
    )

    assert finding is not None
    assert finding.evidence["measurement_window_seconds"] == 1.0
    assert finding.evidence["packets_per_second"] == 1234.0


def test_lifetime_totals_are_attached_when_available() -> None:
    """Cumulative counters are reported as evidence when the context has them."""
    rule = bandwidth_rule()

    finding = rule.evaluate(
        make_context(
            bytes_per_second=THRESHOLD,
            rate_window_seconds=1.0,
            total_bytes=9_000_000,
            total_packets=5000,
        )
    )

    assert finding is not None
    assert finding.evidence["total_bytes"] == 9_000_000
    assert finding.evidence["total_packets"] == 5000


# ---------------------------------------------------------------------------
# The minimum interval between findings (M10.28)
# ---------------------------------------------------------------------------


def test_a_rate_above_the_threshold_reports_at_most_once_per_window() -> None:
    """A sustained spike is one condition, not a finding per evaluation (M10.18)."""
    rule = bandwidth_rule(window_seconds=5.0)

    first = rule.evaluate(
        make_context(
            bytes_per_second=THRESHOLD,
            timestamp=DETECTION_BASE_TIME,
            rate_window_seconds=1.0,
        )
    )
    shortly_after = rule.evaluate(
        make_context(
            bytes_per_second=THRESHOLD,
            timestamp=DETECTION_BASE_TIME + 2.0,
            rate_window_seconds=1.0,
        )
    )

    assert first is not None
    assert shortly_after is None


def test_the_interval_between_spikes_is_configurable() -> None:
    """Once the configured interval has passed, a spike reports again (M10.28)."""
    rule = bandwidth_rule(window_seconds=5.0)

    rule.evaluate(
        make_context(
            bytes_per_second=THRESHOLD,
            timestamp=DETECTION_BASE_TIME,
            rate_window_seconds=1.0,
        )
    )
    later = rule.evaluate(
        make_context(
            bytes_per_second=THRESHOLD,
            timestamp=DETECTION_BASE_TIME + 6.0,
            rate_window_seconds=1.0,
        )
    )

    assert later is not None


def test_a_different_window_length_changes_the_interval() -> None:
    """A shorter configured window allows a second finding sooner (M10.28)."""
    rule = bandwidth_rule(window_seconds=1.0)

    rule.evaluate(
        make_context(
            bytes_per_second=THRESHOLD,
            timestamp=DETECTION_BASE_TIME,
            rate_window_seconds=1.0,
        )
    )
    later = rule.evaluate(
        make_context(
            bytes_per_second=THRESHOLD,
            timestamp=DETECTION_BASE_TIME + 2.0,
            rate_window_seconds=1.0,
        )
    )

    assert later is not None


# ---------------------------------------------------------------------------
# Ordinary traffic and configuration (M10.28)
# ---------------------------------------------------------------------------


def test_normal_traffic_stays_silent() -> None:
    """A typical browsing rate is far below the threshold (M10.28)."""
    rule = bandwidth_rule()

    finding = rule.evaluate(
        make_context(bytes_per_second=150_000.0, rate_window_seconds=1.0)
    )

    assert finding is None


def test_a_non_positive_threshold_is_rejected() -> None:
    """A zero threshold would report all traffic, so it is a config error."""
    with pytest.raises(ValueError):
        HighBandwidthRule(bytes_per_second_threshold=0.0)


# ---------------------------------------------------------------------------
# Bounded state (M10.19)
# ---------------------------------------------------------------------------


def test_state_grows_only_when_a_finding_is_remembered() -> None:
    """The rule holds at most the timestamp of its last finding (M10.19)."""
    rule = bandwidth_rule()

    assert rule.state_size() == 0

    rule.evaluate(
        make_context(
            bytes_per_second=THRESHOLD,
            timestamp=DETECTION_BASE_TIME,
            rate_window_seconds=1.0,
        )
    )

    assert rule.state_size() == 1


def test_reset_allows_the_next_spike_to_report_immediately() -> None:
    """Reset forgets the last finding time (M10.19)."""
    rule = bandwidth_rule(window_seconds=60.0)
    context = make_context(
        bytes_per_second=THRESHOLD,
        timestamp=DETECTION_BASE_TIME,
        rate_window_seconds=1.0,
    )
    rule.evaluate(context)
    assert rule.state_size() == 1

    rule.reset()

    assert rule.state_size() == 0
    assert rule.evaluate(context) is not None
