"""Writing a correlated incident's risk score back onto its alerts (M12.24).

M11 deliberately leaves ``alerts.risk_score`` at ``0`` — the column needs the
incident and historical context M12 owns. This is the other half of that
decision, so it is tested against a real, isolated database rather than a double:
what matters is the SQL that is actually issued and the columns it does and does
not touch.

The two properties worth proving here are the ones a naive writer would get
wrong:

* **Only the score is written.** Status, severity, confidence and ``updated_at``
  belong to M11's record of what was observed and to a human's lifecycle actions.
  Correlation records a *relationship*; it must not rewrite the observations it
  grouped, nor restamp an alert as if a person had touched it (M12.10).
* **A failure is contained where it can be reported.** The writer counts a failure
  and lets it reach the engine, which owns containment on the capture path. A
  locked database must leave the incident intact, let capture continue, and still
  appear in ``persist_errors`` — a failure swallowed inside the writer would be
  invisible to the counter the pipeline reports (M12.25/M12.34).
"""

from __future__ import annotations

import pytest

from app.alerts.timestamps import to_utc_datetime
from app.correlation.incident import CorrelatedIncident
from app.correlation.persistence import IncidentRiskWriter
from app.models.alert import Alert
from app.repositories.alert import AlertRepository
from tests.correlation_fakes import (
    CORRELATION_BASE_TIME,
    DESTINATION_IP,
    SOURCE_IP,
    make_alert,
    make_engine,
)


def _alert_values(**overrides: object) -> dict[str, object]:
    """Build ``alerts`` column values for a repository insert."""
    stamp = to_utc_datetime(CORRELATION_BASE_TIME)
    values: dict[str, object] = {
        "rule_id": None,
        "device_id": None,
        "source_ip": SOURCE_IP,
        "destination_ip": DESTINATION_IP,
        "title": "Port Scan",
        "description": "synthetic alert",
        "severity": "high",
        "risk_score": 0,
        "confidence": 80,
        "status": "open",
        "correlation_key": "port_scan|192.168.1.10|8.8.8.8|TCP|-|-",
        "resolved_at": None,
        "created_at": stamp,
        "updated_at": stamp,
    }
    values.update(overrides)
    return values


def _incident(
    alert_ids: tuple[int, ...], *, score: int = 42, incident_id: str = "inc:test"
) -> CorrelatedIncident:
    """Build the incident shape the writer actually consumes (M12.24)."""
    return CorrelatedIncident(
        incident_id=incident_id,
        title="Port Scan",
        alert_ids=alert_ids,
        risk_score=score,
    )


def _insert_alert(session, **overrides: object) -> int:
    """Insert one alert row and return its primary key."""
    row = AlertRepository(session).insert(**_alert_values(**overrides))
    return int(row.id)


def _stored_score(session, alert_id: int) -> int | None:
    """Return the stored risk score for an alert id."""
    row = session.get(Alert, alert_id)
    return None if row is None else int(row.risk_score)


# --------------------------------------------------------------------------
# The write itself (M12.24)
# --------------------------------------------------------------------------


def test_the_incident_score_is_written_onto_every_member_alert(
    db_session, session_factory
) -> None:
    """An incident's score reaches all of the alerts it groups."""
    first = _insert_alert(db_session)
    second = _insert_alert(db_session)
    writer = IncidentRiskWriter(session_factory)

    written = writer(_incident((first, second), score=73))

    assert written == 2
    assert _stored_score(db_session, first) == 73
    assert _stored_score(db_session, second) == 73
    assert writer.stats()["rows_written"] == 2


def test_an_incident_with_no_alerts_writes_nothing(
    db_session, session_factory
) -> None:
    """A findings-only incident has nothing in the alerts table to stamp."""
    writer = IncidentRiskWriter(session_factory)

    assert writer(_incident(())) == 0
    assert writer.stats()["writes"] == 0


def test_an_unknown_alert_id_is_skipped_rather_than_failing(
    db_session, session_factory
) -> None:
    """A deleted alert cannot fail the write for the alerts that remain."""
    present = _insert_alert(db_session)
    writer = IncidentRiskWriter(session_factory)

    written = writer(_incident((present, 999_999), score=55))

    assert written == 1
    assert _stored_score(db_session, present) == 55


def test_only_the_risk_score_column_is_touched(db_session, session_factory) -> None:
    """Correlation writes a relationship, not a revision of what M11 recorded.

    ``updated_at`` is left alone on purpose: that column dates a human's own
    lifecycle actions, and a machine's grouping is not one of them.
    """
    alert_id = _insert_alert(db_session, status="acknowledged", confidence=80)
    before = db_session.get(Alert, alert_id)
    assert before is not None
    original = (
        before.status,
        before.severity,
        before.confidence,
        before.updated_at,
        before.title,
        before.correlation_key,
    )

    IncidentRiskWriter(session_factory)(_incident((alert_id,), score=61))

    db_session.expire_all()
    after = db_session.get(Alert, alert_id)
    assert after is not None
    assert after.risk_score == 61
    assert (
        after.status,
        after.severity,
        after.confidence,
        after.updated_at,
        after.title,
        after.correlation_key,
    ) == original


def test_an_out_of_range_score_is_bounded_before_it_is_written(
    db_session, session_factory
) -> None:
    """A score outside the column's range is clamped, not rejected.

    The ``alerts.risk_score`` CHECK constraint would refuse an out-of-range value
    and lose the whole update, so the bound is applied on the way in (M12.21).
    """
    alert_id = _insert_alert(db_session)
    writer = IncidentRiskWriter(session_factory)

    writer(_incident((alert_id,), score=10_000))

    assert _stored_score(db_session, alert_id) == 100


def test_a_large_member_list_is_written_in_bounded_chunks(
    db_session, session_factory
) -> None:
    """One statement cannot carry an unbounded ``IN`` clause (M12.24)."""
    ids = tuple(_insert_alert(db_session) for _ in range(5))
    writer = IncidentRiskWriter(session_factory, chunk_size=2)

    written = writer(_incident(ids, score=33))

    assert written == 5
    assert all(_stored_score(db_session, alert_id) == 33 for alert_id in ids)


def test_the_writer_rejects_an_unusable_chunk_size(session_factory) -> None:
    """A chunk below one would make the write a no-op loop."""
    with pytest.raises(ValueError):
        IncidentRiskWriter(session_factory, chunk_size=0)


# --------------------------------------------------------------------------
# Failure containment (M12.25)
# --------------------------------------------------------------------------


def test_a_write_failure_is_counted_and_then_raised() -> None:
    """The writer counts the failure and hands it to the engine (M12.25).

    It must not swallow it: the engine is the layer that reports persistence
    errors, and a writer that hid them would make ``persist_errors`` unable to
    ever fire (M12.34).
    """

    def broken_factory():
        raise RuntimeError("the database is locked")

    writer = IncidentRiskWriter(broken_factory)  # type: ignore[arg-type]

    with pytest.raises(RuntimeError):
        writer(_incident((1,), score=70))

    assert writer.stats()["errors"] == 1
    assert writer.stats()["writes"] == 0
    assert writer.stats()["rows_written"] == 0


def test_the_writer_reports_its_counters_and_resets_them(
    db_session, session_factory
) -> None:
    """Counters are diagnostics, and a reset leaves no mixture behind (M12.34)."""
    alert_id = _insert_alert(db_session)
    writer = IncidentRiskWriter(session_factory)
    writer(_incident((alert_id,), score=20))

    assert writer.stats()["writes"] == 1
    assert writer.stats()["rows_written"] == 1

    writer.reset()
    assert writer.stats() == {"writes": 0, "rows_written": 0, "errors": 0}


# --------------------------------------------------------------------------
# The whole path: engine → incident → alerts table (M12.24/M12.32)
# --------------------------------------------------------------------------


def test_correlating_alerts_stamps_their_score_in_the_database(
    db_session, session_factory
) -> None:
    """The score an incident carries is the score its alerts end up with.

    This is the integration M12.24 exists for, proved end to end: the engine
    scores an incident and the writer propagates that same value to the rows
    whose ids the incident holds.
    """
    first = _insert_alert(db_session, source_ip=SOURCE_IP)
    second = _insert_alert(db_session, source_ip=SOURCE_IP, destination_ip="9.9.9.9")
    writer = IncidentRiskWriter(session_factory)
    engine = make_engine(risk_persistence=writer)

    engine.correlate_alert(make_alert(alert_id=first))
    joined = engine.correlate_alert(make_alert(alert_id=second))

    assert joined.joined is True
    incident = engine.get_incident(joined.incident_id or "")
    assert incident is not None
    # Both alerts carry the incident's own score, not a value of their own.
    assert _stored_score(db_session, first) == incident.risk_score
    assert _stored_score(db_session, second) == incident.risk_score
    assert incident.risk_score > 0


def test_a_persistence_failure_does_not_destroy_the_correlation(
    db_session, session_factory
) -> None:
    """The incident keeps its score in memory even when the write fails (M12.25).

    Both counters record it and neither layer loses anything: the writer counts
    the failed attempt, and the engine — which owns containment on the capture
    path — counts it as a persistence error and keeps the incident's score in
    memory regardless.
    """

    def broken_factory():
        raise RuntimeError("the database is locked")

    alert_id = _insert_alert(db_session)
    writer = IncidentRiskWriter(broken_factory)  # type: ignore[arg-type]
    engine = make_engine(risk_persistence=writer)

    outcome = engine.correlate_alert(make_alert(alert_id=alert_id))

    assert outcome.ok is True
    incident = engine.get_incident(outcome.incident_id or "")
    assert incident is not None
    assert incident.risk_score > 0
    # The alert row is untouched, because nothing could be written to it.
    assert _stored_score(db_session, alert_id) == 0
    assert writer.stats()["errors"] == 1
    # One incident was created, so its score was written once and failed once.
    assert engine.stats()["persist_errors"] == 1
    assert engine.stats()["persisted_alerts"] == 0
    # The correlation itself still succeeded and is queryable (M12.25).
    assert len(engine.open_incidents()) == 1
