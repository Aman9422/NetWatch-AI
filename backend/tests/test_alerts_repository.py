"""Tests for the alert and alert-evidence repositories (M11.30).

The repositories are the only code that knows the column names, so these tests
exercise them directly against an isolated database: storing and reading an
alert, the filtered listing, a validated status write, evidence staging, the
deduplication lookup, and — the property that makes the *stage then commit*
split worth having — that a rollback leaves nothing behind.

The ``db_session`` fixture creates every table in a fresh in-memory engine and
drops them afterwards, so each test starts clean and nothing touches the
developer's real database.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.alerts.timestamps import to_utc_datetime
from app.repositories.alert import AlertRepository
from app.repositories.alert_evidence import AlertEvidenceRepository
from tests.alert_fakes import ALERT_BASE_TIME

KEY = "port_scan|192.168.1.10|8.8.8.8|TCP|-|-"
OTHER_KEY = "syn_flood|192.168.1.99|8.8.8.8|TCP|-|-"


def _values(
    *,
    key: str = KEY,
    title: str = "Port Scan",
    severity: str = "high",
    status: str = "open",
    confidence: int = 80,
    source_ip: str = "192.168.1.10",
    destination_ip: str = "8.8.8.8",
    created_at=None,
) -> dict[str, object]:
    """Build ``alerts`` column values for a repository insert."""
    stamp = created_at or to_utc_datetime(ALERT_BASE_TIME)
    return {
        "rule_id": None,
        "device_id": None,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "title": title,
        "description": "synthetic alert",
        "severity": severity,
        "risk_score": 0,
        "confidence": confidence,
        "status": status,
        "correlation_key": key,
        "resolved_at": None,
        "created_at": stamp,
        "updated_at": stamp,
    }


def _evidence_values(alert_id: int, *, kind: str = "rule", data: str = '{"a":1}'):
    """Build one ``alert_evidence`` row."""
    return {
        "alert_id": alert_id,
        "packet_id": None,
        "evidence_type": kind,
        "evidence_data": data,
        "created_at": to_utc_datetime(ALERT_BASE_TIME),
    }


# -- create and read (M11.17) -----------------------------------------------


def test_insert_and_get_round_trip(db_session) -> None:
    """An inserted alert is retrievable by its new primary key."""
    repository = AlertRepository(db_session)
    row = repository.insert(**_values())

    assert row.id is not None
    fetched = repository.get(row.id)
    assert fetched is not None
    assert fetched.title == "Port Scan"
    assert fetched.severity == "high"
    assert fetched.confidence == 80


def test_get_missing_alert_returns_none(db_session) -> None:
    """A missing id is ``None``, never an exception."""
    assert AlertRepository(db_session).get(12345) is None


def test_list_alerts_is_newest_first(db_session) -> None:
    """The listing is ordered newest first with a deterministic tie-break."""
    repository = AlertRepository(db_session)
    base = to_utc_datetime(ALERT_BASE_TIME)
    repository.insert(**_values(created_at=base))
    repository.insert(**_values(created_at=base + timedelta(seconds=10)))
    repository.insert(**_values(created_at=base + timedelta(seconds=20)))

    listed = repository.list_alerts(limit=10, offset=0)

    stamps = [row.created_at for row in listed]
    assert stamps == sorted(stamps, reverse=True)


def test_list_alerts_paginates(db_session) -> None:
    """``limit`` and ``offset`` frame a stable page."""
    repository = AlertRepository(db_session)
    base = to_utc_datetime(ALERT_BASE_TIME)
    for offset in range(5):
        repository.insert(**_values(created_at=base + timedelta(seconds=offset)))

    page = repository.list_alerts(limit=2, offset=1)

    assert len(page) == 2
    assert repository.count_alerts() == 5


def test_list_alerts_rejects_a_bad_limit(db_session) -> None:
    """A non-positive limit is a query bug, and it is rejected."""
    with pytest.raises(ValueError):
        AlertRepository(db_session).list_alerts(limit=0)


# -- filtering (M11.18) -----------------------------------------------------


def test_filter_by_exact_severity(db_session) -> None:
    """An exact severity filter returns only that severity."""
    repository = AlertRepository(db_session)
    repository.insert(**_values(severity="high"))
    repository.insert(**_values(severity="medium"))

    found = repository.list_alerts(severity="medium", limit=10, offset=0)

    assert [row.severity for row in found] == ["medium"]


def test_filter_by_min_severity(db_session) -> None:
    """A minimum-severity filter returns that severity and above."""
    repository = AlertRepository(db_session)
    for severity in ("low", "medium", "high", "critical"):
        repository.insert(**_values(severity=severity))

    found = repository.list_alerts(min_severity="high", limit=10, offset=0)

    assert sorted(row.severity for row in found) == ["critical", "high"]


def test_filter_by_status(db_session) -> None:
    """A status filter returns only the named stored statuses."""
    repository = AlertRepository(db_session)
    repository.insert(**_values(status="open"))
    repository.insert(**_values(status="acknowledged"))

    found = repository.list_alerts(statuses=("open",), limit=10, offset=0)

    assert [row.status for row in found] == ["open"]


def test_filter_by_source_ip(db_session) -> None:
    """The endpoint filter matches the stored source address."""
    repository = AlertRepository(db_session)
    repository.insert(**_values(source_ip="192.168.1.10"))
    repository.insert(**_values(source_ip="192.168.1.11"))

    found = repository.list_alerts(source_ip="192.168.1.11", limit=10, offset=0)

    assert [row.source_ip for row in found] == ["192.168.1.11"]


def test_filter_by_time_window_is_half_open(db_session) -> None:
    """``since`` is inclusive and ``until`` exclusive, so the window is exact."""
    repository = AlertRepository(db_session)
    base = to_utc_datetime(ALERT_BASE_TIME)
    repository.insert(**_values(created_at=base))
    repository.insert(**_values(created_at=base + timedelta(seconds=10)))

    found = repository.list_alerts(
        since=base,
        until=base + timedelta(seconds=10),
        limit=10,
        offset=0,
    )

    assert len(found) == 1
    assert found[0].created_at == base


def test_filter_by_detector_rule_key(db_session) -> None:
    """``correlation_rule_key`` matches the key's leading detector component."""
    repository = AlertRepository(db_session)
    repository.insert(**_values(key=KEY))
    repository.insert(**_values(key=OTHER_KEY))

    found = repository.list_alerts(
        correlation_rule_key="syn_flood", limit=10, offset=0
    )

    assert len(found) == 1
    assert found[0].correlation_key == OTHER_KEY


def test_filter_rejects_two_severity_constraints(db_session) -> None:
    """Exact and minimum severity together are ambiguous, so rejected."""
    with pytest.raises(ValueError):
        AlertRepository(db_session).list_alerts(
            severity="high", min_severity="medium", limit=10
        )


def test_filter_rejects_an_unknown_severity(db_session) -> None:
    """An unknown severity fails loudly rather than returning everything."""
    with pytest.raises(ValueError):
        AlertRepository(db_session).list_alerts(severity="urgent", limit=10)


def test_filter_rejects_an_empty_rule_key(db_session) -> None:
    """An empty rule-key prefix would match every alert, so it is rejected."""
    with pytest.raises(ValueError):
        AlertRepository(db_session).list_alerts(correlation_rule_key="", limit=10)


# -- lifecycle write (M11.17) -----------------------------------------------


def test_update_status_records_the_move(db_session) -> None:
    """A status write records the new state and stamps the times."""
    repository = AlertRepository(db_session)
    row = repository.insert(**_values())

    stamp = to_utc_datetime(ALERT_BASE_TIME + 60)
    repository.update_status(
        row, status="resolved", updated_at=stamp, resolved_at=stamp
    )

    fetched = repository.get(row.id)
    assert fetched is not None
    assert fetched.status == "resolved"
    assert fetched.updated_at == stamp
    assert fetched.resolved_at == stamp


# -- M2 helper queries (M11.18) ---------------------------------------------


def test_get_unresolved_excludes_every_terminal_state(db_session) -> None:
    """Dismissed counts as resolved, so it is not 'unresolved' (M11.18)."""
    repository = AlertRepository(db_session)
    repository.insert(**_values(status="open"))
    repository.insert(**_values(status="acknowledged"))
    repository.insert(**_values(status="dismissed"))
    repository.insert(**_values(status="resolved"))

    unresolved = repository.get_unresolved(limit=10)

    assert sorted(row.status for row in unresolved) == ["acknowledged", "open"]


def test_get_high_priority_returns_the_threshold_and_above(db_session) -> None:
    """The M2 high-priority helper keeps working under the M11 severities."""
    repository = AlertRepository(db_session)
    repository.insert(**_values(severity="low"))
    repository.insert(**_values(severity="critical"))

    high = repository.get_high_priority("high", limit=10)

    assert [row.severity for row in high] == ["critical"]


def test_count_by_severity_and_status(db_session) -> None:
    """The aggregations group by severity and by stored status."""
    repository = AlertRepository(db_session)
    repository.insert(**_values(severity="high"))
    repository.insert(**_values(severity="high"))
    repository.insert(**_values(severity="low", status="resolved"))

    by_severity = repository.count_by_severity()
    by_status = repository.count_by_status()

    assert by_severity == {"high": 2, "low": 1}
    assert by_status == {"open": 2, "resolved": 1}


# -- evidence (M11.16) ------------------------------------------------------


def test_stage_and_commit_evidence(db_session) -> None:
    """Staged evidence is written on commit and readable afterwards."""
    alerts = AlertRepository(db_session)
    row = alerts.insert(**_values())
    evidence = AlertEvidenceRepository(db_session)

    staged = evidence.stage(
        [
            _evidence_values(row.id, kind="rule"),
            _evidence_values(row.id, kind="behavioral"),
        ]
    )
    evidence.commit()

    assert staged == 2
    assert evidence.count_for_alert(row.id) == 2


def test_evidence_is_listed_oldest_first(db_session) -> None:
    """Evidence accumulates in the order it was attached (M11.18)."""
    alerts = AlertRepository(db_session)
    row = alerts.insert(**_values())
    evidence = AlertEvidenceRepository(db_session)
    evidence.stage(
        [
            _evidence_values(row.id, kind="rule"),
            _evidence_values(row.id, kind="packet"),
        ]
    )
    evidence.commit()

    listed = evidence.list_for_alert(row.id)

    assert [record.evidence_type for record in listed] == ["rule", "packet"]


def test_evidence_can_be_filtered_and_counted_by_type(db_session) -> None:
    """One query returns the per-type counts a detail view needs."""
    alerts = AlertRepository(db_session)
    row = alerts.insert(**_values())
    evidence = AlertEvidenceRepository(db_session)
    evidence.stage(
        [
            _evidence_values(row.id, kind="packet"),
            _evidence_values(row.id, kind="packet"),
            _evidence_values(row.id, kind="rule"),
        ]
    )
    evidence.commit()

    assert len(evidence.list_for_alert(row.id, evidence_type="packet")) == 2
    assert evidence.count_by_type(row.id) == {"packet": 2, "rule": 1}


def test_rollback_discards_staged_evidence(db_session) -> None:
    """A rollback leaves no evidence behind — the alert is never half-written."""
    alerts = AlertRepository(db_session)
    row = alerts.insert(**_values())
    evidence = AlertEvidenceRepository(db_session)

    evidence.stage([_evidence_values(row.id)])
    evidence.rollback()

    assert evidence.count_for_alert(row.id) == 0


def test_write_many_is_atomic(db_session) -> None:
    """A batch write commits every row together."""
    alerts = AlertRepository(db_session)
    row = alerts.insert(**_values())
    evidence = AlertEvidenceRepository(db_session)

    written = evidence.write_many(
        [_evidence_values(row.id, kind="rule"), _evidence_values(row.id, kind="device")]
    )

    assert written == 2
    assert evidence.count_for_alert(row.id) == 2


def test_delete_for_alert_removes_its_evidence(db_session) -> None:
    """Deleting an alert's evidence reports how many rows were removed."""
    alerts = AlertRepository(db_session)
    row = alerts.insert(**_values())
    evidence = AlertEvidenceRepository(db_session)
    evidence.stage([_evidence_values(row.id), _evidence_values(row.id, kind="packet")])
    evidence.commit()

    removed = evidence.delete_for_alert(row.id)

    assert removed == 2
    assert evidence.count_for_alert(row.id) == 0


# -- deduplication lookup (M11.9) -------------------------------------------


def test_find_duplicate_candidate_inside_the_window(db_session) -> None:
    """A key match inside the window is returned as the duplicate candidate."""
    repository = AlertRepository(db_session)
    base = to_utc_datetime(ALERT_BASE_TIME)
    row = repository.insert(**_values(key=KEY, created_at=base))

    cutoff = base - timedelta(seconds=300)
    candidate = repository.find_duplicate_candidate(KEY, cutoff=cutoff)

    assert candidate is not None
    assert candidate.id == row.id


def test_find_duplicate_candidate_outside_the_window_is_none(db_session) -> None:
    """A key match older than the window is not a duplicate."""
    repository = AlertRepository(db_session)
    base = to_utc_datetime(ALERT_BASE_TIME)
    repository.insert(**_values(key=KEY, created_at=base))

    cutoff = base + timedelta(seconds=1)
    assert repository.find_duplicate_candidate(KEY, cutoff=cutoff) is None


def test_find_duplicate_candidate_rejects_an_empty_key(db_session) -> None:
    """An empty key would match anything, which is the opposite of deduplication."""
    with pytest.raises(ValueError):
        AlertRepository(db_session).find_duplicate_candidate(
            "", cutoff=to_utc_datetime(ALERT_BASE_TIME)
        )
