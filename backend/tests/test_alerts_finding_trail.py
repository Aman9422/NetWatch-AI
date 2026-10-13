"""The trail from an alert back to the finding that raised it (M11.7).

M11.7 says an alert names the M10 finding it came from, and ``AlertView.finding_id``
documents it as "the M10 finding that raised this alert". Until M18 nothing
carried it past the process boundary: the runtime alert was built with the id, and
then the persistence boundary wrote a fixed list of columns that did not include
it, against a table that had no column for it. Every alert read back through the
API therefore reported ``finding_id: null``, and the M12 correlation layer lost
the same link whenever it rebuilt an alert event from a stored row.

That is the kind of defect the M18.9 end-to-end check found, and these tests are
the fast, deterministic version of it. They pin the three places the value has to
travel through:

* the ORM model declares the column at all;
* :func:`~app.alerts.persistence.to_alert_row_values` writes it, so an insert
  carries it to the table;
* :meth:`~app.alerts.alert.Alert.from_record` reads it, so a stored row carries
  it back.

The round trip is asserted against a real SQLite file rather than by comparing
two dictionaries: a mapping that wrote the value into a dict the table has no
column for is exactly the bug, and only a real insert catches that.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app import models as _models  # noqa: F401  (registers every table)
from app.alerts.alert import Alert as RuntimeAlert
from app.alerts.persistence import to_alert_row_values
from app.alerts.severity import AlertSeverity
from app.database.base import Base
from app.models.alert import Alert as AlertRow

#: The finding id a driven observation would carry. Not a real id: what matters is
#: that a value with these characters survives the round trip byte for byte.
FINDING_ID = "fnd-1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"

#: The deduplication key an alert is raised under (M11.9). It deliberately does
#: *not* contain the finding id, because it cannot: the key has to stay stable
#: across observations for deduplication to fold a repeat into the same alert.
CORRELATION_KEY = "port_scan|192.168.1.10|-|TCP|-|-"


@pytest.fixture
def engine(tmp_path: Path):
    """A current-schema database on a real file, disposed afterwards.

    A file, not ``:memory:``: the application opens each request's session on its
    own connection, and asserting what a *later* connection reads back is the
    whole point of the round trip below.
    """
    db_path = tmp_path / "m18_finding_trail.db"
    engine = create_engine(
        f"sqlite:///{db_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    try:
        yield engine
    finally:
        engine.dispose()


def _runtime_alert(finding_id: str | None = FINDING_ID) -> RuntimeAlert:
    """Return an alert as the M11 service builds one from a finding (M11.3)."""
    return RuntimeAlert(
        rule_id="port_scan",
        title="Port Scan",
        description="A single source opened many ports.",
        severity=AlertSeverity.HIGH,
        confidence=0.5,
        source_ip="192.168.1.10",
        finding_id=finding_id,
        correlation_key=CORRELATION_KEY,
    )


def _round_trip(engine: Engine, alert: RuntimeAlert) -> RuntimeAlert:
    """Persist an alert through the real mapping and read it back (M11.12).

    The row is inserted on one session and read back on another, so this asserts
    what is *stored* rather than what an identity map happened to still hold in
    memory from the insert.
    """
    with Session(bind=engine) as session:
        row = AlertRow(**to_alert_row_values(alert))
        session.add(row)
        session.commit()
        alert_id = row.id

    with Session(bind=engine) as session:
        stored = session.get(AlertRow, alert_id)
        assert stored is not None
        return RuntimeAlert.from_record(stored)


# ---------------------------------------------------------------------------
# The column exists at all
# ---------------------------------------------------------------------------


def test_the_alerts_table_declares_a_finding_column(engine: Engine) -> None:
    """``create_all`` gives ``alerts`` a ``finding_id`` column and an index."""
    columns = {row["name"] for row in inspect(engine).get_columns("alerts")}
    assert "finding_id" in columns

    indexes = {row["name"] for row in inspect(engine).get_indexes("alerts")}
    # The column is queried by when a client follows an alert back to its
    # finding, so it needs an index of its own rather than a table scan.
    assert "idx_alerts_finding_id" in indexes


def test_the_finding_column_is_nullable(engine: Engine) -> None:
    """A pre-existing alert has no finding id, and that is storable (M18.3).

    Nullable is the honest choice rather than a convenience: an alert whose
    observation was never recorded has no finding behind it, and a migration that
    could not express that would have to invent one.
    """
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO alerts (title, severity, risk_score, confidence, status, "
                "created_at, updated_at) "
                "VALUES ('legacy', 'low', 0, 0, 'open', "
                "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            )
        )
        stored = connection.execute(
            text("SELECT finding_id FROM alerts")
        ).scalar()
    assert stored is None


# ---------------------------------------------------------------------------
# The value survives the round trip
# ---------------------------------------------------------------------------


def test_the_finding_id_is_written_to_the_row(engine: Engine) -> None:
    """The persistence boundary carries the finding id onto the column (M11.12)."""
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO alerts (title, severity, risk_score, confidence, status, "
                "finding_id, created_at, updated_at) "
                "VALUES ('x', 'high', 0, 50, 'open', :finding_id, "
                "'2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            ),
            {"finding_id": FINDING_ID},
        )
        stored = connection.execute(text("SELECT finding_id FROM alerts")).scalar()

    assert stored == FINDING_ID


def test_an_alert_read_back_names_its_finding(engine: Engine) -> None:
    """The defect, asserted absent: a stored alert comes back with its finding.

    Before the column existed this returned ``None`` for every alert, so a client
    following ``GET /api/v1/alerts/{id}`` could never reach the observation the
    alert was raised from (M11.7).
    """
    stored = _round_trip(engine, _runtime_alert())

    assert stored.finding_id == FINDING_ID
    # The rest of the round trip is unchanged by the fix.
    assert stored.rule_id == "port_scan"
    assert stored.severity is AlertSeverity.HIGH
    assert stored.confidence == pytest.approx(0.5)
    assert stored.correlation_key == CORRELATION_KEY


def test_the_finding_id_is_not_recovered_from_the_deduplication_key(
    engine: Engine,
) -> None:
    """The reason the trail needs its own column rather than a key component.

    The key is what makes a repeat observation find the same alert, so it holds
    only what is *stable* across observations. The finding id is unique per
    observation, so it can never be one of its components -- and a value that is
    not in the key must come from somewhere else, which is the column.
    """
    assert FINDING_ID not in CORRELATION_KEY

    stored = _round_trip(engine, _runtime_alert())

    assert stored.finding_id == FINDING_ID
    assert stored.finding_id not in (stored.correlation_key or "")


def test_an_alert_without_a_finding_stays_without_one(engine: Engine) -> None:
    """A missing finding id is written as NULL rather than as a placeholder.

    ``None`` and ``"None"`` are different answers, and only the first is truthful.
    """
    stored = _round_trip(engine, _runtime_alert(finding_id=None))

    assert stored.finding_id is None


def test_two_alerts_from_one_rule_keep_their_own_findings(engine: Engine) -> None:
    """Each stored alert carries the finding that raised it, not a shared value.

    Two observations of the same behaviour deduplicate to the same correlation key
    but come from two different findings, so the column must be per row. A
    boundary that wrote a constant -- or read one back from the key -- would pass
    every single-alert test above and fail this one.
    """
    first = _runtime_alert()
    second = first.model_copy(update={"finding_id": "fnd-0000000000000000000000000000ffff"})

    with Session(bind=engine) as session:
        for alert in (first, second):
            session.add(AlertRow(**to_alert_row_values(alert)))
        session.commit()

    with Session(bind=engine) as session:
        rows = session.query(AlertRow).order_by(AlertRow.id).all()
        findings = [RuntimeAlert.from_record(row).finding_id for row in rows]

    assert findings == [FINDING_ID, "fnd-0000000000000000000000000000ffff"]
