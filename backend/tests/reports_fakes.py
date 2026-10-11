"""Builders for the M17 reporting tests.

A report is assembled from the M16 analytics service, so a report test needs the
same six collaborators the M16 tests build — a statistics manager, a device
registry, a connection tracker, a detection engine, a correlation engine and the
alert read service — all over one isolated session. That is what this module
assembles, so a test states *what it expects a report to say* rather than how the
analytics layer is wired.

Two conventions the assertions depend on:

* **Every report test writes into a temporary storage directory.** The configured
  default is a real directory in the working tree, and a test that generated a
  report there would leave an artifact behind on every run. ``temp_storage()``
  supplies a directory that disappears with the test.
* **Every collaborator is the production class over a deterministic clock**, not a
  stub. A report is only worth testing if the figures it carries came from the
  same code the dashboard reads, so nothing here replaces a service with a double.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.alerts.queries import AlertQueries
from app.analytics.service import AnalyticsService
from app.connections.manager import ConnectionTracker
from app.correlation.engine import CorrelationEngine
from app.detection import DetectionEngine
from app.devices.manager import DeviceDiscoveryManager
from app.reports.content import Metric, ReportContent, ReportSection, ReportTable
from app.reports.service import ReportService
from app.reports.storage import ReportStorage
from app.statistics.manager import TrafficStatisticsManager
from tests.correlation_fakes import make_engine
from tests.detection_fakes import FixedRule
from tests.fakes import PACKET_BASE_TIME, FakeClock

#: Prefix on every temporary storage directory, so one left behind by a crashed
#: run is recognisable rather than mistaken for a project directory.
TEMP_STORAGE_PREFIX = "netwatch-reports-"

#: A period label and identity the content builders use, so a renderer test's
#: expected strings are written once rather than repeated per assertion.
TITLE = "Daily network report 2026-10-09 (PDF)"
REPORT_TYPE = "daily"
OUTPUT_FORMAT = "PDF"
GENERATED_AT = "2026-10-10T04:00:00+00:00"
PERIOD_START = "2026-10-09T00:00:00+00:00"
PERIOD_END = "2026-10-10T00:00:00+00:00"
PERIOD_SECONDS = 86_400.0


@dataclass(frozen=True)
class ReportEnvironment:
    """The six M16 collaborators one report is assembled from.

    Held together because a report reads all six, and a test that wanted a
    different registry should replace the whole environment rather than one field
    of it — a report assembled from half a test's collaborators and half the
    defaults would not describe anything in particular.
    """

    statistics: TrafficStatisticsManager
    devices: DeviceDiscoveryManager
    tracker: ConnectionTracker
    detections: DetectionEngine
    correlations: CorrelationEngine
    alerts: AlertQueries


def make_environment(session_factory: Callable[[], Session]) -> ReportEnvironment:
    """Return a fresh environment of deterministic analytics collaborators.

    The clocks are pinned at :data:`tests.fakes.PACKET_BASE_TIME`, which is where
    the M16 seeders place their rows, so a seeded packet and the registry's view
    of it describe the same instant.
    """
    return ReportEnvironment(
        statistics=TrafficStatisticsManager(),
        devices=DeviceDiscoveryManager(
            inactivity_threshold=60.0,
            retention_seconds=600.0,
            clock=FakeClock(PACKET_BASE_TIME),
        ),
        tracker=ConnectionTracker(
            autostart_cleanup=False, clock=FakeClock(PACKET_BASE_TIME)
        ),
        detections=DetectionEngine([FixedRule()]),
        correlations=make_engine(),
        alerts=AlertQueries(session_factory=session_factory),
    )


def make_analytics(db: Session, environment: ReportEnvironment) -> AnalyticsService:
    """Return the M16 analytics service over one test's collaborators and session."""
    return AnalyticsService(
        db=db,
        statistics=environment.statistics,
        devices=environment.devices,
        tracker=environment.tracker,
        alerts=environment.alerts,
        detections=environment.detections,
        correlations=environment.correlations,
    )


def make_service(
    db: Session, environment: ReportEnvironment, directory: str
) -> ReportService:
    """Return a reporting service writing into ``directory``."""
    return ReportService(
        db=db,
        analytics=make_analytics(db, environment),
        storage=ReportStorage(directory),
    )


@contextmanager
def temp_storage() -> Iterator[ReportStorage]:
    """Yield a storage layer over a directory that disappears with the test."""
    with tempfile.TemporaryDirectory(prefix=TEMP_STORAGE_PREFIX) as directory:
        yield ReportStorage(directory)


def make_metric(label: str = "Total packets stored", value: str = "1,234") -> Metric:
    """Return one labelled scalar."""
    return Metric(label=label, value=value)


def make_table(
    *,
    key: str = "top_sources",
    title: str = "Busiest sources (by bytes)",
    columns: tuple[str, ...] = ("Source", "Packets", "Bytes"),
    rows: tuple[tuple[str, ...], ...] = (("10.0.0.5", "900", "120,000"),),
    notice: str | None = None,
) -> ReportTable:
    """Return one report table, with the standard notice when it holds no rows."""
    resolved_notice = notice
    if resolved_notice is None and not rows:
        resolved_notice = "No data was recorded in this period."
    return ReportTable(
        key=key, title=title, columns=columns, rows=rows, notice=resolved_notice
    )


def make_section(
    *,
    key: str = "traffic",
    title: str = "Traffic",
    metrics: tuple[Metric, ...] | None = None,
    tables: tuple[ReportTable, ...] | None = None,
    available: bool = True,
    notice: str | None = None,
) -> ReportSection:
    """Return one report section."""
    return ReportSection(
        key=key,
        title=title,
        metrics=(make_metric(),) if metrics is None else metrics,
        tables=(make_table(),) if tables is None else tables,
        available=available,
        notice=notice,
    )


def make_content(
    *,
    report_id: int | None = 7,
    title: str = TITLE,
    report_type: str = REPORT_TYPE,
    output_format: str = OUTPUT_FORMAT,
    generated_at: str = GENERATED_AT,
    period_start: str = PERIOD_START,
    period_end: str = PERIOD_END,
    period_seconds: float = PERIOD_SECONDS,
    summary: tuple[Metric, ...] | None = None,
    sections: tuple[ReportSection, ...] | None = None,
) -> ReportContent:
    """Return a small, complete report content model for a renderer test."""
    return ReportContent(
        report_id=report_id,
        title=title,
        report_type=report_type,
        output_format=output_format,
        generated_at=generated_at,
        period_start=period_start,
        period_end=period_end,
        period_seconds=period_seconds,
        summary=(make_metric(),) if summary is None else summary,
        sections=(make_section(),) if sections is None else sections,
    )


def empty_content(*, output_format: str = OUTPUT_FORMAT) -> ReportContent:
    """Return a content model in which no section carries a single row.

    The explicit case both renderers have to state rather than present as an
    unlabelled set of empty tables.
    """
    return make_content(
        output_format=output_format,
        summary=(make_metric(),),
        sections=(
            make_section(
                metrics=(),
                tables=(
                    make_table(
                        key="top_sources",
                        title="Busiest sources (by bytes)",
                        rows=(),
                    ),
                ),
            ),
        ),
    )


__all__ = [
    "GENERATED_AT",
    "OUTPUT_FORMAT",
    "PERIOD_END",
    "PERIOD_SECONDS",
    "PERIOD_START",
    "REPORT_TYPE",
    "TEMP_STORAGE_PREFIX",
    "TITLE",
    "ReportEnvironment",
    "empty_content",
    "make_analytics",
    "make_content",
    "make_environment",
    "make_metric",
    "make_section",
    "make_service",
    "make_table",
    "temp_storage",
]
