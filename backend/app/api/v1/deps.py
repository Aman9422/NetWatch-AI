"""Shared FastAPI dependencies for the ``/api/v1`` routers (M13.28).

M13.28 asks that a route take its collaborators through dependency injection
rather than build a singleton inside the handler. Most of the process-wide
objects already expose their own factory in the module that owns them
(``get_capture_manager``, ``get_device_manager``, ``get_correlation_engine``,
...), and a router imports those directly. This module holds the two things that
had nowhere else to live:

* :func:`get_alert_queries` — the alert read service. It needs a *session
  factory* rather than a session, because it opens one per call: a SQLAlchemy
  session is not thread-safe and FastAPI serves requests from a thread pool, so
  the service cannot hold a session across requests and must not share one.
* :func:`get_report_repository` / :func:`get_notification_repository` /
* :func:`get_setting_repository` — one-constructor wrappers over the
* request-scoped session, so a route depends on the repository it uses rather
* than on ``get_db`` plus a constructor call. Every one of them takes the
* *request-scoped* session, so a request still reads the database through a
* single connection and the session is closed by :func:`app.database.session.get_db`
* when the request ends.
* :func:`get_report_service` — the M17 reporting service, assembled per request
* from this request's session and the analytics service bound to the same one, so
* a generation reads and writes through a single connection.

Nothing here caches a session. Caching one would be the exact bug this module
exists to avoid.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.orm import Session

from app.alerts.queries import AlertQueries
from app.analytics.service import AnalyticsService
from app.connections.manager import ConnectionTracker, get_connection_tracker
from app.correlation import get_correlation_engine
from app.correlation.engine import CorrelationEngine
from app.database.session import get_db
from app.detection import DetectionEngine, get_detection_engine
from app.devices.manager import DeviceDiscoveryManager, get_device_manager
from app.persistence.session_factory import app_session_factory
from app.reports.service import ReportService
from app.repositories.notification import NotificationRepository
from app.repositories.report import ReportRepository
from app.repositories.setting import SettingRepository
from app.statistics.manager import TrafficStatisticsManager, get_statistics_manager

# Shared alert read service. It holds no session, only a factory, so one instance
# is safe to reuse across requests; a session is opened and closed per call.
_alert_queries: AlertQueries | None = None


def get_alert_queries() -> AlertQueries:
    """Return the shared alert read service (M13.13/M13.28).

    The service is process-wide because it is stateless: it stores the session
    *factory* and opens a session inside each call.
    """
    global _alert_queries
    if _alert_queries is None:
        _alert_queries = AlertQueries(session_factory=app_session_factory)
    return _alert_queries


def get_report_repository(db: Session = Depends(get_db)) -> ReportRepository:
    """Return a report repository bound to the request-scoped session (M13.20)."""
    return ReportRepository(db)


def get_notification_repository(
    db: Session = Depends(get_db),
) -> NotificationRepository:
    """Return a notification repository over the request-scoped session (M13.23)."""
    return NotificationRepository(db)


def get_setting_repository(db: Session = Depends(get_db)) -> SettingRepository:
    """Return a setting repository over the request-scoped session (M13.21)."""
    return SettingRepository(db)


def get_analytics_service(
    db: Session = Depends(get_db),
    statistics: TrafficStatisticsManager = Depends(get_statistics_manager),
    devices: DeviceDiscoveryManager = Depends(get_device_manager),
    tracker: ConnectionTracker = Depends(get_connection_tracker),
    alerts: AlertQueries = Depends(get_alert_queries),
    detections: DetectionEngine = Depends(get_detection_engine),
    correlations: CorrelationEngine = Depends(get_correlation_engine),
) -> AnalyticsService:
    """Return the analytics service bound to this request's collaborators (M16.1).

    The service is assembled per request rather than cached, because one of its
    collaborators — the database session — is request-scoped and must not outlive
    the request. The five live services it also holds are process-wide
    singletons, so assembling the wrapper is a handful of attribute assignments
    (M13.28).
    """
    return AnalyticsService(
        db=db,
        statistics=statistics,
        devices=devices,
        tracker=tracker,
        alerts=alerts,
        detections=detections,
        correlations=correlations,
    )


def get_report_service(
    db: Session = Depends(get_db),
    analytics: AnalyticsService = Depends(get_analytics_service),
) -> ReportService:
    """Return the reporting service bound to this request's collaborators (M17.12).

    Assembled per request rather than cached, because both of its collaborators
    are request-scoped: the session, and the analytics service built over that
    same session. A generation therefore reads the analytics tables and writes the
    report's metadata row through one connection, and nothing outlives the request
    that asked for it.

    The storage directory is left to the service's own default, so where artifacts
    live is decided in exactly one place (``settings.report_storage_dir``) rather
    than being passed around here.
    """
    return ReportService(db=db, analytics=analytics)


__all__ = [
    "get_alert_queries",
    "get_analytics_service",
    "get_notification_repository",
    "get_report_repository",
    "get_report_service",
    "get_setting_repository",
]
