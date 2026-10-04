"""Payload projections: runtime objects → the JSON a client receives (M14.8-M14.12).

One function per payload, each a pure projection with no side effect and no
service access. The payloads reuse what M5, M11 and M12 already defined rather
than restating them:

* a **packet** is projected field by field, because M14.8 lists exactly what may
  be sent and a ``model_dump()`` would send whatever M5 adds next — including
  something that should not leave the process;
* an **alert** is the M11.18 wire view, the same projection the REST endpoint
  serves;
* an **incident** is the M12.26 summary the incident listing serves, so the risk
  score and band a client sees live are read from the incident, never recomputed
  (M14.12).

The system payloads take plain arguments rather than service objects: they are
built from a value the owning service already returned (a ``CaptureStatusData``,
a health probe result), so this module never reaches into a manager and can be
tested from literals.

Nothing here may read a database, open a session, or build a service. A projection
that could fail would make publishing a thing that can fail, which M14.14
forbids.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.websockets.event import JsonDocument, iso_utc

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps this module import-light
    from app.alerts.alert import Alert
    from app.correlation.incident import CorrelatedIncident
    from app.schemas.capture import CaptureStatusData
    from app.schemas.packet import NormalizedPacket


def packet_payload(packet: "NormalizedPacket") -> JsonDocument:
    """Project one normalized packet for the packets channel (M14.8).

    The documented fields and the capture interface, and nothing else. There is no
    payload field in :class:`~app.schemas.packet.NormalizedPacket` to leak, and
    this projection would not carry one if there were: M7.5 keeps payloads out of
    storage, and M14.8 repeats the rule for the live stream.
    """
    return {
        "packet_id": packet.packet_id,
        "timestamp": iso_utc(packet.timestamp),
        "interface": packet.interface,
        "source_ip": packet.source_ip,
        "destination_ip": packet.destination_ip,
        "protocol": packet.protocol,
        "source_port": packet.source_port,
        "destination_port": packet.destination_port,
        "length": int(packet.length),
        "packet_type": str(packet.packet_type.value),
    }


def alert_payload(alert: "Alert") -> JsonDocument:
    """Project one runtime alert through the M11.18 wire view (M14.10).

    ``AlertView`` is imported *here* rather than at module level, and that is a
    structural choice rather than a stylistic one. The M11 wire view lives in
    :mod:`app.schemas.alert`, which reaches into the alert package — and the alert
    package reaches back into this one, because the alert service publishes
    through :mod:`app.websockets.events`. A module-level import would close that
    cycle, and importing the alert service could then ask for a half-initialised
    builder module. Deferring it to the first projection breaks the cycle at its
    only weak point and costs nothing: this runs when an event is published, long
    after every module has finished loading.
    """
    from app.schemas.alert import AlertView

    return AlertView.from_alert(alert).model_dump(mode="json")


def incident_payload(incident: "CorrelatedIncident") -> JsonDocument:
    """Project one correlated incident through the M12.26 summary (M14.12).

    ``summary()`` rather than ``as_dict()``: a live incident event is a
    notification that something changed, and the full member lists are what
    ``GET /api/v1/incidents/{id}`` is for. The risk score and band are carried,
    because an incident whose risk moved is exactly what a dashboard must see.
    """
    return dict(incident.summary())


def capture_payload(
    status: "CaptureStatusData", *, reason: str | None = None
) -> JsonDocument:
    """Project a capture state change (M14.11).

    ``reason`` exists for ``capture.error`` and carries a fixed sentence supplied
    by the capture layer — never ``str(exception)``, which can name a device or a
    path (M14.22).
    """
    payload: JsonDocument = {
        "status": status.status,
        "interface": status.interface,
        "packet_count": int(status.packet_count),
    }
    if reason is not None:
        payload["reason"] = str(reason)
    return payload


def dashboard_payload(
    *,
    capture_running: bool,
    interface: str | None,
    packet_count: int,
    packets_per_second: float,
    bytes_per_second: float,
    device_count: int,
    active_connections: int,
    open_alerts: int,
    active_incidents: int,
) -> JsonDocument:
    """Project the bounded dashboard update (M14.9).

    Every argument is a value the owning service already computed. Taking them as
    arguments rather than reading services here is what keeps this projection pure
    and keeps the tick itself — the only place that touches six services — a short
    function in one file.
    """
    return {
        "capture_running": bool(capture_running),
        "interface": interface,
        "packet_count": int(packet_count),
        "packets_per_second": round(float(packets_per_second), 3),
        "bytes_per_second": round(float(bytes_per_second), 3),
        "device_count": int(device_count),
        "active_connections": int(active_connections),
        "open_alerts": int(open_alerts),
        "active_incidents": int(active_incidents),
    }


def service_payload(
    service: str, state: str, *, detail: str | None = None
) -> JsonDocument:
    """Describe one service's state (M14.11).

    Values are supplied by the caller from the service's own state — an M10/M11/M12
    enable flag, a persistence worker's status — so no metric is invented here.
    """
    payload: JsonDocument = {"service": str(service), "state": str(state)}
    if detail is not None:
        payload["detail"] = str(detail)
    return payload


def database_payload(*, dialect: str, reachable: bool) -> JsonDocument:
    """Describe the database probe result (M14.11).

    The same two facts ``GET /api/v1/system/health`` derives, and no more: the
    dialect and whether a query answered. No connection string, no path and no
    driver message reaches the wire (M14.22).
    """
    return {"dialect": str(dialect), "reachable": bool(reachable)}


def keepalive_payload(*, nonce: str | None = None) -> JsonDocument:
    """Build the payload of a ``ping`` or ``pong`` (M14.24).

    A nonce lets a client pair a pong with the ping that caused it, and costs one
    short string. It is optional so the server's own tick can send a bare
    keepalive.
    """
    if nonce is None:
        return {}
    return {"nonce": str(nonce)}


def refusal_payload(reason: str, *, field: str = "message") -> JsonDocument:
    """Build the payload of an ``error`` event (M14.23).

    ``reason`` is a short fixed sentence from a closed set of refusals — never a
    traceback, never a parser's own message echoing the client's bytes back.
    """
    return {"reason": str(reason), "field": str(field)}


__all__ = [
    "alert_payload",
    "capture_payload",
    "dashboard_payload",
    "database_payload",
    "incident_payload",
    "keepalive_payload",
    "packet_payload",
    "refusal_payload",
    "service_payload",
]
