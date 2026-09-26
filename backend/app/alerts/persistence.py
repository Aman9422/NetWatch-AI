"""Map a runtime alert onto the M2 ``alerts`` columns (M11.12).

This is the one boundary where the runtime model meets the table M2 defined, so
every difference between the two is resolved here and nowhere else:

* **confidence is a float 0..1 in the model and an integer percent in the
  column.** The conversion is ``round(value * 100)``, so ``0.923`` is stored as
  ``92`` and read back as ``0.92`` — documented, tested, and the only lossy step
  in the M11 alert path. Storing a fraction as a percentage is the M2 column's
  choice, and rounding rather than truncating avoids a systematic downward bias.
* **``risk_score`` is written as ``0``.** M11 does not score risk; M12 owns it.
  Writing the column explicitly (rather than leaving it to the default) makes
  that a deliberate, greppable decision rather than an accident of omission.
* **``device_id`` is written as ``NULL``.** The column is a foreign key into the
  M2 ``devices`` table, but M8's registry is the authority on what a device is
  and M11 must not create a device row to satisfy a reference. The device
  associations the finding resolved are preserved as ``device`` evidence records
  instead (M11.15), which reference the M8 identity rather than inventing a row.
* **``rule_id`` is the rule *catalogue* foreign key.** The detector's string rule
  id has no column of its own; it is carried in ``correlation_key``, and this
  mapping takes the resolved row id (or ``None``) as an argument rather than
  trying to derive it (M11.18).
* **timestamps are supplied, not defaulted.** An alert is dated to when the
  behaviour was *observed*, not to when the row was written, so ``created_at``
  and ``updated_at`` are passed explicitly and override the columns' server
  defaults.
"""

from __future__ import annotations

from app.alerts.alert import Alert
from app.alerts.timestamps import now_utc_datetime

#: The column's full-scale value: a confidence of 1.0 is stored as 100.
_CONFIDENCE_SCALE = 100

#: Risk is M12's concern; M11 states it as unset rather than guessing.
_UNSET_RISK_SCORE = 0


def confidence_to_percent(confidence: float) -> int:
    """Return the 0..100 integer the ``confidence`` column stores.

    The value is clamped to ``[0, 100]`` first: the model already validates the
    0..1 range, but a mapping must not be the thing that lets an out-of-range
    value reach a CHECK constraint and fail an insert.
    """
    bounded = min(max(float(confidence), 0.0), 1.0)
    return int(round(bounded * _CONFIDENCE_SCALE))


def to_alert_row_values(
    alert: Alert, *, rule_row_id: int | None = None
) -> dict[str, object]:
    """Return the ``alerts`` column values for a runtime alert (M11.12).

    Args:
        alert: The runtime alert to persist. It need not have an id yet; if it
            does, the caller is updating an existing row rather than inserting.
        rule_row_id: The ``detection_rules.id`` the alert's detector resolved to,
            or ``None`` when the catalogue has no row for it. The string rule id
            travels in ``correlation_key`` regardless (M11.9).

    Returns:
        Keyword arguments for the ``Alert`` model. Every column the runtime model
        can speak to is set explicitly, so nothing depends on a column default
        that a future schema change could move.
    """
    created_at = alert.created_at or now_utc_datetime()
    return {
        "rule_id": rule_row_id,
        # Documented: M8 owns devices, so no device row is invented here (M11.15).
        "device_id": None,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity.value,
        "risk_score": _UNSET_RISK_SCORE,
        "confidence": confidence_to_percent(alert.confidence),
        "status": alert.status.value,
        "correlation_key": alert.correlation_key,
        "resolved_at": alert.resolved_at,
        "created_at": created_at,
        "updated_at": alert.updated_at or created_at,
    }
