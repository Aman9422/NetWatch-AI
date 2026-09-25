"""Bounded retention and querying of detection findings (M10.22).

The engine produces findings but does not persist them: M10 owns no finding
table, and the alert and storage layers belong to later milestones. What it does
own is an *in-process*, bounded history, so the findings a session produced can
be inspected while it runs.

"Bounded" is the operative word (M10.19). The history keeps at most
``max_findings`` entries and drops the oldest, so a rule that fires continuously
cannot grow memory without limit. Once the cap is reached, a query returns the
most recent findings and reports its own truncation through :meth:`count`.

Queries are read-only and never mutate the stored findings.
"""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Iterable

from app.detection.finding import DetectionFinding

# Default cap on retained findings, kept in step with the settings default.
DEFAULT_MAX_FINDINGS = 1000


class FindingHistory:
    """A thread-safe, size-limited store of detection findings (M10.22)."""

    def __init__(self, max_findings: int = DEFAULT_MAX_FINDINGS) -> None:
        if max_findings < 1:
            raise ValueError("max_findings must be at least 1")
        self._max_findings = max_findings
        self._lock = threading.Lock()
        # Insertion order is observation order; the deque drops the oldest.
        self._findings: deque[DetectionFinding] = deque(maxlen=max_findings)

    @property
    def max_findings(self) -> int:
        """Return the maximum number of findings retained."""
        return self._max_findings

    def add(self, finding: DetectionFinding) -> None:
        """Record one finding, dropping the oldest when the cap is reached."""
        with self._lock:
            self._findings.append(finding)

    def add_many(self, findings: Iterable[DetectionFinding]) -> None:
        """Record several findings in one lock acquisition."""
        with self._lock:
            self._findings.extend(findings)

    def count(self) -> int:
        """Return how many findings are currently retained."""
        with self._lock:
            return len(self._findings)

    def query(
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

        Filters combine with AND. ``since`` is inclusive and ``until`` exclusive,
        so two adjacent windows never both claim the same instant (M10.13).

        Returns:
            Matching findings, newest first. ``limit`` caps the result after
            ordering, so a limit always returns the most recent matches.
        """
        with self._lock:
            snapshot = list(self._findings)

        matches = [
            finding
            for finding in reversed(snapshot)
            if _matches(
                finding,
                rule_id=rule_id,
                source_ip=source_ip,
                destination_ip=destination_ip,
                device_id=device_id,
                since=since,
                until=until,
            )
        ]
        if limit is not None and limit >= 0:
            return matches[:limit]
        return matches

    def clear(self) -> None:
        """Discard every retained finding."""
        with self._lock:
            self._findings.clear()


def _matches(
    finding: DetectionFinding,
    *,
    rule_id: str | None,
    source_ip: str | None,
    destination_ip: str | None,
    device_id: str | None,
    since: float | None,
    until: float | None,
) -> bool:
    """Return True when ``finding`` satisfies every supplied filter."""
    if rule_id is not None and finding.rule_id != rule_id:
        return False
    if source_ip is not None and finding.source_ip != source_ip:
        return False
    if destination_ip is not None and finding.destination_ip != destination_ip:
        return False
    if device_id is not None and device_id not in (
        finding.source_device_id,
        finding.destination_device_id,
    ):
        return False
    if since is not None and finding.timestamp < since:
        return False
    if until is not None and finding.timestamp >= until:
        return False
    return True
