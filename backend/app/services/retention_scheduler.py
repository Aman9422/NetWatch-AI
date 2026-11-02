"""Running the retention policies periodically (M19.4/M19.5).

M7 designed packet retention to "run opportunistically in the background" and
contained every failure so it could never disturb capture — and then nothing ever
called it. The configured window was readable, documented, and unenforced: the
only way ``PACKET_RETENTION_DAYS`` had any effect was for an operator to POST the
M7 verification endpoint by hand, and a retention policy that never runs protects
nothing. Report artifacts had no policy at all (M19.5).

This module is the missing caller, and it is deliberately the smallest one that
fits the architecture the project already has rather than a new subsystem:

* the mechanism is the **same sweep thread the connection tracker already uses**
  (M9.15/M9.18) — a :class:`threading.Event` waited on for an interval, a
  ``join`` on stop, and one ``except Exception`` inside the loop so a failing pass
  is logged and the sweep continues;
* it holds **one thread for every policy**, not one per policy, and a pass is a
  handful of indexed deletes, so the cost of the layer is a thread that sleeps;
* it is **owned by the application lifespan**, started after the schema exists and
  stopped during shutdown, so no sweep outlives the process (M19.4);
* it starts nothing at all when the interval is ``0``, which is how an operator
  says "enforce no retention policy automatically".

**One policy cannot break another.** Each policy runs inside its own guard, so a
failure in report retention cannot stop packet retention from running in the same
pass, and neither can stop the sweep. That separation is the point of the module:
the failure modes of two unrelated stores must not be coupled merely because they
share a clock.

**The first pass is one interval after startup, never at startup.** Application
startup must not begin by deleting rows: a retention window measured in days is
satisfied by an hourly pass, and the delay means starting the application is never
the moment anything disappears.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from app.config.settings import settings

logger = logging.getLogger(__name__)

#: Seconds between passes when a caller does not supply one. An hour: a retention
#: window measured in days does not need to be checked more often, and a pass is a
#: single indexed delete rather than a scan.
DEFAULT_INTERVAL_SECONDS = 3600.0

#: How long ``stop`` waits for the thread to notice it was asked to stop, over and
#: above the interval. Never unbounded: shutdown must not be able to hang on a
#: sweep that is busy in a database call.
STOP_GRACE_SECONDS = 5.0


class RetentionOutcomeLike(Protocol):
    """What a sweep needs from one policy's pass (M19.5).

    Structural rather than a shared base class, because the two outcome types
    already exist and belong to the layers that produced them: the packet service's
    outcome is defined beside packet retention and the report service's beside
    report retention. A protocol means neither layer has to import a scheduler
    concept to describe its own result.
    """

    @property
    def enabled(self) -> bool:
        """Whether the policy is switched on at all."""

    @property
    def succeeded(self) -> bool:
        """Whether the pass completed, whether or not it removed anything."""

    def summary(self) -> str:
        """Return a short human description of the pass."""


@dataclass(frozen=True)
class RetentionPolicy:
    """One retention policy the sweep runs (M19.5).

    Attributes:
        name: Short identifier used in the pass log, e.g. ``packets``.
        cleanup: Runs one pass and returns its outcome. It is expected to contain
            its own failures, but the sweep guards the call anyway: a policy that
            raises must not be able to stop the sweep or its sibling policies.
    """

    name: str
    cleanup: Callable[[], RetentionOutcomeLike]


@dataclass(frozen=True)
class SweepOutcome:
    """What one policy did in one pass (M19.4).

    Attributes:
        name: The policy's name.
        enabled: Whether the policy was switched on.
        succeeded: Whether the pass completed.
        summary: One line describing the pass, safe to log.
    """

    name: str
    enabled: bool
    succeeded: bool
    summary: str


class RetentionSweeper:
    """Applies the retention policies on an interval, on one background thread.

    The thread is a daemon, so a process that exits without a clean shutdown is
    not held open by a sweep, and :meth:`stop` joins it explicitly so a clean
    shutdown leaves no thread behind (M19.4).
    """

    def __init__(
        self,
        *,
        policies: Sequence[RetentionPolicy],
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
        autostart: bool = True,
    ) -> None:
        """Create the sweeper.

        Args:
            policies: The policies to apply, in the order they should run.
            interval_seconds: Seconds between passes. ``0`` or a negative value
                means "do not run automatically", and no thread is started.
            autostart: Whether :meth:`start` is called immediately. ``False``
                leaves the sweeper inert until a caller starts it, which is what a
                test uses to drive :meth:`run_once` deterministically.
        """
        self._policies = tuple(policies)
        self._interval = float(interval_seconds)
        self._stop_event = threading.Event()
        self._lifecycle_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        if autostart:
            self.start()

    @property
    def policies(self) -> tuple[RetentionPolicy, ...]:
        """Return the policies this sweeper applies."""
        return self._policies

    @property
    def interval_seconds(self) -> float:
        """Return the configured interval between passes."""
        return self._interval

    @property
    def is_running(self) -> bool:
        """Return whether the sweep thread is alive."""
        thread = self._thread
        return thread is not None and thread.is_alive()

    def start(self) -> bool:
        """Start the sweep thread, returning whether it was started.

        An interval of zero means there is nothing to schedule, so no thread is
        created: the honest behaviour for "run no retention policy automatically"
        is to have no scheduler rather than one that does nothing forever.
        """
        if self._interval <= 0:
            logger.info("Retention sweep disabled (interval 0); no policy will run")
            return False
        with self._lifecycle_lock:
            if self.is_running:
                return False
            self._stop_event.clear()
            thread = threading.Thread(
                target=self._loop,
                name="retention-sweep",
                daemon=True,
            )
            self._thread = thread
            thread.start()
        logger.info(
            "Retention sweep started: %s, every %.0f second(s)",
            ", ".join(policy.name for policy in self._policies) or "no policies",
            self._interval,
        )
        return True

    def stop(self, timeout: float | None = None) -> None:
        """Ask the sweep to stop and wait for the thread to finish.

        Args:
            timeout: Seconds to wait. Defaults to one interval plus a small grace,
                so a shutdown is never blocked indefinitely by a sweep that is busy
                in a database call.
        """
        self._stop_event.set()
        with self._lifecycle_lock:
            thread = self._thread
            self._thread = None
        if thread is None or not thread.is_alive():
            return
        wait = timeout if timeout is not None else self._interval + STOP_GRACE_SECONDS
        thread.join(timeout=max(0.0, wait))
        if thread.is_alive():
            # Worth saying out loud: the thread is a daemon, so this cannot hold
            # the process open, but an operator should know a pass was cut short.
            logger.warning("Retention sweep did not stop within %.1f second(s)", wait)
        else:
            logger.info("Retention sweep stopped")

    def run_once(self) -> list[SweepOutcome]:
        """Run every policy once, in order, and return what each one did.

        This is the whole behaviour of a pass, and it is callable directly, which
        is what makes the sweep verifiable without waiting for an interval or
        sleeping in a test.
        """
        outcomes: list[SweepOutcome] = []
        for policy in self._policies:
            outcomes.append(self._run_policy(policy))
        return outcomes

    def _run_policy(self, policy: RetentionPolicy) -> SweepOutcome:
        """Run one policy, returning a described outcome and never raising."""
        try:
            outcome = policy.cleanup()
        except Exception:  # noqa: BLE001 - one policy must not stop the others
            logger.exception("Retention policy %s failed; continuing", policy.name)
            return SweepOutcome(
                name=policy.name,
                enabled=True,
                succeeded=False,
                summary="pass raised an unhandled failure",
            )
        summary = outcome.summary()
        succeeded = bool(outcome.succeeded)
        enabled = bool(outcome.enabled)
        if not succeeded:
            logger.error("Retention policy %s did not complete: %s", policy.name, summary)
        elif enabled:
            logger.info("Retention policy %s: %s", policy.name, summary)
        else:
            logger.debug("Retention policy %s: disabled", policy.name)
        return SweepOutcome(
            name=policy.name, enabled=enabled, succeeded=succeeded, summary=summary
        )

    def _loop(self) -> None:
        """Run a pass every interval until stopped (M19.4).

        ``Event.wait`` returns as soon as the event is set, so a stop during the
        interval is not delayed by it, and the first pass is one interval after
        startup rather than at startup.
        """
        while not self._stop_event.wait(self._interval):
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 - the sweep must survive any failure
                logger.exception("Retention sweep pass failed; continuing")


def build_retention_policies() -> list[RetentionPolicy]:
    """Return the retention policies the application applies (M19.5).

    Both services are imported here rather than at module scope: the scheduler is
    the composition point for retention, and importing the stores it drives at
    import time would make this module a dependency of anything that merely wants
    to know what a policy looks like.

    The packet policy is first because packet rows are the high-volume store: if a
    pass is going to be cut short, the largest source of growth should have been
    dealt with first.
    """
    from app.persistence.retention import get_packet_retention_service
    from app.reports.retention import get_report_retention_service

    return [
        RetentionPolicy(
            name="packets",
            cleanup=lambda: get_packet_retention_service().cleanup_outcome(),
        ),
        RetentionPolicy(
            name="reports",
            cleanup=lambda: get_report_retention_service().cleanup_outcome(),
        ),
    ]


_sweeper: RetentionSweeper | None = None
_sweeper_lock = threading.Lock()


def get_retention_sweeper() -> RetentionSweeper:
    """Return the process-wide retention sweeper, building it once (M13.28).

    Built with ``autostart=False`` so the caller decides when the thread starts:
    application startup starts it, and a test can ask for the same object and drive
    a pass by hand instead.
    """
    global _sweeper
    with _sweeper_lock:
        if _sweeper is None:
            _sweeper = RetentionSweeper(
                policies=build_retention_policies(),
                interval_seconds=settings.retention_sweep_interval_seconds,
                autostart=False,
            )
        return _sweeper


def reset_retention_sweeper() -> None:
    """Drop the cached sweeper, stopping it first. For tests and reloads."""
    global _sweeper
    with _sweeper_lock:
        current = _sweeper
        _sweeper = None
    if current is not None:
        current.stop(timeout=0.0)


__all__ = [
    "DEFAULT_INTERVAL_SECONDS",
    "STOP_GRACE_SECONDS",
    "RetentionPolicy",
    "RetentionOutcomeLike",
    "RetentionSweeper",
    "SweepOutcome",
    "build_retention_policies",
    "get_retention_sweeper",
    "reset_retention_sweeper",
]
