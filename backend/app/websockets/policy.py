"""Per-channel back-pressure and rate policy (M14.15/M14.16).

The policy table is the one place a channel's queue depth, rate ceiling and
enabled state are decided. Everything else — the manager, the connection, the
routes, the tests — reads a :class:`ChannelPolicy` rather than a setting, so there
is no second opinion about how deep a queue may grow.

Why a table rather than four fields on the manager: the channels are deliberately
*not* uniform. A packet subscriber's queue is small because packets are telemetry
that goes stale in milliseconds, an alert subscriber's is large because an alert
is the thing the application exists to surface, and the dashboard's is smallest
because a superseded dashboard sample has no value at all. Writing that down once,
with the reason next to it, is what keeps the difference intentional.

The rate limiter is a token bucket measured on :func:`time.monotonic`, and it is
applied **per channel** rather than per connection (M14.16): the point is to bound
what the application broadcasts in total, so ten subscribers cannot multiply the
publishing work by ten. Buckets are only ever touched on the event loop, so they
need no lock (M14.21).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.websockets.channels import CHANNELS, Channel

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.config.settings import Settings

#: Smallest queue any channel may be configured with. A depth of zero would make
#: every event a drop, which is a configuration mistake rather than a choice.
MIN_QUEUE_SIZE = 1

#: How a channel treats a full queue. Every channel currently uses
#: :attr:`DropStrategy.DROP_OLDEST`; the enum exists so the choice is explicit and
#: testable rather than implied by an ``if``.
class DropStrategy:
    """What to drop when a connection's queue is full (M14.15)."""

    DROP_OLDEST = "drop_oldest"
    DROP_NEWEST = "drop_newest"


@dataclass(frozen=True)
class ChannelPolicy:
    """One channel's buffering and rate configuration.

    Attributes:
        channel: Which stream this policy governs.
        queue_size: Hard cap on one connection's outbound queue.
        max_events_per_second: Ceiling on events broadcast per second across the
            whole channel, or ``None`` for no ceiling.
        drop_strategy: What a full queue drops.
        priority: ``"telemetry"``, ``"security"`` or ``"state"`` — reported by
            diagnostics so the difference between the channels is visible.
        enabled: False switches the channel off entirely: no event is produced for
            it, so the cost is zero rather than small.
    """

    channel: Channel
    queue_size: int
    max_events_per_second: float | None = None
    drop_strategy: str = DropStrategy.DROP_OLDEST
    priority: str = "state"
    enabled: bool = True

    def __post_init__(self) -> None:
        """Refuse a policy that could not work.

        Raises:
            ValueError: If the queue size is below :data:`MIN_QUEUE_SIZE` or the
                rate ceiling is negative. A negative rate would silently drop
                every event, which is a configuration bug that must fail loudly.
        """
        if int(self.queue_size) < MIN_QUEUE_SIZE:
            raise ValueError("queue_size must be at least 1")
        if self.max_events_per_second is not None and float(
            self.max_events_per_second
        ) < 0.0:
            raise ValueError("max_events_per_second must not be negative")


class TokenBucket:
    """A continuous-refill token bucket, sized to one second of allowance.

    Refilling continuously (rather than resetting once a second) is what lets a
    quiet period repay a short burst while a sustained flood settles exactly at the
    configured rate — the behaviour M14.16 asks for, without a hard edge a client
    could straddle.
    """

    def __init__(self, rate_per_second: float | None) -> None:
        """Create a bucket allowing ``rate_per_second`` events per second.

        ``None`` disables limiting entirely, which is how a channel with no rate
        ceiling is expressed rather than by a very large number that is really a
        hidden limit.
        """
        self._rate = None if rate_per_second is None else float(rate_per_second)
        self._capacity = 0.0 if self._rate is None else self._rate
        self._tokens = self._capacity
        self._updated = time.monotonic()

    @property
    def rate_per_second(self) -> float | None:
        """Return the configured ceiling, or ``None`` when unlimited."""
        return self._rate

    @property
    def unlimited(self) -> bool:
        """Return True when this bucket never refuses an event."""
        return self._rate is None

    def allow(self, *, now: float | None = None) -> bool:
        """Consume one token, returning whether the event may be sent."""
        if self._rate is None:
            return True
        moment = time.monotonic() if now is None else float(now)
        elapsed = max(0.0, moment - self._updated)
        self._updated = moment
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        if self._tokens < 1.0:
            return False
        self._tokens -= 1.0
        return True


@dataclass(frozen=True)
class PolicySet:
    """The four channel policies and their rate buckets (M14.15/M14.16)."""

    policies: dict[Channel, ChannelPolicy]
    buckets: dict[Channel, TokenBucket]

    def policy(self, channel: Channel) -> ChannelPolicy:
        """Return the policy for ``channel``.

        Every channel in :data:`~app.websockets.channels.CHANNELS` has an entry by
        construction, so a missing one is a programming error rather than a
        client's: raising here is right.
        """
        return self.policies[channel]

    def queue_size(self, channel: Channel) -> int:
        """Return the outbound queue depth for ``channel``."""
        return self.policy(channel).queue_size

    def is_enabled(self, channel: Channel) -> bool:
        """Return whether ``channel`` produces events at all (M14.16)."""
        return self.policy(channel).enabled

    def allow(self, channel: Channel, *, now: float | None = None) -> bool:
        """Return whether ``channel`` may broadcast one more event now."""
        policy = self.policy(channel)
        if not policy.enabled:
            return False
        return self.buckets[channel].allow(now=now)


def build_policy_set(settings: "Settings") -> PolicySet:
    """Build the four channel policies from application settings.

    This is the only place the settings object touches the WebSocket layer, so the
    manager and the connections stay configuration-free and a test can hand in a
    literal :class:`ChannelPolicy` instead.
    """
    policies: dict[Channel, ChannelPolicy] = {
        Channel.PACKETS: ChannelPolicy(
            channel=Channel.PACKETS,
            queue_size=max(int(settings.packet_ws_queue_size), MIN_QUEUE_SIZE),
            max_events_per_second=float(settings.packet_ws_max_events_per_second),
            priority="telemetry",
            enabled=bool(settings.packet_ws_enabled),
        ),
        Channel.DASHBOARD: ChannelPolicy(
            channel=Channel.DASHBOARD,
            queue_size=max(
                int(settings.websocket_dashboard_queue_size), MIN_QUEUE_SIZE
            ),
            max_events_per_second=None,
            priority="telemetry",
        ),
        Channel.ALERTS: ChannelPolicy(
            channel=Channel.ALERTS,
            queue_size=max(int(settings.websocket_alert_queue_size), MIN_QUEUE_SIZE),
            max_events_per_second=None,
            priority="security",
        ),
        Channel.SYSTEM: ChannelPolicy(
            channel=Channel.SYSTEM,
            queue_size=max(int(settings.websocket_system_queue_size), MIN_QUEUE_SIZE),
            max_events_per_second=None,
            priority="state",
        ),
    }
    buckets = {
        channel: TokenBucket(policy.max_events_per_second)
        for channel, policy in policies.items()
    }
    return PolicySet(policies=policies, buckets=buckets)


def default_policies() -> PolicySet:
    """Build the documented defaults without reading application settings.

    Used by the tests and by any caller that wants a manager with the documented
    behaviour and no environment dependency: a unit test of broadcasting should not
    have to construct the whole settings object.
    """
    policies: dict[Channel, ChannelPolicy] = {
        Channel.PACKETS: ChannelPolicy(
            channel=Channel.PACKETS,
            queue_size=256,
            max_events_per_second=200.0,
            priority="telemetry",
        ),
        Channel.DASHBOARD: ChannelPolicy(
            channel=Channel.DASHBOARD, queue_size=32, priority="telemetry"
        ),
        Channel.ALERTS: ChannelPolicy(
            channel=Channel.ALERTS, queue_size=512, priority="security"
        ),
        Channel.SYSTEM: ChannelPolicy(
            channel=Channel.SYSTEM, queue_size=128, priority="state"
        ),
    }
    buckets = {
        channel: TokenBucket(policy.max_events_per_second)
        for channel, policy in policies.items()
    }
    return PolicySet(policies=policies, buckets=buckets)


def all_channels_have_policies(policies: PolicySet) -> bool:
    """Return True when every channel has a policy. Asserted by the tests."""
    return all(channel in policies.policies for channel in CHANNELS)


__all__ = [
    "MIN_QUEUE_SIZE",
    "ChannelPolicy",
    "DropStrategy",
    "PolicySet",
    "TokenBucket",
    "all_channels_have_policies",
    "build_policy_set",
    "default_policies",
]
