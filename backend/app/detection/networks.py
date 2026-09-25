"""Internal-address classification for the internal scan detector (M10.11).

The internal scan detector has to say what an *internal destination* is rather
than assume that every private address is suspicious. This module defines that
policy once, from two observable facts:

* an address that is not globally routable is internal — the private-use,
  loopback, link-local, reserved, multicast and unspecified blocks that
  :mod:`ipaddress` already knows about;
* the host's **own** addresses are internal even when they are publicly
  routable, because traffic to them never left the machine or its segment.

The host's addresses come from the M3 interface manager through an injected
provider. Resolution is cached for a short TTL because a detector asks this
question for the destination of almost every packet and enumerating interfaces
is far too expensive to run per packet.

The module holds no packet state and performs no detection itself.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections.abc import Callable

# How long a resolved local-address set is cached, mirroring the M6.7 direction
# classifier. Short enough to notice a hot-plugged interface, long enough that
# the provider is not called per packet.
_LOCAL_ADDRESSES_TTL_SECONDS = 5.0

# Addresses as supplied by the interface manager, keyed by text form.
LocalAddressProvider = Callable[[], set[str]]


def is_private_address(address: str | None) -> bool:
    """Return True when ``address`` is not globally routable.

    Anything that is not a parseable IPv4/IPv6 address is *not* internal: an
    unreadable address is left uncounted rather than guessed at.
    """
    if not address:
        return False
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return bool(
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_reserved
        or parsed.is_multicast
        or parsed.is_unspecified
    )


class InternalNetworkClassifier:
    """Decides whether an address belongs to the monitored network (M10.11)."""

    def __init__(
        self,
        local_addresses_provider: LocalAddressProvider | None = None,
        ttl_seconds: float = _LOCAL_ADDRESSES_TTL_SECONDS,
    ) -> None:
        self._local_addresses_provider = local_addresses_provider
        self._ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._cache: set[str] | None = None
        self._cached_at = 0.0

    def is_internal(self, address: str | None) -> bool:
        """Return True when ``address`` is part of the monitored network."""
        if not address:
            return False
        if is_private_address(address):
            return True
        return address in self._local_addresses()

    def set_local_addresses_provider(
        self, provider: LocalAddressProvider | None
    ) -> None:
        """Replace the local-address provider and invalidate the cache."""
        with self._lock:
            self._local_addresses_provider = provider
            self._cache = None
            self._cached_at = 0.0

    def _local_addresses(self) -> set[str]:
        """Return the cached set of the host's own addresses.

        A provider failure is cached as an empty set for the same TTL, so an
        enumeration outage degrades the classifier to its address-block rules
        instead of stalling detection.
        """
        provider = self._local_addresses_provider
        if provider is None:
            return set()

        now = time.monotonic()
        with self._lock:
            cached = self._cache
            if cached is not None and now - self._cached_at < self._ttl_seconds:
                return cached

        try:
            resolved = provider()
        except Exception:  # noqa: BLE001 - a failure means "addresses unknown"
            resolved = set()

        with self._lock:
            self._cache = resolved
            self._cached_at = time.monotonic()
        return resolved
