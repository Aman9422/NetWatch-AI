"""Interface manager for selecting and validating capture interfaces.

The manager does NOT start packet capture. It only manages which interface has
been selected for a future capture session (M4).
"""

import logging
from collections.abc import Callable

from app.config.settings import settings
from app.schemas.interface import NetworkInterface
from app.services.interface_discovery import discover_interfaces

logger = logging.getLogger(__name__)


class InterfaceValidationError(Exception):
    """Controlled error raised when an interface cannot be selected.

    Attributes:
        message: Human-readable error description.
        code: Machine-readable error code for the API layer.
    """

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class InterfaceManager:
    """Manages discovery, validation, and selection of network interfaces."""

    def __init__(
        self,
        discovery: Callable[[], list[dict]] | None = None,
        default_interface: str | None = None,
    ) -> None:
        self._discovery = discovery or discover_interfaces
        self._selected: NetworkInterface | None = None
        self._set_default(default_interface)

    def _set_default(self, default_interface: str | None) -> None:
        """Apply the configured default interface if it is valid.

        An invalid or unavailable default is never activated; it is only logged.
        """
        if not default_interface or not default_interface.strip():
            return
        try:
            selected = self.select_interface(default_interface)
            logger.info("Applied default capture interface: %s", selected.name)
        except InterfaceValidationError as exc:
            logger.warning("Default interface '%s' not applied: %s", default_interface, exc.message)

    def list_interfaces(self) -> list[NetworkInterface]:
        """Return all normalized network interfaces."""
        raw = self._discovery()
        interfaces = [NetworkInterface(**item) for item in raw]
        logger.info("Discovered %d network interface(s)", len(interfaces))
        return interfaces

    def get_interface(self, name: str) -> NetworkInterface | None:
        """Return the interface matching ``name``, or ``None`` if not found."""
        name = (name or "").strip()
        for interface in self.list_interfaces():
            if interface.name.lower() == name.lower():
                return interface
        return None

    def validate_interface(self, name: str) -> NetworkInterface:
        """Validate that an interface exists and is available.

        Raises:
            InterfaceValidationError: If the name is empty, the interface does
                not exist, or it is not available (down).
        """
        name = (name or "").strip()
        if not name:
            logger.warning("Interface validation failed: empty name")
            raise InterfaceValidationError("Interface name is required", "EMPTY_INTERFACE_NAME")

        interface = self.get_interface(name)
        if interface is None:
            logger.warning("Interface validation failed: '%s' not found", name)
            raise InterfaceValidationError(f"Interface '{name}' not found", "INTERFACE_NOT_FOUND")

        if not interface.is_up:
            logger.warning("Interface validation failed: '%s' is unavailable", name)
            raise InterfaceValidationError(f"Interface '{name}' is not available", "INTERFACE_UNAVAILABLE")

        return interface

    def select_interface(self, name: str) -> NetworkInterface:
        """Validate, then select an interface as the active capture interface."""
        interface = self.validate_interface(name)

        if self._selected and self._selected.name.lower() == interface.name.lower():
            logger.info("Interface already selected: %s", interface.name)
            return interface

        logger.info("Interface selected: %s", interface.name)
        self._selected = interface
        return interface

    def get_selected_interface(self) -> NetworkInterface | None:
        """Return the currently selected interface, or ``None`` if none."""
        return self._selected

    def get_local_addresses(self) -> set[str]:
        """Return every IP address assigned to any known interface.

        Used to classify traffic direction (M6.7). A discovery failure simply
        yields an empty set so callers fall back to ``unknown`` rather than
        guessing a direction.
        """
        try:
            interfaces = self.list_interfaces()
        except Exception:  # noqa: BLE001 - never let discovery break a caller
            logger.exception("Interface discovery failed while reading local addresses")
            return set()
        addresses: set[str] = set()
        for interface in interfaces:
            addresses.update(interface.ip_addresses)
        return addresses


# Shared singleton used by the application at runtime.
_interface_manager = InterfaceManager(default_interface=settings.default_capture_interface)


def get_interface_manager() -> InterfaceManager:
    """FastAPI dependency returning the shared interface manager instance."""
    return _interface_manager
