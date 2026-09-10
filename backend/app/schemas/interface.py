"""Pydantic schemas for network interfaces."""

import re

from pydantic import BaseModel, Field, field_validator


def normalize_mac(value: str) -> str:
    """Normalize a MAC address to canonical ``AA:BB:CC:DD:EE:FF`` form.

    Handles the common OS-specific separators:
      * Unix colons:       ``cc:28:aa:72:aa:99``
      * Windows dashes:    ``CC-28-AA-72-AA-99``
      * Cisco dotted:      ``cc28.aa72.aa99``
      * No separators:     ``cc28aa72aa99``

    Non-hex characters are removed; if the result is not a standard 6-byte
    (12 hex digit) address, the uppercased original is returned unchanged.
    """
    hex_digits = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(hex_digits) != 12:
        return value.upper()
    return ":".join(hex_digits[i : i + 2] for i in range(0, 12, 2)).upper()


class NetworkInterface(BaseModel):
    """Normalized representation of a network interface.

    This is the common structure used throughout the application, regardless of
    the underlying operating system.
    """

    name: str
    description: str | None = None
    mac_address: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    is_up: bool = False

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        """Ensure the interface name is not blank."""
        value = value.strip()
        if not value:
            raise ValueError("Interface name must not be empty")
        return value

    @field_validator("mac_address")
    @classmethod
    def _normalize_mac(cls, value: str | None) -> str | None:
        """Normalize MACs so the application always sees one canonical format."""
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        return normalize_mac(value)

    @field_validator("ip_addresses")
    @classmethod
    def _normalize_ips(cls, value: list[str]) -> list[str]:
        """Strip whitespace and remove duplicate IP addresses."""
        cleaned: list[str] = []
        for ip in value:
            ip = ip.strip()
            if ip and ip not in cleaned:
                cleaned.append(ip)
        return cleaned


class InterfaceSelectionRequest(BaseModel):
    """Request body for selecting an interface."""

    name: str = Field(..., description="Name of the interface to select")

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        """Strip the name and reject blank values."""
        value = value.strip()
        if not value:
            raise ValueError("Interface name must not be empty")
        return value
