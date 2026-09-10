"""Capture status vocabulary and controlled errors for the M4 capture engine."""

from enum import Enum


class CaptureStatus(str, Enum):
    """Lifecycle states of a packet capture session."""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


class CaptureErrorCode:
    """Machine-readable error codes surfaced by the capture API."""

    ALREADY_RUNNING = "CAPTURE_ALREADY_RUNNING"
    NOT_RUNNING = "CAPTURE_NOT_RUNNING"
    NO_INTERFACE = "CAPTURE_NO_INTERFACE"
    START_FAILED = "CAPTURE_START_FAILED"
    STOP_FAILED = "CAPTURE_STOP_FAILED"


class CaptureError(Exception):
    """Base error for controlled capture failures.

    Attributes:
        message: Human-readable description safe to return to the client.
        code: Machine-readable code for the API layer.
    """

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class CaptureAlreadyRunningError(CaptureError):
    """Raised when a capture is started while one is already active."""

    def __init__(self, message: str = "Packet capture is already running") -> None:
        super().__init__(message, CaptureErrorCode.ALREADY_RUNNING)


class CaptureNotRunningError(CaptureError):
    """Raised when stopping a capture that is not running."""

    def __init__(self, message: str = "Packet capture is not running") -> None:
        super().__init__(message, CaptureErrorCode.NOT_RUNNING)


class CaptureInterfaceError(CaptureError):
    """Raised when no valid interface is available for capture."""

    def __init__(self, message: str = "No capture interface selected") -> None:
        super().__init__(message, CaptureErrorCode.NO_INTERFACE)


class CaptureStartError(CaptureError):
    """Raised when a capture session cannot be started."""

    def __init__(self, message: str = "Unable to start packet capture") -> None:
        super().__init__(message, CaptureErrorCode.START_FAILED)


class CaptureStopError(CaptureError):
    """Raised when a capture session cannot be stopped cleanly."""

    def __init__(self, message: str = "Unable to stop packet capture") -> None:
        super().__init__(message, CaptureErrorCode.STOP_FAILED)
