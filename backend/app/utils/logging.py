"""Logging configuration for NetWatch AI."""

import logging
import sys

from app.config.settings import settings

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"


def configure_logging(level: str | None = None) -> None:
    """Configure application logging.

    Args:
        level: Logging level name (e.g. ``"DEBUG"``, ``"INFO"``). Defaults to
            the configured log level from settings.
    """
    log_level = (level or settings.log_level).upper()
    numeric_level = getattr(logging, log_level, logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Avoid duplicate handlers when called multiple times (e.g. in tests).
    if root_logger.handlers:
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)
    formatter = logging.Formatter(_LOG_FORMAT)
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    logging.getLogger("uvicorn").setLevel(numeric_level)
