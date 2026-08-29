"""Tests for the NetWatch AI configuration module."""

from app.config.settings import Settings, settings


def test_default_settings() -> None:
    """Settings defaults are applied when no environment variables are set."""
    test_settings = Settings()
    assert test_settings.app_name == "NetWatch AI"
    assert test_settings.app_version == "0.1.0"
    assert test_settings.app_env == "development"
    assert test_settings.host == "127.0.0.1"
    assert test_settings.port == 8000
    assert test_settings.log_level == "INFO"
    assert test_settings.database_url == "sqlite:///./netwatch.db"


def test_global_settings_instance() -> None:
    """The module-level settings singleton exposes expected values."""
    assert settings.app_name == "NetWatch AI"
    assert settings.app_version == "0.1.0"
    assert settings.app_env == "development"
    assert settings.host == "127.0.0.1"
    assert settings.port == 8000
    assert settings.log_level == "INFO"
    assert settings.database_url == "sqlite:///./netwatch.db"
