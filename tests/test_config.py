"""Tests for configuration settings (Phase 3)."""

import os
import pytest

from zerotrace.config import Settings, get_settings


def test_default_settings_values():
    """Test default settings values are sensible."""
    settings = Settings()
    
    assert settings.app_name == "ZeroTrace"
    assert settings.app_version == "0.1.0"
    assert settings.debug == False
    assert settings.host == "127.0.0.1"
    assert settings.port == 8000
    assert settings.log_level == "INFO"
    assert settings.log_format == "json"


def test_settings_reads_log_level_from_env():
    """Test Settings reads log_level from environment variable."""
    original = os.environ.get("ZEROTRACE_LOG_LEVEL")
    
    try:
        os.environ["ZEROTRACE_LOG_LEVEL"] = "DEBUG"
        test_settings = Settings()
        assert test_settings.log_level == "DEBUG"
    finally:
        if original is not None:
            os.environ["ZEROTRACE_LOG_LEVEL"] = original
        else:
            os.environ.pop("ZEROTRACE_LOG_LEVEL", None)


def test_settings_reads_port_from_env():
    """Test Settings reads port from environment variable."""
    original = os.environ.get("ZEROTRACE_PORT")
    
    try:
        os.environ["ZEROTRACE_PORT"] = "8888"
        test_settings = Settings()
        assert test_settings.port == 8888
    finally:
        if original is not None:
            os.environ["ZEROTRACE_PORT"] = original
        else:
            os.environ.pop("ZEROTRACE_PORT", None)


def test_settings_reads_debug_from_env():
    """Test Settings reads debug from environment variable."""
    original = os.environ.get("ZEROTRACE_DEBUG")
    
    try:
        os.environ["ZEROTRACE_DEBUG"] = "true"
        test_settings = Settings()
        assert test_settings.debug == True
    finally:
        if original is not None:
            os.environ["ZEROTRACE_DEBUG"] = original
        else:
            os.environ.pop("ZEROTRACE_DEBUG", None)


def test_postgresql_database_url_from_env():
    """Test settings accepts PostgreSQL URLs via DATABASE_URL env var."""
    original = os.environ.get("DATABASE_URL")
    
    try:
        os.environ["DATABASE_URL"] = "postgresql+asyncpg://localhost:5432/zerotrace"
        test_settings = Settings()
        assert "postgresql+asyncpg" in test_settings.database_url
    finally:
        if original is not None:
            os.environ["DATABASE_URL"] = original
        else:
            os.environ.pop("DATABASE_URL", None)


def test_database_url_defaults_to_sqlite():
    """Test database URL defaults to SQLite if not set."""
    original = os.environ.get("DATABASE_URL")
    
    try:
        os.environ.pop("DATABASE_URL", None)
        test_settings = Settings()
        assert "sqlite" in test_settings.database_url
    finally:
        if original is not None:
            os.environ["DATABASE_URL"] = original


def test_data_directories_exist():
    """Test computed directory properties exist."""
    settings = Settings()
    
    assert hasattr(settings, 'data_dir')
    assert hasattr(settings, 'db_path')
    assert hasattr(settings, 'audit_log_path')
    assert hasattr(settings, 'reports_dir')
    assert hasattr(settings, 'cache_dir')


def test_get_settings_returns_settings_instance():
    """Test get_settings returns a Settings instance."""
    s = get_settings()
    assert isinstance(s, Settings)


def test_settings_model_config():
    """Test Settings model has correct configuration."""
    # Verify pydantic-settings model config
    assert hasattr(Settings, 'model_config')
    
    # Test that it loads from .env file if it exists
    settings = Settings()
    assert isinstance(settings, Settings)