"""Tests for structured logging configuration (Phase 3)."""

import logging
import json
import pytest

from zerotrace.logging_config import JSONFormatter, TextFormatter, get_logger


class TestJSONFormatter:
    """Tests for JSON log formatting."""
    
    def test_json_formatter_produces_valid_json(self):
        """Test that JSONFormatter outputs valid JSON."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        formatter = JSONFormatter()
        output = formatter.format(record)
        
        parsed = json.loads(output)
        assert parsed["level"] == "INFO"
        assert parsed["message"] == "Test message"
        assert parsed["logger"] == "test"
    
    def test_json_formatter_includes_timestamp(self):
        """Test that JSON output includes ISO timestamp."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None,
        )
        formatter = JSONFormatter()
        output = formatter.format(record)
        
        parsed = json.loads(output)
        assert "timestamp" in parsed
        # ISO format should contain 'T' separator
        assert "T" in parsed["timestamp"]
    
    def test_json_formatter_includes_extra_fields(self):
        """Test that JSON format includes extra context fields."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None,
        )
        # Add extra fields like scan_id
        record.scan_id = "test-scan-123"
        record.target_url = "http://localhost:8080"
        
        formatter = JSONFormatter()
        output = formatter.format(record)
        
        parsed = json.loads(output)
        assert parsed["scan_id"] == "test-scan-123"
        assert parsed["target_url"] == "http://localhost:8080"
    
    def test_json_formatter_handles_exceptions(self):
        """Test formatter includes exception info when present."""
        try:
            raise ValueError("Test error")
        except ValueError:
            import sys
            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="test.py",
                lineno=1,
                msg="Exception occurred",
                args=(),
                exc_info=sys.exc_info(),
            )
        
        formatter = JSONFormatter()
        output = formatter.format(record)
        parsed = json.loads(output)
        
        # Should include exception field
        assert "exception" in parsed
        assert "ValueError: Test error" in parsed["exception"]


class TestTextFormatter:
    """Tests for text log formatting."""
    
    def test_text_formatter_is_human_readable(self):
        """Test that TextFormatter produces human-readable output."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        formatter = TextFormatter()
        output = formatter.format(record)
        
        # Should contain timestamp, level, and message
        assert "INFO" in output
        assert "Test message" in output
    
    def test_text_formatter_has_consistent_format(self):
        """Test text format includes expected components."""
        record = logging.LogRecord(
            name="zerotrace.engine.orchestrator",
            level=logging.DEBUG,
            pathname="orchestrator.py",
            lineno=42,
            msg="Debug message",
            args=(),
            exc_info=None,
        )
        formatter = TextFormatter()
        output = formatter.format(record)
        
        # Should have timestamp bracket format
        assert "[" in output and "]" in output
        # Should have level padded to 7 chars
        assert "DEBUG  " in output or "DEBUG " in output
        # Should have logger name (last part)
        assert "orchestrator" in output


class TestGetLogger:
    """Tests for get_logger function."""
    
    def test_get_logger_returns_named_logger(self):
        """Test get_logger returns a properly named logger."""
        logger = get_logger("test_module")
        assert logger.name == "zerotrace.test_module"
    
    def test_get_logger_returns_logger_instance(self):
        """Test get_logger returns a logging.Logger instance."""
        logger = get_logger("another_module")
        assert isinstance(logger, logging.Logger)
    
    def test_different_names_return_different_loggers(self):
        """Test that different names create different logger instances."""
        logger1 = get_logger("module1")
        logger2 = get_logger("module2")
        
        assert logger1.name != logger2.name
        assert logger1.name == "zerotrace.module1"
        assert logger2.name == "zerotrace.module2"