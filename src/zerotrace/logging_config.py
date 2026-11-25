"""Structured logging configuration for ZeroTrace."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from zerotrace.config import settings


class JSONFormatter(logging.Formatter):
    """Format log records as JSON for structured log consumption."""

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            log_data["exception"] = self.formatException(record.exc_info)

        # Include correlation IDs or extra fields if set
        for key in ("scan_id", "finding_id", "target_url", "module"):
            if hasattr(record, key):
                log_data[key] = getattr(record, key)

        return json.dumps(log_data, default=str)


class TextFormatter(logging.Formatter):
    """Human-readable text formatter for console output."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        level = record.levelname.ljust(7)
        logger = record.name.split(".")[-1]
        message = record.getMessage()
        return f"{timestamp} [{level}] {logger}: {message}"


def setup_logging() -> None:
    """Configure the root logger based on settings."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers
    root.handlers.clear()

    formatter = (
        JSONFormatter()
        if settings.log_format == "json"
        else TextFormatter()
    )

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    root.addHandler(stream)

    logging.info(
        "Logging initialized",
        extra={
            "level": settings.log_level,
            "format": settings.log_format,
        },
    )


def get_logger(name: str) -> logging.Logger:
    """Get a named logger instance."""
    return logging.getLogger(f"zerotrace.{name}")
