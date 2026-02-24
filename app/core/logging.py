"""
Structured JSON logging via structlog.

Every log entry includes: timestamp, level, event, logger name,
and any bound context (tenant_id, user_id, request_id).

Usage:
    logger = get_logger(__name__)
    logger.info("user.login", user_id=42, tenant_id="acme")
    logger.warning("auth.invalid_token", reason="expired")
    logger.error("db.query_failed", table="users", error=str(e))
"""

import logging
import sys
from typing import Any

import structlog
from structlog.types import EventDict, WrappedLogger

from app.core.config import settings


def add_severity_field(
    logger: WrappedLogger, method: str, event_dict: EventDict
) -> EventDict:
    """Map structlog levels to GCP/Datadog severity strings."""
    level_map = {
        "debug": "DEBUG",
        "info": "INFO",
        "warning": "WARNING",
        "error": "ERROR",
        "critical": "CRITICAL",
    }
    event_dict["severity"] = level_map.get(method, "INFO")
    return event_dict


def setup_logging() -> None:
    """Configure structlog for JSON (production) or console (dev) output."""
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        add_severity_field,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionRenderer(),
    ]

    if settings.LOG_FORMAT == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(settings.LOG_LEVEL)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Suppress noisy third-party loggers
    for noisy in ("uvicorn.access", "sqlalchemy.engine"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.BoundLogger:
    """Return a bound structlog logger for a module."""
    return structlog.get_logger(name)
