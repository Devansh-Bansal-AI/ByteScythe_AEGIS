"""
AEGIS Active Attribution Engine — Structured Logging & Request Tracing

WHY THIS EXISTS:
----------------
The audit identified "No logging, metrics, or tracing" as a critical gap.
Without correlation IDs, debugging a failed attribution score across
ingestion → graph engine → scorer → API response is impossible.

IMPLEMENTATION:
--------------
1. JSON-structured log formatter (machine-parseable for ELK/Datadog)
2. Per-request correlation ID (X-Request-ID header, auto-generated UUID)
3. Request/response timing (latency tracking)
4. Attaches context: client IP, method, path, status code
"""

import json
import logging
import time
import uuid
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for production observability."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Attach correlation ID if available
        if hasattr(record, "correlation_id"):
            log_entry["correlation_id"] = record.correlation_id

        # Attach exception info
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


class RequestTracingMiddleware(BaseHTTPMiddleware):
    """
    Adds correlation IDs and timing to every request.

    Sets X-Request-ID response header for client-side correlation.
    Logs request start/end with latency.
    """

    async def dispatch(self, request: Request, call_next):
        # Generate or use provided correlation ID
        correlation_id = request.headers.get(
            "X-Request-ID", str(uuid.uuid4())[:8]
        )

        # Attach to request state for use in route handlers
        request.state.correlation_id = correlation_id

        start_time = time.monotonic()

        response = await call_next(request)

        # Compute latency
        latency_ms = (time.monotonic() - start_time) * 1000

        # Add tracing headers to response
        response.headers["X-Request-ID"] = correlation_id
        response.headers["X-Response-Time"] = f"{latency_ms:.1f}ms"

        # Log request completion
        logger = logging.getLogger("aegis.access")
        client_ip = request.client.host if request.client else "unknown"
        logger.info(
            f"{request.method} {request.url.path} → {response.status_code} "
            f"({latency_ms:.1f}ms) [{client_ip}] [{correlation_id}]"
        )

        return response


def configure_structured_logging(level: str = "INFO"):
    """
    Configure structured JSON logging for the entire application.

    Call this once at startup before any other logging.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove default handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add JSON handler for production
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    root_logger.addHandler(handler)

    # Suppress noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
