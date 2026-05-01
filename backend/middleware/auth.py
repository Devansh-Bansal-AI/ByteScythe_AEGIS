"""
AEGIS Active Attribution Engine — API Key Authentication Middleware

WHY THIS EXISTS:
----------------
An open C2 detection API is itself a security vulnerability. If an attacker
can query /api/v1/graph/active-threats, they learn:
  - Which of their C2 nodes have been detected
  - Their confidence scores (enabling evasion tuning)
  - The graph topology of the defender's visibility

IMPLEMENTATION:
--------------
- Reads API key from environment variable AEGIS_API_KEY
- Validates X-API-Key header on every request
- Exempts: health check (/), WebSocket upgrade, docs
- Returns 401 with opaque error (no key leakage)
- If AEGIS_API_KEY is not set, authentication is DISABLED (dev mode)
"""

import os
import logging
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# Paths exempt from authentication
EXEMPT_PATHS = frozenset({
    "/",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/health",
})

# Prefixes exempt from authentication
EXEMPT_PREFIXES = (
    "/ws/",   # WebSocket endpoints handle their own auth
)


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """
    Validates X-API-Key header against AEGIS_API_KEY environment variable.

    If AEGIS_API_KEY is not set, authentication is disabled entirely
    (development/hackathon mode).
    """

    def __init__(self, app, api_key: Optional[str] = None):
        super().__init__(app)
        self.api_key = api_key or os.getenv("AEGIS_API_KEY", "")

        if self.api_key:
            logger.info("API Key authentication ENABLED")
        else:
            logger.warning(
                "⚠ API Key authentication DISABLED — set AEGIS_API_KEY to enable"
            )

    async def dispatch(self, request: Request, call_next):
        # Skip auth if no key is configured (dev mode)
        if not self.api_key:
            return await call_next(request)

        # Skip exempt paths
        path = request.url.path
        if path in EXEMPT_PATHS:
            return await call_next(request)

        # Skip exempt prefixes (WebSocket)
        if any(path.startswith(prefix) for prefix in EXEMPT_PREFIXES):
            return await call_next(request)

        # Validate API key
        provided_key = request.headers.get("X-API-Key", "")

        if not provided_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing API key. Provide X-API-Key header."},
            )

        if provided_key != self.api_key:
            logger.warning(
                f"Authentication failed from {request.client.host}: invalid API key"
            )
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid API key."},
            )

        return await call_next(request)
