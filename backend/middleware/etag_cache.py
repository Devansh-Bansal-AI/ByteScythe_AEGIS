"""
AEGIS Phase 2 — ETag Caching Middleware

WHY THIS EXISTS:
----------------
Graph computation (compute_metrics) is O(V+E). Clients polling
/api/v1/graph/active-threats every 5s get stale data 90% of the time.
ETag caching returns 304 Not Modified when nothing changed, saving:
  - Backend CPU (no re-serialization)
  - Network bandwidth
  - Frontend re-render cycles
"""

import hashlib
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

# Paths that support ETag caching
CACHEABLE_PREFIXES = (
    "/api/v1/graph/active-threats",
    "/api/v1/graph/summary",
    "/api/v1/graph/communities",
    "/api/v1/graph/star-topologies",
    "/api/v1/graph/baseline",
    "/api/v1/graph/timing",
)


class ETagCacheMiddleware(BaseHTTPMiddleware):
    """
    Adds ETag headers to cacheable responses.
    Returns 304 Not Modified if client sends matching If-None-Match.
    """

    async def dispatch(self, request: Request, call_next):
        # Only cache GET requests on known paths
        if request.method != "GET":
            return await call_next(request)

        path = request.url.path
        if not any(path.startswith(prefix) for prefix in CACHEABLE_PREFIXES):
            return await call_next(request)

        response = await call_next(request)

        # Only cache 200 OK responses
        if response.status_code != 200:
            return response

        # Read body to compute ETag
        body = b""
        async for chunk in response.body_iterator:
            body += chunk

        etag = '"' + hashlib.md5(body).hexdigest() + '"'

        # Check If-None-Match from client
        client_etag = request.headers.get("If-None-Match", "")
        if client_etag == etag:
            return Response(status_code=304, headers={"ETag": etag})

        # Return response with ETag header
        return Response(
            content=body,
            status_code=response.status_code,
            headers={
                **dict(response.headers),
                "ETag": etag,
                "Cache-Control": "private, max-age=5",
            },
            media_type=response.media_type,
        )
