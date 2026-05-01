"""
AEGIS Active Attribution Engine — Token Bucket Rate Limiter

WHY THIS EXISTS:
----------------
Without rate limiting, an attacker can:
  1. DoS the scoring engine (compute_metrics is O(V+E))
  2. Brute-force API keys
  3. Exhaust the asyncio worker pool, freezing the dashboard

IMPLEMENTATION:
--------------
Token Bucket algorithm per client IP:
  - Each IP starts with `burst` tokens
  - Tokens refill at `rate` tokens/second
  - Each request consumes 1 token
  - When empty → 429 Too Many Requests with Retry-After header

Configurable via:
  - AEGIS_RATE_LIMIT_RATE: tokens per second (default: 10)
  - AEGIS_RATE_LIMIT_BURST: max burst size (default: 50)
"""

import os
import time
import logging
from typing import Dict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


class TokenBucket:
    """Per-client token bucket."""

    __slots__ = ('tokens', 'last_refill', 'rate', 'burst')

    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.last_refill = time.monotonic()

    def consume(self) -> bool:
        """Try to consume a token. Returns True if allowed."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.last_refill = now

        # Refill tokens
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    @property
    def retry_after(self) -> float:
        """Seconds until next token is available."""
        if self.tokens >= 1.0:
            return 0.0
        return (1.0 - self.tokens) / self.rate


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Token bucket rate limiter per client IP.

    Exempt paths: health check, WebSocket upgrade.
    """

    EXEMPT_PATHS = frozenset({"/", "/health"})

    def __init__(self, app, rate: float = None, burst: int = None):
        super().__init__(app)
        self.rate = rate or float(os.getenv("AEGIS_RATE_LIMIT_RATE", "10"))
        self.burst = burst or int(os.getenv("AEGIS_RATE_LIMIT_BURST", "50"))
        self._buckets: Dict[str, TokenBucket] = {}

        # Periodic cleanup threshold
        self._max_buckets = 10_000
        self._last_cleanup = time.monotonic()

        logger.info(
            f"Rate limiting ENABLED: {self.rate} req/s, burst={self.burst}"
        )

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP, respecting X-Forwarded-For behind a proxy."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _cleanup_stale_buckets(self):
        """Remove buckets that haven't been used in 5 minutes."""
        now = time.monotonic()
        if now - self._last_cleanup < 60:
            return

        stale_threshold = now - 300  # 5 minutes
        stale_keys = [
            ip for ip, bucket in self._buckets.items()
            if bucket.last_refill < stale_threshold
        ]
        for key in stale_keys:
            del self._buckets[key]

        self._last_cleanup = now

    async def dispatch(self, request: Request, call_next):
        # Skip exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Skip WebSocket
        if request.url.path.startswith("/ws/"):
            return await call_next(request)

        client_ip = self._get_client_ip(request)

        # Get or create bucket
        if client_ip not in self._buckets:
            if len(self._buckets) >= self._max_buckets:
                self._cleanup_stale_buckets()
            self._buckets[client_ip] = TokenBucket(self.rate, self.burst)

        bucket = self._buckets[client_ip]

        if not bucket.consume():
            retry_after = max(1, int(bucket.retry_after) + 1)
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Slow down."},
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)
