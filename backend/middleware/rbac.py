"""
AEGIS Phase 3 — JWT Role-Based Access Control (RBAC)

WHY THIS EXISTS:
----------------
Phase 1 added API key auth (single shared secret).
RBAC adds per-user identity with granular permissions:
  - analyst: read-only access to dashboards and reports
  - operator: can quarantine nodes and trigger SOAR actions
  - admin: full system access including configuration

TOKEN FORMAT:
------------
{
  "sub": "user@org.com",
  "role": "operator",
  "org": "acme-corp",
  "exp": 1700000000,
  "iat": 1699996400
}
"""

import os
import hmac
import hashlib
import json
import base64
import time
import logging
from typing import Optional, List
from dataclasses import dataclass
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

JWT_SECRET = os.getenv("AEGIS_JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("AEGIS_JWT_EXPIRY_HOURS", "24"))

# Role hierarchy
ROLES = {
    "viewer": 0,
    "analyst": 1,
    "operator": 2,
    "admin": 3,
}

# Endpoint → minimum role required
ENDPOINT_PERMISSIONS = {
    # Read-only endpoints — analyst level
    "/api/v1/graph/active-threats": "analyst",
    "/api/v1/graph/summary": "analyst",
    "/api/v1/graph/communities": "analyst",
    "/api/v1/graph/timing": "analyst",
    "/api/v1/graph/baseline": "analyst",
    "/api/v1/graph/sankey": "analyst",
    "/api/v1/graph/node/": "analyst",
    # Operational endpoints — operator level
    "/api/nodes/": "operator",
    "/api/v1/graph/blast-radius/": "operator",
    "/api/v1/soar/": "operator",
    "/api/v1/cases/": "operator",
    # Admin endpoints
    "/api/v1/graph/pipeline/": "admin",
    "/api/v1/graph/ingestion/": "admin",
    "/metrics": "admin",
}


@dataclass
class JWTPayload:
    sub: str          # user identity
    role: str         # role name
    org: str          # organization/tenant
    exp: float        # expiry timestamp
    iat: float        # issued at


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def create_jwt(sub: str, role: str, org: str = "default") -> str:
    """Create a signed JWT token."""
    if not JWT_SECRET:
        raise ValueError("AEGIS_JWT_SECRET must be set to create tokens")

    header = _b64url_encode(json.dumps({"alg": JWT_ALGORITHM, "typ": "JWT"}).encode())
    now = time.time()
    payload_data = {
        "sub": sub,
        "role": role,
        "org": org,
        "exp": now + JWT_EXPIRY_HOURS * 3600,
        "iat": now,
    }
    payload = _b64url_encode(json.dumps(payload_data).encode())

    signature_input = f"{header}.{payload}".encode()
    signature = hmac.new(JWT_SECRET.encode(), signature_input, hashlib.sha256).digest()
    sig = _b64url_encode(signature)

    return f"{header}.{payload}.{sig}"


def verify_jwt(token: str) -> Optional[JWTPayload]:
    """Verify and decode a JWT token. Returns None if invalid."""
    if not JWT_SECRET:
        return None

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, sig_b64 = parts

        # Verify signature
        signature_input = f"{header_b64}.{payload_b64}".encode()
        expected_sig = hmac.new(
            JWT_SECRET.encode(), signature_input, hashlib.sha256
        ).digest()
        actual_sig = _b64url_decode(sig_b64)

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        # Decode payload
        payload_data = json.loads(_b64url_decode(payload_b64))

        # Check expiry
        if payload_data.get("exp", 0) < time.time():
            return None

        return JWTPayload(
            sub=payload_data.get("sub", ""),
            role=payload_data.get("role", "viewer"),
            org=payload_data.get("org", "default"),
            exp=payload_data.get("exp", 0),
            iat=payload_data.get("iat", 0),
        )
    except Exception as e:
        logger.debug(f"JWT verification failed: {e}")
        return None


def has_permission(role: str, required_role: str) -> bool:
    """Check if a role meets the minimum required permission level."""
    return ROLES.get(role, 0) >= ROLES.get(required_role, 0)


def get_required_role(path: str) -> str:
    """Get the minimum role required for a given endpoint path."""
    for prefix, role in ENDPOINT_PERMISSIONS.items():
        if path.startswith(prefix):
            return role
    return "analyst"  # Default: analyst-level access


class RBACMiddleware(BaseHTTPMiddleware):
    """
    JWT-based RBAC middleware.

    If AEGIS_JWT_SECRET is not set, RBAC is disabled (dev mode).
    Falls back to API key auth from Phase 1 if no JWT is present.
    """

    EXEMPT_PATHS = frozenset({"/", "/health", "/docs", "/redoc", "/openapi.json"})

    def __init__(self, app):
        super().__init__(app)
        if JWT_SECRET:
            logger.info("JWT RBAC authentication ENABLED")
        else:
            logger.warning(
                "⚠ JWT RBAC DISABLED — set AEGIS_JWT_SECRET to enable"
            )

    async def dispatch(self, request: Request, call_next):
        # Skip if JWT not configured
        if not JWT_SECRET:
            return await call_next(request)

        # Skip exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Skip WebSocket
        if request.url.path.startswith("/ws/"):
            return await call_next(request)

        # Extract token from Authorization: Bearer <token>
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return await call_next(request)  # Fall through to API key auth

        token = auth_header[7:]
        payload = verify_jwt(token)

        if not payload:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or expired JWT token."},
            )

        # Check role permission
        required_role = get_required_role(request.url.path)
        if not has_permission(payload.role, required_role):
            logger.warning(
                f"RBAC denied: {payload.sub} (role={payload.role}) "
                f"tried to access {request.url.path} (requires {required_role})"
            )
            return JSONResponse(
                status_code=403,
                content={
                    "detail": f"Insufficient permissions. Role '{payload.role}' "
                    f"cannot access this endpoint (requires '{required_role}').",
                },
            )

        # Attach user info to request state
        request.state.user = payload
        request.state.org = payload.org

        return await call_next(request)
