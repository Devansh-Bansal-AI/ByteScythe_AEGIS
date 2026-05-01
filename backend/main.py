"""
AEGIS Active Attribution Engine — Application Entry Point (v2.1)

Changes from v2.0:
- Added authentication middleware (API key)
- Added rate limiting middleware (token bucket)
- Added request tracing middleware (correlation IDs)
- Fixed CORS trailing slash on Vercel URL
- Removed legacy AEGISThreatModel preload (dead weight)
- Added structured JSON logging
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from backend.api.routes import router
from backend.api.graph_routes import router as graph_router
from backend.db.database import init_db
from backend.services.pipeline import stream_telemetry
from backend.services.async_pipeline import start_pipeline, stop_pipeline
from backend.middleware.auth import APIKeyAuthMiddleware
from backend.middleware.rate_limit import RateLimitMiddleware
from backend.middleware.logging import RequestTracingMiddleware, configure_structured_logging
import logging
import os

# Configure structured logging FIRST
configure_structured_logging(level=os.getenv("AEGIS_LOG_LEVEL", "INFO"))

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Handles startup and shutdown events for the Attribution Engine.
    """
    # STARTUP
    logger.info("🛡️ AEGIS Active Attribution Engine v2.1 — Initialization Sequence")

    # Initialize database with new schema
    init_db()
    logger.info("✅ Database initialized with Attribution Engine schema")

    # Start async processing pipeline
    await start_pipeline()
    logger.info("✅ Async processing pipeline started")

    logger.info("🚀 AEGIS Active Attribution Engine online and operational")

    yield

    # SHUTDOWN
    logger.info("🛑 AEGIS shutting down...")
    await stop_pipeline()
    logger.info("✅ Async pipeline stopped")


app = FastAPI(
    title="AEGIS Active Attribution Engine API",
    description="Enterprise-grade C2 detection with graph + temporal intelligence",
    version="2.1.0",
    lifespan=lifespan
)

# ── Middleware Stack (order matters: outermost runs first) ──
# 1. Request tracing (correlation IDs, latency)
app.add_middleware(RequestTracingMiddleware)

# 2. Rate limiting (token bucket per IP)
app.add_middleware(RateLimitMiddleware)

# 3. Authentication (API key)
app.add_middleware(APIKeyAuthMiddleware)

# 4. CORS (fixed: removed trailing slash from Vercel URL)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://aegis-frontend-navy.vercel.app",
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Response-Time"],
)

# ── Routes ──
# Legacy routes
app.include_router(router, prefix="/api")

# Attribution Engine routes
app.include_router(graph_router, prefix="/api")


@app.get("/")
def health_check():
    """Deep health check — verifies all engines are accessible."""
    from backend.engine.graph_engine import get_graph_engine
    from backend.engine.temporal_engine import get_temporal_engine
    from backend.engine.header_fingerprint import get_header_engine

    graph = get_graph_engine()
    temporal = get_temporal_engine()
    headers = get_header_engine()

    return {
        "status": "AEGIS Active Attribution Engine is ONLINE",
        "version": "2.1.0",
        "capabilities": [
            "graph_analytics",
            "temporal_fingerprinting",
            "header_fingerprinting",
            "c2_attribution",
        ],
        "engines": {
            "graph": {"nodes": len(graph.graph), "edges": graph.graph.number_of_edges()},
            "temporal": {"tracked_nodes": len(temporal._timestamps)},
            "headers": {"markov_trained": headers._markov.is_trained},
        },
    }


@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    """
    Live telemetry stream endpoint.
    Streams all telemetry log events and schema rotation notices to the client.
    """
    await websocket.accept()
    logger.info("WebSocket client connected to /ws/telemetry")
    try:
        async for event_json in stream_telemetry():
            await websocket.send_text(event_json)
        # Stream complete — send a done signal
        await websocket.send_text('{"event": "stream_complete"}')
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected.")
    except (RuntimeError, ValueError, TypeError) as e:
        logger.error(f"WebSocket error: {e}")
