"""
AEGIS Active Attribution Engine — Application Entry Point (v3.0)

Full Enterprise Stack:
- Phase 1: API key auth, rate limiting, request tracing
- Phase 2: ETag caching, Prometheus metrics, score persistence
- Phase 3: JWT RBAC, MITRE ATT&CK mapping
- Phase 4: SOAR automation, case management, NLQ, threat intel
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from backend.api.routes import router
from backend.api.graph_routes import router as graph_router
from backend.api.enterprise_routes import router as enterprise_router
from backend.db.database import init_db
from backend.db.score_persistence import ScorePersistence
from backend.services.pipeline import stream_telemetry
from backend.services.async_pipeline import start_pipeline, stop_pipeline
from backend.middleware.auth import APIKeyAuthMiddleware
from backend.middleware.rate_limit import RateLimitMiddleware
from backend.middleware.rbac import RBACMiddleware
from backend.middleware.etag_cache import ETagCacheMiddleware
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
    logger.info("🛡️ AEGIS Active Attribution Engine v3.0 — Initialization Sequence")

    # Initialize database with new schema
    init_db()
    logger.info("✅ Database initialized with Attribution Engine schema")

    # Initialize Phase 2-4 tables (score persistence, cases, SOAR, threat intel)
    from backend.config import Config
    ScorePersistence(str(Config.DB_PATH))
    logger.info("✅ Phase 2-4 database tables initialized")

    # Initialize SOAR engine
    from backend.engine.soar import get_soar_engine
    get_soar_engine()
    logger.info("✅ SOAR engine initialized (dry_run=" + os.getenv('AEGIS_SOAR_DRY_RUN', 'true') + ")")

    # Initialize threat intel feed
    from backend.engine.threat_intel import get_threat_intel
    feed = get_threat_intel()
    logger.info(f"✅ Threat intel feed loaded ({feed.get_stats()['total_indicators']} indicators)")

    # Start async processing pipeline
    await start_pipeline()
    logger.info("✅ Async processing pipeline started")

    logger.info("🚀 AEGIS Active Attribution Engine v3.0 online and operational")

    yield

    # SHUTDOWN
    logger.info("🛑 AEGIS shutting down...")
    await stop_pipeline()
    logger.info("✅ Async pipeline stopped")


app = FastAPI(
    title="AEGIS Active Attribution Engine API",
    description="Enterprise-grade C2 detection with graph analytics, temporal fingerprinting, MITRE ATT&CK mapping, SOAR automation, and natural language querying",
    version="3.0.0",
    lifespan=lifespan
)

# ── Middleware Stack (order matters: outermost runs first) ──
# 1. Request tracing (correlation IDs, latency)
app.add_middleware(RequestTracingMiddleware)

# 2. ETag caching (Phase 2 — 304 Not Modified for unchanged data)
app.add_middleware(ETagCacheMiddleware)

# 3. Rate limiting (token bucket per IP)
app.add_middleware(RateLimitMiddleware)

# 4. RBAC (Phase 3 — JWT role-based access)
app.add_middleware(RBACMiddleware)

# 5. Authentication (API key — Phase 1 fallback)
app.add_middleware(APIKeyAuthMiddleware)

# 6. CORS
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
    expose_headers=["X-Request-ID", "X-Response-Time", "ETag"],
)

# ── Routes ──
# Legacy routes
app.include_router(router, prefix="/api")

# Attribution Engine routes (Phase 1)
app.include_router(graph_router, prefix="/api")

# Enterprise routes (Phase 2-4: metrics, MITRE, SOAR, cases, NLQ, threat intel)
app.include_router(enterprise_router)


@app.get("/")
def health_check():
    """Deep health check — verifies all engines are accessible."""
    from backend.engine.graph_engine import get_graph_engine
    from backend.engine.temporal_engine import get_temporal_engine
    from backend.engine.header_fingerprint import get_header_engine

    graph = get_graph_engine()
    temporal = get_temporal_engine()
    headers = get_header_engine()

    from backend.engine.soar import get_soar_engine
    from backend.engine.threat_intel import get_threat_intel
    soar = get_soar_engine()
    intel = get_threat_intel()

    return {
        "status": "AEGIS Active Attribution Engine is ONLINE",
        "version": "3.0.0",
        "capabilities": [
            "graph_analytics",
            "temporal_fingerprinting",
            "header_fingerprinting",
            "c2_attribution",
            "mitre_attack_mapping",
            "soar_automation",
            "case_management",
            "natural_language_query",
            "threat_intel_feeds",
        ],
        "engines": {
            "graph": {"nodes": len(graph.graph), "edges": graph.graph.number_of_edges()},
            "temporal": {"tracked_nodes": len(temporal._timestamps)},
            "headers": {"markov_trained": headers._markov.is_trained},
            "soar": soar.get_stats(),
            "threat_intel": intel.get_stats(),
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
