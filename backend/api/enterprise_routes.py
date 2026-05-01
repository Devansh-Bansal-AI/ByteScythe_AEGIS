"""
AEGIS Phase 2–4 — Enterprise API Routes

New endpoints:
  Phase 2: /metrics, /v1/graph/scores/history
  Phase 3: /v1/mitre/*, /auth/token
  Phase 4: /v1/soar/*, /v1/cases/*, /v1/nlq, /v1/threat-intel/*
"""

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from typing import Optional
import time
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


# ═══════════════════════════════════════
#  PHASE 2: Metrics + Score Persistence
# ═══════════════════════════════════════

@router.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics():
    """Prometheus metrics endpoint."""
    from backend.services.metrics import get_metrics
    metrics = get_metrics()
    metrics.collect_engine_stats()
    return metrics.render_all()


@router.get("/api/v1/graph/scores/history/{node_id}")
def get_score_history(node_id: str, limit: int = Query(50, le=500)):
    """Get historical attribution scores for a node."""
    from backend.db.score_persistence import ScorePersistence
    from backend.config import Config
    persistence = ScorePersistence(str(Config.DB_PATH))
    scores = persistence.get_historical_scores(node_id, limit=limit)
    return {"node_id": node_id, "history": scores, "count": len(scores)}


@router.get("/api/v1/graph/scores/latest")
def get_latest_scores(min_confidence: float = Query(0, ge=0, le=100),
                      limit: int = Query(100, le=1000)):
    """Get latest persisted scores, filtered by confidence."""
    from backend.db.score_persistence import ScorePersistence
    from backend.config import Config
    persistence = ScorePersistence(str(Config.DB_PATH))
    scores = persistence.get_latest_scores(min_confidence, limit)
    return {"scores": scores, "count": len(scores)}


# ═══════════════════════════════════════
#  PHASE 3: MITRE ATT&CK + Auth
# ═══════════════════════════════════════

@router.get("/api/v1/mitre/techniques")
def list_mitre_techniques():
    """List all MITRE ATT&CK techniques in the catalog."""
    from backend.engine.mitre_mapper import get_mitre_mapper
    mapper = get_mitre_mapper()
    return {"techniques": mapper.get_all_techniques(), "count": len(mapper._catalog)}


@router.get("/api/v1/mitre/map/{node_id}")
def map_node_to_mitre(node_id: str):
    """Map a specific node's attribution signals to MITRE ATT&CK TTPs."""
    from backend.engine.attribution_scorer import get_attribution_scorer
    from backend.engine.mitre_mapper import get_mitre_mapper

    scorer = get_attribution_scorer()
    result = scorer.score_node(node_id)
    result_dict = result.to_dict()

    mapper = get_mitre_mapper()
    ttps = mapper.map_attribution(result_dict)
    narrative = mapper.get_attack_narrative(ttps)

    return {
        "node_id": node_id,
        "c2_confidence": result.c2_confidence,
        "mitre_ttps": ttps,
        "ttp_count": len(ttps),
        "attack_narrative": narrative,
    }


@router.post("/api/v1/auth/token")
def create_auth_token(request: Request):
    """Create a JWT token (admin only, for development/testing)."""
    from backend.middleware.rbac import create_jwt, JWT_SECRET
    import json

    if not JWT_SECRET:
        raise HTTPException(400, "AEGIS_JWT_SECRET not configured")

    try:
        # In production, validate credentials against user store
        body = {"sub": "dev@aegis.local", "role": "admin", "org": "default"}
        token = create_jwt(body["sub"], body["role"], body["org"])
        return {"token": token, "type": "Bearer", "expires_in": "24h"}
    except Exception as e:
        raise HTTPException(500, str(e))


# ═══════════════════════════════════════
#  PHASE 4: SOAR + Cases + NLQ + Intel
# ═══════════════════════════════════════

@router.post("/api/v1/soar/evaluate/{node_id}")
def soar_evaluate_node(node_id: str):
    """Trigger SOAR evaluation for a specific node."""
    from backend.engine.attribution_scorer import get_attribution_scorer
    from backend.engine.mitre_mapper import get_mitre_mapper
    from backend.engine.soar import get_soar_engine

    scorer = get_attribution_scorer()
    result = scorer.score_node(node_id)
    result_dict = result.to_dict()

    mapper = get_mitre_mapper()
    ttps = mapper.map_attribution(result_dict)

    soar = get_soar_engine()
    actions = soar.evaluate_node(
        node_id=node_id,
        confidence=result.c2_confidence,
        threat_level=result.threat_level.value,
        signals=result_dict.get("signals", []),
        mitre_ttps=ttps,
    )

    return {
        "node_id": node_id,
        "confidence": result.c2_confidence,
        "actions_taken": len(actions),
        "actions": [
            {
                "action_id": a.action_id,
                "type": a.action_type.value,
                "status": a.status.value,
                "result": a.result,
            }
            for a in actions
        ],
    }


@router.get("/api/v1/soar/actions")
def list_soar_actions(node_id: Optional[str] = None,
                      limit: int = Query(50, le=500)):
    """List SOAR actions, optionally filtered by node."""
    from backend.engine.soar import get_soar_engine
    soar = get_soar_engine()
    return {"actions": soar.get_actions(node_id, limit)}


@router.get("/api/v1/soar/stats")
def soar_stats():
    """Get SOAR engine statistics."""
    from backend.engine.soar import get_soar_engine
    return get_soar_engine().get_stats()


# ─── Case Management ───

@router.get("/api/v1/cases")
def list_cases(status: Optional[str] = None):
    """List investigation cases."""
    from backend.engine.soar import get_soar_engine
    soar = get_soar_engine()
    cases = soar.list_cases(status)
    return {"cases": cases, "count": len(cases)}


@router.get("/api/v1/cases/{case_id}")
def get_case(case_id: str):
    """Get a specific case by ID."""
    from backend.engine.soar import get_soar_engine
    soar = get_soar_engine()
    case = soar.get_case(case_id)
    if not case:
        raise HTTPException(404, f"Case {case_id} not found")
    return case.to_dict()


@router.patch("/api/v1/cases/{case_id}")
def update_case(case_id: str, updates: dict):
    """Update a case (assign, change priority, add notes)."""
    from backend.engine.soar import get_soar_engine
    soar = get_soar_engine()
    case = soar.update_case(case_id, updates)
    if not case:
        raise HTTPException(404, f"Case {case_id} not found")
    return case.to_dict()


@router.post("/api/v1/cases/{case_id}/close")
def close_case(case_id: str):
    """Close a case."""
    from backend.engine.soar import get_soar_engine
    soar = get_soar_engine()
    case = soar.close_case(case_id)
    if not case:
        raise HTTPException(404, f"Case {case_id} not found")
    return {"message": f"Case {case_id} closed", "case": case.to_dict()}


# ─── Natural Language Query ───

@router.post("/api/v1/nlq")
async def natural_language_query(request: Request):
    """Execute a natural language query against the AEGIS engine."""
    from backend.engine.nlq import get_nlq_engine

    body = await request.json()
    query = body.get("query", "")

    if not query:
        raise HTTPException(400, "Missing 'query' field")

    nlq = get_nlq_engine()
    parsed = nlq.parse(query)
    result = await nlq.execute(query)

    return {
        "query": query,
        "parsed_intent": parsed["intent"],
        "confidence": parsed["confidence"],
        "result": result,
    }


# ─── Threat Intelligence ───

@router.get("/api/v1/threat-intel/stats")
def threat_intel_stats():
    """Get threat intelligence feed statistics."""
    from backend.engine.threat_intel import get_threat_intel
    return get_threat_intel().get_stats()


@router.get("/api/v1/threat-intel/enrich/{node_id}")
def enrich_node(node_id: str, user_agent: str = ""):
    """Enrich a node with threat intelligence context."""
    from backend.engine.threat_intel import get_threat_intel
    feed = get_threat_intel()
    return feed.enrich_attribution(node_id, user_agent)


@router.post("/api/v1/threat-intel/ingest/stix")
async def ingest_stix(request: Request):
    """Ingest a STIX 2.1 bundle of indicators."""
    from backend.engine.threat_intel import get_threat_intel
    body = await request.json()
    feed = get_threat_intel()
    count = feed.ingest_stix_bundle(body)
    return {"message": f"Ingested {count} indicators", "count": count}
