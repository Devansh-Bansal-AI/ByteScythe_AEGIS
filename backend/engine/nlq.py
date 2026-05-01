"""
AEGIS Phase 4 — Natural Language Query Engine

WHY THIS EXISTS:
----------------
SOC analysts shouldn't need to learn API parameters.
"Show me all beaconing nodes from the last 24 hours" should just work.

IMPLEMENTATION:
--------------
Pattern-matching NLQ parser that translates natural language queries
into structured API calls. This is a rule-based system — upgrade to
LLM-powered NLQ when OpenAI/Gemini API integration is added.
"""

import re
import time
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class NLQueryEngine:
    """Translates natural language queries into AEGIS API parameters."""

    # Query patterns → structured intent
    PATTERNS = [
        # Threat queries
        (r"(?:show|list|find|get)\s+(?:all\s+)?(?:critical|high)\s+threats?",
         "threats", {"min_score": 75}),
        (r"(?:show|list|find|get)\s+(?:all\s+)?threats?\s+(?:above|over|>\s*)(\d+)",
         "threats", {"min_score_from_match": 1}),
        (r"(?:show|list|find|get)\s+(?:all\s+)?beaconing\s+nodes?",
         "beacons", {}),
        (r"(?:show|list|find|get)\s+(?:all\s+)?shadow\s+controllers?",
         "shadow_controllers", {}),
        (r"(?:show|list|find|get)\s+(?:all\s+)?star\s+topolog(?:y|ies)",
         "star_topologies", {}),
        (r"(?:show|list|find|get)\s+(?:all\s+)?communities",
         "communities", {}),

        # Time-scoped queries
        (r"(?:from|in|during)\s+(?:the\s+)?last\s+(\d+)\s+hours?",
         "time_filter", {"hours_from_match": 1}),
        (r"(?:from|in|during)\s+(?:the\s+)?last\s+(\d+)\s+minutes?",
         "time_filter", {"minutes_from_match": 1}),
        (r"(?:from|in|during)\s+(?:the\s+)?last\s+(\d+)\s+days?",
         "time_filter", {"days_from_match": 1}),

        # Node-specific queries
        (r"(?:inspect|details?|info)\s+(?:for\s+)?(?:node\s+)?(\d+\.\d+\.\d+\.\d+)",
         "node_details", {"node_id_from_match": 1}),
        (r"blast\s+radius\s+(?:for\s+)?(?:node\s+)?(\d+\.\d+\.\d+\.\d+)",
         "blast_radius", {"node_id_from_match": 1}),
        (r"(?:quarantine|isolate)\s+(?:node\s+)?(\d+\.\d+\.\d+\.\d+)",
         "quarantine", {"node_id_from_match": 1}),

        # Status queries
        (r"(?:system|engine|pipeline)\s+status",
         "status", {}),
        (r"(?:how\s+many|count)\s+(?:active\s+)?threats?",
         "threat_count", {}),
        (r"summary|overview|dashboard",
         "summary", {}),

        # MITRE queries
        (r"(?:mitre|att&ck|ttp)\s+(?:mapping|techniques?)",
         "mitre_catalog", {}),
        (r"(?:show|list)\s+(?:all\s+)?cases?",
         "cases", {}),

        # SOAR queries
        (r"(?:show|list)\s+(?:all\s+)?(?:soar\s+)?actions?",
         "soar_actions", {}),
    ]

    def parse(self, query: str) -> Dict[str, Any]:
        """
        Parse a natural language query into a structured intent.

        Returns:
            {
                "intent": "threats" | "beacons" | "node_details" | ...,
                "params": {...},
                "raw_query": "...",
                "confidence": 0.0-1.0
            }
        """
        query_lower = query.lower().strip()

        for pattern, intent, base_params in self.PATTERNS:
            match = re.search(pattern, query_lower)
            if match:
                params = dict(base_params)

                # Extract dynamic values from regex groups
                for key, group_idx in list(params.items()):
                    if key.endswith("_from_match"):
                        real_key = key.replace("_from_match", "")
                        try:
                            params[real_key] = match.group(group_idx)
                        except (IndexError, AttributeError):
                            pass
                        del params[key]

                # Apply time filters if present
                time_match = re.search(
                    r"last\s+(\d+)\s+(hour|minute|day)s?", query_lower
                )
                if time_match:
                    amount = int(time_match.group(1))
                    unit = time_match.group(2)
                    multiplier = {"hour": 3600, "minute": 60, "day": 86400}
                    params["since"] = time.time() - amount * multiplier.get(unit, 3600)

                return {
                    "intent": intent,
                    "params": params,
                    "raw_query": query,
                    "confidence": 0.85,
                    "matched_pattern": pattern,
                }

        # No pattern matched
        return {
            "intent": "unknown",
            "params": {},
            "raw_query": query,
            "confidence": 0.0,
            "suggestion": self._suggest_query(query_lower),
        }

    def _suggest_query(self, query: str) -> str:
        """Suggest a valid query when parsing fails."""
        suggestions = [
            "show all critical threats",
            "show beaconing nodes",
            "show shadow controllers",
            "system status",
            "show threats above 60",
            "inspect node 192.168.1.100",
            "blast radius for 10.0.0.1",
            "show all cases",
            "mitre techniques",
        ]
        return f"Try: '{suggestions[hash(query) % len(suggestions)]}'"

    async def execute(self, query: str) -> Dict[str, Any]:
        """Parse and execute a natural language query."""
        parsed = self.parse(query)
        intent = parsed["intent"]
        params = parsed["params"]

        try:
            if intent == "threats":
                from backend.engine.attribution_scorer import get_attribution_scorer
                scorer = get_attribution_scorer()
                min_score = float(params.get("min_score", 50))
                results = scorer.score_all_nodes(min_score=min_score)
                return {"type": "threats", "data": results, "count": len(results)}

            elif intent == "beacons":
                from backend.engine.temporal_engine import get_temporal_engine
                engine = get_temporal_engine()
                data = engine.get_timing_data_for_visualization()
                beacons = [p for p in data.get("profiles", []) if p.get("is_beacon")]
                return {"type": "beacons", "data": beacons, "count": len(beacons)}

            elif intent == "shadow_controllers":
                from backend.engine.temporal_engine import get_temporal_engine
                engine = get_temporal_engine()
                controllers = engine.detect_shadow_controllers()
                return {"type": "shadow_controllers", "data": controllers, "count": len(controllers)}

            elif intent == "summary":
                from backend.engine.attribution_scorer import get_attribution_scorer
                scorer = get_attribution_scorer()
                summary = scorer.get_threat_summary()
                return {"type": "summary", "data": summary}

            elif intent == "node_details":
                node_id = params.get("node_id", "")
                from backend.engine.attribution_scorer import get_attribution_scorer
                scorer = get_attribution_scorer()
                result = scorer.score_node(node_id)
                return {"type": "node_details", "data": result.to_dict() if result else None}

            elif intent == "mitre_catalog":
                from backend.engine.mitre_mapper import get_mitre_mapper
                mapper = get_mitre_mapper()
                return {"type": "mitre_catalog", "data": mapper.get_all_techniques()}

            elif intent == "cases":
                from backend.engine.soar import get_soar_engine
                soar = get_soar_engine()
                return {"type": "cases", "data": soar.list_cases()}

            elif intent == "soar_actions":
                from backend.engine.soar import get_soar_engine
                soar = get_soar_engine()
                return {"type": "soar_actions", "data": soar.get_actions()}

            elif intent == "status":
                from backend.engine.graph_engine import get_graph_engine
                from backend.engine.temporal_engine import get_temporal_engine
                graph = get_graph_engine()
                temporal = get_temporal_engine()
                return {
                    "type": "status",
                    "data": {
                        "graph_nodes": len(graph.graph),
                        "graph_edges": graph.graph.number_of_edges(),
                        "temporal_tracked": len(temporal._timestamps),
                    }
                }

            else:
                return {
                    "type": "error",
                    "message": f"Could not understand query: '{query}'",
                    "suggestion": parsed.get("suggestion", ""),
                }

        except Exception as e:
            logger.error(f"NLQ execution error: {e}")
            return {"type": "error", "message": str(e)}


# Singleton
_nlq: Optional[NLQueryEngine] = None


def get_nlq_engine() -> NLQueryEngine:
    global _nlq
    if _nlq is None:
        _nlq = NLQueryEngine()
    return _nlq
