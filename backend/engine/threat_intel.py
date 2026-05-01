"""
AEGIS Phase 4 — Threat Intelligence Feed Integration

WHY THIS EXISTS:
----------------
AEGIS currently detects C2 based only on behavioral signals.
Threat Intel feeds add KNOWN indicators (IPs, domains, hashes)
from the global security community, enabling:
  1. Instant match against known C2 infrastructure
  2. Enrichment of attribution results with threat intel context
  3. Cross-referencing internal detections with public IOCs

SUPPORTED FEED FORMATS:
-----------------------
  - STIX 2.1 (Structured Threat Information Expression)
  - CSV IOC lists (IP, domain, hash)
  - Custom JSON feeds
"""

import json
import time
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ThreatIndicator:
    """A single threat intelligence indicator."""
    indicator: str          # The IOC value (IP, domain, hash)
    indicator_type: str     # 'ip', 'domain', 'hash', 'ua', 'url'
    source: str             # Feed name
    threat_type: str        # 'c2', 'malware', 'phishing', 'scanner'
    confidence: float       # 0.0-1.0
    first_seen: float
    last_seen: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


class ThreatIntelFeed:
    """
    In-memory threat intelligence store.

    In production, back this with the threat_intel SQLite table
    and schedule periodic feed pulls via cron/Celery.
    """

    def __init__(self):
        self._indicators: Dict[str, ThreatIndicator] = {}
        self._last_update = 0.0

        # Pre-load with known C2 infrastructure patterns
        self._load_builtin_indicators()

    def _load_builtin_indicators(self):
        """Load built-in C2 indicators (example dataset)."""
        known_c2_patterns = [
            ("python-requests/", "ua", "c2", 0.7, ["cobalt-strike", "python"]),
            ("curl/", "ua", "scanner", 0.5, ["scanner", "recon"]),
            ("Go-http-client/", "ua", "c2", 0.6, ["golang-implant"]),
            ("Java/", "ua", "c2", 0.5, ["java-rat"]),
            ("Wget/", "ua", "scanner", 0.4, ["wget", "download"]),
            ("PowerShell/", "ua", "c2", 0.8, ["powershell-empire"]),
        ]

        now = time.time()
        for pattern, itype, threat, conf, tags in known_c2_patterns:
            self.add_indicator(ThreatIndicator(
                indicator=pattern,
                indicator_type=itype,
                source="aegis-builtin",
                threat_type=threat,
                confidence=conf,
                first_seen=now,
                last_seen=now,
                tags=tags,
            ))

    def add_indicator(self, indicator: ThreatIndicator):
        """Add or update a threat indicator."""
        key = f"{indicator.indicator_type}:{indicator.indicator}"
        existing = self._indicators.get(key)
        if existing:
            # Update: keep earliest first_seen, update last_seen
            indicator.first_seen = min(existing.first_seen, indicator.first_seen)
            indicator.confidence = max(existing.confidence, indicator.confidence)
        self._indicators[key] = indicator

    def check_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """Check if an IP matches any threat indicator."""
        return self._indicators.get(f"ip:{ip}")

    def check_ua(self, user_agent: str) -> List[ThreatIndicator]:
        """Check if a User-Agent matches known malicious patterns."""
        matches = []
        for key, ind in self._indicators.items():
            if ind.indicator_type == "ua" and ind.indicator in user_agent:
                matches.append(ind)
        return matches

    def check_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """Check if a domain matches any threat indicator."""
        return self._indicators.get(f"domain:{domain}")

    def enrich_attribution(self, node_id: str, user_agent: str = "",
                           headers: dict = None) -> Dict[str, Any]:
        """
        Enrich an attribution result with threat intel context.

        Returns additional evidence from threat intel matching.
        """
        enrichments = {
            "ip_match": None,
            "ua_matches": [],
            "threat_intel_score_boost": 0.0,
            "tags": [],
            "sources": [],
        }

        # Check IP against known C2 infrastructure
        ip_match = self.check_ip(node_id)
        if ip_match:
            enrichments["ip_match"] = {
                "source": ip_match.source,
                "threat_type": ip_match.threat_type,
                "confidence": ip_match.confidence,
                "tags": ip_match.tags,
            }
            enrichments["threat_intel_score_boost"] += ip_match.confidence * 15
            enrichments["tags"].extend(ip_match.tags)
            enrichments["sources"].append(ip_match.source)

        # Check User-Agent
        if user_agent:
            ua_matches = self.check_ua(user_agent)
            for match in ua_matches:
                enrichments["ua_matches"].append({
                    "pattern": match.indicator,
                    "threat_type": match.threat_type,
                    "confidence": match.confidence,
                    "tags": match.tags,
                })
                enrichments["threat_intel_score_boost"] += match.confidence * 5
                enrichments["tags"].extend(match.tags)
                enrichments["sources"].append(match.source)

        # Deduplicate
        enrichments["tags"] = list(set(enrichments["tags"]))
        enrichments["sources"] = list(set(enrichments["sources"]))

        return enrichments

    def ingest_stix_bundle(self, bundle: dict) -> int:
        """Ingest a STIX 2.1 bundle of indicators."""
        count = 0
        objects = bundle.get("objects", [])
        now = time.time()

        for obj in objects:
            if obj.get("type") != "indicator":
                continue

            pattern = obj.get("pattern", "")
            name = obj.get("name", "")

            # Parse STIX pattern (simplified)
            indicator_value = ""
            indicator_type = "unknown"
            if "ipv4-addr" in pattern:
                indicator_type = "ip"
                indicator_value = pattern.split("'")[1] if "'" in pattern else ""
            elif "domain-name" in pattern:
                indicator_type = "domain"
                indicator_value = pattern.split("'")[1] if "'" in pattern else ""

            if indicator_value:
                self.add_indicator(ThreatIndicator(
                    indicator=indicator_value,
                    indicator_type=indicator_type,
                    source=obj.get("created_by_ref", "stix-feed"),
                    threat_type="c2",
                    confidence=float(obj.get("confidence", 50)) / 100,
                    first_seen=now,
                    last_seen=now,
                    metadata={"stix_id": obj.get("id", "")},
                ))
                count += 1

        self._last_update = now
        logger.info(f"Ingested {count} indicators from STIX bundle")
        return count

    def get_stats(self) -> dict:
        by_type = {}
        for ind in self._indicators.values():
            by_type[ind.indicator_type] = by_type.get(ind.indicator_type, 0) + 1

        return {
            "total_indicators": len(self._indicators),
            "by_type": by_type,
            "last_update": self._last_update,
            "sources": list(set(i.source for i in self._indicators.values())),
        }


# Singleton
_feed: Optional[ThreatIntelFeed] = None


def get_threat_intel() -> ThreatIntelFeed:
    global _feed
    if _feed is None:
        _feed = ThreatIntelFeed()
    return _feed
