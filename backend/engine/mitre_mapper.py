"""
AEGIS Phase 3 — MITRE ATT&CK TTP Mapping Engine

WHY THIS EXISTS:
----------------
Attribution scores are meaningless to SOC analysts without context.
MITRE ATT&CK mapping translates detection signals into standardized
Tactics, Techniques, and Procedures (TTPs) that analysts already know.

Example: "beacon_score=0.92" becomes "T1071.001 - Application Layer Protocol: Web"

This enables:
  1. Standardized incident reports
  2. Threat intelligence sharing (STIX/TAXII compatible)
  3. Attack pattern correlation across organizations
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MITRETechnique:
    """A single MITRE ATT&CK technique."""
    id: str             # e.g., "T1071.001"
    name: str           # e.g., "Application Layer Protocol: Web Protocols"
    tactic: str         # e.g., "Command and Control"
    description: str
    detection_signal: str  # Which AEGIS signal triggers this
    confidence_threshold: float  # Minimum score to map


# MITRE ATT&CK Techniques relevant to C2 detection
C2_TTP_CATALOG: List[MITRETechnique] = [
    # === Command and Control Tactic ===
    MITRETechnique(
        id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
        description="Adversaries use HTTP/HTTPS to communicate with C2, blending with normal web traffic.",
        detection_signal="temporal",
        confidence_threshold=0.3,
    ),
    MITRETechnique(
        id="T1573.002",
        name="Encrypted Channel: Asymmetric Cryptography",
        tactic="Command and Control",
        description="C2 communications encrypted with TLS to evade content inspection.",
        detection_signal="header",
        confidence_threshold=0.5,
    ),
    MITRETechnique(
        id="T1095",
        name="Non-Application Layer Protocol",
        tactic="Command and Control",
        description="C2 using non-standard protocols or ports to evade detection.",
        detection_signal="graph",
        confidence_threshold=0.6,
    ),
    MITRETechnique(
        id="T1571",
        name="Non-Standard Port",
        tactic="Command and Control",
        description="C2 communication over uncommon ports to bypass firewalls.",
        detection_signal="behavioral",
        confidence_threshold=0.5,
    ),
    MITRETechnique(
        id="T1132.001",
        name="Data Encoding: Standard Encoding",
        tactic="Command and Control",
        description="C2 payloads encoded in Base64 or similar to evade inspection.",
        detection_signal="header",
        confidence_threshold=0.4,
    ),
    MITRETechnique(
        id="T1001.001",
        name="Data Obfuscation: Junk Data",
        tactic="Command and Control",
        description="Adding junk data to C2 communications to evade pattern matching.",
        detection_signal="temporal",
        confidence_threshold=0.5,
    ),
    MITRETechnique(
        id="T1568.002",
        name="Dynamic Resolution: Domain Generation Algorithms",
        tactic="Command and Control",
        description="Using algorithmically generated domains for C2 resilience.",
        detection_signal="graph",
        confidence_threshold=0.7,
    ),
    MITRETechnique(
        id="T1090.001",
        name="Proxy: Internal Proxy",
        tactic="Command and Control",
        description="Using compromised internal hosts as C2 relays.",
        detection_signal="graph",
        confidence_threshold=0.6,
    ),

    # === Discovery Tactic ===
    MITRETechnique(
        id="T1046",
        name="Network Service Discovery",
        tactic="Discovery",
        description="Scanning for services to expand attack surface.",
        detection_signal="behavioral",
        confidence_threshold=0.4,
    ),

    # === Lateral Movement Tactic ===
    MITRETechnique(
        id="T1021",
        name="Remote Services",
        tactic="Lateral Movement",
        description="Using legitimate remote services for lateral movement.",
        detection_signal="graph",
        confidence_threshold=0.5,
    ),

    # === Exfiltration Tactic ===
    MITRETechnique(
        id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        description="Data exfiltrated over the existing C2 communication channel.",
        detection_signal="method_ratio",
        confidence_threshold=0.6,
    ),

    # === Collection Tactic ===
    MITRETechnique(
        id="T1119",
        name="Automated Collection",
        tactic="Collection",
        description="Automated scripts collecting data at regular intervals.",
        detection_signal="temporal",
        confidence_threshold=0.7,
    ),
]


class MITREMapper:
    """Maps AEGIS attribution signals to MITRE ATT&CK TTPs."""

    def __init__(self):
        self._catalog = C2_TTP_CATALOG
        # Index by detection signal for fast lookup
        self._by_signal: Dict[str, List[MITRETechnique]] = {}
        for tech in self._catalog:
            self._by_signal.setdefault(tech.detection_signal, []).append(tech)

    def map_attribution(self, attribution_result: dict) -> List[dict]:
        """
        Given an attribution result with signals, return matching MITRE TTPs.

        Returns list of {technique_id, name, tactic, confidence, description}
        """
        mapped = []
        signals = attribution_result.get("signals", [])

        for signal in signals:
            signal_name = signal.get("name", "")
            raw_score = signal.get("raw_score", 0)

            candidates = self._by_signal.get(signal_name, [])
            for tech in candidates:
                if raw_score >= tech.confidence_threshold:
                    mapped.append({
                        "technique_id": tech.id,
                        "name": tech.name,
                        "tactic": tech.tactic,
                        "confidence": min(raw_score, 1.0),
                        "description": tech.description,
                        "detection_signal": signal_name,
                        "signal_score": raw_score,
                    })

        # Deduplicate by technique_id (keep highest confidence)
        seen = {}
        for m in mapped:
            tid = m["technique_id"]
            if tid not in seen or m["confidence"] > seen[tid]["confidence"]:
                seen[tid] = m

        result = sorted(seen.values(), key=lambda x: x["confidence"], reverse=True)
        return result

    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Lookup a specific technique by ID."""
        for tech in self._catalog:
            if tech.id == technique_id:
                return tech
        return None

    def get_all_techniques(self) -> List[dict]:
        """Return the full TTP catalog."""
        return [
            {
                "id": t.id,
                "name": t.name,
                "tactic": t.tactic,
                "description": t.description,
                "detection_signal": t.detection_signal,
                "confidence_threshold": t.confidence_threshold,
            }
            for t in self._catalog
        ]

    def get_attack_narrative(self, mapped_ttps: List[dict]) -> str:
        """Generate a human-readable attack narrative from mapped TTPs."""
        if not mapped_ttps:
            return "No MITRE ATT&CK techniques matched for this node."

        tactics = {}
        for ttp in mapped_ttps:
            tactics.setdefault(ttp["tactic"], []).append(ttp)

        narrative_parts = ["## Attack Chain Analysis\n"]
        tactic_order = [
            "Discovery", "Collection", "Lateral Movement",
            "Command and Control", "Exfiltration",
        ]

        for tactic in tactic_order:
            if tactic in tactics:
                narrative_parts.append(f"### {tactic}")
                for t in tactics[tactic]:
                    conf_pct = int(t["confidence"] * 100)
                    narrative_parts.append(
                        f"- **{t['technique_id']}** {t['name']} "
                        f"(confidence: {conf_pct}%)"
                    )
                narrative_parts.append("")

        return "\n".join(narrative_parts)


# Singleton
_mapper: Optional[MITREMapper] = None


def get_mitre_mapper() -> MITREMapper:
    global _mapper
    if _mapper is None:
        _mapper = MITREMapper()
    return _mapper
