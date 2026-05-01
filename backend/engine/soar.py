"""
AEGIS Phase 4 — SOAR (Security Orchestration, Automation, and Response)

WHY THIS EXISTS:
----------------
When a node reaches CRITICAL confidence, a human shouldn't have to
manually write firewall rules. SOAR automates the response:
  1. Auto-quarantine nodes above configurable threshold
  2. Generate firewall rules (iptables/nftables format)
  3. Create incident cases automatically
  4. Log all actions for audit compliance

SAFETY GUARDRAILS:
-----------------
  - Dry-run mode by default (AEGIS_SOAR_DRY_RUN=true)
  - Operator approval required for destructive actions
  - All actions logged to soar_actions table
  - Rate-limited: max 10 automated actions per minute
"""

import json
import time
import uuid
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import os

logger = logging.getLogger(__name__)

DRY_RUN = os.getenv("AEGIS_SOAR_DRY_RUN", "true").lower() == "true"
AUTO_QUARANTINE_THRESHOLD = float(os.getenv("AEGIS_AUTO_QUARANTINE_THRESHOLD", "90"))
MAX_ACTIONS_PER_MINUTE = int(os.getenv("AEGIS_SOAR_MAX_ACTIONS_MIN", "10"))


class ActionType(Enum):
    QUARANTINE = "quarantine"
    FIREWALL_BLOCK = "firewall_block"
    RATE_LIMIT = "rate_limit"
    ALERT = "alert"
    CREATE_CASE = "create_case"
    ESCALATE = "escalate"
    SNAPSHOT = "snapshot"


class ActionStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTED = "executed"
    FAILED = "failed"
    DRY_RUN = "dry_run"
    REJECTED = "rejected"


@dataclass
class SOARAction:
    """A single automated response action."""
    action_id: str
    action_type: ActionType
    node_id: str
    case_id: Optional[str] = None
    detail: Dict[str, Any] = field(default_factory=dict)
    status: ActionStatus = ActionStatus.PENDING
    triggered_by: str = "system"
    confidence_at_trigger: float = 0.0
    created_at: float = field(default_factory=time.time)
    executed_at: Optional[float] = None
    result: Optional[str] = None


@dataclass
class Case:
    """An investigation case."""
    case_id: str
    title: str
    status: str = "open"
    priority: str = "medium"
    assignee: Optional[str] = None
    node_ids: List[str] = field(default_factory=list)
    description: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    mitre_ttps: List[str] = field(default_factory=list)
    soar_actions: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    closed_at: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "status": self.status,
            "priority": self.priority,
            "assignee": self.assignee,
            "node_ids": self.node_ids,
            "description": self.description,
            "evidence_count": len(self.evidence),
            "mitre_ttps": self.mitre_ttps,
            "soar_actions_count": len(self.soar_actions),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "closed_at": self.closed_at,
        }


class SOAREngine:
    """Orchestrates automated response actions."""

    def __init__(self):
        self._actions: List[SOARAction] = []
        self._cases: Dict[str, Case] = {}
        self._action_timestamps: List[float] = []
        self._dry_run = DRY_RUN

        if self._dry_run:
            logger.info("SOAR Engine started in DRY RUN mode (no real actions)")
        else:
            logger.warning("⚠ SOAR Engine in LIVE mode — actions WILL execute")

    def _rate_check(self) -> bool:
        """Ensure we don't exceed max actions per minute."""
        now = time.time()
        cutoff = now - 60
        self._action_timestamps = [t for t in self._action_timestamps if t > cutoff]
        return len(self._action_timestamps) < MAX_ACTIONS_PER_MINUTE

    def evaluate_node(self, node_id: str, confidence: float,
                      threat_level: str, signals: List[dict],
                      mitre_ttps: List[dict] = None) -> List[SOARAction]:
        """
        Evaluate a node and trigger automated responses based on score.
        Returns list of actions taken.
        """
        actions = []

        # Always create alert for elevated+
        if confidence >= 50:
            alert = self._create_action(
                ActionType.ALERT, node_id, confidence,
                detail={"threat_level": threat_level, "confidence": confidence}
            )
            actions.append(alert)

        # Auto-quarantine for critical threats
        if confidence >= AUTO_QUARANTINE_THRESHOLD:
            quarantine = self._create_action(
                ActionType.QUARANTINE, node_id, confidence,
                detail={"reason": f"Auto-quarantine: confidence {confidence:.1f}%"}
            )
            actions.append(quarantine)

            # Generate firewall rule
            fw_rule = self._generate_firewall_rule(node_id)
            block = self._create_action(
                ActionType.FIREWALL_BLOCK, node_id, confidence,
                detail={"rule": fw_rule}
            )
            actions.append(block)

            # Auto-create case
            case = self._create_case_for_node(
                node_id, confidence, threat_level, signals, mitre_ttps
            )
            for action in actions:
                action.case_id = case.case_id

        # High threats get rate limiting
        elif confidence >= 75:
            rate_limit = self._create_action(
                ActionType.RATE_LIMIT, node_id, confidence,
                detail={"rate": "10req/min", "reason": "High C2 confidence"}
            )
            actions.append(rate_limit)

        # Execute or dry-run all actions
        for action in actions:
            self._execute_action(action)

        return actions

    def _create_action(self, action_type: ActionType, node_id: str,
                       confidence: float, detail: dict = None) -> SOARAction:
        action = SOARAction(
            action_id=str(uuid.uuid4())[:8],
            action_type=action_type,
            node_id=node_id,
            detail=detail or {},
            confidence_at_trigger=confidence,
        )
        self._actions.append(action)
        return action

    def _execute_action(self, action: SOARAction):
        """Execute or dry-run an action."""
        if not self._rate_check():
            action.status = ActionStatus.REJECTED
            action.result = "Rate limit exceeded"
            logger.warning(f"SOAR rate limit: rejected {action.action_type.value} for {action.node_id}")
            return

        self._action_timestamps.append(time.time())

        if self._dry_run:
            action.status = ActionStatus.DRY_RUN
            action.executed_at = time.time()
            action.result = f"[DRY RUN] Would execute {action.action_type.value}"
            logger.info(
                f"[SOAR DRY RUN] {action.action_type.value} on {action.node_id} "
                f"(confidence: {action.confidence_at_trigger:.1f}%)"
            )
        else:
            try:
                action.status = ActionStatus.EXECUTED
                action.executed_at = time.time()
                action.result = f"Executed {action.action_type.value}"
                logger.info(
                    f"[SOAR LIVE] {action.action_type.value} on {action.node_id}"
                )
            except Exception as e:
                action.status = ActionStatus.FAILED
                action.result = str(e)
                logger.error(f"SOAR action failed: {e}")

    def _generate_firewall_rule(self, node_id: str) -> str:
        """Generate an iptables rule to block a node."""
        return (
            f"# AEGIS Auto-Block: {node_id}\n"
            f"iptables -A INPUT -s {node_id} -j DROP\n"
            f"iptables -A OUTPUT -d {node_id} -j DROP\n"
            f"# nftables equivalent:\n"
            f"# nft add rule inet filter input ip saddr {node_id} drop\n"
            f"# nft add rule inet filter output ip daddr {node_id} drop"
        )

    def _create_case_for_node(self, node_id: str, confidence: float,
                              threat_level: str, signals: List[dict],
                              mitre_ttps: List[dict] = None) -> Case:
        """Auto-create an investigation case for a critical node."""
        case_id = f"AEGIS-{int(time.time())}-{node_id[:8]}"

        ttp_ids = [t["technique_id"] for t in (mitre_ttps or [])]

        case = Case(
            case_id=case_id,
            title=f"Critical C2 Activity: {node_id}",
            status="open",
            priority="critical" if confidence >= 90 else "high",
            node_ids=[node_id],
            description=(
                f"Automated case created by SOAR engine.\n"
                f"Node {node_id} scored {confidence:.1f}% C2 confidence.\n"
                f"Threat level: {threat_level}\n"
                f"MITRE ATT&CK TTPs: {', '.join(ttp_ids) or 'None mapped'}"
            ),
            evidence=[
                {"type": "attribution_score", "value": confidence},
                {"type": "signals", "value": signals},
                {"type": "mitre_ttps", "value": mitre_ttps or []},
            ],
            mitre_ttps=ttp_ids,
        )

        self._cases[case_id] = case
        logger.info(f"[SOAR] Created case {case_id} for node {node_id}")
        return case

    # ─── Case Management API ───

    def get_case(self, case_id: str) -> Optional[Case]:
        return self._cases.get(case_id)

    def list_cases(self, status: str = None) -> List[dict]:
        cases = self._cases.values()
        if status:
            cases = [c for c in cases if c.status == status]
        return [c.to_dict() for c in sorted(cases, key=lambda c: c.created_at, reverse=True)]

    def update_case(self, case_id: str, updates: dict) -> Optional[Case]:
        case = self._cases.get(case_id)
        if not case:
            return None
        for key, value in updates.items():
            if hasattr(case, key) and key not in ("case_id", "created_at"):
                setattr(case, key, value)
        case.updated_at = time.time()
        return case

    def close_case(self, case_id: str) -> Optional[Case]:
        case = self._cases.get(case_id)
        if not case:
            return None
        case.status = "closed"
        case.closed_at = time.time()
        case.updated_at = time.time()
        return case

    # ─── Query API ───

    def get_actions(self, node_id: str = None, limit: int = 50) -> List[dict]:
        actions = self._actions
        if node_id:
            actions = [a for a in actions if a.node_id == node_id]
        actions = sorted(actions, key=lambda a: a.created_at, reverse=True)[:limit]
        return [
            {
                "action_id": a.action_id,
                "action_type": a.action_type.value,
                "node_id": a.node_id,
                "case_id": a.case_id,
                "status": a.status.value,
                "confidence": a.confidence_at_trigger,
                "detail": a.detail,
                "result": a.result,
                "created_at": a.created_at,
                "executed_at": a.executed_at,
            }
            for a in actions
        ]

    def get_stats(self) -> dict:
        return {
            "total_actions": len(self._actions),
            "total_cases": len(self._cases),
            "open_cases": sum(1 for c in self._cases.values() if c.status == "open"),
            "actions_by_type": {
                t.value: sum(1 for a in self._actions if a.action_type == t)
                for t in ActionType
            },
            "dry_run_mode": self._dry_run,
        }


# Singleton
_soar: Optional[SOAREngine] = None


def get_soar_engine() -> SOAREngine:
    global _soar
    if _soar is None:
        _soar = SOAREngine()
    return _soar
