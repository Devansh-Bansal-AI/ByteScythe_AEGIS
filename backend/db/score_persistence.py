"""
AEGIS Phase 2 — Attribution Score Persistence Layer

WHY THIS EXISTS:
----------------
Attribution scores are currently computed on-the-fly and lost on restart.
This module periodically flushes scores to SQLite, enabling:
  1. Historical trend analysis ("Was this node suspicious last week?")
  2. Survival across restarts (no cold-start scoring gap)
  3. Audit trail for forensic investigations
"""

import sqlite3
import time
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# New table for persisted attribution scores
ATTRIBUTION_SCORES_TABLE = """
CREATE TABLE IF NOT EXISTS attribution_scores (
    node_id             TEXT NOT NULL,
    c2_confidence       REAL NOT NULL,
    threat_level        TEXT NOT NULL,
    timing_score        REAL DEFAULT 0,
    header_score        REAL DEFAULT 0,
    graph_score         REAL DEFAULT 0,
    behavioral_score    REAL DEFAULT 0,
    method_ratio_score  REAL DEFAULT 0,
    data_quality        REAL DEFAULT 1.0,
    primary_indicators  TEXT,            -- JSON array
    recommended_actions TEXT,            -- JSON array
    computed_at         REAL NOT NULL,
    PRIMARY KEY (node_id, computed_at)
);
"""

ATTRIBUTION_SCORES_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_attr_node ON attribution_scores(node_id);
CREATE INDEX IF NOT EXISTS idx_attr_confidence ON attribution_scores(c2_confidence);
CREATE INDEX IF NOT EXISTS idx_attr_level ON attribution_scores(threat_level);
CREATE INDEX IF NOT EXISTS idx_attr_time ON attribution_scores(computed_at);
"""

# Case management table for Phase 4
CASES_TABLE = """
CREATE TABLE IF NOT EXISTS cases (
    case_id             TEXT PRIMARY KEY,
    title               TEXT NOT NULL,
    status              TEXT DEFAULT 'open',
    priority            TEXT DEFAULT 'medium',
    assignee            TEXT,
    node_ids            TEXT,            -- JSON array of related nodes
    description         TEXT,
    evidence            TEXT,            -- JSON: collected evidence artifacts
    mitre_ttps          TEXT,            -- JSON array of MITRE ATT&CK TTPs
    soar_actions        TEXT,            -- JSON array of automated actions taken
    created_at          REAL NOT NULL,
    updated_at          REAL NOT NULL,
    closed_at           REAL
);
"""

CASES_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_priority ON cases(priority);
"""

# SOAR action log
SOAR_ACTIONS_TABLE = """
CREATE TABLE IF NOT EXISTS soar_actions (
    action_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id             TEXT,
    node_id             TEXT NOT NULL,
    action_type         TEXT NOT NULL,
    action_detail       TEXT,            -- JSON payload
    status              TEXT DEFAULT 'pending',
    triggered_by        TEXT DEFAULT 'system',
    confidence_at_trigger REAL,
    executed_at         REAL,
    result              TEXT
);
"""

SOAR_ACTIONS_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_soar_node ON soar_actions(node_id);
CREATE INDEX IF NOT EXISTS idx_soar_case ON soar_actions(case_id);
"""

# Threat intel feed cache
THREAT_INTEL_TABLE = """
CREATE TABLE IF NOT EXISTS threat_intel (
    indicator           TEXT PRIMARY KEY,
    indicator_type      TEXT NOT NULL,    -- 'ip', 'domain', 'hash', 'ua'
    source              TEXT,
    threat_type         TEXT,
    confidence          REAL DEFAULT 0,
    first_seen          REAL,
    last_seen           REAL,
    metadata            TEXT             -- JSON
);
"""


NEW_TABLES = [
    ATTRIBUTION_SCORES_TABLE,
    CASES_TABLE,
    SOAR_ACTIONS_TABLE,
    THREAT_INTEL_TABLE,
]

NEW_INDEXES = [
    ATTRIBUTION_SCORES_INDEXES,
    CASES_INDEXES,
    SOAR_ACTIONS_INDEXES,
]


class ScorePersistence:
    """Manages persisting and querying attribution scores."""

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._ensure_tables()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _ensure_tables(self):
        conn = self._get_conn()
        for ddl in NEW_TABLES:
            conn.execute(ddl)
        for idx_block in NEW_INDEXES:
            for stmt in idx_block.strip().split(';'):
                if stmt.strip():
                    try:
                        conn.execute(stmt)
                    except sqlite3.OperationalError:
                        pass
        conn.commit()
        conn.close()

    def persist_scores(self, results: List[Dict[str, Any]]) -> int:
        """Batch-insert attribution results. Returns count of rows inserted."""
        import json
        conn = self._get_conn()
        count = 0
        for r in results:
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO attribution_scores
                    (node_id, c2_confidence, threat_level,
                     timing_score, header_score, graph_score,
                     behavioral_score, method_ratio_score,
                     data_quality, primary_indicators,
                     recommended_actions, computed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        r.get("node_id", ""),
                        r.get("c2_confidence", 0),
                        r.get("threat_level", "low"),
                        r.get("signals", [{}])[0].get("raw_score", 0) if r.get("signals") else 0,
                        r.get("signals", [{}, {}])[1].get("raw_score", 0) if len(r.get("signals", [])) > 1 else 0,
                        r.get("signals", [{}, {}, {}])[2].get("raw_score", 0) if len(r.get("signals", [])) > 2 else 0,
                        r.get("signals", [{}, {}, {}, {}])[3].get("raw_score", 0) if len(r.get("signals", [])) > 3 else 0,
                        r.get("signals", [{}, {}, {}, {}, {}])[4].get("raw_score", 0) if len(r.get("signals", [])) > 4 else 0,
                        r.get("data_quality", 1.0),
                        json.dumps(r.get("primary_indicators", [])),
                        json.dumps(r.get("recommended_actions", [])),
                        r.get("computed_at", time.time()),
                    ),
                )
                count += 1
            except Exception as e:
                logger.error(f"Failed to persist score for {r.get('node_id')}: {e}")
        conn.commit()
        conn.close()
        logger.info(f"Persisted {count} attribution scores to database")
        return count

    def get_historical_scores(
        self, node_id: str, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Retrieve historical scores for a node, newest first."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT * FROM attribution_scores
            WHERE node_id = ? ORDER BY computed_at DESC LIMIT ?""",
            (node_id, limit),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_latest_scores(
        self, min_confidence: float = 0, limit: int = 500
    ) -> List[Dict[str, Any]]:
        """Get the latest score for each node, filtered by confidence."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT a.* FROM attribution_scores a
            INNER JOIN (
                SELECT node_id, MAX(computed_at) as max_time
                FROM attribution_scores
                GROUP BY node_id
            ) b ON a.node_id = b.node_id AND a.computed_at = b.max_time
            WHERE a.c2_confidence >= ?
            ORDER BY a.c2_confidence DESC
            LIMIT ?""",
            (min_confidence, limit),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
