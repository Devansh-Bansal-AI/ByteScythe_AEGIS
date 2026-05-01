"""SQLite database connection and initialization for AEGIS Active Attribution Engine."""

import sqlite3
import os
from pathlib import Path

# Support both `python -m backend.db.database` and direct execution
try:
    from backend.config import Config
    from backend.db.models import ALL_TABLES, ALL_INDEXES
except ImportError:
    import config as _cfg
    Config = _cfg.Config
    from db.models import ALL_TABLES, ALL_INDEXES


def get_db() -> sqlite3.Connection:
    """Returns a new SQLite connection with Row factory for dict-like access."""
    conn = sqlite3.connect(str(Config.DB_PATH))
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for concurrent reads during heavy writes
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    """Creates all tables and indexes if they don't already exist."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Create tables
    for ddl in ALL_TABLES:
        cursor.execute(ddl)

    # Migration: Add legacy column if needed
    try:
        cursor.execute("ALTER TABLE node_registry ADD COLUMN is_quarantined INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    # Migration: Add attribution engine columns to existing tables
    attribution_columns = [
        ("telemetry_logs", "timestamp", "REAL"),
        ("telemetry_logs", "time_delta_ms", "REAL"),
        ("telemetry_logs", "source_ip", "TEXT"),
        ("telemetry_logs", "target_endpoint", "TEXT"),
        ("telemetry_logs", "user_agent", "TEXT"),
        ("telemetry_logs", "header_order", "TEXT"),
        ("telemetry_logs", "header_hash", "TEXT"),
        ("telemetry_logs", "c2_confidence", "REAL DEFAULT 0"),
        ("telemetry_logs", "beacon_score", "REAL DEFAULT 0"),
        ("telemetry_logs", "graph_anomaly_score", "REAL DEFAULT 0"),
        ("telemetry_logs", "header_anomaly_score", "REAL DEFAULT 0"),
    ]
    
    for table, column, coltype in attribution_columns:
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
        except sqlite3.OperationalError:
            pass  # Column already exists
    
    # Create indexes AFTER columns are added
    for idx_ddl in ALL_INDEXES:
        for statement in idx_ddl.strip().split(';'):
            if statement.strip():
                try:
                    cursor.execute(statement)
                except sqlite3.OperationalError:
                    pass  # Index already exists or column doesn't exist

    conn.commit()
    conn.close()
