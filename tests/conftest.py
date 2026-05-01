"""
Pytest configuration and fixtures for AEGIS test suite.
"""

import pytest
import sqlite3
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from backend.main import app
from backend.db.database import get_db, init_db
from backend.config import DB_PATH


@pytest.fixture(scope="function")
def test_db():
    """Create a temporary test database for each test."""
    # Create a temporary database file
    temp_db = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.db')
    temp_db_path = Path(temp_db.name)
    temp_db.close()

    # Override the database path
    original_db_path = DB_PATH
    import backend.config
    backend.config.DB_PATH = temp_db_path
    backend.config.Config.DB_PATH = temp_db_path

    # Initialize the test database
    init_db()

    # Seed with test data
    conn = sqlite3.connect(str(temp_db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Insert test nodes
    cursor.executemany(
        "INSERT INTO node_registry (node_uuid, hardware_serial, is_infected, is_quarantined) VALUES (?, ?, ?, ?)",
        [
            (1, "SN-TEST-001", "NO", 0),
            (2, "SN-TEST-002", "YES", 0),
            (3, "SN-TEST-003", "YES", 1),  # Already quarantined
        ]
    )

    # Insert test telemetry
    cursor.executemany(
        """INSERT INTO telemetry_logs
        (log_id, node_id, json_status, http_response_code, response_time_ms,
         system_load, hardware_serial, is_infected, flag_spoofed, flag_ddos,
         flag_malware, threat_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (1, 1, "OPERATIONAL", 200, 45.2, 0.3, "SN-TEST-001", "NO", 0, 0, 0, 0),
            (2, 2, "OPERATIONAL", 500, 250.5, 0.8, "SN-TEST-002", "YES", 1, 0, 1, 2),
            (3, 3, "OPERATIONAL", 503, 300.0, 0.9, "SN-TEST-003", "YES", 1, 1, 1, 3),
        ]
    )

    conn.commit()
    conn.close()

    yield temp_db_path

    # Cleanup
    backend.config.DB_PATH = original_db_path
    backend.config.Config.DB_PATH = original_db_path
    temp_db_path.unlink(missing_ok=True)


@pytest.fixture(scope="function")
def client(test_db):
    """Create a test client for the FastAPI app."""
    return TestClient(app)


@pytest.fixture(scope="function")
def db_connection(test_db):
    """Provide a database connection for direct queries."""
    conn = sqlite3.connect(str(test_db))
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()
