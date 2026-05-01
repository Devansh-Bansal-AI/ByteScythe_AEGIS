"""
AEGIS — Header Fingerprinting Test Suite
"""
import pytest
from backend.engine.header_fingerprint import (
    HeaderFingerprintEngine, MarkovTransitionMatrix,
    KNOWN_BROWSER_FINGERPRINTS, SUSPICIOUS_PATTERNS,
)

@pytest.fixture
def engine():
    return HeaderFingerprintEngine()

@pytest.fixture
def trained_markov():
    m = MarkovTransitionMatrix()
    m.train_from_known_browsers()
    return m

class TestHeaderHashing:
    def test_same_order_same_hash(self, engine):
        h1 = engine._hash_header_order(["Host", "User-Agent"])
        h2 = engine._hash_header_order(["Host", "User-Agent"])
        assert h1 == h2

    def test_different_order_different_hash(self, engine):
        h1 = engine._hash_header_order(["Host", "User-Agent"])
        h2 = engine._hash_header_order(["User-Agent", "Host"])
        assert h1 != h2

    def test_case_insensitive(self, engine):
        h1 = engine._hash_header_order(["host"])
        h2 = engine._hash_header_order(["Host"])
        assert h1 == h2

class TestPatternDetection:
    def test_chrome_detected(self, engine):
        fp = engine.analyze_request("n1",
            {h: "" for h in KNOWN_BROWSER_FINGERPRINTS["chrome_standard"]},
            KNOWN_BROWSER_FINGERPRINTS["chrome_standard"])
        assert fp.is_browser is True

    def test_python_requests_suspicious(self, engine):
        hdrs = {h: "" for h in SUSPICIOUS_PATTERNS["python_requests"]}
        hdrs["user-agent"] = "python-requests/2.28.0"
        fp = engine.analyze_request("n2", hdrs, SUSPICIOUS_PATTERNS["python_requests"])
        assert fp.is_suspicious is True

class TestMarkov:
    def test_trained(self, trained_markov):
        assert trained_markov.is_trained
        assert len(trained_markov.get_matrix_snapshot()) > 0

    def test_browser_sequence_scores_high(self, trained_markov):
        s = trained_markov.score_sequence(KNOWN_BROWSER_FINGERPRINTS["chrome_standard"])
        assert s > 0.0

    def test_empty_returns_one(self, trained_markov):
        assert trained_markov.score_sequence([]) == 1.0

class TestNodeProfile:
    def test_profile_created(self, engine):
        engine.analyze_request("p1", {"host": "x"}, ["host"])
        p = engine.get_node_profile("p1")
        assert p is not None
        assert p.total_requests == 1

    def test_stats(self, engine):
        engine.analyze_request("s1",
            {h: "" for h in KNOWN_BROWSER_FINGERPRINTS["chrome_standard"]},
            KNOWN_BROWSER_FINGERPRINTS["chrome_standard"])
        stats = engine.get_fingerprint_stats()
        assert stats["total_nodes"] >= 1
