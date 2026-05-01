"""
AEGIS Attribution Engine — Temporal Fingerprinting Test Suite

Tests:
1. Inter-arrival time computation
2. Beacon detection (pure beacon, jittered, shadow controller)
3. Shannon entropy computation
4. Shadow controller composite scoring
5. Coordinated beaconing detection
6. Visualization data export
"""

import pytest
import numpy as np
from backend.engine.temporal_engine import TemporalFingerprintEngine


@pytest.fixture
def engine():
    return TemporalFingerprintEngine()


class TestTimestampRecording:
    """Test basic timestamp ingestion."""

    def test_record_first_request(self, engine):
        delta = engine.record_request("node-1", 1000.0)
        assert delta is None  # No delta for first request

    def test_record_second_request_returns_delta(self, engine):
        engine.record_request("node-1", 1000.0)
        delta = engine.record_request("node-1", 1300.0)
        assert delta == 300.0

    def test_memory_bound(self, engine):
        for i in range(1500):
            engine.record_request("node-1", float(i))
        assert len(engine._timestamps["node-1"]) == 1000


class TestDeltaComputation:
    """Test inter-arrival time calculation."""

    def test_empty_deltas(self, engine):
        deltas = engine.compute_deltas("nonexistent")
        assert len(deltas) == 0

    def test_single_request_no_deltas(self, engine):
        engine.record_request("node-1", 1000.0)
        deltas = engine.compute_deltas("node-1")
        assert len(deltas) == 0

    def test_correct_deltas(self, engine):
        for t in [1000, 1300, 1600, 1900]:
            engine.record_request("node-1", float(t))
        deltas = engine.compute_deltas("node-1")
        np.testing.assert_array_equal(deltas, [300, 300, 300])


class TestShannonEntropy:
    """Test Shannon entropy computation on timing intervals."""

    def test_perfect_beacon_low_entropy(self):
        """Perfectly uniform intervals should have near-zero entropy."""
        deltas = np.array([300.0] * 100)
        raw, normalized = TemporalFingerprintEngine.compute_timing_entropy(deltas)
        assert normalized < 0.3

    def test_random_traffic_high_entropy(self):
        """Random intervals should have high entropy."""
        rng = np.random.default_rng(42)
        deltas = rng.exponential(scale=500, size=100)
        raw, normalized = TemporalFingerprintEngine.compute_timing_entropy(deltas)
        assert normalized > 0.5

    def test_insufficient_data(self):
        deltas = np.array([300.0, 300.0])
        raw, normalized = TemporalFingerprintEngine.compute_timing_entropy(deltas)
        assert raw == 0.0
        assert normalized == 0.0


class TestShadowControllerScore:
    """Test shadow controller composite scoring."""

    def test_perfect_shadow_controller(self):
        """Moderate jitter + medium entropy + high consistency = high score."""
        score = TemporalFingerprintEngine.compute_shadow_controller_score(
            jitter=0.15,
            entropy_normalized=0.45,
            interval_consistency=0.6,
        )
        assert score > 0.7

    def test_human_traffic_low_score(self):
        """High jitter + high entropy = low shadow score."""
        score = TemporalFingerprintEngine.compute_shadow_controller_score(
            jitter=0.8,
            entropy_normalized=0.9,
            interval_consistency=0.1,
        )
        assert score < 0.3

    def test_pure_beacon_moderate_score(self):
        """Zero jitter + zero entropy — pure beacon, not shadow controller."""
        score = TemporalFingerprintEngine.compute_shadow_controller_score(
            jitter=0.01,
            entropy_normalized=0.05,
            interval_consistency=0.95,
        )
        # Shadow controller detection is for JITTERED beacons, not pure ones
        assert score < 0.7


class TestBeaconDetection:
    """Test full beacon analysis pipeline."""

    def test_pure_beacon_detected(self, engine):
        """Fixed 300ms intervals should be classified as beacon."""
        for i in range(50):
            engine.record_request("beacon-node", float(i * 300))
        profile = engine.analyze_node("beacon-node")
        assert profile is not None
        assert profile.is_beacon is True
        assert profile.pattern_type in ("beacon", "jittered_beacon")
        assert profile.beacon_score > 0.5

    def test_human_traffic_not_beacon(self, engine):
        """Random intervals should NOT be classified as beacon."""
        rng = np.random.default_rng(42)
        t = 0.0
        for _ in range(50):
            t += rng.exponential(scale=5000)
            engine.record_request("human-node", t)
        profile = engine.analyze_node("human-node")
        assert profile is not None
        assert profile.is_beacon is False
        assert profile.pattern_type == "human"

    def test_jittered_beacon(self, engine):
        """300ms ± 10% jitter should be detected."""
        rng = np.random.default_rng(42)
        t = 0.0
        for _ in range(50):
            t += 300 + rng.uniform(-30, 30)  # 300ms ± 10%
            engine.record_request("jitter-node", t)
        profile = engine.analyze_node("jitter-node")
        assert profile is not None
        assert profile.beacon_score > 0.4

    def test_insufficient_data_returns_none(self, engine):
        engine.record_request("short-node", 1000.0)
        engine.record_request("short-node", 2000.0)
        profile = engine.analyze_node("short-node")
        assert profile is None


class TestCoordinatedBeaconing:
    """Test synchronized beacon cluster detection."""

    def test_synchronized_beacons(self, engine):
        """Multiple nodes beaconing at the same instant → coordinated."""
        for t in range(10):
            base_time = float(t * 1000)
            engine.record_request("bot-1", base_time)
            engine.record_request("bot-2", base_time + 10)
            engine.record_request("bot-3", base_time + 20)
        clusters = engine.detect_coordinated_beaconing(time_window_ms=100)
        assert len(clusters) > 0
        assert any(c["node_count"] >= 2 for c in clusters)

    def test_no_coordination_in_random_traffic(self, engine):
        """Random traffic shouldn't form coordination clusters."""
        rng = np.random.default_rng(42)
        for _ in range(20):
            engine.record_request("random-1", rng.uniform(0, 100000))
            engine.record_request("random-2", rng.uniform(0, 100000))
        clusters = engine.detect_coordinated_beaconing(time_window_ms=50)
        # May find some by chance, but should be very few
        assert len(clusters) <= 5


class TestVisualizationExport:
    """Test timing data export for scatter plots."""

    def test_export_contains_points(self, engine):
        for i in range(20):
            engine.record_request("vis-node", float(i * 500))
        data = engine.get_timing_data_for_visualization()
        assert "points" in data
        assert "profiles" in data
        assert len(data["points"]) > 0

    def test_export_max_points(self, engine):
        for i in range(100):
            engine.record_request("vis-node", float(i * 100))
        data = engine.get_timing_data_for_visualization(max_points=10)
        assert len(data["points"]) <= 10

    def test_export_node_filter(self, engine):
        for i in range(20):
            engine.record_request("node-a", float(i * 500))
            engine.record_request("node-b", float(i * 700))
        data = engine.get_timing_data_for_visualization(node_id="node-a")
        assert all(p["node"] == "node-a" for p in data["points"])
