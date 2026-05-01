"""
AEGIS — Attribution Scorer Test Suite
"""
import pytest
from backend.engine.attribution_scorer import AttributionScorer, get_attribution_scorer
from backend.engine.graph_engine import get_graph_engine, reset_graph_engine
from backend.engine.temporal_engine import get_temporal_engine, reset_temporal_engine
from backend.engine.header_fingerprint import get_header_engine, reset_header_engine


@pytest.fixture(autouse=True)
def reset_engines():
    """Reset all singletons between tests."""
    reset_graph_engine()
    reset_temporal_engine()
    reset_header_engine()
    yield
    reset_graph_engine()
    reset_temporal_engine()
    reset_header_engine()


@pytest.fixture
def scorer():
    return AttributionScorer()


@pytest.fixture
def populated_scorer(scorer):
    """Scorer with a node that has data in all engines."""
    graph = get_graph_engine()
    temporal = get_temporal_engine()
    header = get_header_engine()

    node_id = "192.168.1.100"

    # Feed graph engine — high out-degree
    for i in range(20):
        graph.add_interaction(node_id, f"/api/cmd/{i}", 1000.0 + i * 300,
                              metadata={"http_method": "POST"})

    # Feed temporal engine — fixed intervals (beacon)
    for i in range(50):
        temporal.record_request(node_id, float(i * 300))

    # Feed header engine — suspicious pattern
    header.analyze_request(node_id,
        {"user-agent": "python-requests/2.28.0", "accept-encoding": "gzip",
         "accept": "*/*", "connection": "keep-alive"},
        ["user-agent", "accept-encoding", "accept", "connection"])

    graph.compute_metrics(force=True)
    return scorer


class TestWeightConfiguration:
    def test_weights_sum_to_one(self, scorer):
        total = (scorer.WEIGHT_TIMING + scorer.WEIGHT_HEADER +
                 scorer.WEIGHT_GRAPH + scorer.WEIGHT_BEHAVIORAL +
                 scorer.WEIGHT_METHOD)
        assert abs(total - 1.0) < 0.001

    def test_timing_is_highest_weight(self, scorer):
        assert scorer.WEIGHT_TIMING >= scorer.WEIGHT_HEADER
        assert scorer.WEIGHT_TIMING >= scorer.WEIGHT_GRAPH


class TestScoring:
    def test_score_returns_result(self, populated_scorer):
        result = populated_scorer.score_node("192.168.1.100")
        assert result is not None
        assert 0 <= result.c2_confidence <= 100
        assert result.threat_level.value in ("low", "elevated", "high", "critical")

    def test_unknown_node_low_score(self, scorer):
        result = scorer.score_node("nonexistent-node")
        assert result.c2_confidence < 50

    def test_result_has_signals(self, populated_scorer):
        result = populated_scorer.score_node("192.168.1.100")
        assert len(result.signals) == 5
        for s in result.signals:
            assert hasattr(s, "name")
            assert hasattr(s, "weight")

    def test_score_all_nodes(self, populated_scorer):
        results = populated_scorer.score_all_nodes(min_score=0)
        assert len(results) > 0
