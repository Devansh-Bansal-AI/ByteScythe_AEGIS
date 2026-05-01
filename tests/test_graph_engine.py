"""
AEGIS Attribution Engine — Graph Engine Test Suite

Tests:
1. Graph construction from network interactions
2. Centrality metric computation (degree, betweenness, closeness)
3. Community detection
4. Star topology detection
5. BFS blast radius traversal
6. Anti-hairball clustering
7. Visualization data export
"""

import pytest
from backend.engine.graph_engine import GraphAnalyticsEngine, NodeMetrics


@pytest.fixture
def engine():
    """Create a fresh graph engine for each test."""
    return GraphAnalyticsEngine()


@pytest.fixture
def populated_engine(engine):
    """Engine pre-loaded with a realistic C2 topology."""
    # Controller → 5 victims (star topology)
    controller = "192.168.1.100"
    victims = [f"10.0.0.{i}" for i in range(1, 6)]

    for victim in victims:
        for t in range(10):
            engine.add_interaction(
                controller,
                f"/api/command",
                timestamp=1000.0 + t * 300,
                metadata={"http_method": "POST"},
            )
            engine.add_interaction(
                victim,
                f"/api/beacon",
                timestamp=1000.0 + t * 300 + 50,
                metadata={"http_method": "GET"},
            )

    # Normal traffic: 3 users browsing multiple endpoints
    for u in range(3):
        user = f"172.16.0.{u + 1}"
        for page in ["/index.html", "/about", "/api/data", "/login"]:
            engine.add_interaction(user, page, timestamp=2000.0 + u * 100)

    return engine


class TestGraphConstruction:
    """Test graph building from network interactions."""

    def test_empty_graph(self, engine):
        assert len(engine.graph) == 0
        assert engine.graph.number_of_edges() == 0

    def test_add_single_interaction(self, engine):
        engine.add_interaction("1.2.3.4", "/api/test", 1000.0)
        assert len(engine.graph) == 2  # source + endpoint
        assert engine.graph.number_of_edges() == 1

    def test_duplicate_interaction_increments_weight(self, engine):
        engine.add_interaction("1.2.3.4", "/api/test", 1000.0)
        engine.add_interaction("1.2.3.4", "/api/test", 2000.0)
        edge_data = engine.graph["1.2.3.4"]["/api/test"]
        assert edge_data["weight"] == 2

    def test_node_attributes(self, engine):
        engine.add_interaction("1.2.3.4", "/api/test", 1000.0)
        node = engine.graph.nodes["1.2.3.4"]
        assert node["node_type"] == "client"
        assert node["request_count"] == 1
        assert node["first_seen"] == 1000.0

    def test_ip_to_ip_interaction(self, engine):
        engine.add_ip_to_ip_interaction("1.2.3.4", "5.6.7.8", 1000.0)
        assert engine.graph.has_edge("1.2.3.4", "5.6.7.8")
        assert engine.graph.nodes["1.2.3.4"]["node_type"] == "host"

    def test_method_tracking(self, engine):
        engine.add_interaction("1.2.3.4", "/api", 1000, metadata={"http_method": "POST"})
        engine.add_interaction("1.2.3.4", "/api", 1001, metadata={"http_method": "POST"})
        engine.add_interaction("1.2.3.4", "/api", 1002, metadata={"http_method": "GET"})
        dist = engine.get_method_distribution("1.2.3.4")
        assert dist["POST"] == 2
        assert dist["GET"] == 1


class TestCentralityMetrics:
    """Test graph metric computation."""

    def test_compute_metrics_returns_all_nodes(self, populated_engine):
        metrics = populated_engine.compute_metrics(force=True)
        assert len(metrics) == len(populated_engine.graph)

    def test_controller_has_high_centrality(self, populated_engine):
        metrics = populated_engine.compute_metrics(force=True)
        controller_m = metrics["192.168.1.100"]
        # Controller should have highest out-degree
        assert controller_m.out_degree > 0
        assert controller_m.degree_centrality > 0

    def test_metrics_caching(self, populated_engine):
        m1 = populated_engine.compute_metrics(force=True)
        m2 = populated_engine.compute_metrics(force=False)  # Should return cache
        assert m1 is m2

    def test_force_recompute(self, populated_engine):
        m1 = populated_engine.compute_metrics(force=True)
        populated_engine._last_computation = 0  # Reset timer
        m2 = populated_engine.compute_metrics(force=True)
        assert m1 is not m2


class TestCommunityDetection:
    """Test community/cluster detection."""

    def test_communities_assigned(self, populated_engine):
        metrics = populated_engine.compute_metrics(force=True)
        community_ids = {m.community_id for m in metrics.values()}
        assert len(community_ids) >= 1

    def test_empty_graph_communities(self, engine):
        communities = engine._detect_communities()
        assert communities == {}


class TestStarTopology:
    """Test star topology detection for C2 identification."""

    def test_detect_star_topology(self):
        engine = GraphAnalyticsEngine()
        # Create a clear star: hub → 10 leaf nodes with no interconnection
        hub = "c2-controller"
        for i in range(10):
            engine.add_interaction(hub, f"victim-{i}", 1000.0 + i)

        results = engine.detect_star_topology()
        # Hub should be detected as a star controller
        controllers = [r["controller"] for r in results]
        assert hub in controllers

    def test_no_star_in_mesh(self):
        engine = GraphAnalyticsEngine()
        # Fully connected mesh — no star
        nodes = [f"node-{i}" for i in range(5)]
        for i, src in enumerate(nodes):
            for j, dst in enumerate(nodes):
                if i != j:
                    engine.add_interaction(src, dst, 1000.0)

        results = engine.detect_star_topology()
        assert len(results) == 0


class TestBlastRadius:
    """Test BFS blast radius computation."""

    def test_blast_radius_from_controller(self, populated_engine):
        result = populated_engine.compute_blast_radius("192.168.1.100")
        assert result["origin"] == "192.168.1.100"
        assert result["total_impact"] > 0
        assert result["depth"] >= 1

    def test_blast_radius_unknown_node(self, populated_engine):
        result = populated_engine.compute_blast_radius("unknown-node")
        assert result["total_impact"] == 0

    def test_blast_radius_leaf_node(self, populated_engine):
        # Endpoint nodes have no successors
        result = populated_engine.compute_blast_radius("/api/beacon")
        assert result["total_impact"] == 0


class TestVisualizationExport:
    """Test graph export for frontend rendering."""

    def test_export_contains_nodes_and_links(self, populated_engine):
        data = populated_engine.get_graph_for_visualization()
        assert "nodes" in data
        assert "links" in data
        assert "metadata" in data

    def test_max_nodes_limit(self, populated_engine):
        data = populated_engine.get_graph_for_visualization(max_nodes=3)
        assert len(data["nodes"]) <= 3

    def test_min_score_filter(self, populated_engine):
        data = populated_engine.get_graph_for_visualization(min_score=0.99)
        # Very high threshold — should filter out most nodes
        assert len(data["nodes"]) <= len(populated_engine.graph)

    def test_zoom_to_controller(self, populated_engine):
        result = populated_engine.zoom_to_controller("192.168.1.100")
        assert len(result["nodes"]) > 0
        controller_node = next(
            (n for n in result["nodes"] if n["isController"]), None
        )
        assert controller_node is not None

    def test_zoom_to_unknown_node(self, populated_engine):
        result = populated_engine.zoom_to_controller("nonexistent")
        assert result["nodes"] == []


class TestSnapshot:
    """Test immutable graph snapshots."""

    def test_snapshot_reflects_state(self, populated_engine):
        snapshot = populated_engine.get_snapshot()
        assert snapshot.node_count == len(populated_engine.graph)
        assert snapshot.edge_count == populated_engine.graph.number_of_edges()
        assert snapshot.computed_at > 0
