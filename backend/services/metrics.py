"""
AEGIS Phase 2 — Prometheus Metrics Endpoint

WHY THIS EXISTS:
----------------
Without metrics, you're flying blind in production.
This module exposes a /metrics endpoint in Prometheus text format,
enabling Grafana dashboards for:
  - Engine health (graph size, scoring latency)
  - API performance (request rates, error rates)
  - Attribution results (threat counts by level)
  - Ingestion pipeline status

NOTE: Uses a minimal hand-rolled exporter to avoid the
prometheus_client dependency. Upgrade to prometheus_client
when deploying with a real Prometheus server.
"""

import time
import logging
from typing import Dict, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Counter:
    """Prometheus-style counter (monotonically increasing)."""
    name: str
    help: str
    _value: float = 0.0
    labels: Dict[str, float] = field(default_factory=dict)

    def inc(self, amount: float = 1.0, label: str = ""):
        if label:
            self.labels[label] = self.labels.get(label, 0) + amount
        else:
            self._value += amount

    @property
    def value(self) -> float:
        return self._value

    def render(self) -> str:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} counter"]
        if self.labels:
            for lbl, val in self.labels.items():
                lines.append(f'{self.name}{{label="{lbl}"}} {val}')
        else:
            lines.append(f"{self.name} {self._value}")
        return "\n".join(lines)


@dataclass
class Gauge:
    """Prometheus-style gauge (can go up and down)."""
    name: str
    help: str
    _value: float = 0.0

    def set(self, value: float):
        self._value = value

    def inc(self, amount: float = 1.0):
        self._value += amount

    def dec(self, amount: float = 1.0):
        self._value -= amount

    @property
    def value(self) -> float:
        return self._value

    def render(self) -> str:
        return (
            f"# HELP {self.name} {self.help}\n"
            f"# TYPE {self.name} gauge\n"
            f"{self.name} {self._value}"
        )


@dataclass
class Histogram:
    """Simple histogram with predefined buckets."""
    name: str
    help: str
    buckets: tuple = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
    _observations: list = field(default_factory=list)
    _sum: float = 0.0
    _count: int = 0

    def observe(self, value: float):
        self._observations.append(value)
        self._sum += value
        self._count += 1
        # Keep bounded
        if len(self._observations) > 10000:
            self._observations = self._observations[-5000:]

    def render(self) -> str:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} histogram"]
        for b in self.buckets:
            count = sum(1 for o in self._observations if o <= b)
            lines.append(f'{self.name}_bucket{{le="{b}"}} {count}')
        lines.append(f'{self.name}_bucket{{le="+Inf"}} {self._count}')
        lines.append(f"{self.name}_sum {self._sum}")
        lines.append(f"{self.name}_count {self._count}")
        return "\n".join(lines)


class AEGISMetrics:
    """Central metrics registry for AEGIS."""

    def __init__(self):
        # API metrics
        self.http_requests_total = Counter(
            "aegis_http_requests_total",
            "Total HTTP requests processed",
        )
        self.http_errors_total = Counter(
            "aegis_http_errors_total",
            "Total HTTP error responses (4xx/5xx)",
        )
        self.http_request_duration = Histogram(
            "aegis_http_request_duration_seconds",
            "HTTP request duration in seconds",
        )

        # Engine metrics
        self.graph_nodes = Gauge(
            "aegis_graph_nodes_total",
            "Total nodes in the attribution graph",
        )
        self.graph_edges = Gauge(
            "aegis_graph_edges_total",
            "Total edges in the attribution graph",
        )
        self.temporal_tracked_nodes = Gauge(
            "aegis_temporal_tracked_nodes",
            "Nodes being tracked by temporal engine",
        )
        self.scoring_duration = Histogram(
            "aegis_scoring_duration_seconds",
            "Attribution scoring computation duration",
        )

        # Threat metrics
        self.threats_by_level = Counter(
            "aegis_threats_total",
            "Threats detected by level",
        )

        # Pipeline metrics
        self.ingestion_total = Counter(
            "aegis_ingestion_total",
            "Total telemetry records ingested",
        )
        self.pipeline_queue_size = Gauge(
            "aegis_pipeline_queue_size",
            "Current async pipeline queue depth",
        )

        # Score persistence
        self.scores_persisted = Counter(
            "aegis_scores_persisted_total",
            "Attribution scores saved to database",
        )

        # SOAR metrics
        self.soar_actions_total = Counter(
            "aegis_soar_actions_total",
            "Automated response actions executed",
        )
        self.soar_actions_by_type = Counter(
            "aegis_soar_actions_by_type",
            "SOAR actions by type",
        )

        self._start_time = time.time()

    def render_all(self) -> str:
        """Render all metrics in Prometheus text exposition format."""
        uptime = Gauge("aegis_uptime_seconds", "Time since engine start")
        uptime.set(time.time() - self._start_time)

        metrics = [
            self.http_requests_total,
            self.http_errors_total,
            self.http_request_duration,
            self.graph_nodes,
            self.graph_edges,
            self.temporal_tracked_nodes,
            self.scoring_duration,
            self.threats_by_level,
            self.ingestion_total,
            self.pipeline_queue_size,
            self.scores_persisted,
            self.soar_actions_total,
            self.soar_actions_by_type,
            uptime,
        ]
        return "\n\n".join(m.render() for m in metrics) + "\n"

    def collect_engine_stats(self):
        """Pull current stats from running engines."""
        try:
            from backend.engine.graph_engine import get_graph_engine
            from backend.engine.temporal_engine import get_temporal_engine

            graph = get_graph_engine()
            self.graph_nodes.set(len(graph.graph))
            self.graph_edges.set(graph.graph.number_of_edges())

            temporal = get_temporal_engine()
            self.temporal_tracked_nodes.set(len(temporal._timestamps))
        except Exception as e:
            logger.debug(f"Could not collect engine stats: {e}")


# Singleton
_metrics: Optional[AEGISMetrics] = None


def get_metrics() -> AEGISMetrics:
    global _metrics
    if _metrics is None:
        _metrics = AEGISMetrics()
    return _metrics
