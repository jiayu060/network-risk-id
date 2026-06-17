"""Graph Rare Path Mining anomaly detector.

Builds a communication graph from normalized logs and identifies rare
communication paths as anomalies. Key insight: attack chains traverse
unusual edges in the communication graph.
"""

import math
from collections import defaultdict
from typing import Optional

import numpy as np

from src.detectors.base import AnomalyDetector


class GraphRarePathDetector(AnomalyDetector):
    """Detects anomalies by finding rare paths in the communication graph."""

    def __init__(self, min_path_length: int = 2, max_path_length: int = 5,
                 rarity_percentile: float = 95, **kwargs):
        super().__init__(name="graph_rare_path", weight=kwargs.pop("weight", 1.5))
        self.min_path_length = min_path_length
        self.max_path_length = max_path_length
        self.rarity_percentile = rarity_percentile
        # Internal graph representation
        self._graph: dict = {}  # node -> list[(neighbor, edge_type, count)]
        self._edge_counts: dict = {}  # (src, dst, edge_type) -> count
        self._total_edges: int = 0
        self._node_rarity: dict = {}  # node -> aggregated rarity score
        self._baseline_edge_probs: dict = {}  # baseline probabilities

    def fit(self, X: np.ndarray) -> AnomalyDetector:
        # GraphRarePath is primarily fit from the graph structure,
        # not from feature vectors directly. The fit from features
        # is a no-op; the real "fit" happens when building the graph.
        self._fitted = True
        return self

    def build_graph(self, records: list[dict]) -> "GraphRarePathDetector":
        """Build communication graph from list of normalized log records."""
        self._graph = defaultdict(list)
        self._edge_counts = defaultdict(int)
        self._total_edges = 0

        for r in records:
            src = r.get("src_ip") or "unknown"
            dst = r.get("dst_ip")
            if not dst:
                continue
            edge_type = r.get("event_type", "unknown")
            edge_key = (src, dst, edge_type)
            self._edge_counts[edge_key] += 1
            self._total_edges += 1

        # Build adjacency list
        for (src, dst, etype), count in self._edge_counts.items():
            self._graph.setdefault(src, []).append((dst, etype, count))
            # Ensure all nodes exist
            self._graph.setdefault(dst, [])

        # Precompute baseline edge probabilities
        for key, count in self._edge_counts.items():
            self._baseline_edge_probs[key] = count / max(self._total_edges, 1)

        return self

    def fit_from_graph(self, graph_data: dict) -> AnomalyDetector:
        """Fit the rarity model from graph data."""
        self._graph = graph_data.get("graph", {})
        self._edge_counts = graph_data.get("edge_counts", {})
        self._total_edges = graph_data.get("total_edges", 1)
        self._baseline_edge_probs = graph_data.get("baseline_edge_probs", {})
        self._fitted = True
        return self

    def score_nodes(self) -> dict[str, float]:
        """Compute per-node anomaly scores based on rare path participation."""
        if not self._graph:
            return {}

        node_scores = {}
        all_paths = self._find_rare_paths()

        # Aggregate: nodes appearing in rare paths get higher scores
        path_score_map = defaultdict(list)
        for path, path_score in all_paths:
            for node in path:
                path_score_map[node].append(path_score)

        for node, scores in path_score_map.items():
            # Average of top-K path scores for this node
            top_scores = sorted(scores, reverse=True)[:10]
            node_scores[node] = sum(top_scores) / len(top_scores) if top_scores else 0.0

        # Nodes with no rare paths get 0
        for node in self._graph:
            if node not in node_scores:
                node_scores[node] = 0.0

        self._node_rarity = node_scores
        return node_scores

    def _find_rare_paths(self) -> list[tuple[tuple, float]]:
        """BFS-based rare path discovery in the communication graph."""
        rare_paths = []
        all_scores = []

        # Only explore from anomalous seed nodes (high-degree or suspicious)
        seeds = self._get_anomalous_seeds()

        for seed in seeds:
            paths = self._bfs_paths(seed)
            for path, score in paths:
                all_scores.append((path, score))

        if not all_scores:
            return []

        # Keep paths above rarity_percentile
        scores = [s for _, s in all_scores]
        threshold = np.percentile(scores, self.rarity_percentile) if scores else 0

        for path, score in all_scores:
            if score >= threshold:
                rare_paths.append((path, score))

        return rare_paths

    def _get_anomalous_seeds(self) -> list:
        """Select seed nodes for rare path exploration."""
        seeds = []
        for node, edges in self._graph.items():
            degree = len(edges)
            # Seeds: nodes with unusual connectivity (not too low, not too high)
            if 2 <= degree <= 1000:
                # Prefer nodes with rare edge types
                rare_edge_count = 0
                for dst, etype, count in edges:
                    key = (node, dst, etype)
                    prob = self._baseline_edge_probs.get(key, 1.0)
                    rarity = -math.log(max(prob, 1e-10))
                    if rarity > 5:  # roughly 1/150 rarity
                        rare_edge_count += 1
                if rare_edge_count >= 1:
                    seeds.append(node)
        # Fallback: top-degree nodes if no rare-edge nodes found
        if not seeds:
            seeds = sorted(self._graph.keys(), key=lambda n: len(self._graph[n]), reverse=True)[:100]
        return seeds

    def _bfs_paths(self, start: str) -> list[tuple[tuple, float]]:
        """BFS from start node up to max_path_length, collecting rare paths."""
        paths = []
        # Queue: (current_node, path_tuple, cumulative_rarity)
        queue = [(start, (start,), 0.0)]
        visited_depth = defaultdict(set)
        visited_depth[0].add(start)

        while queue:
            node, path, cum_rarity = queue.pop(0)
            depth = len(path) - 1
            if depth >= self.max_path_length:
                continue

            for dst, etype, count in self._graph.get(node, []):
                edge_key = (node, dst, etype)
                prob = self._baseline_edge_probs.get(edge_key, 1.0 / max(self._total_edges, 1))
                edge_rarity = -math.log(max(prob, 1e-10))

                new_path = path + (dst,)
                new_rarity = cum_rarity + edge_rarity
                mean_rarity = new_rarity / len(new_path)

                if depth + 1 >= self.min_path_length:
                    paths.append((new_path, mean_rarity))

                # Continue BFS if not revisiting at same depth
                if dst not in visited_depth[depth + 1]:
                    visited_depth[depth + 1].add(dst)
                    queue.append((dst, new_path, new_rarity))

                # Prune: limit queue growth
                if len(queue) > 10000:
                    break
            if len(queue) > 10000:
                break

        return paths

    def score(self, X: np.ndarray) -> np.ndarray:
        """Per-row anomaly scores based on graph rarity.

        This is a fallback: the primary interface for GraphRarePath is score_nodes().
        """
        return np.zeros(len(X)) if X.shape[0] > 0 else np.array([])

    def get_rare_paths_for_ip(self, ip: str) -> list[tuple[tuple, float]]:
        """Get all rare paths involving a specific IP address."""
        all_rare = self._find_rare_paths()
        return [(p, s) for p, s in all_rare if ip in p]
