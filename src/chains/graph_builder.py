"""Temporal communication graph builder for attack chain mining."""

from collections import defaultdict
from typing import Optional

import networkx as nx
import numpy as np


class TemporalGraph:
    """Time-windowed directed multigraph for attack chain discovery.

    Nodes: IPs, hosts, users, domains, processes
    Edges: network_connect, auth, dns_query, process_create, file_access

    Each node and edge carries a risk_score reflecting aggregated anomaly scores.
    """

    def __init__(self):
        self.graph = nx.MultiDiGraph()
        self._node_events: dict[str, list] = defaultdict(list)
        self._edge_events: dict[tuple, list] = defaultdict(list)

    def add_window(
        self,
        normalized_records: list[dict],
        anomaly_scores: Optional[dict[str, float]] = None,
    ):
        """Ingest one time window's worth of normalized logs and anomaly scores."""
        if anomaly_scores is None:
            anomaly_scores = {}

        for record in normalized_records:
            src_ip = record.get("src_ip") or "unknown"
            dst_ip = record.get("dst_ip") or "unknown"
            event_type = record.get("event_type", "unknown")
            user = record.get("user")
            domain = record.get("domain")
            process_name = record.get("process_name")
            timestamp = record.get("timestamp", 0)
            src_port = record.get("src_port")
            dst_port = record.get("dst_port")
            proto = record.get("proto")

            # Build nodes
            nodes_to_add = [("ip", src_ip), ("ip", dst_ip)]
            if user:
                nodes_to_add.append(("user", user))
            if domain:
                nodes_to_add.append(("domain", domain))
            if process_name:
                nodes_to_add.append(("process", f"{src_ip}:{process_name}"))

            for entity_type, entity_id in nodes_to_add:
                if entity_id == "unknown":
                    continue
                if not self.graph.has_node(entity_id):
                    self.graph.add_node(
                        entity_id,
                        entity_type=entity_type,
                        risk_score=0.0,
                        first_seen=timestamp,
                        last_seen=timestamp,
                        total_events=0,
                        is_anomalous=False,
                        tags=[],
                    )
                node = self.graph.nodes[entity_id]
                node["total_events"] += 1
                node["last_seen"] = max(node["last_seen"], timestamp)
                node["first_seen"] = min(node["first_seen"], timestamp)
                self._node_events[entity_id].append(record)

            # Build edges
            edge_type = event_type
            if edge_type in ("auth_success", "auth_failure"):
                edge_label = "auth"
            elif edge_type == "dns_query":
                edge_label = "dns"
            elif edge_type in ("process_create",):
                edge_label = "process"
            elif edge_type in ("file_create", "file_delete"):
                edge_label = "file"
            elif edge_type == "waf_alert":
                edge_label = "http"
            else:
                edge_label = "network"

            edge_key = (src_ip, dst_ip, edge_label)
            self._edge_events[edge_key].append(record)

            if not self.graph.has_edge(src_ip, dst_ip, key=edge_label):
                self.graph.add_edge(
                    src_ip, dst_ip, key=edge_label,
                    edge_type=edge_label,
                    risk_score=0.0,
                    event_count=0,
                    bytes_out=0,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    ports=set(),
                    protocols=set(),
                )
            edge_data = self.graph[src_ip][dst_ip][edge_label]
            edge_data["event_count"] += 1
            edge_data["last_seen"] = max(edge_data["last_seen"], timestamp)
            edge_data["first_seen"] = min(edge_data["first_seen"], timestamp)
            if record.get("bytes_out"):
                edge_data["bytes_out"] += record["bytes_out"]
            if dst_port:
                edge_data["ports"].add(dst_port)
            if proto:
                edge_data["protocols"].add(proto)

    def apply_anomaly_scores(self, node_scores: dict[str, float]):
        """Apply anomaly scores to graph nodes."""
        for node_id, score in node_scores.items():
            if self.graph.has_node(node_id):
                node = self.graph.nodes[node_id]
                node["risk_score"] = max(node["risk_score"], score)
                if score > 0.7:
                    node["is_anomalous"] = True

    def get_anomalous_nodes(self, min_risk: float = 0.7) -> list[str]:
        """Return nodes with risk_score >= min_risk."""
        return [
            n for n in self.graph.nodes
            if self.graph.nodes[n].get("risk_score", 0) >= min_risk
        ]

    def get_anomalous_subgraph(self, min_risk: float = 0.7) -> nx.MultiDiGraph:
        """Return subgraph induced by anomalous nodes."""
        anomalous = set(self.get_anomalous_nodes(min_risk))
        return self.graph.subgraph(anomalous).copy()

    def get_node_neighborhood(self, node_id: str, depth: int = 2) -> nx.MultiDiGraph:
        """Get k-hop neighborhood of a node."""
        if not self.graph.has_node(node_id):
            return nx.MultiDiGraph()
        nodes = {node_id}
        frontier = {node_id}
        for _ in range(depth):
            new_frontier = set()
            for n in frontier:
                for neighbor in self.graph.predecessors(n):
                    if neighbor not in nodes:
                        new_frontier.add(neighbor)
                for neighbor in self.graph.successors(n):
                    if neighbor not in nodes:
                        new_frontier.add(neighbor)
            nodes.update(new_frontier)
            frontier = new_frontier
        return self.graph.subgraph(nodes).copy()

    def to_dict(self) -> dict:
        """Serialize graph for storage."""
        return {
            "nodes": [
                {"id": n, **self.graph.nodes[n]}
                for n in self.graph.nodes
            ],
            "edges": [
                {"src": u, "dst": v, "key": k, **d}
                for u, v, k, d in self.graph.edges(keys=True, data=True)
            ],
        }

    @staticmethod
    def from_dict(data: dict) -> "TemporalGraph":
        """Deserialize graph from dictionary."""
        tg = TemporalGraph()
        for node_data in data.get("nodes", []):
            node_id = node_data.pop("id")
            tg.graph.add_node(node_id, **node_data)
        for edge_data in data.get("edges", []):
            src = edge_data.pop("src")
            dst = edge_data.pop("dst")
            key = edge_data.pop("key", 0)
            tg.graph.add_edge(src, dst, key=key, **edge_data)
        return tg

    @property
    def node_count(self) -> int:
        return self.graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self.graph.number_of_edges()
