"""Lateral movement detection via graph pattern matching.

Lateral movement manifests as:
  Host A --auth--> Host B --network_connect/new_process--> Host C
where A, B, C are internal IPs and the auth event has suspicious characteristics.
"""

import uuid
from datetime import datetime, timezone

from src.chains.graph_builder import TemporalGraph
from src.core.types import AttackChain, ChainNode, ChainEdge
from src.utils.ip_utils import is_internal_ip


class LateralMovementDetector:
    """Detects lateral movement patterns in the temporal graph."""

    def __init__(self, off_hours_start: int = 20, off_hours_end: int = 6):
        self.off_hours_start = off_hours_start
        self.off_hours_end = off_hours_end

    def detect(self, temporal_graph: TemporalGraph) -> list[AttackChain]:
        """Find lateral movement chains in the graph."""
        graph = temporal_graph.graph
        chains = []

        # Find candidate pivot hosts: internal IPs with both incoming auth and outgoing connections
        pivots = []
        for node in graph.nodes:
            if not is_internal_ip(node):
                continue
            node_data = graph.nodes[node]
            if node_data.get("entity_type") != "ip":
                continue

            in_auth = [u for u in graph.predecessors(node)
                       if graph.has_edge(u, node) and
                       any(graph[u][node][k].get("edge_type") == "auth" for k in graph[u][node])]
            out_conn = [v for v in graph.successors(node)
                        if graph.has_edge(node, v) and
                        any(graph[node][v][k].get("edge_type") in ("network", "dns")
                            for k in graph[node][v])]

            if in_auth and out_conn:
                pivots.append((node, in_auth, out_conn))

        for pivot, auth_sources, conn_targets in pivots:
            pivot_risk = graph.nodes[pivot].get("risk_score", 0)

            for src in auth_sources:
                src_risk = graph.nodes[src].get("risk_score", 0)

                for key in graph[src][pivot]:
                    auth_edge = graph[src][pivot][key]
                    if auth_edge.get("edge_type") != "auth":
                        continue

                    auth_ts = auth_edge.get("first_seen", 0)
                    is_suspicious = self._is_suspicious_auth(auth_edge, auth_ts)
                    auth_risk = auth_edge.get("risk_score", 0)

                    # Gate: need at least one suspicious signal
                    if not is_suspicious and auth_risk < 0.3 and pivot_risk < 0.3:
                        continue

                    for dst in conn_targets:
                        dst_risk = graph.nodes[dst].get("risk_score", 0)

                        for ck in graph[pivot][dst]:
                            conn_edge = graph[pivot][dst][ck]
                            if conn_edge.get("edge_type") not in ("network", "dns"):
                                continue

                            # Keep if there's at least moderate risk somewhere in the path
                            max_path_risk = max(src_risk, pivot_risk, dst_risk,
                                               conn_edge.get("risk_score", 0))
                            if max_path_risk < 0.3 and not is_suspicious:
                                continue

                            chain = self._build_chain(src, pivot, dst, auth_edge, conn_edge)
                            if chain:
                                chains.append(chain)

        # Sort by risk score, filter zero-score chains, limit output
        chains = [c for c in chains if c.total_risk_score > 0.1]
        chains.sort(key=lambda c: c.total_risk_score, reverse=True)
        return chains[:30]

    def _is_suspicious_auth(self, auth_edge: dict, timestamp: int) -> bool:
        """Check if an auth event has suspicious characteristics."""
        # Off-hours login
        try:
            hour = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc).hour
        except (ValueError, OSError):
            hour = 12
        if self.off_hours_start <= hour or hour < self.off_hours_end:
            return True

        # High risk score on edge
        if auth_edge.get("risk_score", 0) > 0.5:
            return True

        # Many events (possible brute force)
        if auth_edge.get("event_count", 0) > 50:
            return True

        return False

    def _build_chain(self, src: str, pivot: str, dst: str,
                     auth_edge: dict, conn_edge: dict) -> AttackChain:
        """Construct an AttackChain from a lateral movement pattern."""
        chain_id = str(uuid.uuid4())[:8]

        nodes = [
            ChainNode(entity=src, entity_type="ip", role="source",
                      risk_score=auth_edge.get("risk_score", 0)),
            ChainNode(entity=pivot, entity_type="ip", role="pivot",
                      risk_score=auth_edge.get("risk_score", 0)),
            ChainNode(entity=dst, entity_type="ip", role="target",
                      risk_score=conn_edge.get("risk_score", 0)),
        ]

        edges = [
            ChainEdge(src=src, dst=pivot, edge_type="auth",
                      timestamp_first=auth_edge.get("first_seen", 0),
                      timestamp_last=auth_edge.get("last_seen", 0),
                      event_count=auth_edge.get("event_count", 1),
                      anomalous_score=auth_edge.get("risk_score", 0)),
            ChainEdge(src=pivot, dst=dst, edge_type=conn_edge.get("edge_type", "network"),
                      timestamp_first=conn_edge.get("first_seen", 0),
                      timestamp_last=conn_edge.get("last_seen", 0),
                      event_count=conn_edge.get("event_count", 1),
                      anomalous_score=conn_edge.get("risk_score", 0)),
        ]

        # Aggregate risk: use max of all risk signals, floor at 0.5 for valid patterns
        risk_score = max(
            auth_edge.get("risk_score", 0),
            conn_edge.get("risk_score", 0),
        )
        if risk_score < 0.1:
            risk_score = 0.5  # pattern-based floor for valid lateral movement
        confidence = risk_score * 0.9

        return AttackChain(
            chain_id=chain_id,
            chain_type="lateral_movement",
            kill_chain_phases=["Lateral Movement"],
            nodes=nodes,
            edges=edges,
            total_risk_score=risk_score,
            confidence=confidence,
            first_seen=auth_edge.get("first_seen", 0),
            last_seen=conn_edge.get("last_seen", 0),
            affected_assets=[src, pivot, dst],
            mitre_techniques=["T1021", "T1078"],
            description=f"Lateral movement from {src} via {pivot} to {dst}",
        )
