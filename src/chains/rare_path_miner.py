"""Rare path mining: BFS-based attack chain discovery in communication graphs."""

import math
import uuid
from collections import defaultdict

import networkx as nx

from src.chains.graph_builder import TemporalGraph
from src.core.types import AttackChain, ChainNode, ChainEdge
from src.utils.ip_utils import is_internal_ip


class RarePathMiner:
    """Mines rare communication paths from the temporal graph as attack chain candidates."""

    def __init__(self, min_path_length: int = 2, max_path_length: int = 3,
                 rarity_threshold: float = 0.65):
        self.min_path_length = min_path_length
        self.max_path_length = max_path_length
        self.rarity_threshold = rarity_threshold

    def mine(self, temporal_graph: TemporalGraph) -> list[AttackChain]:
        """Discover all rare paths and convert to AttackChain objects."""
        graph = temporal_graph.graph
        if graph.number_of_nodes() == 0:
            return []

        # Compute global edge frequency statistics
        edge_freq = {}
        for u, v, k, data in graph.edges(keys=True, data=True):
            edge_type = data.get("edge_type", "unknown")
            edge_freq[(u, v, edge_type)] = data.get("event_count", 1)
        max_freq = max(edge_freq.values()) if edge_freq else 1

        # Normalize frequencies
        for key in edge_freq:
            edge_freq[key] = edge_freq[key] / max_freq

        chains = []
        anomalous_nodes = temporal_graph.get_anomalous_nodes(min_risk=0.30)

        # If no nodes pass the anomaly threshold, use nodes with any non-zero score
        if not anomalous_nodes:
            anomalous_nodes = [n for n in graph.nodes
                               if graph.nodes[n].get("risk_score", 0) > 0.0][:50]

        # Also include nodes with rare edges as seeds
        seed_nodes = set(anomalous_nodes)
        for node in graph.nodes:
            degree = graph.degree(node)
            if 2 <= degree <= 500:
                for neighbor in graph.successors(node):
                    for key, edge_data in graph[node][neighbor].items():
                        freq = edge_freq.get((node, neighbor, edge_data.get("edge_type", "unknown")), 1.0)
                        if freq < 0.05:  # rare edge
                            seed_nodes.add(node)
                            break

        # Sort seeds by risk score: high-risk nodes first, ensures best seeds processed
        sorted_seeds = sorted(seed_nodes, key=lambda n: graph.nodes[n].get("risk_score", 0), reverse=True)
        for seed in sorted_seeds[:40]:
            paths = self._bfs_rare_paths(graph, seed, edge_freq)
            for path_nodes, path_edges, score in paths:
                if score >= self.rarity_threshold:
                    # Only keep if at least one node has significant risk
                    max_node_risk = max(graph.nodes[n].get("risk_score", 0) for n in path_nodes)
                    if max_node_risk < 0.50:
                        continue
                    chain = self._path_to_chain(graph, path_nodes, path_edges, score)
                    if chain:
                        chains.append(chain)

        # Explicit internal→external detection: find C2 and data exfil chains
        # Only for high-risk internal nodes — avoids FPs from random baseline external connections
        for node in list(sorted_seeds[:50]):
            if not is_internal_ip(node):
                continue
            node_risk = graph.nodes[node].get("risk_score", 0)
            if node_risk < 0.6:  # Only high-risk nodes warrant C2/exfil classification
                continue
            for neighbor in graph.successors(node):
                # Skip internal IPs
                if is_internal_ip(neighbor):
                    continue
                # Skip CIDR notation (subnet scan targets, handled by recon_scan)
                if "/" in neighbor:
                    continue
                # Skip well-known DNS resolvers only for non-DNS edges
                is_dns_resolver = neighbor.startswith(("8.8.", "1.1.", "9.9."))
                # External/rare target found
                for key in graph[node][neighbor]:
                    ed = graph[node][neighbor][key]
                    etype = ed.get("edge_type", "unknown")
                    # DNS edges: allow DGA detection even via known resolvers
                    if etype == "dns":
                        event_count = ed.get("event_count", 1)
                        chain = self._path_to_chain(
                            graph, [node, neighbor],
                            [(node, neighbor, etype, key)],
                            max(node_risk, 0.5),
                        )
                        if chain:
                            chain.chain_type = "dga_activity"
                            chains.append(chain)
                        continue
                    if etype not in ("network",):
                        continue
                    if is_dns_resolver:
                        continue
                    event_count = ed.get("event_count", 1)
                    bytes_out_max = ed.get("bytes_out", 0) or 0
                    ports = ed.get("ports", set())
                    if isinstance(ports, list):
                        ports = set(ports)
                    huge_transfer = bytes_out_max > 100_000_000
                    non_standard = [p for p in ports if p not in (80, 443, 53)]
                    # C2 beacon when periodic (3+ events) on standard ports,
                    # even if some other record on same edge had large transfer
                    has_beacon = event_count >= 3 and not non_standard
                    should_exfil = huge_transfer or non_standard
                        # Generate C2 beacon chain when periodic pattern exists
                        if has_beacon:
                            beacon_chain = self._path_to_chain(
                                graph, [node, neighbor],
                                [(node, neighbor, etype, key)],
                                max(node_risk, 0.5),
                            )
                            if beacon_chain:
                                beacon_chain.chain_type = "c2_beacon"
                                chains.append(beacon_chain)
                        # Generate data exfil chain when large transfer or non-standard ports
                        if should_exfil:
                            exfil_chain = self._path_to_chain(
                                graph, [node, neighbor],
                                [(node, neighbor, etype, key)],
                                max(node_risk, 0.6),
                            )
                            if exfil_chain:
                                exfil_chain.chain_type = "data_exfil"
                                chains.append(exfil_chain)
                        # Fallback: neither clear beacon nor clear exfil → default c2_beacon
                        # Data exfil is already caught by should_exfil (huge bytes / non-standard ports)
                        if not has_beacon and not should_exfil:
                            chain = self._path_to_chain(
                                graph, [node, neighbor],
                                [(node, neighbor, etype, key)],
                                max(node_risk, 0.5),
                            )
                            if chain:
                                chain.chain_type = "c2_beacon"
                                chains.append(chain)

        # Internal→internal attack detection (data exfil to internal drop, lateral movement, internal recon)
        for node in graph.nodes:
            node_risk = graph.nodes[node].get("risk_score", 0)
            if node_risk < 0.5:
                continue
            for neighbor in graph.successors(node):
                for key in graph[node][neighbor]:
                    ed = graph[node][neighbor][key]
                    etype = ed.get("edge_type", "unknown")
                    bo = ed.get("bytes_out", 0) or 0
                    ports = ed.get("ports", set())
                    if isinstance(ports, list):
                        ports = set(ports)
                    ec = ed.get("event_count", 1)

                    # Internal data exfil: large transfer to internal drop server
                    if bo > 100_000_000 and etype in ("network", "file"):
                        chain = self._path_to_chain(
                            graph, [node, neighbor],
                            [(node, neighbor, etype, key)],
                            max(node_risk, 0.6),
                        )
                        if chain:
                            chain.chain_type = "data_exfil"
                            chain.description = f"Internal data exfil: {bo/1e9:.1f}GB transferred from {node} to {neighbor}"
                            chains.append(chain)

                    # Internal lateral movement: auth edges between internal hosts
                    if etype == "auth" and ec >= 1:
                        chain = self._path_to_chain(
                            graph, [node, neighbor],
                            [(node, neighbor, etype, key)],
                            max(node_risk, 0.5),
                        )
                        if chain:
                            chain.chain_type = "lateral_movement"
                            chain.description = f"Lateral movement: auth from {node} to {neighbor} ({ec} attempts)"
                            chains.append(chain)

                    # Internal DNS recon / zone transfer
                    if etype == "dns":
                        chain = self._path_to_chain(
                            graph, [node, neighbor],
                            [(node, neighbor, etype, key)],
                            max(node_risk, 0.5),
                        )
                        if chain:
                            chain.chain_type = "internal_recon"
                            chain.description = f"Internal DNS reconnaissance: {node} querying {neighbor}"
                            chains.append(chain)

        # Fallback: direct connections between high-anomaly nodes with rare edges
        # These are typically C2 beacons or direct compromise
        high_anomaly = sorted(seed_nodes, key=lambda n: graph.nodes[n].get("risk_score", 0), reverse=True)[:20]
        for i, n1 in enumerate(high_anomaly):
            for n2 in high_anomaly[i+1:]:
                if graph.has_edge(n1, n2):
                    for key in graph[n1][n2]:
                        edge_data = graph[n1][n2][key]
                        node_score = max(
                            graph.nodes[n1].get("risk_score", 0),
                            graph.nodes[n2].get("risk_score", 0),
                        )
                        edge_type = edge_data.get("edge_type", "unknown")
                        freq = edge_freq.get((n1, n2, edge_type), 1.0)
                        # Only include if both nodes are highly anomalous AND edge is rare
                        if node_score >= 0.80 and freq < 0.10:
                            chain = self._path_to_chain(
                                graph,
                                [n1, n2],
                                [(n1, n2, edge_type, key)],
                                node_score,
                            )
                            chains.append(chain)

        # Brute force detection: auth edges with multiple failures
        for node in graph.nodes:
            node_risk = graph.nodes[node].get("risk_score", 0)
            if node_risk < 0.4:
                continue
            for neighbor in graph.successors(node):
                for key in graph[node][neighbor]:
                    ed = graph[node][neighbor][key]
                    if ed.get("edge_type") != "auth":
                        continue
                    auth_count = ed.get("event_count", 1)
                    if auth_count >= 3:
                        chain = self._path_to_chain(
                            graph, [node, neighbor],
                            [(node, neighbor, "auth", key)],
                            max(node_risk, 0.5),
                        )
                        if chain:
                            chain.chain_type = "brute_force"
                            chain.description = f"Brute force: {auth_count} auth attempts from {node} to {neighbor}"
                            chains.append(chain)

        # Port scan aggregation: flag nodes with many distinct targets
        for node in anomalous_nodes:
            if graph.nodes[node].get("risk_score", 0) < 0.5:
                continue
            targets = set()
            scan_edges = []
            for neighbor in graph.successors(node):
                for key in graph[node][neighbor]:
                    ed = graph[node][neighbor][key]
                    if ed.get("edge_type") in ("network", "dns"):
                        targets.add(neighbor)
                        scan_edges.append((node, neighbor, ed.get("edge_type", "network"), key))
            if len(targets) >= 10:
                chain = self._path_to_chain(graph, [node], scan_edges[:1],
                                            graph.nodes[node].get("risk_score", 0))
                if chain:
                    chain.chain_type = "recon_scan"
                    chain.affected_assets = [node] + list(targets)[:20]
                    chain.description = f"Port scan: {node} probed {len(targets)} targets"
                    chains.append(chain)

        # Pattern-based chain detection for specialized edge types
        specialized_types = [
            "credential_theft", "anti_forensics", "persistence",
            "mitm_attack", "tool_download", "internal_recon",
        ]
        for node in graph.nodes:
            node_risk = graph.nodes[node].get("risk_score", 0)
            if node_risk < 0.5:
                continue
            for neighbor in graph.successors(node):
                for key in graph[node][neighbor]:
                    ed = graph[node][neighbor][key]
                    etype = ed.get("edge_type", "")
                    if etype in specialized_types:
                        chain = self._path_to_chain(
                            graph, [node, neighbor],
                            [(node, neighbor, etype, key)],
                            max(node_risk, 0.6),
                        )
                        if chain:
                            chain.chain_type = etype
                            chains.append(chain)

        # Deduplicate
        chains = self._deduplicate_chains(chains)
        return chains

    def _bfs_rare_paths(self, graph: nx.MultiDiGraph, seed: str,
                         edge_freq: dict) -> list:
        """BFS from seed collecting rare paths, sorted by combined score.

        Collects all valid paths then returns the highest-scoring ones.
        This ensures genuinely rare edges (like external C2/exfil connections)
        are prioritized over common internal edges.
        """
        results = []
        queue = [(seed, [seed], [], 0.0)]  # (node, node_path, edge_path, cum_rarity)
        visited_depth = defaultdict(set)
        visited_depth[0].add(seed)
        total_expanded = 0

        while queue and total_expanded < 4000:
            node, node_path, edge_path, cum_rarity = queue.pop(0)
            depth = len(node_path) - 1
            total_expanded += 1

            if depth >= self.max_path_length:
                continue

            for neighbor in graph.successors(node):
                for key, edge_data in graph[node][neighbor].items():
                    edge_type = edge_data.get("edge_type", "unknown")
                    freq = edge_freq.get((node, neighbor, edge_type), 1.0)
                    edge_rarity = -math.log(max(freq, 1e-6))

                    new_node_path = node_path + [neighbor]
                    new_edge_path = edge_path + [(node, neighbor, edge_type, key)]
                    new_rarity = cum_rarity + edge_rarity
                    mean_rarity = new_rarity / max(len(new_edge_path), 1)

                    # Normalize mean rarity to [0, 1]
                    rarity_score = min(mean_rarity / 8.0, 1.0)

                    # Combined score: rarity (70%) + average node anomaly risk (30%)
                    node_risks = [graph.nodes[n].get("risk_score", 0) for n in new_node_path]
                    avg_node_risk = sum(node_risks) / max(len(node_risks), 1)
                    combined_score = 0.70 * rarity_score + 0.30 * avg_node_risk

                    if depth + 1 >= self.min_path_length:
                        results.append((new_node_path, new_edge_path, combined_score))

                    if neighbor not in visited_depth[depth + 1]:
                        visited_depth[depth + 1].add(neighbor)
                        queue.append((neighbor, new_node_path, new_edge_path, new_rarity))

                if len(queue) > 5000 or total_expanded >= 4000:
                    break
            if len(queue) > 5000 or total_expanded >= 4000:
                break

        # Sort by combined score descending, return top paths per seed
        results.sort(key=lambda x: x[2], reverse=True)
        return results[:10]

    def _path_to_chain(self, graph: nx.MultiDiGraph, node_path: list,
                       edge_path: list, score: float) -> AttackChain:
        """Convert a rare path into an AttackChain object."""
        chain_id = str(uuid.uuid4())[:8]
        nodes_out = []
        edges_out = []
        affected = []

        for i, node_id in enumerate(node_path):
            node_data = graph.nodes.get(node_id, {})
            role = "source" if i == 0 else ("target" if i == len(node_path) - 1 else "pivot")
            nodes_out.append(ChainNode(
                entity=node_id,
                entity_type=node_data.get("entity_type", "ip"),
                role=role,
                risk_score=node_data.get("risk_score", 0.0),
            ))
            affected.append(node_id)

        for src, dst, etype, key in edge_path:
            edge_data = graph[src][dst].get(key, {})
            edges_out.append(ChainEdge(
                src=src,
                dst=dst,
                edge_type=etype,
                timestamp_first=edge_data.get("first_seen", 0),
                timestamp_last=edge_data.get("last_seen", 0),
                event_count=edge_data.get("event_count", 1),
                anomalous_score=score,
            ))

        return AttackChain(
            chain_id=chain_id,
            chain_type=self._classify_chain_type(edge_path, graph),
            nodes=nodes_out,
            edges=edges_out,
            total_risk_score=score,
            confidence=score,
            first_seen=min(e.timestamp_first for e in edges_out) if edges_out else 0,
            last_seen=max(e.timestamp_last for e in edges_out) if edges_out else 0,
            affected_assets=affected,
        )

    def _classify_chain_type(self, edge_path: list, graph: nx.MultiDiGraph) -> str:
        """Classify chain based on edge types, node IP ranges, and connection patterns."""
        edge_types = [e[2] for e in edge_path]

        # Collect all nodes in the path
        nodes_in_path = set()
        for e in edge_path:
            nodes_in_path.add(e[0])
            nodes_in_path.add(e[1])
        internal_nodes = [n for n in nodes_in_path if is_internal_ip(n)]
        external_nodes = [n for n in nodes_in_path if not is_internal_ip(n) and not n.startswith("8.8.")]

        # Collect evidence from edge data for fine-grained classification
        total_events = 0
        total_dst_ips = set()
        evidence_keywords = set()
        for src, dst, etype, key in edge_path:
            if graph.has_edge(src, dst, key):
                ed = graph[src][dst][key]
                total_events += ed.get("event_count", 1)
            total_dst_ips.add(dst)
            # Also check raw edge data for classification keywords
            ed2 = graph[src][dst].get(key, {}) if graph.has_edge(src, dst, key) else {}

        # Check if any source node has many targets (port scan pattern)
        source_nodes = set(e[0] for e in edge_path)
        max_out_degree = 0
        max_distinct_ports = 0
        for src_node in source_nodes:
            targets = set()
            ports = set()
            for dst in graph.successors(src_node):
                targets.add(dst)
                for key in graph[src_node][dst]:
                    ed = graph[src_node][dst][key]
                    ports.update(ed.get("ports", []))
            max_out_degree = max(max_out_degree, len(targets))
            max_distinct_ports = max(max_distinct_ports, len(ports))

        # Anti-forensics: accessing/deleting security logs, audit trails
        if "anti_forensics" in edge_types:
            return "anti_forensics"

        # Credential access: reading SAM, SYSTEM, NTDS, kdbx files
        if "credential_theft" in edge_types:
            return "credential_theft"

        # Persistence: startup folder write, scheduled task creation
        if "persistence" in edge_types:
            return "persistence"

        # Tool download: external retrieval
        if "tool_download" in edge_types:
            return "tool_download"

        # MIITM: ARP poisoning
        if "mitm_attack" in edge_types:
            return "mitm_attack"

        # Internal recon: hosts file, system info gathering
        if "internal_recon" in edge_types:
            return "internal_recon"

        # Lateral movement: auth + network edge sequence
        if "auth" in edge_types and "network" in edge_types:
            return "lateral_movement"

        # DGA: DNS edges (typically to DNS resolver from internal host)
        if "dns" in edge_types:
            return "dga_activity"

        # Port scan: many targets AND many distinct ports
        if len(total_dst_ips) >= 5 and "network" in edge_types and not external_nodes:
            return "recon_scan"
        if max_out_degree >= 8 and max_distinct_ports >= 5 and "network" in edge_types:
            return "recon_scan"

        # Data exfil vs C2 beacon: internal → external with network edges
        if external_nodes and internal_nodes and "network" in edge_types:
            # Check edge data for volume and port signals
            is_exfil = False
            is_beacon = False
            for src, dst, etype, key in edge_path:
                if graph.has_edge(src, dst, key):
                    ed = graph[src][dst][key]
                    bo = ed.get("bytes_out", 0) or 0
                    ports = ed.get("ports", set())
                    if isinstance(ports, list):
                        ports = set(ports)
                    ec = ed.get("event_count", 1)
                    # Data exfil signals: large transfer or non-standard port
                    if bo > 100_000_000 or any(p not in (80, 443, 53) for p in ports):
                        is_exfil = True
                    # C2 beacon signals: periodic on standard ports with small bytes
                    elif ec >= 3 and bo < 10_000_000:
                        is_beacon = True
            if is_exfil:
                return "data_exfil"
            if is_beacon:
                return "c2_beacon"
            # Multi-hop with external → data_exfil
            if len(edge_path) >= 2 or total_events >= 8:
                return "data_exfil"
            # Single hop, no strong signal → c2_beacon as default
            return "c2_beacon"

        # Multi-hop with mixed types
        if len(set(edge_types)) >= 3:
            return "supply_chain"

        # Internal-to-internal suspicious network pattern (potential lateral movement)
        if "network" in edge_types and not external_nodes and len(edge_path) >= 2:
            return "lateral_movement"

        return "suspicious_activity"

    def _deduplicate_chains(self, chains: list[AttackChain]) -> list[AttackChain]:
        """Remove chains that are sub-paths of other chains."""
        if len(chains) <= 1:
            return chains

        # Use set-based dedup: collapse to canonical entity set + chain type key
        seen = {}
        for chain in chains:
            key = (frozenset(n.entity for n in chain.nodes), chain.chain_type)
            if key not in seen:
                seen[key] = chain
            elif chain.total_risk_score > seen[key].total_risk_score:
                seen[key] = chain

        # Sort by length descending and remove sub-paths (O(N * K) where K is small)
        # Only remove true sub-paths: same or compatible chain type, strict subset of entities
        kept = sorted(seen.values(), key=lambda c: len(c.nodes), reverse=True)
        result = []
        for chain in kept:
            chain_entities = set(n.entity for n in chain.nodes)
            is_subset = False
            for kept_chain in result[:100]:
                kept_entities = set(n.entity for n in kept_chain.nodes)
                if chain_entities != kept_entities and chain_entities.issubset(kept_entities):
                    # Only skip if chain types are compatible (same or related)
                    if chain.chain_type == kept_chain.chain_type:
                        is_subset = True
                        break
                    # Also skip if the longer chain covers the shorter chain's type
                    # (e.g., lateral_movement subsumes individual auth/network paths)
            if not is_subset:
                result.append(chain)

        return result
