"""Persistent traceability graph with SQLite backend."""

import json
import sqlite3
import time
from typing import Optional

import networkx as nx


class TraceabilityGraph:
    """Accumulates nodes and edges across ALL processing windows.

    Provides query: trace_path, expand_neighborhood, entity_timeline.
    Persists to SQLite for durability across restarts.
    """

    def __init__(self, db_path: str = None):
        if db_path is None:
            from pathlib import Path
            db_path = str(Path(__file__).parent.parent.parent / "data" / "state" / "traceability.db")
        self.db_path = db_path
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.graph = nx.MultiDiGraph()
        self._init_schema()
        self._load_from_db()

    def _init_schema(self):
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS nodes (
                entity_id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                risk_score REAL DEFAULT 0.0,
                first_seen INTEGER,
                last_seen INTEGER,
                tags TEXT DEFAULT '[]',
                updated_at REAL
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS edges (
                src TEXT,
                dst TEXT,
                edge_type TEXT,
                risk_score REAL DEFAULT 0.0,
                event_count INTEGER DEFAULT 1,
                first_seen INTEGER,
                last_seen INTEGER,
                ports TEXT DEFAULT '[]',
                protocols TEXT DEFAULT '[]',
                PRIMARY KEY (src, dst, edge_type)
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS entity_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                event_type TEXT,
                description TEXT,
                risk_delta REAL DEFAULT 0.0
            )
        """)
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_timeline_entity ON entity_timeline(entity_id, timestamp)")
        self.db.commit()

    def _load_from_db(self):
        """Restore the graph from SQLite."""
        for row in self.db.execute("SELECT * FROM nodes"):
            entity_id, entity_type, risk_score, first_seen, last_seen, tags, _ = row
            self.graph.add_node(entity_id, entity_type=entity_type,
                                risk_score=risk_score, first_seen=first_seen,
                                last_seen=last_seen, tags=json.loads(tags))

        for row in self.db.execute("SELECT * FROM edges"):
            src, dst, etype, risk_score, event_count, first_seen, last_seen, ports, protocols = row
            self.graph.add_edge(src, dst, key=etype,
                                edge_type=etype, risk_score=risk_score,
                                event_count=event_count, first_seen=first_seen,
                                last_seen=last_seen,
                                ports=json.loads(ports), protocols=json.loads(protocols))

    def merge_window(self, temporal_graph):
        """Merge a new window's temporal graph into the persistent traceability graph."""
        now = time.time()
        graph = temporal_graph.graph

        for node_id, node_data in graph.nodes(data=True):
            if self.graph.has_node(node_id):
                existing = self.graph.nodes[node_id]
                existing["risk_score"] = max(existing.get("risk_score", 0),
                                             node_data.get("risk_score", 0))
                existing["last_seen"] = max(existing.get("last_seen", 0),
                                            node_data.get("last_seen", 0))
                existing_tags = set(existing.get("tags", []))
                existing_tags.update(node_data.get("tags", []))
                existing["tags"] = list(existing_tags)
            else:
                self.graph.add_node(node_id, **node_data)

            # Upsert to SQLite
            nd = self.graph.nodes[node_id]
            self.db.execute(
                "INSERT OR REPLACE INTO nodes VALUES (?, ?, ?, ?, ?, ?, ?)",
                (node_id, nd.get("entity_type", "ip"), nd.get("risk_score", 0),
                 nd.get("first_seen", 0), nd.get("last_seen", 0),
                 json.dumps(nd.get("tags", [])), now)
            )

        for u, v, key, edge_data in graph.edges(keys=True, data=True):
            etype = edge_data.get("edge_type", "unknown")
            if self.graph.has_edge(u, v, key=etype):
                existing = self.graph[u][v][etype]
                existing["risk_score"] = max(existing.get("risk_score", 0),
                                             edge_data.get("risk_score", 0))
                existing["event_count"] += edge_data.get("event_count", 0)
                existing["last_seen"] = max(existing.get("last_seen", 0),
                                            edge_data.get("last_seen", 0))
                # Handle ports: convert to set, merge, store as list
                existing_ports = set(existing.get("ports", []))
                existing_ports.update(edge_data.get("ports", set()))
                existing["ports"] = list(existing_ports)
                existing_protos = set(existing.get("protocols", []))
                existing_protos.update(edge_data.get("protocols", set()))
                existing["protocols"] = list(existing_protos)
            else:
                self.graph.add_edge(u, v, key=etype, **edge_data)

            ed = self.graph[u][v][etype]
            ports = ed.get("ports", [])
            if isinstance(ports, set):
                ports = list(ports)
            protocols = ed.get("protocols", [])
            if isinstance(protocols, set):
                protocols = list(protocols)
            self.db.execute(
                "INSERT OR REPLACE INTO edges VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (u, v, etype, ed.get("risk_score", 0), ed.get("event_count", 0),
                 ed.get("first_seen", 0), ed.get("last_seen", 0),
                 json.dumps(ports), json.dumps(protocols))
            )

        self.db.commit()

    def trace_path(self, src: str, dst: str, max_depth: int = 5) -> Optional[list]:
        """Find the highest-risk path between two entities."""
        if not self.graph.has_node(src) or not self.graph.has_node(dst):
            return None

        # Weight edges by (1 - risk_score) so high-risk edges are preferred (shorter)
        def weight(u, v, d):
            return 1.0 - min(d.get("risk_score", 0), 0.99)

        try:
            path = nx.shortest_path(self.graph, src, dst,
                                    weight=lambda u, v, d: weight(u, v, d))
            if len(path) <= max_depth + 1:
                return path
        except (nx.NetworkXNoPath, nx.NetworkXError):
            pass
        return None

    def expand_neighborhood(self, entity_id: str, depth: int = 2) -> dict:
        """Get k-hop neighborhood as node-link JSON."""
        if not self.graph.has_node(entity_id):
            return {"nodes": [], "edges": []}
        nodes = {entity_id}
        frontier = {entity_id}
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

        subgraph = self.graph.subgraph(nodes)
        return nx.node_link_data(subgraph)

    def entity_timeline(self, entity_id: str, limit: int = 100) -> list[dict]:
        """Get chronological event timeline for an entity."""
        rows = self.db.execute(
            "SELECT timestamp, event_type, description, risk_delta FROM entity_timeline "
            "WHERE entity_id = ? ORDER BY timestamp DESC LIMIT ?",
            (entity_id, limit)
        ).fetchall()
        return [{"timestamp": r[0], "event_type": r[1],
                 "description": r[2], "risk_delta": r[3]} for r in rows]

    def add_timeline_event(self, entity_id: str, timestamp: int,
                           event_type: str, description: str, risk_delta: float = 0.0):
        """Record an event in an entity's timeline."""
        self.db.execute(
            "INSERT INTO entity_timeline (entity_id, timestamp, event_type, description, risk_delta) "
            "VALUES (?, ?, ?, ?, ?)",
            (entity_id, timestamp, event_type, description, risk_delta)
        )
        self.db.commit()

    def get_risk_subgraph(self, min_risk: float = 0.5) -> dict:
        """Return subgraph of nodes with risk_score >= min_risk."""
        nodes = {n for n in self.graph.nodes
                 if self.graph.nodes[n].get("risk_score", 0) >= min_risk}
        subgraph = self.graph.subgraph(nodes)
        return nx.node_link_data(subgraph)

    def close(self):
        self.db.close()

    def __del__(self):
        try:
            self.db.close()
        except Exception:
            pass
