"""Core dataclass types shared across pipeline stages."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EntityRiskProfile:
    entity_id: str
    entity_type: str  # 'ip', 'host', 'user', 'domain', 'process'
    score: float = 0.0
    baseline_score: float = 0.0
    last_updated: float = 0.0
    associated_chains: list = field(default_factory=list)
    evidence_count: int = 0
    first_seen: int = 0
    risk_trend: str = "stable"  # 'increasing', 'stable', 'decreasing'
    tags: list = field(default_factory=list)


@dataclass
class ChainNode:
    entity: str
    entity_type: str
    role: str  # 'source', 'pivot', 'target', 'C2_infra'
    risk_score: float = 0.0
    evidence: list = field(default_factory=list)


@dataclass
class ChainEdge:
    src: str
    dst: str
    edge_type: str
    timestamp_first: int = 0
    timestamp_last: int = 0
    event_count: int = 0
    anomalous_score: float = 0.0
    evidence: list = field(default_factory=list)


@dataclass
class AttackChain:
    chain_id: str
    chain_type: str
    kill_chain_phases: list = field(default_factory=list)
    nodes: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    total_risk_score: float = 0.0
    confidence: float = 0.0
    first_seen: int = 0
    last_seen: int = 0
    affected_assets: list = field(default_factory=list)
    mitre_techniques: list = field(default_factory=list)
    description: str = ""
    investigation_priority: int = 3  # 1 (highest) to 5 (lowest)


@dataclass
class DetectionResult:
    detector_name: str
    scores: list  # array of anomaly scores per row
    threshold: float
    alerts: list  # indices above threshold
    explanations: Optional[list] = None


@dataclass
class InjectedAttack:
    attack_id: str
    attack_type: str
    entities: list
    start_time: int
    end_time: int
    params: dict = field(default_factory=dict)


@dataclass
class DailyReport:
    date: str
    total_events: int = 0
    anomalies_detected: int = 0
    chains_discovered: int = 0
    high_risk_entities: list = field(default_factory=list)
    top_chains: list = field(default_factory=list)
    mitre_coverage: dict = field(default_factory=dict)
    investigation_recommendations: list = field(default_factory=list)
