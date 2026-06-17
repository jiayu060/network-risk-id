"""FastAPI REST API for the Network Risk Identification Engine."""

import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="网络风险识别分析引擎 API",
    description="Network Risk Identification & Analysis Engine",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Global pipeline state ----
_pipeline = None
_pipeline_data = None


def get_pipeline():
    """Lazy-init the pipeline with synthetic data or configured data source."""
    global _pipeline, _pipeline_data
    if _pipeline_data is not None:
        return _pipeline, _pipeline_data

    from src.pipeline.orchestrator import PipelineOrchestrator

    _pipeline = PipelineOrchestrator()

    # Check for data directory or use synthetic data
    data_dir = os.environ.get("NRID_DATA_DIR", "")
    if data_dir and Path(data_dir).exists():
        _pipeline_data = _pipeline.run_from_files(data_dir, "syslog")
    else:
        # Generate synthetic data for demo
        import random
        from src.evaluation.attack_injector import AttackInjector

        injector = AttackInjector()
        internal = [f"10.1.{i}.{j}" for i in range(5) for j in range(1, 20)]
        external = [f"203.0.113.{i}" for i in range(1, 50)]
        ports = [80, 443, 22, 53, 445, 3389, 8080]

        base_records = []
        for _ in range(2000):
            base_records.append({
                "src_ip": random.choice(internal), "dst_ip": random.choice(internal + external),
                "dst_port": random.choice(ports), "proto": "TCP", "event_type": "network_connect",
                "timestamp": injector.base_ts + random.randint(0, 86400000),
                "bytes_out": random.randint(10, 50000),
            })

        c2 = injector.inject_c2_beacon("10.1.2.15", "203.0.113.50", interval_sec=300, duration_hours=6)
        lm = injector.inject_lateral_movement("10.1.0.5", "192.168.1.50", ["10.1.2.15"])
        exfil = injector.inject_data_exfil("10.1.3.8", "198.51.100.20", num_connections=50)
        dga = injector.inject_dga("10.1.4.12", num_domains=200)
        scan = injector.inject_port_scan("10.1.1.99", "192.168.0.0/16", num_targets=100)

        all_records = base_records + c2 + lm + exfil + dga + scan
        _pipeline_data = _pipeline.run(all_records)

    return _pipeline, _pipeline_data


# ---- Pydantic Models ----
class ChainSummary(BaseModel):
    chain_id: str
    chain_type: str
    risk_score: float
    confidence: float
    affected_assets: list[str]
    mitre_techniques: list[str]
    description: str
    priority: int


class EntitySummary(BaseModel):
    entity_id: str
    entity_type: str
    risk_score: float
    risk_trend: str
    evidence_count: int
    tags: list[str]


class AlertSummary(BaseModel):
    alert_id: str
    entity_id: str
    score: float
    tier: str
    timestamp: str
    description: str


# ---- Routes ----
@app.get("/")
def root():
    return {"service": "network-risk-id", "version": "0.1.0", "status": "running"}


@app.get("/api/chains")
def list_chains(
    min_risk: float = Query(0.7, ge=0, le=1),
    chain_type: Optional[str] = None,
    limit: int = Query(50, le=200),
):
    _, data = get_pipeline()
    chains = data.get("chains", [])
    filtered = []
    for c in chains:
        if c.total_risk_score < min_risk:
            continue
        if chain_type and c.chain_type != chain_type:
            continue
        filtered.append({
            "chain_id": c.chain_id,
            "chain_type": c.chain_type,
            "risk_score": round(c.total_risk_score, 3),
            "confidence": round(c.confidence, 3),
            "nodes": [{"entity": n.entity, "role": n.role, "risk_score": n.risk_score} for n in c.nodes],
            "edges": [{"src": e.src, "dst": e.dst, "edge_type": e.edge_type, "event_count": e.event_count} for e in c.edges],
            "mitre_techniques": c.mitre_techniques,
            "description": c.description,
            "priority": c.investigation_priority,
            "affected_assets": c.affected_assets,
        })
        if len(filtered) >= limit:
            break
    return {"chains": filtered, "total": len(filtered), "filters": {"min_risk": min_risk, "chain_type": chain_type}}


@app.get("/api/chains/{chain_id}")
def get_chain(chain_id: str):
    _, data = get_pipeline()
    for c in data.get("chains", []):
        if c.chain_id == chain_id:
            return {
                "chain_id": c.chain_id,
                "chain_type": c.chain_type,
                "risk_score": round(c.total_risk_score, 3),
                "confidence": round(c.confidence, 3),
                "nodes": [{"entity": n.entity, "role": n.role, "entity_type": n.entity_type, "risk_score": n.risk_score} for n in c.nodes],
                "edges": [{"src": e.src, "dst": e.dst, "edge_type": e.edge_type, "event_count": e.event_count} for e in c.edges],
                "mitre_techniques": c.mitre_techniques,
                "kill_chain_phases": c.kill_chain_phases,
                "description": c.description,
                "priority": c.investigation_priority,
                "affected_assets": c.affected_assets,
            }
    return {"chain_id": chain_id, "error": "not_found"}


@app.get("/api/entities")
def list_entities(
    min_risk: float = Query(0.5, ge=0, le=1),
    entity_type: Optional[str] = None,
    limit: int = Query(50, le=200),
):
    _, data = get_pipeline()
    entities = data.get("top_entities", [])
    filtered = []
    for e in entities:
        if e["risk_score"] < min_risk:
            continue
        if entity_type and e.get("entity_type") != entity_type:
            continue
        filtered.append(e)
    return {"entities": filtered[:limit], "total": len(filtered)}


@app.get("/api/entities/{entity_id}")
def get_entity(entity_id: str):
    pipeline, data = get_pipeline()
    p = pipeline.scorer.get_entity_risk(entity_id) if pipeline else None
    if p is None or p.score == 0:
        return {"entity_id": entity_id, "risk_score": 0.0, "risk_trend": "stable", "associated_chains": [], "neighborhood": {"nodes": [], "edges": []}}

    # Get neighborhood from traceability
    trace_result = pipeline.traceability.expand_neighborhood(entity_id, depth=1) if pipeline else {"nodes": [], "edges": []}

    return {
        "entity_id": entity_id,
        "entity_type": p.entity_type,
        "risk_score": round(p.score, 4),
        "risk_trend": p.risk_trend,
        "evidence_count": p.evidence_count,
        "first_seen": p.first_seen,
        "associated_chains": p.associated_chains,
        "tags": p.tags,
        "neighborhood": trace_result,
    }


@app.get("/api/entities/{entity_id}/timeline")
def get_entity_timeline(entity_id: str, limit: int = Query(100, le=1000)):
    pipeline, _ = get_pipeline()
    events = pipeline.entity_timeline(entity_id, limit) if pipeline else []
    return {"entity_id": entity_id, "events": events}


@app.get("/api/alerts")
def list_alerts(
    min_score: float = Query(0.9, ge=0, le=1),
    tier: Optional[str] = None,
    limit: int = Query(100, le=500),
):
    pipeline, _ = get_pipeline()
    alerts = pipeline.get_alerts(min_score=min_score, limit=limit) if pipeline else []
    if tier:
        alerts = [a for a in alerts if a["tier"] == tier]
    return {"alerts": alerts[:limit], "total": len(alerts)}


@app.get("/api/reports/daily")
def get_daily_report(date: Optional[str] = None):
    _, data = get_pipeline()
    if date is None:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    report = data.get("report")
    if report is None:
        return {"date": date, "summary": {}, "top_chains": [], "top_entities": [], "mitre_coverage": {}, "recommendations": []}
    return {
        "date": date,
        "summary": {
            "total_events": report.total_events,
            "anomalies_detected": report.anomalies_detected,
            "chains_discovered": report.chains_discovered,
        },
        "top_chains": report.top_chains[:10],
        "top_entities": report.high_risk_entities[:10],
        "mitre_coverage": report.mitre_coverage,
        "recommendations": report.investigation_recommendations[:5],
    }


@app.get("/api/graph/subgraph")
def get_risk_subgraph(min_risk: float = Query(0.5, ge=0, le=1)):
    _, data = get_pipeline()
    graph_data = data.get("graph_data", {})
    nodes = []
    edges = []
    for n in graph_data.get("nodes", []):
        if n.get("risk_score", 0) >= min_risk:
            nodes.append({"id": n["id"], "entity_type": n.get("entity_type", "ip"), "risk_score": n.get("risk_score", 0)})
    for e in graph_data.get("edges", []):
        if e.get("anomalous_score", 0) >= min_risk:
            edges.append({"source": e["src"], "target": e["dst"], "edge_type": e.get("edge_type", "unknown"), "score": e.get("anomalous_score", 0)})
    return {"nodes": nodes, "edges": edges}


@app.get("/api/graph/trace")
def trace_path(src: str, dst: str, max_depth: int = Query(5, le=10)):
    pipeline, _ = get_pipeline()
    result = pipeline.trace_path(src, dst, max_depth) if pipeline else {"path": [], "exists": False}
    return result


@app.get("/api/health")
def health_check():
    _, data = get_pipeline()
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "events_processed": data.get("total_events", 0),
        "chains_detected": len(data.get("chains", [])),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
