"""Unified pipeline orchestrator: parse → features → detect → chains → risk → report."""

import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

import numpy as np

from src.core.types import AttackChain, EntityRiskProfile, DailyReport
from src.features.extractor import FeatureExtractor
from src.detectors.ensemble import DetectorEnsemble
from src.chains.graph_builder import TemporalGraph
from src.chains.rare_path_miner import RarePathMiner
from src.chains.lateral_movement import LateralMovementDetector
from src.chains.chain_classifier import ChainClassifier
from src.chains.dga_detector import DGADetector
from src.risk.scorer import EntityRiskScorer
from src.risk.aggregator import RiskAggregator
from src.risk.traceability import TraceabilityGraph


class PipelineOrchestrator:
    """End-to-end pipeline: raw records → chains + risk scores + report."""

    def __init__(
        self,
        window_size_ms: int = 3_600_000,
        half_life_hours: float = 24.0,
        db_path: str = None,
    ):
        if db_path is None:
            db_path = str(Path(__file__).parent.parent.parent / "data" / "state" / "traceability.db")
        self.extractor = FeatureExtractor(window_size_ms=window_size_ms)
        self.ensemble = DetectorEnsemble()
        self.miner = RarePathMiner()
        self.lm_detector = LateralMovementDetector()
        self.classifier = ChainClassifier()
        self.dga = DGADetector()
        self.scorer = EntityRiskScorer(half_life_hours=half_life_hours)
        self.aggregator = RiskAggregator(self.scorer)
        self.traceability = TraceabilityGraph(db_path=db_path)

    def run(self, records: list[dict]) -> dict:
        """Full pipeline: records → results.

        Returns dict with keys:
            chains, ip_scores, entity_profiles, top_entities, dga_results,
            edge_summary, total_events, entity_count, graph_data
        """
        total = len(records)

        # ---- Step 1: Feature extraction ----
        entity_groups = defaultdict(list)
        for r in records:
            eid = f"{r.get('src_ip', 'unknown')}:{r.get('event_type', 'unknown')}"
            entity_groups[eid].append(r)

        feature_vectors = {}
        entity_list = []
        for eid, rows in entity_groups.items():
            vec = self.extractor._compute_entity_features(rows, 3600.0)
            feature_vectors[eid] = vec
            entity_list.append(eid)

        if not feature_vectors:
            return {
                "chains": [], "ip_scores": {}, "entity_profiles": [],
                "top_entities": [], "dga_results": [], "edge_summary": {},
                "total_events": total, "entity_count": 0, "graph_data": {},
                "report": None,
            }

        X = np.array(list(feature_vectors.values()))

        # ---- Step 2: Anomaly detection (adaptive detector selection) ----
        # For small datasets, use only fast detectors to avoid training overhead
        if X.shape[0] < 200:
            self.ensemble.detectors = {
                "isolation_forest": self.ensemble.detectors.get("isolation_forest"),
                "ecod": self.ensemble.detectors.get("ecod"),
            }
            # Remove detectors that don't exist (fallback)
            self.ensemble.detectors = {k: v for k, v in self.ensemble.detectors.items() if v is not None}
        if not self.ensemble.detectors:
            # Ensure at least isolation_forest
            from src.detectors.isolation_forest import IsolationForestDetector
            self.ensemble.detectors = {"isolation_forest": IsolationForestDetector()}

        self.ensemble.fit(X)
        scores = self.ensemble.score(X)
        entity_scores_raw = {entity_list[i]: float(scores[i]) for i in range(len(entity_list))}

        # Aggregate per-IP scores
        ip_scores = {}
        for eid, s in entity_scores_raw.items():
            ip = eid.split(":")[0] if ":" in eid else eid
            ip_scores[ip] = max(ip_scores.get(ip, 0), s)

        # ---- Step 3: Build graph + mine chains ----
        tg = TemporalGraph()
        tg.add_window(records)
        tg.apply_anomaly_scores(ip_scores)

        chains = self.miner.mine(tg)
        chains.extend(self.lm_detector.detect(tg))
        chains = self.classifier.classify_batch(chains)

        # ---- Step 4: DGA detection ----
        all_domains = [r["domain"] for r in records if r.get("domain")]
        dga_results = []
        if all_domains:
            self.dga.fit(all_domains)
            dga_results = self.dga.detect(all_domains)

        # ---- Step 5: Risk scoring ----
        self.scorer.update(chains, ip_scores)
        self.traceability.merge_window(tg)

        top_entities = []
        for ip, s in sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:30]:
            p = self.scorer.get_entity_risk(ip)
            top_entities.append({
                "entity_id": ip, "entity_type": "ip",
                "risk_score": round(s, 3), "risk_trend": p.risk_trend,
                "evidence_count": p.evidence_count,
                "chains": p.associated_chains, "tags": p.tags,
            })

        # ---- Step 6: Edge summary for traceability ----
        edge_summary = defaultdict(list)
        for r in records:
            if r.get("src_ip") and r.get("dst_ip"):
                edge_summary[(r["src_ip"], r["dst_ip"])].append(r)

        report = self.aggregator.generate_daily_report(
            date=time.strftime("%Y-%m-%d"),
            chains=chains,
            total_events=total,
        )

        return {
            "chains": chains,
            "ip_scores": ip_scores,
            "entity_profiles": list(self.scorer.entity_scores.values()),
            "top_entities": top_entities,
            "dga_results": dga_results,
            "edge_summary": dict(edge_summary),
            "total_events": total,
            "entity_count": len(entity_list),
            "graph_data": tg.to_dict(),
            "report": report,
        }

    def run_from_files(self, input_dir: str, source_type: str) -> dict:
        """Parse log files then run the full pipeline."""
        from src.parsers.parser_registry import ParserRegistry

        parser = ParserRegistry.get_parser(source_type)
        records = []
        for f in Path(input_dir).rglob("*.log"):
            records.extend(self._parse_file(parser, str(f)))
        for f in Path(input_dir).rglob("*.txt"):
            records.extend(self._parse_file(parser, str(f)))
        return self.run(records)

    def run_from_parquet(self, parquet_dir: str) -> dict:
        """Read normalized Parquet files then run the full pipeline."""
        import pyarrow.parquet as pq

        records = []
        for f in Path(parquet_dir).rglob("*.parquet"):
            table = pq.read_table(str(f))
            records.extend(table.to_pylist())
        return self.run(records)

    @staticmethod
    def _parse_file(parser, path: str) -> list[dict]:
        records = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = parser.parse_line(line)
                        if r:
                            records.append(r)
                    except Exception:
                        pass
        except Exception:
            pass
        return records

    def trace_path(self, src: str, dst: str, max_depth: int = 5) -> dict:
        """Query traceability between two entities."""
        return self.traceability.trace_path(src, dst, max_depth)

    def entity_timeline(self, entity_id: str, limit: int = 100) -> list:
        """Get chronological timeline for an entity."""
        return self.traceability.entity_timeline(entity_id, limit)

    def get_alerts(self, min_score: float = 0.9, limit: int = 100) -> list:
        """Generate alerts from high-risk entities."""
        alerts = []
        for profile in self.scorer.get_top_entities(limit):
            if profile.score >= min_score:
                alerts.append({
                    "alert_id": f"ALT-{profile.entity_id}",
                    "entity_id": profile.entity_id,
                    "score": round(profile.score, 3),
                    "tier": "critical" if profile.score > 0.95 else "investigation",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "description": f"High risk entity: {profile.entity_id} (score={profile.score:.3f})",
                })
        return alerts
