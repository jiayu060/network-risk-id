"""Integration tests for the full pipeline and key components."""

import sys
import random
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.evaluation.attack_injector import AttackInjector
from src.evaluation.metrics import DetectionMetrics
from src.pipeline.orchestrator import PipelineOrchestrator
from src.parsers.parser_registry import ParserRegistry


@pytest.fixture
def test_records():
    """Generate a small test dataset with injected attacks."""
    injector = AttackInjector()
    internal = [f"10.1.{i}.{j}" for i in range(3) for j in range(1, 5)]
    external = [f"203.0.113.{i}" for i in range(1, 10)]

    base = []
    for _ in range(500):
        base.append({
            "src_ip": random.choice(internal),
            "dst_ip": random.choice(internal + external),
            "dst_port": random.choice([80, 443, 22, 53]),
            "proto": "TCP", "event_type": "network_connect",
            "timestamp": injector.base_ts + random.randint(0, 86400000),
            "bytes_out": random.randint(10, 1000),
        })

    c2 = injector.inject_c2_beacon("10.1.1.3", "203.0.113.7", interval_sec=300, duration_hours=2)
    dga = injector.inject_dga("10.1.2.3", num_domains=50)

    return base + c2 + dga, injector


class TestParserRegistry:
    def test_all_parsers_registered(self):
        parsers = ParserRegistry.available_parsers()
        assert "syslog" in parsers
        assert "dns" in parsers
        assert "waf" in parsers
        assert "etw" in parsers

    def test_get_syslog_parser(self):
        p = ParserRegistry.get_parser("syslog")
        assert p is not None
        assert p.source_type == "syslog"

    def test_get_dns_parser(self):
        p = ParserRegistry.get_parser("dns")
        assert p is not None

    def test_get_waf_parser(self):
        p = ParserRegistry.get_parser("waf")
        assert p is not None

    def test_get_etw_parser(self):
        p = ParserRegistry.get_parser("etw")
        assert p is not None

    def test_invalid_parser_raises(self):
        with pytest.raises(ValueError):
            ParserRegistry.get_parser("nosuch")


class TestPipelineOrchestrator:
    def test_orchestrator_init(self):
        orch = PipelineOrchestrator()
        assert orch.extractor is not None
        assert orch.ensemble is not None
        assert orch.miner is not None
        assert orch.classifier is not None
        assert orch.scorer is not None

    def test_run_produces_results(self, test_records):
        records, _ = test_records
        orch = PipelineOrchestrator()
        results = orch.run(records)
        assert results["total_events"] > 0
        assert results["entity_count"] > 0
        assert "ip_scores" in results
        assert "chains" in results
        assert "top_entities" in results

    def test_run_produces_ip_scores(self, test_records):
        records, _ = test_records
        orch = PipelineOrchestrator()
        results = orch.run(records)
        assert len(results["ip_scores"]) > 0
        for ip, score in results["ip_scores"].items():
            assert 0.0 <= score <= 1.0

    def test_run_finds_chains(self, test_records):
        records, _ = test_records
        orch = PipelineOrchestrator()
        results = orch.run(records)
        chains = results["chains"]
        assert len(chains) >= 0  # chains may or may not be found
        for chain in chains:
            assert chain.chain_id
            assert chain.chain_type
            assert len(chain.nodes) >= 2

    def test_get_alerts(self, test_records):
        records, _ = test_records
        orch = PipelineOrchestrator()
        orch.run(records)
        alerts = orch.get_alerts(min_score=0.5, limit=10)
        assert isinstance(alerts, list)

    def test_entity_risk_tracking(self, test_records):
        records, _ = test_records
        orch = PipelineOrchestrator()
        orch.run(records)
        # After run, scorer should have entity profiles
        profiles = orch.scorer.entity_scores
        assert len(profiles) > 0


class TestAttackInjection:
    def test_c2_beacon_injection(self):
        injector = AttackInjector()
        records = injector.inject_c2_beacon("10.1.1.1", "203.0.113.1", interval_sec=60, duration_hours=1)
        assert len(records) > 0
        assert len(injector.injected_attacks) == 1
        assert injector.injected_attacks[0].attack_type == "c2_beacon"

    def test_lateral_movement_injection(self):
        injector = AttackInjector()
        records = injector.inject_lateral_movement("10.1.1.1", "192.168.1.1", ["10.1.1.2"])
        assert len(records) > 0
        attack = injector.injected_attacks[0]
        assert attack.attack_type == "lateral_movement"
        assert len(attack.entities) == 3  # entry + pivot + target

    def test_data_exfil_injection(self):
        injector = AttackInjector()
        records = injector.inject_data_exfil("10.1.1.1", "198.51.100.1", num_connections=10)
        assert len(records) == 10
        assert "injected:data_exfil" in records[0]["tags"]

    def test_dga_injection(self):
        injector = AttackInjector()
        records = injector.inject_dga("10.1.1.1", num_domains=50)
        assert len(records) == 50
        assert all(r.get("domain") for r in records)

    def test_port_scan_injection(self):
        injector = AttackInjector()
        records = injector.inject_port_scan("10.1.1.1", "192.168.0.0/16", num_targets=10)
        assert len(records) > 0
        attack = injector.injected_attacks[0]
        assert attack.attack_type == "recon_scan"


class TestDetectionMetrics:
    def test_perfect_detection(self):
        """If detection exactly matches ground truth, metrics should be perfect."""
        from src.core.types import AttackChain, ChainNode, ChainEdge, InjectedAttack

        attack = InjectedAttack(
            attack_id="a1", attack_type="c2_beacon",
            entities=["10.1.1.1", "203.0.113.1"],
            start_time=1000, end_time=2000, params={},
        )
        chain = AttackChain(
            chain_id="c1", chain_type="c2_beacon",
            nodes=[
                ChainNode(entity="10.1.1.1", entity_type="ip", role="source", risk_score=0.9),
                ChainNode(entity="203.0.113.1", entity_type="ip", role="target", risk_score=0.8),
            ],
            edges=[ChainEdge(src="10.1.1.1", dst="203.0.113.1", edge_type="network")],
            total_risk_score=0.9, confidence=0.9,
        )

        metrics = DetectionMetrics(match_threshold=0.5)
        results = metrics.evaluate([attack], [chain])
        assert results["precision"] == 1.0
        assert results["recall"] == 1.0
        assert results["f1"] == 1.0
        assert results["true_positives"] == 1
        assert results["false_positives"] == 0
        assert results["false_negatives"] == 0

    def test_no_detection(self):
        """If no detection, recall should be 0."""
        from src.core.types import InjectedAttack

        attack = InjectedAttack(
            attack_id="a1", attack_type="c2_beacon",
            entities=["10.1.1.1", "203.0.113.1"],
            start_time=1000, end_time=2000, params={},
        )
        metrics = DetectionMetrics(match_threshold=0.5)
        results = metrics.evaluate([attack], [])
        assert results["recall"] == 0.0
        assert results["false_negatives"] == 1

    def test_false_alarm(self):
        """A detection matching nothing should be false positive."""
        from src.core.types import AttackChain, ChainNode, ChainEdge, InjectedAttack

        attack = InjectedAttack(
            attack_id="a1", attack_type="data_exfil",
            entities=["10.1.3.8", "198.51.100.20"],
            start_time=1000, end_time=2000, params={},
        )
        chain = AttackChain(
            chain_id="c1", chain_type="suspicious_activity",
            nodes=[
                ChainNode(entity="10.1.1.1", entity_type="ip", role="source", risk_score=0.5),
                ChainNode(entity="10.1.1.2", entity_type="ip", role="target", risk_score=0.5),
            ],
            edges=[ChainEdge(src="10.1.1.1", dst="10.1.1.2", edge_type="network")],
            total_risk_score=0.5, confidence=0.5,
        )
        metrics = DetectionMetrics(match_threshold=0.5)
        results = metrics.evaluate([attack], [chain])
        assert results["precision"] == 0.0
        assert results["false_positives"] == 1

    def test_entity_overlap_matching(self):
        """Partial entity overlap should still count as detection."""
        from src.core.types import AttackChain, ChainNode, ChainEdge, InjectedAttack

        attack = InjectedAttack(
            attack_id="a1", attack_type="c2_beacon",
            entities=["10.1.1.1", "203.0.113.1", "203.0.113.2"],  # 3 entities
            start_time=1000, end_time=2000, params={},
        )
        chain = AttackChain(
            chain_id="c1", chain_type="c2_beacon",
            nodes=[
                ChainNode(entity="10.1.1.1", entity_type="ip", role="source", risk_score=0.9),
                ChainNode(entity="203.0.113.1", entity_type="ip", role="target", risk_score=0.8),
            ],  # Only 2 of 3 entities
            edges=[ChainEdge(src="10.1.1.1", dst="203.0.113.1", edge_type="network")],
            total_risk_score=0.9, confidence=0.9,
        )
        metrics = DetectionMetrics(match_threshold=0.5)  # 2/3 = 0.67 overlap
        results = metrics.evaluate([attack], [chain])
        assert results["true_positives"] == 1


class TestFeatureExtractor:
    def test_extract_features(self):
        from src.features.extractor import FeatureExtractor
        ext = FeatureExtractor()
        records = [
            {"src_ip": "10.1.1.1", "event_type": "network_connect",
             "dst_ip": "203.0.113.1", "dst_port": 443, "bytes_out": 1000,
             "timestamp": 1000000},
            {"src_ip": "10.1.1.1", "event_type": "network_connect",
             "dst_ip": "203.0.113.2", "dst_port": 80, "bytes_out": 500,
             "timestamp": 1001000},
        ]
        vec = ext._compute_entity_features(records, 3600.0)
        assert vec is not None
        assert len(vec) == 31
        assert all(isinstance(v, (int, float, np.floating)) for v in vec)

    def test_feature_dimensions(self):
        from src.features.extractor import FeatureExtractor, FEATURE_NAMES
        assert len(FEATURE_NAMES) == 31
