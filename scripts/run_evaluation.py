#!/usr/bin/env python3
"""Run full evaluation: inject attacks → detect → measure metrics."""

import sys
import json
import random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.evaluation.attack_injector import AttackInjector
from src.evaluation.metrics import DetectionMetrics
from src.pipeline.orchestrator import PipelineOrchestrator


def run_evaluation(seed: int = 42):
    random.seed(seed)
    print("=" * 60)
    print("  网络风险识别引擎 — 评估运行")
    print("=" * 60)

    # Step 1: Generate baseline + injected logs
    print("\n[1/4] 生成测试数据...")
    injector = AttackInjector()

    internal_ips = [f"10.1.{i}.{j}" for i in range(5) for j in range(1, 20)]
    external_ips = [f"203.0.113.{i}" for i in range(1, 50)]
    ports = [80, 443, 22, 53, 445, 3389, 8080]

    base_records = []
    for _ in range(2000):
        src = random.choice(internal_ips)
        dst = random.choice(internal_ips + external_ips)
        base_records.append({
            "src_ip": src, "dst_ip": dst,
            "dst_port": random.choice(ports),
            "proto": "TCP", "event_type": "network_connect",
            "timestamp": injector.base_ts + random.randint(0, 86400000),
            "bytes_out": random.randint(10, 50000),
        })

    print("  注入 C2 Beacon...")
    c2_records = injector.inject_c2_beacon("10.1.2.15", "203.0.113.50", interval_sec=300, duration_hours=6)
    print("  注入 Lateral Movement...")
    lm_records = injector.inject_lateral_movement("10.1.0.5", "192.168.1.50", ["10.1.2.15"])
    print("  注入 Data Exfiltration...")
    exfil_records = injector.inject_data_exfil("10.1.3.8", "198.51.100.20", num_connections=50)
    print("  注入 DGA Activity...")
    dga_records = injector.inject_dga("10.1.4.12", num_domains=200)
    print("  注入 Port Scan...")
    scan_records = injector.inject_port_scan("10.1.1.99", "192.168.0.0/16", num_targets=100)

    all_records = base_records + c2_records + lm_records + exfil_records + dga_records + scan_records
    total_injected = len(all_records) - len(base_records)
    print(f"  总共生成 {len(all_records)} 条记录 ({len(base_records)} baseline + {total_injected} injected)")

    # Step 2: Run full pipeline via orchestrator (all 5 detectors)
    print("\n[2/4] 运行全流水线 (5个检测器集成)...")
    orch = PipelineOrchestrator()
    results = orch.run(all_records)

    chains = results["chains"]
    ip_scores = results["ip_scores"]
    high_risk = sum(1 for s in ip_scores.values() if s > 0.5)
    print(f"  {results['entity_count']} 个实体, {len(ip_scores)} 个IP")
    print(f"  检测到 {high_risk} 个高风险IP")
    print(f"  发现 {len(chains)} 条攻击链")
    for c in sorted(chains, key=lambda c: c.total_risk_score, reverse=True)[:5]:
        print(f"    [{c.chain_type}] {c.chain_id} score={c.total_risk_score:.3f} {' → '.join(n.entity for n in c.nodes[:5])}")

    # Step 3: Evaluate metrics
    print("\n[3/4] 评估指标计算...")
    metrics = DetectionMetrics(match_threshold=0.5)
    eval_results = metrics.evaluate(injector.injected_attacks, chains)
    latency = metrics.compute_latency(injector.injected_attacks, chains)

    # Output
    print("\n" + "=" * 60)
    print("  评估结果")
    print("=" * 60)
    print(f"  精确率 (Precision):  {eval_results['precision']:.2%}")
    print(f"  召回率 (Recall):     {eval_results['recall']:.2%}")
    print(f"  F1 分数:             {eval_results['f1']:.2%}")
    print(f"  真阳性: {eval_results['true_positives']}  假阳性: {eval_results['false_positives']}  假阴性: {eval_results['false_negatives']}")
    detect_latency = latency.get('mean_s', 0) if isinstance(latency, dict) else 0
    print(f"  检测延迟 (均值):     {detect_latency:.1f}s")

    print("\n  各类型指标:")
    for atype, m in eval_results.get("per_type", {}).items():
        print(f"    {atype:25s}  P={m.get('precision',0):.2f}  R={m.get('recall',0):.2f}")

    # Save results
    output_path = Path(__file__).parent.parent / "data" / "evaluation_results.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "results": eval_results,
            "latency": latency,
            "config": {
                "num_records": len(all_records),
                "num_entities": results["entity_count"],
                "num_chains": len(chains),
                "num_high_risk_ips": high_risk,
            }
        }, f, indent=2, default=str)
    print(f"\n  结果已保存至: {output_path}")
    print("=" * 60)

    return eval_results


if __name__ == "__main__":
    run_evaluation()
