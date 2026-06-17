"""CLI entry point for network-risk-id."""

import json
import os
import sys

import click

from src.parsers.parser_registry import ParserRegistry


@click.group()
@click.version_option(version="0.1.0", prog_name="network-risk-id")
def main():
    """网络风险识别分析引擎 — Network Risk Identification Engine"""


@main.command()
@click.option("--source-type", "-s", required=True, help="Log source type (syslog, etw, waf, dns)")
@click.option("--input", "-i", required=True, help="Input file or directory path")
@click.option("--output", "-o", required=True, help="Output directory for normalized Parquet")
@click.option("--pattern", default="*.log", help="File pattern when input is a directory")
def parse(source_type: str, input: str, output: str, pattern: str):
    """Parse raw logs and output normalized Parquet files."""
    from src.pipeline.normalizer import LogNormalizer

    normalizer = LogNormalizer()
    if os.path.isdir(input):
        normalizer.normalize_directory(input, source_type, output, pattern)
    else:
        normalizer.normalize_file(input, source_type, output)


@main.command()
@click.option("--window", "-w", default="1h", help="Time window size (e.g. 1h, 6h, 1d)")
@click.option("--input-dir", "-i", required=True, help="Directory with normalized Parquet or raw log files")
@click.option("--source-type", "-s", default="syslog", help="Log source type if input is raw logs")
@click.option("--output-dir", "-o", required=True, help="Output directory for features")
def extract(window: str, input_dir: str, source_type: str, output_dir: str):
    """Extract features from normalized logs or raw logs."""
    from src.pipeline.orchestrator import PipelineOrchestrator

    orch = PipelineOrchestrator()
    records = _load_records(input_dir, source_type)
    results = orch.run(records)

    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "features.json")
    with open(out_path, "w") as f:
        json.dump({
            "entity_count": results["entity_count"],
            "total_events": results["total_events"],
        }, f, indent=2)
    click.echo(f"Extracted features for {results['entity_count']} entities → {out_path}")


@main.command()
@click.option("--window", "-w", default="1h", help="Time window size")
@click.option("--input-dir", "-i", required=True, help="Directory with raw log files or normalized Parquet")
@click.option("--source-type", "-s", default="syslog", help="Log source type")
@click.option("--output-dir", "-o", required=True, help="Output directory for anomaly scores")
@click.option("--detectors", "-d", default="all", help="Comma-separated detector names or 'all'")
def detect(window: str, input_dir: str, source_type: str, output_dir: str, detectors: str):
    """Run anomaly detection on logs."""
    from src.pipeline.orchestrator import PipelineOrchestrator

    orch = PipelineOrchestrator()
    records = _load_records(input_dir, source_type)
    results = orch.run(records)

    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "anomaly_scores.json")
    with open(out_path, "w") as f:
        json.dump({
            "ip_scores": results["ip_scores"],
            "alerts": orch.get_alerts(min_score=0.9),
            "high_risk_count": sum(1 for s in results["ip_scores"].values() if s > 0.5),
        }, f, indent=2)
    high = sum(1 for s in results["ip_scores"].values() if s > 0.5)
    alerts = orch.get_alerts(min_score=0.9)
    click.echo(f"Detection complete: {len(results['ip_scores'])} IPs, {high} high-risk, {len(alerts)} alerts → {out_path}")


@main.command()
@click.option("--input-dir", "-i", required=True, help="Directory with log files")
@click.option("--source-type", "-s", default="syslog", help="Log source type")
@click.option("--output-dir", "-o", required=True, help="Output directory for attack chains")
def mine_chains(input_dir: str, source_type: str, output_dir: str):
    """Mine attack chains from logs."""
    from src.pipeline.orchestrator import PipelineOrchestrator

    orch = PipelineOrchestrator()
    records = _load_records(input_dir, source_type)
    results = orch.run(records)

    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "chains.json")
    chains_data = []
    for c in results["chains"]:
        chains_data.append({
            "chain_id": c.chain_id,
            "chain_type": c.chain_type,
            "risk_score": c.total_risk_score,
            "confidence": c.confidence,
            "nodes": [{"entity": n.entity, "role": n.role, "risk_score": n.risk_score} for n in c.nodes],
            "edges": [{"src": e.src, "dst": e.dst, "edge_type": e.edge_type, "event_count": e.event_count} for e in c.edges],
            "mitre_techniques": c.mitre_techniques,
            "description": c.description,
            "priority": c.investigation_priority,
        })
    with open(out_path, "w") as f:
        json.dump({"chains": chains_data, "total": len(chains_data)}, f, indent=2)
    click.echo(f"Found {len(chains_data)} attack chains → {out_path}")


@main.command()
@click.option("--entity", "-e", help="Entity ID (IP address) to query risk score for")
@click.option("--input-dir", "-i", help="Directory with log files")
@click.option("--source-type", "-s", default="syslog", help="Log source type")
@click.option("--limit", "-n", default=20, help="Number of top entities to show")
def risk(entity: str, input_dir: str, source_type: str, limit: int):
    """Query entity risk scores."""
    from src.pipeline.orchestrator import PipelineOrchestrator

    if input_dir:
        orch = PipelineOrchestrator()
        records = _load_records(input_dir, source_type)
        orch.run(records)

    if entity:
        if input_dir:
            p = orch.scorer.get_entity_risk(entity)
        else:
            click.echo("Need --input-dir to load data first")
            return
        click.echo(f"Entity: {entity}")
        click.echo(f"  Risk Score: {p.score:.4f}")
        click.echo(f"  Trend: {p.risk_trend}")
        click.echo(f"  Evidence Count: {p.evidence_count}")
        click.echo(f"  Tags: {p.tags}")
        click.echo(f"  Associated Chains: {p.associated_chains}")
    elif input_dir:
        top = orch.scorer.get_top_entities(limit)
        click.echo(f"\n{'Entity':<20} {'Score':>8}  {'Trend':<12}  {'Type':<8}")
        click.echo("-" * 56)
        for p in top:
            click.echo(f"{p.entity_id:<20} {p.score:>8.4f}  {p.risk_trend:<12}  {p.entity_type:<8}")
    else:
        click.echo("Specify --entity or --input-dir")


@main.command()
@click.option("--date", "-d", help="Date to generate report for (YYYY-MM-DD)")
@click.option("--input-dir", "-i", help="Directory with log files")
@click.option("--source-type", "-s", default="syslog", help="Log source type")
def report(date: str, input_dir: str, source_type: str):
    """Generate daily risk report."""
    from src.pipeline.orchestrator import PipelineOrchestrator

    if not input_dir:
        click.echo("--input-dir is required")
        return

    orch = PipelineOrchestrator()
    records = _load_records(input_dir, source_type)
    results = orch.run(records)
    rpt = results["report"]

    if date is None:
        import time
        date = time.strftime("%Y-%m-%d")

    click.echo(f"\n{'='*60}")
    click.echo(f"  每日风险报告 — {date}")
    click.echo(f"{'='*60}")
    click.echo(f"  处理事件: {rpt.total_events:,}")
    click.echo(f"  检测异常: {rpt.anomalies_detected}")
    click.echo(f"  发现攻击链: {rpt.chains_discovered}")
    click.echo(f"\n  Top高风险实体:")
    for e in rpt.high_risk_entities[:10]:
        click.echo(f"    {e['entity_id']:<18} score={e['score']:.3f}  trend={e['trend']}")
    click.echo(f"\n  Top攻击链:")
    for c in rpt.top_chains[:5]:
        click.echo(f"    [{c['type']}] {c['description'][:80]}... risk={c['risk_score']:.2f}")
    if rpt.mitre_coverage:
        click.echo(f"\n  MITRE ATT&CK 覆盖: {rpt.mitre_coverage}")
    click.echo(f"\n  处置建议:")
    for i, rec in enumerate(rpt.investigation_recommendations[:5], 1):
        click.echo(f"    {i}. {rec}")
    click.echo(f"{'='*60}")


@main.command()
@click.option("--port", "-p", default=8503, help="Dashboard port")
def dashboard(port: int):
    """Launch interactive Streamlit dashboard."""
    import subprocess
    dashboard_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard", "app.py")
    subprocess.run([sys.executable, "-m", "streamlit", "run", dashboard_path,
                    "--server.port", str(port),
                    "--server.headless", "true",
                    "--browser.gatherUsageStats", "false"])


@main.command()
@click.option("--output", "-o", default=None, help="Output path for evaluation results JSON")
def evaluate(output: str):
    """Run full evaluation with synthetic attack injection."""
    from scripts.run_evaluation import run_evaluation
    results = run_evaluation()
    click.echo(f"\nPrecision: {results['precision']:.2%}  Recall: {results['recall']:.2%}  F1: {results['f1']:.2%}")
    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        click.echo(f"Results saved to {output}")


def _load_records(input_dir: str, source_type: str = "syslog") -> list[dict]:
    """Load records from Parquet files or raw log files in a directory."""
    import pyarrow.parquet as pq
    from pathlib import Path

    records = []
    path = Path(input_dir)
    if not path.exists():
        click.echo(f"Error: directory not found: {input_dir}", err=True)
        return records

    # Try Parquet first
    parquet_files = list(path.rglob("*.parquet"))
    if parquet_files:
        for f in parquet_files:
            try:
                table = pq.read_table(str(f))
                records.extend(table.to_pylist())
            except Exception as e:
                click.echo(f"Warning: failed to read {f}: {e}", err=True)
        if records:
            return records

    # Fall back to log files
    parser = ParserRegistry.get_parser(source_type)
    for pattern in ["*.log", "*.txt", "*"]:
        for f in path.rglob(pattern):
            if f.suffix in (".parquet", ".json"):
                continue
            try:
                with open(str(f), "r", encoding="utf-8", errors="replace") as fh:
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
        if records:
            break

    return records


if __name__ == "__main__":
    main()
