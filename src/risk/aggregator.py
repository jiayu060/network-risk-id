"""Risk aggregator: generates daily reports and investigation recommendations."""

from collections import Counter

from src.core.types import AttackChain, EntityRiskProfile, DailyReport
from src.risk.scorer import EntityRiskScorer


class RiskAggregator:
    """Generates aggregated risk reports from chains and entity scores."""

    def __init__(self, scorer: EntityRiskScorer):
        self.scorer = scorer

    def generate_daily_report(self, date: str, chains: list[AttackChain],
                               total_events: int = 0) -> DailyReport:
        """Generate a comprehensive daily risk report."""
        report = DailyReport(date=date)

        # Basic stats
        report.total_events = total_events
        report.anomalies_detected = sum(
            p.evidence_count for p in self.scorer.entity_scores.values()
        )
        report.chains_discovered = len(chains)

        # Top high-risk entities
        report.high_risk_entities = []
        top = self.scorer.get_top_entities(20)
        for profile in top:
            report.high_risk_entities.append({
                "entity_id": profile.entity_id,
                "entity_type": profile.entity_type,
                "score": round(profile.score, 2),
                "trend": profile.risk_trend,
                "evidence_count": profile.evidence_count,
                "chains": profile.associated_chains[-5:],  # last 5 chains
            })

        # Top chains
        report.top_chains = []
        sorted_chains = sorted(chains, key=lambda c: c.total_risk_score, reverse=True)
        for chain in sorted_chains[:10]:
            report.top_chains.append({
                "chain_id": chain.chain_id,
                "type": chain.chain_type,
                "risk_score": round(chain.total_risk_score, 2),
                "confidence": round(chain.confidence, 2),
                "phases": chain.kill_chain_phases,
                "affected": chain.affected_assets,
                "description": chain.description,
                "priority": chain.investigation_priority,
            })

        # MITRE coverage
        report.mitre_coverage = self._compute_mitre_coverage(chains)

        # Investigation recommendations
        report.investigation_recommendations = self._generate_recommendations(
            chains, top
        )

        return report

    def _compute_mitre_coverage(self, chains: list[AttackChain]) -> dict:
        """Compute which MITRE techniques were observed today."""
        coverage = Counter()
        for chain in chains:
            for tech in chain.mitre_techniques:
                coverage[tech] += 1
        return dict(coverage.most_common(20))

    def _generate_recommendations(self, chains: list[AttackChain],
                                   top_entities: list[EntityRiskProfile]) -> list[dict]:
        """Generate actionable investigation recommendations."""
        recommendations = []

        # High-priority chains = immediate action items
        for chain in sorted(chains, key=lambda c: c.investigation_priority)[:5]:
            rec = self._chain_to_recommendation(chain)
            if rec:
                recommendations.append(rec)

        # High-risk entities without chains = investigate
        for profile in top_entities[:5]:
            if not profile.associated_chains:
                recommendations.append({
                    "priority": 2,
                    "action": f"Investigate high-risk entity: {profile.entity_id}",
                    "reason": f"Anomaly score {profile.score:.2f} with no associated attack chain",
                    "evidence": [f"Entity type: {profile.entity_type}",
                                f"Evidence count: {profile.evidence_count}",
                                f"Risk trend: {profile.risk_trend}"],
                })

        return recommendations

    def _chain_to_recommendation(self, chain: AttackChain) -> dict:
        """Convert an attack chain into an actionable recommendation."""
        chain_type_actions = {
            "c2_beacon": {
                "action": "Block outbound traffic from {source} to {target}",
                "reason": "C2 beaconing detected with {confidence:.0%} confidence",
            },
            "lateral_movement": {
                "action": "Isolate {pivot} and audit authentication logs",
                "reason": "Lateral movement detected via compromised credentials",
            },
            "data_exfil": {
                "action": "Block outbound transfer from {source} to {target}",
                "reason": "Suspected data exfiltration to external host",
            },
            "dga_activity": {
                "action": "Block DGA domains on DNS server and scan host {source}",
                "reason": "DGA-based C2 communication detected",
            },
        }

        template = chain_type_actions.get(
            chain.chain_type,
            {"action": "Investigate all entities: {entities}", "reason": "Suspicious activity chain detected"}
        )

        entities = {}
        for n in chain.nodes:
            if n.role == "source":
                entities["source"] = n.entity
            elif n.role == "target":
                entities["target"] = n.entity
            elif n.role == "pivot":
                entities["pivot"] = n.entity
        entities["entities"] = ", ".join(n.entity for n in chain.nodes)

        try:
            action = template["action"].format(**entities, description=chain.description)
        except KeyError:
            action = template["action"].replace("{entities}", entities.get("entities", "unknown"))
        reason = template["reason"].format(confidence=chain.confidence)

        return {
            "priority": chain.investigation_priority,
            "action": action,
            "reason": reason,
            "evidence": [
                f"Chain ID: {chain.chain_id}",
                f"Chain type: {chain.chain_type}",
                f"Risk score: {chain.total_risk_score:.2f}",
                f"Affected: {', '.join(chain.affected_assets[:5])}",
                f"MITRE: {', '.join(chain.mitre_techniques[:5])}",
            ],
        }
