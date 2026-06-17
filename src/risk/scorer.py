"""Entity risk scoring with exponential time decay."""

import time
from collections import defaultdict

from src.core.types import EntityRiskProfile, AttackChain


class EntityRiskScorer:
    """Accumulates entity risk scores with exponential time decay.

    Risk decay follows: score *= 2^(-dt / half_life)
    """

    def __init__(self, half_life_hours: float = 24.0):
        self.half_life = half_life_hours * 3600
        self.decay_factor_per_sec = 2 ** (-1 / self.half_life)
        self.entity_scores: dict[str, EntityRiskProfile] = {}

    def update(self, chains: list[AttackChain], anomaly_scores: dict[str, float],
               current_time: float = None):
        """Update entity risk scores with new chains and anomaly scores."""
        if current_time is None:
            current_time = time.time()

        # Decay all existing scores
        for entity_id in list(self.entity_scores.keys()):
            profile = self.entity_scores[entity_id]
            elapsed = current_time - profile.last_updated
            profile.score *= self.decay_factor_per_sec ** elapsed
            profile.last_updated = current_time

        # Add anomaly scores
        for entity_id, score in anomaly_scores.items():
            if score <= 0:
                continue
            entity_type = self._infer_entity_type(entity_id)

            if entity_id in self.entity_scores:
                profile = self.entity_scores[entity_id]
                profile.score += score
                profile.evidence_count += 1
            else:
                self.entity_scores[entity_id] = EntityRiskProfile(
                    entity_id=entity_id,
                    entity_type=entity_type,
                    score=score,
                    first_seen=int(current_time),
                    last_updated=current_time,
                    evidence_count=1,
                )

        # Add chain contributions
        for chain in chains:
            for node in chain.nodes:
                entity_id = node.entity
                if entity_id in self.entity_scores:
                    profile = self.entity_scores[entity_id]
                    profile.score += chain.total_risk_score * 0.5
                    if chain.chain_id not in profile.associated_chains:
                        profile.associated_chains.append(chain.chain_id)
                    profile.tags.extend(chain.mitre_techniques)
                    profile.tags = list(set(profile.tags))
                else:
                    self.entity_scores[entity_id] = EntityRiskProfile(
                        entity_id=entity_id,
                        entity_type=node.entity_type,
                        score=chain.total_risk_score * 0.5,
                        first_seen=int(current_time),
                        last_updated=current_time,
                        associated_chains=[chain.chain_id],
                        evidence_count=1,
                        tags=list(chain.mitre_techniques),
                    )

        # Compute risk trends
        for entity_id, profile in self.entity_scores.items():
            if profile.baseline_score > 0:
                ratio = profile.score / max(profile.baseline_score, 0.01)
                if ratio > 2.0:
                    profile.risk_trend = "increasing"
                elif ratio < 0.5:
                    profile.risk_trend = "decreasing"
                else:
                    profile.risk_trend = "stable"

    def get_entity_risk(self, entity_id: str) -> EntityRiskProfile:
        """Get risk profile for a single entity."""
        if entity_id in self.entity_scores:
            # Apply decay before returning
            profile = self.entity_scores[entity_id]
            elapsed = time.time() - profile.last_updated
            profile.score *= self.decay_factor_per_sec ** elapsed
            profile.last_updated = time.time()
            return profile
        return EntityRiskProfile(entity_id=entity_id, entity_type="unknown", score=0.0)

    def get_top_entities(self, n: int = 50) -> list[EntityRiskProfile]:
        """Get top N highest-risk entities."""
        profiles = []
        for entity_id in self.entity_scores:
            profiles.append(self.get_entity_risk(entity_id))
        profiles.sort(key=lambda p: p.score, reverse=True)
        return profiles[:n]

    def to_dict(self) -> dict:
        return {eid: {
            "entity_id": p.entity_id,
            "entity_type": p.entity_type,
            "score": p.score,
            "baseline_score": p.baseline_score,
            "last_updated": p.last_updated,
            "associated_chains": p.associated_chains,
            "evidence_count": p.evidence_count,
            "first_seen": p.first_seen,
            "risk_trend": p.risk_trend,
            "tags": p.tags,
        } for eid, p in self.entity_scores.items()}

    def set_baselines(self):
        """Set current scores as baselines for trend detection."""
        for profile in self.entity_scores.values():
            profile.baseline_score = profile.score

    def _infer_entity_type(self, entity_id: str) -> str:
        """Guess entity type from ID format."""
        import re
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", entity_id):
            return "ip"
        if re.match(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]+$", entity_id):
            return "ip"
        if "." in entity_id and not "@" in entity_id:
            return "domain"
        if "@" in entity_id:
            return "user"
        if "\\" in entity_id:
            return "process"
        return "host"
