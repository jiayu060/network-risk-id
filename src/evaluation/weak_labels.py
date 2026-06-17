"""Weak label generation for semi-supervised evaluation."""

from src.core.types import AttackChain


class WeakLabelGenerator:
    """Generates weak labels from threat intel, heuristic rules, and analyst feedback."""

    # High-confidence heuristic rules
    RULES = [
        ("suspicious_port", lambda c: any(
            e.get("dst_port") in (4444, 1337, 31337, 6667, 6666, 8888)
            for e in c if isinstance(e, dict)
        )),
        ("dga_tld", lambda c: any(
            (n.entity if hasattr(n, 'entity') else str(n)).endswith(('.xyz', '.top', '.pw', '.tk', '.ml', '.ga'))
            for n in (c.nodes if hasattr(c, 'nodes') else [])
        )),
        ("off_hours_activity", lambda c: 0.5),  # default moderate confidence
    ]

    def __init__(self, threat_intel_matcher=None):
        self.ti_matcher = threat_intel_matcher

    def label_chain(self, chain: AttackChain) -> dict:
        """Generate weak label for an attack chain.

        Returns {label: 'malicious'|'suspicious'|'benign'|'unknown', confidence: float}
        """
        confidences = []

        # Heuristic rules
        for rule_name, rule_fn in self.RULES:
            try:
                confidence = rule_fn(chain)
                if isinstance(confidence, bool):
                    confidence = 0.9 if confidence else 0.0
                confidences.append(confidence)
            except Exception:
                pass

        # Threat intel matching
        if self.ti_matcher:
            for node in chain.nodes:
                match = self.ti_matcher.check_entity(node.entity, node.entity_type)
                if match:
                    confidences.append(match.get("confidence", 0.8))

        if not confidences:
            return {"label": "unknown", "confidence": 0.0}

        avg_confidence = sum(confidences) / len(confidences)

        if avg_confidence >= 0.8:
            label = "malicious"
        elif avg_confidence >= 0.5:
            label = "suspicious"
        else:
            label = "unknown"

        return {"label": label, "confidence": round(avg_confidence, 3)}

    def label_chains(self, chains: list[AttackChain]) -> list[dict]:
        """Label multiple chains."""
        return [self.label_chain(c) for c in chains]

    def get_high_confidence_matches(self, chains: list[AttackChain],
                                     min_confidence: float = 0.8) -> list[AttackChain]:
        """Filter chains with high-confidence malicious labels."""
        results = []
        for chain in chains:
            label = self.label_chain(chain)
            if label["label"] == "malicious" and label["confidence"] >= min_confidence:
                results.append(chain)
        return results
