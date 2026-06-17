"""Detection evaluation metrics: precision, recall, F1, latency."""

from src.core.types import AttackChain, InjectedAttack


class DetectionMetrics:
    """Computes detection metrics by matching detected chains to injected ground truth."""

    def __init__(self, match_threshold: float = 0.7):
        self.match_threshold = match_threshold  # entity overlap ratio for true positive

    def evaluate(self, ground_truth: list[InjectedAttack],
                 detected_chains: list[AttackChain]) -> dict:
        """Compute detection metrics.

        A detection is a True Positive if it shares >= match_threshold
        of entities with an injected attack AND the chain type matches.
        """
        tp = 0
        fn = 0
        matched_gt = set()
        matched_detected = set()

        # Entity-overlap matching
        for i, gt in enumerate(ground_truth):
            gt_entities = set(gt.entities)
            best_overlap = 0.0
            best_j = -1
            for j, dc in enumerate(detected_chains):
                dc_entities = {n.entity for n in dc.nodes}
                overlap = len(gt_entities & dc_entities) / max(len(gt_entities), 1)

                # Bonus for type match
                if self._type_match(gt.attack_type, dc.chain_type):
                    overlap *= 1.2

                if overlap > best_overlap:
                    best_overlap = overlap
                    best_j = j

            if best_overlap >= self.match_threshold:
                tp += 1
                matched_gt.add(i)
                if best_j >= 0:
                    matched_detected.add(best_j)
            else:
                fn += 1

        fp = len(detected_chains) - len(matched_detected)

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-10)

        # Per-type metrics
        per_type = self._per_type_metrics(ground_truth, detected_chains)

        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "total_injected": len(ground_truth),
            "total_detected": len(detected_chains),
            "per_type": per_type,
        }

    def _per_type_metrics(self, ground_truth: list[InjectedAttack],
                           detected_chains: list[AttackChain]) -> dict:
        """Per-attack-type precision/recall."""
        types = {}
        for gt in ground_truth:
            t = gt.attack_type
            types.setdefault(t, {"injected": 0, "detected": 0, "matched": 0})
            types[t]["injected"] += 1

            gt_entities = set(gt.entities)
            for dc in detected_chains:
                dc_entities = {n.entity for n in dc.nodes}
                overlap = len(gt_entities & dc_entities) / max(len(gt_entities), 1)
                if overlap >= self.match_threshold:
                    types[t]["matched"] += 1
                    break

        for t in types:
            types[t]["recall"] = round(types[t]["matched"] / max(types[t]["injected"], 1), 4)

        for dc in detected_chains:
            t = dc.chain_type
            if t in types:
                types[t]["detected"] += 1
            else:
                types.setdefault(t, {"injected": 0, "detected": 0, "matched": 0})
                types[t]["detected"] += 1

        for t in types:
            types[t]["precision"] = round(
                types[t].get("matched", 0) / max(types[t].get("detected", 0), 1), 4
            )

        return types

    def _type_match(self, injected_type: str, detected_type: str) -> bool:
        """Check if injected attack type semantically matches detected chain type."""
        type_map = {
            "c2_beacon": ["c2_beacon"],
            "lateral_movement": ["lateral_movement"],
            "data_exfil": ["data_exfil"],
            "dga_activity": ["dga_activity"],
            "recon_scan": ["recon_scan"],
            "ransomware_pattern": ["ransomware_pattern", "c2_beacon"],
            "credential_theft": ["credential_theft"],
            "brute_force": ["brute_force", "credential_theft"],
            "anti_forensics": ["anti_forensics"],
            "persistence": ["persistence"],
            "mitm_attack": ["mitm_attack"],
            "tool_download": ["tool_download"],
            "internal_recon": ["internal_recon"],
            "privilege_escalation": ["privilege_escalation"],
        }
        return detected_type in type_map.get(injected_type, ["suspicious_activity"])

    def compute_latency(self, ground_truth: list[InjectedAttack],
                         detected_chains: list[AttackChain]) -> dict:
        """Compute detection latency in seconds."""
        latencies = []
        for gt in ground_truth:
            gt_entities = set(gt.entities)
            for dc in detected_chains:
                dc_entities = {n.entity for n in dc.nodes}
                overlap = len(gt_entities & dc_entities) / max(len(gt_entities), 1)
                if overlap >= self.match_threshold:
                    # Latency = detection time - attack start time
                    latency_s = (dc.first_seen - gt.start_time) / 1000.0
                    latencies.append(max(0, latency_s))
                    break

        if not latencies:
            return {"mean_ms": 0, "min_ms": 0, "max_ms": 0}

        return {
            "mean_s": round(sum(latencies) / len(latencies), 2),
            "min_s": round(min(latencies), 2),
            "max_s": round(max(latencies), 2),
            "mean_ms": round(sum(latencies) / len(latencies) * 1000, 0),
        }
