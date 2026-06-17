"""DGA (Domain Generation Algorithm) detection via domain feature analysis."""

import math
from collections import defaultdict

import numpy as np
from src.utils.text_utils import shannon_entropy, consonant_vowel_ratio, max_consonant_run


class DGADetector:
    """Detects DGA activity by analyzing domain name features.

    DGA domains differ from legitimate domains in:
    - Higher entropy
    - Higher consonant-to-vowel ratio
    - Longer max consonant runs
    - Lower n-gram frequency score
    - Higher digit fraction
    """

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self._model = None
        self._fitted = False

    def fit(self, domains: list[str]):
        """Fit a DGA detection model on a list of domains."""
        if len(domains) < 10:
            return

        features = self._extract_features(domains)
        X = np.array([list(f.values()) for f in features])

        try:
            from sklearn.ensemble import IsolationForest
            self._model = IsolationForest(contamination=self.contamination, random_state=42)
            self._model.fit(X)
            self._fitted = True
        except ImportError:
            # Manual threshold-based approach
            self._manual_fit(X)

    def _manual_fit(self, X: np.ndarray):
        """Fallback: set thresholds based on feature distributions."""
        self._feature_means = X.mean(axis=0)
        self._feature_stds = X.std(axis=0)
        self._fitted = True

    def detect(self, domains: list[str]) -> list[dict[str, float]]:
        """Score each domain for DGA likelihood.

        Returns list of {domain, score, is_dga} dicts.
        """
        results = []
        if not domains:
            return results

        features = self._extract_features(domains)

        for i, domain in enumerate(domains):
            f = features[i]
            if self._model is not None and hasattr(self._model, 'decision_function'):
                X_sample = np.array([list(f.values())])
                score = -float(self._model.score_samples(X_sample)[0])
                score = 1.0 / (1.0 + math.exp(-score))  # sigmoid
            elif self._fitted:
                # Manual scoring: z-score on each feature
                X_row = np.array(list(f.values()))
                z_scores = (X_row - self._feature_means) / (self._feature_stds + 1e-10)
                score = 1.0 / (1.0 + math.exp(-np.abs(z_scores).mean()))
            else:
                score = self._heuristic_score(domain)

            results.append({
                "domain": domain,
                "score": round(score, 4),
                "is_dga": score > 0.7,
                "features": {k: round(v, 4) for k, v in f.items()},
            })

        return results

    def detect_hosts(self, host_domains: dict[str, list[str]]) -> dict[str, float]:
        """Score hosts by DGA activity level.

        Returns {host_id: dga_score} mapping.
        """
        host_scores = {}
        for host, domains in host_domains.items():
            results = self.detect(domains)
            dga_count = sum(1 for r in results if r["is_dga"])
            if len(results) > 0:
                host_scores[host] = dga_count / len(results)
            else:
                host_scores[host] = 0.0
        return host_scores

    def _extract_features(self, domains: list[str]) -> list[dict[str, float]]:
        """Extract DGA-relevant features from domain names."""
        features = []
        for domain in domains:
            # Strip TLD(s)
            body = domain.split(".")[0] if "." in domain else domain
            tld = domain.rsplit(".", 1)[-1] if "." in domain else ""

            features.append({
                "length": float(len(body)),
                "entropy": shannon_entropy(body),
                "cv_ratio": min(consonant_vowel_ratio(body), 100.0),
                "digit_fraction": sum(c.isdigit() for c in domain) / max(len(domain), 1),
                "max_consonant_run": float(max_consonant_run(body)),
                "unique_char_ratio": len(set(body)) / max(len(body), 1),
                "tld_length": float(len(tld)),
            })
        return features

    def _heuristic_score(self, domain: str) -> float:
        """Rule-based DGA scoring without training data."""
        body = domain.split(".")[0] if "." in domain else domain
        entropy = shannon_entropy(body)
        cv = min(consonant_vowel_ratio(body), 100.0)
        max_run = max_consonant_run(body)
        digits = sum(c.isdigit() for c in domain) / max(len(domain), 1)

        # High entropy, high CV ratio, long consonant runs, many digits
        score = 0.0
        if entropy > 3.0:
            score += 0.3
        if cv > 4.0:
            score += 0.3
        if max_run > 4:
            score += 0.2
        if digits > 0.1:
            score += 0.2

        return min(score, 1.0)
