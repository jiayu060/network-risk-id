"""Isolation Forest anomaly detector."""

import numpy as np
from sklearn.ensemble import IsolationForest as SklearnIF

from src.detectors.base import AnomalyDetector


class IsolationForestDetector(AnomalyDetector):
    """scikit-learn Isolation Forest wrapper for anomaly detection."""

    def __init__(self, n_estimators: int = 100, contamination: float = 0.05,
                 max_samples: int = 256, bootstrap: bool = False, **kwargs):
        super().__init__(name="isolation_forest", weight=kwargs.pop("weight", 1.0))
        self.model = SklearnIF(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples=max_samples,
            bootstrap=bootstrap,
            random_state=42,
            n_jobs=1,
        )

    def fit(self, X: np.ndarray) -> AnomalyDetector:
        if X.shape[0] < 10:
            return self  # not enough data
        # Handle NaN/Inf
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        self.model.fit(X)
        self._fitted = True
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        if not self._fitted or X.shape[0] == 0:
            return np.zeros(len(X))
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        # Invert: decision_function returns higher for normal, lower for anomalous
        scores = -self.model.score_samples(X)
        # Normalize to [0, 1]
        s_min, s_max = np.percentile(scores, [1, 99])
        if s_max - s_min < 1e-10:
            return np.zeros_like(scores)
        return np.clip((scores - s_min) / (s_max - s_min), 0, 1)

    def explain(self, X: np.ndarray, indices: np.ndarray = None) -> list:
        """Return average path length contribution."""
        if indices is None:
            indices = np.argsort(self.score(X))[-20:]
        explanations = []
        for i in indices:
            explanations.append({"index": int(i), "score": float(self.score(X[i:i + 1])[0])})
        return explanations
