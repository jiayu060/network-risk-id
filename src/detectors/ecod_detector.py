"""ECOD (Empirical Cumulative Distribution-based Outlier Detection) detector.

A non-parametric, fast detector ideal for streaming/ batch processing of TB-scale data.
"""

import numpy as np

from src.detectors.base import AnomalyDetector


class ECODDetector(AnomalyDetector):
    """Fast non-parametric outlier detection based on tail probabilities per dimension."""

    def __init__(self, contamination: float = 0.05, **kwargs):
        super().__init__(name="ecod", weight=kwargs.pop("weight", 0.9))
        self.contamination = contamination
        # Per-dimension: (n_samples, sorted_values) for ECDF
        self._ecdf: list[tuple[np.ndarray, np.ndarray]] = []

    def fit(self, X: np.ndarray) -> AnomalyDetector:
        if X.shape[0] < 10:
            return self
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        self._d = X.shape[1]
        self._ecdf = []

        for j in range(self._d):
            col = np.sort(X[:, j])
            n = len(col)
            # Build ECDF: cumulative probabilities at sorted values
            probs = (np.arange(1, n + 1)) / n
            self._ecdf.append((col, probs))

        # Fit a left and right tail model per dimension
        self._left_tail: list[np.ndarray] = []
        self._right_tail: list[np.ndarray] = []
        for j in range(self._d):
            col = X[:, j]
            # Left tail: P(X <= x), right tail: P(X >= x)
            left = np.searchsorted(self._ecdf[j][0], col, side="right").astype(float) / len(col)
            right = 1.0 - np.searchsorted(self._ecdf[j][0], col, side="left").astype(float) / len(col)
            self._left_tail.append(left.mean())
            self._right_tail.append(right.mean())

        self._fitted = True
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        if not self._fitted or X.shape[0] == 0:
            return np.zeros(len(X))
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        n, d = X.shape
        scores = np.zeros(n)

        for j in range(min(d, len(self._ecdf))):
            col_sorted, probs = self._ecdf[j]
            n_vals = len(col_sorted)

            # Left tail probability
            left_idx = np.searchsorted(col_sorted, X[:, j], side="right").astype(float)
            left_prob = left_idx / n_vals
            # Right tail probability
            right_prob = 1.0 - left_prob

            # Use the more extreme tail
            tail = np.minimum(left_prob, right_prob)
            # -log transform + aggregate
            scores += -np.log(np.maximum(tail, 1e-10))

        # Normalize to [0, 1]
        if scores.max() - scores.min() < 1e-10:
            return np.zeros_like(scores)
        scores = (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)
        return scores
