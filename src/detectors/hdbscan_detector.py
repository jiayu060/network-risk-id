"""HDBSCAN-based anomaly detector with GLOSH outlier scoring."""

import numpy as np

from src.detectors.base import AnomalyDetector


class HDBSCANDetector(AnomalyDetector):
    """Uses HDBSCAN clustering — unclustered points + GLOSH scores as anomalies."""

    def __init__(self, min_cluster_size: int = 50, min_samples: int = 10,
                 cluster_selection_epsilon: float = 0.5, **kwargs):
        super().__init__(name="hdbscan", weight=kwargs.pop("weight", 0.8))
        self.min_cluster_size = min_cluster_size
        self.min_samples = min_samples
        self.cluster_selection_epsilon = cluster_selection_epsilon
        self._labels: np.ndarray = None
        self._outlier_scores: np.ndarray = None

    def fit(self, X: np.ndarray) -> AnomalyDetector:
        if X.shape[0] < 10:
            return self
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        try:
            import hdbscan
            clusterer = hdbscan.HDBSCAN(
                min_cluster_size=self.min_cluster_size,
                min_samples=self.min_samples,
                cluster_selection_epsilon=self.cluster_selection_epsilon,
                prediction_data=True,
            )
            self._labels = clusterer.fit_predict(X)
            # GLOSH: Global-Local Outlier Score from Hierarchies
            self._outlier_scores = clusterer.outlier_scores_
            self._clusterer = clusterer
        except ImportError:
            # Fallback: use sklearn DBSCAN + distance-based outlier
            from sklearn.cluster import DBSCAN
            from sklearn.neighbors import LocalOutlierFactor
            clusterer = DBSCAN(eps=0.5, min_samples=self.min_samples)
            self._labels = clusterer.fit_predict(X)
            lof = LocalOutlierFactor(novelty=False)
            try:
                lof.fit(X)
                self._outlier_scores = -lof.negative_outlier_factor_
            except Exception:
                # Approximate: distance from each point to its nearest cluster center
                self._outlier_scores = np.ones(len(X))
                for label in set(self._labels) - {-1}:
                    mask = self._labels == label
                    center = X[mask].mean(axis=0)
                    self._outlier_scores[mask] = np.linalg.norm(X[mask] - center, axis=1)
                if -1 in set(self._labels):
                    self._outlier_scores[self._labels == -1] = np.max(self._outlier_scores)

        self._fitted = True
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        if not self._fitted or X.shape[0] == 0:
            return np.zeros(len(X))
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        try:
            import hdbscan
            if hasattr(self, '_clusterer'):
                labels, strengths = hdbscan.approximate_predict(self._clusterer, X)
                # Unclustered points (-1) are anomalies, or use GLOSH
                scores = np.where(labels == -1, 0.9, strengths)
            else:
                scores = np.zeros(len(X))
        except (ImportError, AttributeError):
            from sklearn.neighbors import LocalOutlierFactor
            try:
                lof = LocalOutlierFactor(novelty=True)
                lof.fit(X)
                scores = -lof.decision_function(X)
            except Exception:
                scores = np.ones(len(X)) * 0.5

        # Normalize
        s_min, s_max = np.percentile(scores, [1, 99])
        if s_max - s_min < 1e-10:
            return np.zeros_like(scores)
        return np.clip((scores - s_min) / (s_max - s_min), 0, 1)
