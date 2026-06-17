"""Detector ensemble with weighted rank aggregation."""

import numpy as np
from scipy import stats as scipy_stats

from src.detectors.base import AnomalyDetector
from src.detectors.isolation_forest import IsolationForestDetector
from src.detectors.graph_rare_path import GraphRarePathDetector

# Lazy imports for optional heavy dependencies
try:
    from src.detectors.ecod_detector import ECODDetector
    _HAS_ECOD = True
except ImportError:
    ECODDetector = None
    _HAS_ECOD = False

try:
    from src.detectors.hdbscan_detector import HDBSCANDetector
    _HAS_HDBSCAN = True
except ImportError:
    HDBSCANDetector = None
    _HAS_HDBSCAN = False

try:
    from src.detectors.autoencoder import AutoencoderDetector
    _HAS_AUTOENCODER = True
except ImportError:
    AutoencoderDetector = None
    _HAS_AUTOENCODER = False


class DetectorEnsemble:
    """Runs multiple detectors in parallel and aggregates scores via rank aggregation."""

    @property
    def DEFAULT_DETECTORS(self):
        detectors = {
            "isolation_forest": (IsolationForestDetector, {"weight": 1.0}),
            "graph_rare_path": (GraphRarePathDetector, {"weight": 1.5}),
        }
        if _HAS_ECOD:
            detectors["ecod"] = (ECODDetector, {"weight": 0.9})
        if _HAS_HDBSCAN:
            detectors["hdbscan"] = (HDBSCANDetector, {"weight": 0.8})
        if _HAS_AUTOENCODER:
            detectors["autoencoder"] = (AutoencoderDetector, {"weight": 1.2})
        return detectors

    def __init__(self, detectors: dict = None):
        if detectors is None:
            detectors = self.DEFAULT_DETECTORS
        self._detector_specs = detectors
        self.detectors: dict[str, AnomalyDetector] = {}
        self._init_detectors()

    def _init_detectors(self):
        for name, (cls, params) in self._detector_specs.items():
            self.detectors[name] = cls(**params)

    def fit(self, X: np.ndarray) -> "DetectorEnsemble":
        """Fit all detectors."""
        for name, detector in self.detectors.items():
            try:
                detector.fit(X)
            except Exception as e:
                print(f"Warning: Detector '{name}' failed to fit: {e}")
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        """Compute aggregated anomaly scores via rank aggregation."""
        if X.shape[0] == 0:
            return np.array([])

        scores = {}
        for name, detector in self.detectors.items():
            try:
                s = detector.score(X)
                if s is not None and len(s) == len(X) and np.any(np.isfinite(s)):
                    scores[name] = s
            except Exception as e:
                print(f"Warning: Detector '{name}' failed to score: {e}")

        if not scores:
            return np.zeros(len(X))

        return self._rank_aggregate(scores)

    def _rank_aggregate(self, scores: dict[str, np.ndarray]) -> np.ndarray:
        """Weighted rank aggregation: mean of ranks weighted by detector weight."""
        n = len(next(iter(scores.values())))
        aggregated = np.zeros(n)
        total_weight = 0.0

        for name, s in scores.items():
            weight = self.detectors[name].weight
            # Convert to ranks (tied ranks use average method)
            try:
                ranks = scipy_stats.rankdata(s, method="average") / n
                aggregated += weight * ranks
                total_weight += weight
            except Exception:
                pass

        if total_weight == 0:
            return np.zeros(n)

        return aggregated / total_weight

    def detect_alerts(self, X: np.ndarray, tier1_threshold: float = 0.90,
                      tier2_threshold: float = 0.98) -> tuple[list[int], list[int]]:
        """Two-tier alerting: returns (investigation_alerts, critical_alerts)."""
        scores = self.score(X)
        tier1 = np.where(scores >= tier1_threshold)[0].tolist()
        tier2 = np.where(scores >= tier2_threshold)[0].tolist()
        return tier1, tier2

    def fit_graph(self, graph_data: dict):
        """Fit graph-based detectors from graph data."""
        grp = self.detectors.get("graph_rare_path")
        if grp and isinstance(grp, GraphRarePathDetector):
            grp.fit_from_graph(graph_data)
