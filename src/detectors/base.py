"""Abstract base class for anomaly detectors."""

from abc import ABC, abstractmethod
from typing import Optional

import numpy as np


class AnomalyDetector(ABC):
    """Interface that every anomaly detector must implement."""

    def __init__(self, name: str, weight: float = 1.0):
        self.name = name
        self.weight = weight
        self._fitted = False

    @abstractmethod
    def fit(self, X: np.ndarray) -> "AnomalyDetector":
        """Train the detector on the given feature matrix."""
        ...

    @abstractmethod
    def score(self, X: np.ndarray) -> np.ndarray:
        """Return anomaly scores for each row (higher = more anomalous)."""
        ...

    def explain(self, X: np.ndarray, indices: Optional[np.ndarray] = None) -> Optional[list]:
        """Return per-row explanations for top anomalies."""
        return None

    @property
    def is_fitted(self) -> bool:
        return self._fitted
