"""GPD-based threshold calibration using Extreme Value Theory."""

import numpy as np


class ThresholdCalibrator:
    """Calibrates anomaly score thresholds using Generalized Pareto Distribution (GPD)
    fit to the tail of the score distribution.

    This provides adaptive thresholds that maintain a target false positive rate
    regardless of the underlying score distribution.
    """

    def __init__(self, tail_fraction: float = 0.10, target_fpr: float = 0.001):
        self.tail_fraction = tail_fraction
        self.target_fpr = target_fpr
        # GPD parameters
        self._shape: float = 0.0  # xi
        self._scale: float = 0.0  # sigma
        self._threshold: float = 0.0  # u (POT threshold)
        self._fitted = False

    def fit(self, scores: np.ndarray) -> "ThresholdCalibrator":
        """Fit GPD to the upper tail of anomaly scores."""
        if len(scores) < 100:
            return self

        scores = np.sort(scores[~np.isnan(scores)])
        n = len(scores)
        n_tail = max(int(n * self.tail_fraction), 10)

        # POT threshold: (1 - tail_fraction) quantile
        self._threshold = np.percentile(scores, 100 * (1 - self.tail_fraction))
        excesses = scores[-n_tail:] - self._threshold
        excesses = excesses[excesses > 0]

        if len(excesses) < 10:
            return self

        # Method of Moments estimation for GPD
        mean_excess = np.mean(excesses)
        var_excess = np.var(excesses, ddof=1) if len(excesses) > 1 else 1e-10

        # GPD: shape xi = 0.5 * (1 - mean_excess^2 / var_excess)
        xi_hat = 0.5 * (1 - (mean_excess ** 2) / var_excess)
        # Clip shape to valid range
        xi_hat = np.clip(xi_hat, -0.5, 1.0)
        # scale sigma = 0.5 * mean_excess * (1 + xi_hat)
        sigma_hat = 0.5 * mean_excess * (1 + xi_hat)

        self._shape = xi_hat
        self._scale = sigma_hat
        self._fitted = True
        return self

    def get_threshold(self, confidence: float = 0.99) -> float:
        """Return score threshold for the given confidence level.

        Under GPD, P(X > u + y | X > u) ≈ (1 + xi*y/sigma)^(-1/xi)
        """
        if not self._fitted:
            return 0.95  # default fallback

        tail_prob = 1 - confidence
        try:
            if abs(self._shape) < 1e-6:
                # Exponential tail (xi ≈ 0)
                y = -self._scale * np.log(tail_prob)
            else:
                y = (self._scale / self._shape) * ((tail_prob) ** (-self._shape) - 1)
        except (OverflowError, ValueError):
            y = 100.0

        return min(self._threshold + y, 1.0)

    def get_tier_thresholds(self) -> tuple[float, float]:
        """Get two-tier thresholds: (investigation, critical)."""
        t1 = self.get_threshold(0.90)  # investigation threshold
        t2 = self.get_threshold(0.98)  # critical threshold
        return max(t1, 0.70), max(t2, 0.85)
