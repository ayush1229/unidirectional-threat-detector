"""Continuous-time hidden Markov candidate with log-IAT emissions.

Transition probabilities use exp(Q * elapsed), preserving irregular timing.
Likelihoods are features for validation-trained C2 fusion, never probabilities.
"""

import numpy as np
from scipy.linalg import expm
from scipy.optimize import minimize
from scipy.special import logsumexp


class ContinuousTimeHMM:
    def __init__(self, rates=(0.02, 0.02), means=(1.0, 3.0), scales=(0.3, 0.8)):
        self.rates = np.asarray(rates, dtype=float)
        self.means = np.asarray(means, dtype=float)
        self.scales = np.asarray(scales, dtype=float)

    def transition(self, elapsed):
        a, b = self.rates
        t = max(float(elapsed), 0.0)
        s = a + b
        if s <= 1e-12:
            return np.eye(2)
        e = np.exp(-s * t)
        inv_s = 1.0 / s
        return np.array([
            [(b + a * e) * inv_s, a * (1.0 - e) * inv_s],
            [b * (1.0 - e) * inv_s, (a + b * e) * inv_s]
        ])

    def log_likelihood(self, gaps):
        gaps = np.asarray(gaps, dtype=float)
        if len(gaps) == 0 or np.any(gaps <= 0):
            raise ValueError("positive inter-arrival intervals required")
        alpha = np.log(np.array([0.5, 0.5]))
        for gap in gaps:
            emission = -0.5 * ((np.log(gap) - self.means) / self.scales) ** 2 - np.log(self.scales) - 0.5 * np.log(2 * np.pi) - np.log(gap)
            alpha = logsumexp(alpha[:, None] + np.log(np.maximum(self.transition(gap), 1e-300)), axis=0) + emission
        return float(logsumexp(alpha))

    def fit(self, sequences, *, split, maxiter=100):
        if split != "train" or not sequences:
            raise ValueError("CT-HMM requires training sequences")
        initial = np.r_[np.log(self.rates), self.means, np.log(self.scales)]
        def objective(theta):
            self.rates, self.means, self.scales = np.exp(theta[:2]), theta[2:4], np.exp(theta[4:])
            return -sum(self.log_likelihood(s) for s in sequences)
        result = minimize(objective, initial, method="L-BFGS-B", bounds=[(-10, 2)] * 2 + [(-8, 16)] * 2 + [(-4, 3)] * 2, options={"maxiter": maxiter})
        objective(result.x)
        self.fit_converged = bool(result.success)
        return self
