"""Constant-memory online population moments."""
from dataclasses import dataclass
from math import sqrt

from agent1_observation_dns.contracts import measured


@dataclass
class Moments:
    count: int = 0
    mean: float = 0
    m2: float = 0
    m3: float = 0
    minimum: float = float("inf")
    maximum: float = float("-inf")

    def add(self, value: float) -> None:
        previous = self.count
        self.count += 1
        delta = value - self.mean
        dn = delta / self.count
        term = delta * dn * previous
        self.m3 += term * dn * (self.count - 2) - 3 * dn * self.m2
        self.m2 += term
        self.mean += dn
        self.minimum = min(self.minimum, value)
        self.maximum = max(self.maximum, value)

    def features(self, prefix: str) -> dict:
        std = sqrt(max(0, self.m2 / self.count)) if self.count else None
        values = {"min": self.minimum if self.count else None,
                  "max": self.maximum if self.count else None,
                  "mean": self.mean if self.count else None, "std": std,
                  "cv": std / self.mean if self.count and self.mean else None,
                  "skew": (sqrt(self.count) * self.m3 / self.m2 ** 1.5)
                  if self.count >= 3 and self.m2 > 0 else None}
        return {f"{prefix}_{name}": measured(value, "INSUFFICIENT_VARIATION_OR_SAMPLES")
                for name, value in values.items()}
