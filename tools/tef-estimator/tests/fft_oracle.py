"""Exact compound-loss oracle via FFT, for testing Monte Carlo engines.

Annual loss S = X_1 + ... + X_N, with N independent of the i.i.d. X_i, has
probability generating function G_S(z) = G_N(G_X(z)). The severity is
discretised by mass rounding on a grid of step h (mass on
[(k - 1/2)h, (k + 1/2)h) goes to kh), G_X is evaluated on the unit circle by
FFT, and the aggregate pmf is recovered by inverse FFT.

Two error sources are controlled explicitly instead of hoped away:
- Wraparound: aggregate mass beyond the FFT length aliases back onto small
  losses. The grid is zero-padded to twice its length and exponentially
  tilted (Grubel & Hermesmeier 1999), which damps aliasing by exp(-tilt).
- Truncation: severity mass beyond the grid is dropped. It is reported as
  `severity_tail` so a test can assert it is negligible.

The remaining error is discretisation, at most h/2 on any quantile.
"""

from __future__ import annotations

from typing import Callable, Sequence

import numpy as np

Pgf = Callable[[np.ndarray], np.ndarray]


def poisson_pgf(rate: float) -> Pgf:
    return lambda z: np.exp(rate * (z - 1.0))


def negbin_pgf(mean: float, shape: float) -> Pgf:
    """Gamma-mixed Poisson with the given mean and Gamma shape r (variance = mean + mean^2 / r)."""
    return lambda z: (1.0 + (mean / shape) * (1.0 - z)) ** (-shape)


def mixed_poisson_pgf(rates: Sequence[float], weights: Sequence[float]) -> Pgf:
    """Poisson with a random rate given as quadrature nodes and weights (weights sum to 1)."""
    rates = np.asarray(rates, dtype=float)
    weights = np.asarray(weights, dtype=float) / np.sum(weights)
    return lambda z: sum(w * np.exp(r * (z - 1.0)) for r, w in zip(rates, weights))


class CompoundLoss:
    """Aggregate loss distribution of a compound frequency-severity model."""

    def __init__(self, severity_cdf: Callable[[np.ndarray], np.ndarray], pgf: Pgf,
                 h: float, n: int = 1 << 18, tilt: float = 20.0):
        self.h = float(h)
        edges = (np.arange(n + 1) - 0.5) * self.h
        edges[0] = 0.0
        cdf = np.asarray(severity_cdf(edges), dtype=float)
        severity = np.diff(cdf)
        severity[0] += cdf[0]  # any mass at zero
        self.severity_tail = float(1.0 - cdf[-1])

        m = 2 * n  # zero padding
        theta = tilt / m
        k = np.arange(m)
        x = np.zeros(m)
        x[:n] = severity
        tilted = np.fft.ifft(pgf(np.fft.fft(x * np.exp(-theta * k))))
        self.pmf = np.clip(np.real(tilted) * np.exp(theta * k), 0.0, None)
        self.cdf = np.cumsum(self.pmf)

    @property
    def mean(self) -> float:
        return float(np.sum(np.arange(self.pmf.size) * self.h * self.pmf))

    def quantile(self, q: float) -> float:
        return float(np.searchsorted(self.cdf, q) * self.h)

    def cdf_at(self, x: float) -> float:
        """P(S <= x), with x rounded to the nearest grid point."""
        k = int(np.floor(x / self.h + 0.5))
        return float(self.cdf[min(max(k, 0), self.cdf.size - 1)])

    def prob_zero(self) -> float:
        return float(self.pmf[0])
