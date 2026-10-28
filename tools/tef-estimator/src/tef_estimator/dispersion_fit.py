"""Negative binomial (NB2) shape fits on monthly count series.

The same likelihood as statsmodels' NegativeBinomial(loglike_method="nb2"),
implemented on scipy so the package can refit dispersion without the
analysis-only dependencies of scripts/dispersion_timescale_check.py.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy import optimize, special


@dataclass(frozen=True)
class ShapeFit:
    shape_r: float
    converged: bool
    n_months: int
    total: float


def moments_shape(counts) -> float | None:
    """Raw-basis shape by method of moments: mean^2 / (sample variance - mean).

    Absorbs any trend into the variance, so it is the sensitivity bound for
    the detrended fit. None when the series is not overdispersed (Poisson).
    """
    y = np.asarray(counts, dtype=float)
    if len(y) < 3:
        raise ValueError(f"need at least 3 months to fit a shape, got {len(y)}")
    mean, var = y.mean(), y.var(ddof=1)
    if var <= mean:
        return None
    return float(mean ** 2 / (var - mean))


def nb2_shape(counts, *, trend: bool = True) -> ShapeFit:
    """Fit an NB2 regression on monthly counts and return the shape r = 1/alpha.

    ``trend=True`` is the detrended basis (log-linear time trend, as for the
    bundled defaults); ``trend=False`` is a constant-mean fit.
    """
    y = np.asarray(counts, dtype=float)
    n = len(y)
    if n < 3:
        raise ValueError(f"need at least 3 months to fit a shape, got {n}")
    if y.sum() <= 0:
        raise ValueError("cannot fit a shape on an all-zero series")

    t = np.arange(n) / max(n - 1, 1)
    X = np.column_stack([np.ones(n), t]) if trend else np.ones((n, 1))

    def nll(p: np.ndarray) -> float:
        beta, alpha = p[:-1], np.exp(p[-1])
        mu = np.exp(X @ beta)
        inv = 1.0 / alpha
        ll = (special.gammaln(y + inv) - special.gammaln(inv) - special.gammaln(y + 1)
              + inv * np.log(inv / (inv + mu)) + y * np.log(mu / (inv + mu)))
        return -float(ll.sum())

    p0 = np.zeros(X.shape[1] + 1)
    p0[0] = np.log(y.mean())
    p0[-1] = np.log(0.05)
    res = optimize.minimize(nll, p0, method="L-BFGS-B")
    return ShapeFit(
        shape_r=float(1.0 / np.exp(res.x[-1])),
        converged=bool(res.success),
        n_months=n,
        total=float(y.sum()),
    )


def month_range(start: str, end: str) -> list[str]:
    """Inclusive list of YYYY-MM strings."""
    y, m = map(int, start.split("-"))
    ey, em = map(int, end.split("-"))
    out = []
    while (y, m) <= (ey, em):
        out.append(f"{y:04d}-{m:02d}")
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    return out


def shift_month(month: str, delta: int) -> str:
    y, m = map(int, month.split("-"))
    idx = y * 12 + (m - 1) + delta
    return f"{idx // 12:04d}-{idx % 12 + 1:02d}"
