"""
Distribution utilities for Monte Carlo parameterisation.

PERT for input uncertainty, lognormal for TEF output distributions.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from scipy import stats

from tef_estimator.data import PERTRange


def pert_distribution(r: PERTRange, lam: float = 4.0) -> stats.rv_continuous:
    """Create a PERT (modified Beta) distribution from a PERTRange.

    Parameters
    ----------
    r : PERTRange
        (min, mode, max) triple.
    lam : float
        Shape parameter controlling concentration around the mode.
        Default 4.0 is standard PERT.

    Returns
    -------
    scipy.stats frozen distribution
    """
    a, b, c = r.low, r.mode, r.high
    if a >= c:
        raise ValueError(f"PERT requires low < high, got ({a}, {c})")

    # PERT alpha/beta parameters
    mu = (a + lam * b + c) / (lam + 2)
    if abs(c - a) < 1e-12:
        # Degenerate — return a constant
        return stats.uniform(loc=a, scale=0)

    # Symmetric PERT (mode at the midpoint): b == mu, so the (b - mu)
    # denominator below would be zero. alpha == beta in closed form.
    if abs(b - mu) < 1e-12:
        shape = 1.0 + lam / 2.0
        return stats.beta(shape, shape, loc=a, scale=c - a)

    alpha_param = ((mu - a) * (2 * b - a - c)) / ((b - mu) * (c - a))
    if alpha_param <= 0:
        alpha_param = 1.0  # Fallback for edge cases
    beta_param = alpha_param * (c - mu) / (mu - a)
    if beta_param <= 0:
        beta_param = 1.0

    return stats.beta(alpha_param, beta_param, loc=a, scale=c - a)


def pert_sample(r: PERTRange, size: int = 10_000, rng: np.random.Generator | None = None) -> np.ndarray:
    """Draw samples from a PERT distribution."""
    dist = pert_distribution(r)
    if rng is None:
        rng = np.random.default_rng()
    return dist.rvs(size=size, random_state=rng)


@dataclass(frozen=True)
class LognormalParams:
    """Lognormal distribution parameters for Monte Carlo consumers.

    mu and sigma are the parameters of the underlying normal distribution
    (i.e., ln(X) ~ Normal(mu, sigma)).
    """
    mu: float
    sigma: float

    @property
    def median(self) -> float:
        return math.exp(self.mu)

    @property
    def mean(self) -> float:
        return math.exp(self.mu + self.sigma**2 / 2)

    @property
    def p5(self) -> float:
        return math.exp(self.mu - 1.645 * self.sigma)

    @property
    def p95(self) -> float:
        return math.exp(self.mu + 1.645 * self.sigma)

    @property
    def p10(self) -> float:
        return math.exp(self.mu - 1.2816 * self.sigma)

    @property
    def p90(self) -> float:
        return math.exp(self.mu + 1.2816 * self.sigma)

    def sample(self, size: int = 10_000, rng: np.random.Generator | None = None) -> np.ndarray:
        if rng is None:
            rng = np.random.default_rng()
        return rng.lognormal(self.mu, self.sigma, size=size)

    @classmethod
    def from_median_and_range(cls, median: float, low: float, high: float) -> LognormalParams:
        """Derive lognormal params from a positioned estimate and its range.

        Parameters
        ----------
        median : float
            Positioned point estimate (becomes the lognormal median).
        low : float
            Lower bound of the range (targets ~5th percentile).
        high : float
            Upper bound (targets ~95th percentile).
        """
        mu = math.log(max(median, 1e-10))
        sigma_from_low = (mu - math.log(max(low, 1e-10))) / 1.645
        sigma_from_high = (math.log(max(high, 1e-10)) - mu) / 1.645
        sigma = max(0.1, (sigma_from_low + sigma_from_high) / 2)
        return cls(mu=round(mu, 6), sigma=round(sigma, 6))

    @classmethod
    def fenton_wilkinson(cls, components: list[LognormalParams]) -> LognormalParams:
        """Aggregate independent lognormals via the Fenton-Wilkinson approximation.

        Given X = Σ X_i where each X_i ~ Lognormal(μ_i, σ_i), the sum is
        approximated as X ~ Lognormal(μ_FW, σ_FW) by matching the first two
        moments of the sum to those of a lognormal.
        """
        if not components:
            return cls(mu=0.0, sigma=0.1)
        if len(components) == 1:
            return components[0]

        mean_total = 0.0
        var_total = 0.0
        for c in components:
            m_i = math.exp(c.mu + c.sigma ** 2 / 2.0)
            v_i = m_i ** 2 * (math.exp(c.sigma ** 2) - 1.0)
            mean_total += m_i
            var_total += v_i

        if mean_total <= 0:
            return cls(mu=0.0, sigma=0.1)

        sigma_sq = math.log(1.0 + var_total / mean_total ** 2)
        mu_fw = math.log(mean_total) - sigma_sq / 2.0
        sigma_fw = math.sqrt(sigma_sq)
        return cls(mu=round(mu_fw, 6), sigma=round(max(0.1, sigma_fw), 6))


_TIMESCALES = ("month", "year")
_BASES = ("detrended", "raw")


@dataclass(frozen=True)
class DispersionParams:
    """Burstiness of the event rate over time (Gamma-mixed rate, negative binomial counts).

    The rate in a given year is the TEF rate times a shared shock
    G ~ Gamma(shape, scale=1/shape), so E[G] = 1 and the mean is unchanged.
    Counts given the shocked rate are Poisson, which makes the annual count
    negative binomial with VMR = 1 + rate / annual_shape.

    This is *not* credibility k: k describes how rates differ between
    organizations; the shape here describes how one organization's rate is
    shaken in time by shocks it shares with others (campaign waves,
    mass exploitation). It is also not a model of inter-arrival times.

    shape_r is fitted on *monthly* series. ``timescale`` says how long a shock
    lasts: "month" (independent monthly shocks, annual shape = 12 r; default,
    see docs/dispersion-timescale.md) or "year" (one shock persists all year,
    annual shape = r). shape_r=None means Poisson.
    """
    shape_r: float | None
    timescale: str = "month"
    basis: str = "detrended"
    source: str = ""
    raw_shape_r: float | None = None

    def __post_init__(self):
        for name in ("shape_r", "raw_shape_r"):
            value = getattr(self, name)
            if value is not None and not (value > 0 and math.isfinite(value)):
                raise ValueError(f"{name} must be a positive finite number or None, got {value!r}")
        if self.timescale not in _TIMESCALES:
            raise ValueError(f"timescale must be one of {_TIMESCALES}, got {self.timescale!r}")
        if self.basis not in _BASES:
            raise ValueError(f"basis must be one of {_BASES}, got {self.basis!r}")
        if self.shape_r is not None and not self.source.strip():
            raise ValueError("a dispersion shape needs a source citation")

    @property
    def is_poisson(self) -> bool:
        return self.shape_r is None

    @property
    def annual_shape(self) -> float | None:
        """Gamma shape of the annual rate multiplier (None = Poisson)."""
        if self.shape_r is None:
            return None
        return self.shape_r * (12.0 if self.timescale == "month" else 1.0)

    def vmr(self, annual_rate: float) -> float:
        """Variance-to-mean ratio of the annual count at a given rate."""
        shape = self.annual_shape
        return 1.0 if shape is None else 1.0 + annual_rate / shape

    def with_timescale(self, timescale: str) -> DispersionParams:
        return DispersionParams(self.shape_r, timescale, self.basis, self.source, self.raw_shape_r)

    def as_raw(self) -> DispersionParams:
        """The raw (trend-included) fit, kept as the sensitivity bound."""
        if self.raw_shape_r is None:
            return self
        return DispersionParams(self.raw_shape_r, self.timescale, "raw", self.source, self.raw_shape_r)

    def to_dict(self, annual_rate: float | None = None) -> dict:
        d = {
            "shape_r_month": self.shape_r,
            "raw_shape_r_month": self.raw_shape_r,
            "timescale": self.timescale,
            "annual_shape": self.annual_shape,
            "basis": self.basis,
            "source": self.source,
        }
        if annual_rate is not None:
            d["vmr_at_median"] = self.vmr(annual_rate)
        return d


POISSON = DispersionParams(shape_r=None)


def sample_annual_counts(
    annual_rates: np.ndarray,
    dispersion: DispersionParams | None,
    rng: np.random.Generator | None = None,
) -> np.ndarray:
    """Draw one annual event count per rate.

    ``annual_rates`` carries the uncertainty about the rate itself (e.g. draws
    from the TEF lognormal). The dispersion shock is the separate, year-to-year
    variability on top of it. With no dispersion the counts are Poisson.
    """
    if rng is None:
        rng = np.random.default_rng()
    rates = np.asarray(annual_rates, dtype=float)
    if np.any(rates < 0):
        raise ValueError("annual rates must be non-negative")
    shape = None if dispersion is None else dispersion.annual_shape
    if shape is not None:
        rates = rates * rng.gamma(shape, 1.0 / shape, size=rates.shape)
    return rng.poisson(rates)


def dampen_composite(raw_composite: float, k: float, max_cap: float = 5.0) -> float:
    """Apply dampening to a raw multiplicative composite.

    Dampened = 1 + (Raw - 1) × k, capped at max_cap.

    Parameters
    ----------
    raw_composite : float
        Product of all multipliers.
    k : float
        Dampening coefficient (0 = no effect beyond base, 1 = full independence).
    max_cap : float
        Hard ceiling on the dampened composite.
    """
    dampened = 1.0 + (raw_composite - 1.0) * k
    return min(dampened, max_cap)
