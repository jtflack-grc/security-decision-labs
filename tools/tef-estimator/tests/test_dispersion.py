"""Distributions: PERT, lognormal, dampening, and the negative-binomial dispersion model."""

import numpy as np
import pytest
from scipy import stats

from tef_estimator.config import TEFConfig
from tef_estimator.data.common import Geography, PERTRange, RemoteAccessType, RevenueBand, Sector
from tef_estimator.data.scenarios.bec import BECScenario
from tef_estimator.distributions import (
    POISSON,
    DispersionParams,
    LognormalParams,
    dampen_composite,
    pert_distribution,
    sample_annual_counts,
)
from tef_estimator.engine import TEFEngine
from tef_estimator.profile import OrganizationProfile

def _nb(shape, rate):
    """scipy negative binomial with mean `rate` and Gamma shape `shape`."""
    return stats.nbinom(n=shape, p=shape / (shape + rate))


def _profile():
    return OrganizationProfile(
        sector=Sector.MANUFACTURING,
        revenue_band=RevenueBand.R_100M_1B,
        geography=Geography.US,
        remote_access=[RemoteAccessType.FORTINET],
        employee_count=2000,
    )


class TestExactCounts:
    """1. The sampler against the closed-form negative binomial."""

    @pytest.mark.parametrize("shape,rate", [(2.2, 5.0), (7.6, 1.0), (46.4, 50.0)])
    def test_histogram_matches_pmf(self, shape, rate):
        d = DispersionParams(shape, timescale="year", source="test")
        counts = sample_annual_counts(np.full(200_000, rate), d, np.random.default_rng(42))
        nb = _nb(shape, rate)
        top = int(nb.ppf(0.999))
        observed = np.bincount(np.minimum(counts, top), minlength=top + 1)
        expected = np.append(nb.pmf(np.arange(top)), nb.sf(top - 1)) * counts.size
        keep = expected >= 5
        chi2 = (((observed - expected) ** 2) / expected)[keep].sum()
        assert stats.chi2.sf(chi2, keep.sum() - 1) > 0.001

    @pytest.mark.parametrize("shape,rate", [(2.2, 5.0), (46.4, 50.0)])
    def test_mean_and_vmr(self, shape, rate):
        d = DispersionParams(shape, timescale="year", source="test")
        counts = sample_annual_counts(np.full(400_000, rate), d, np.random.default_rng(7))
        assert counts.mean() == pytest.approx(rate, rel=0.01)
        assert counts.var() / counts.mean() == pytest.approx(d.vmr(rate), rel=0.03)
        assert d.vmr(rate) == pytest.approx(_nb(shape, rate).var() / rate)


class TestPoissonLimit:
    """2. No shape means Poisson; a very large shape converges to Poisson."""

    def test_none_is_bit_identical_to_poisson(self):
        rates = np.linspace(0.01, 20, 5000)
        a = sample_annual_counts(rates, None, np.random.default_rng(1))
        b = sample_annual_counts(rates, POISSON, np.random.default_rng(1))
        c = np.random.default_rng(1).poisson(rates)
        assert np.array_equal(a, c) and np.array_equal(b, c)

    def test_large_shape_converges(self):
        d = DispersionParams(1e9, source="test")
        counts = sample_annual_counts(np.full(200_000, 10.0), d, np.random.default_rng(3))
        assert counts.var() / counts.mean() == pytest.approx(1.0, abs=0.02)


class TestTimescale:
    """3. Independent monthly shocks give annual shape 12 r; a year-long shock gives r."""

    def test_annual_shape(self):
        assert DispersionParams(2.2, timescale="year", source="t").annual_shape == pytest.approx(2.2)
        assert DispersionParams(2.2, timescale="month", source="t").annual_shape == pytest.approx(26.4)
        assert POISSON.annual_shape is None

    def test_twelve_independent_months_match_12r(self):
        r, rate = 2.2, 6.0
        rng = np.random.default_rng(11)
        monthly = rng.gamma(r, 1 / r, size=(300_000, 12)) * (rate / 12)
        counts = rng.poisson(monthly).sum(axis=1)
        expected = DispersionParams(r, timescale="month", source="t").vmr(rate)
        assert counts.var() / counts.mean() == pytest.approx(expected, rel=0.03)


class TestValidation:
    """4. Bad inputs are rejected."""

    @pytest.mark.parametrize("r", [0, -1, float("inf"), float("nan")])
    def test_bad_shape(self, r):
        with pytest.raises(ValueError):
            DispersionParams(r, source="t")

    def test_bad_timescale(self):
        with pytest.raises(ValueError):
            DispersionParams(2.0, timescale="week", source="t")

    def test_bad_basis(self):
        with pytest.raises(ValueError):
            DispersionParams(2.0, basis="fitted", source="t")

    def test_shape_needs_source(self):
        with pytest.raises(ValueError, match="source"):
            DispersionParams(2.0)

    def test_negative_rate_rejected(self):
        with pytest.raises(ValueError):
            sample_annual_counts(np.array([-1.0]), POISSON)

    def test_config_rejects_uncited_default(self):
        with pytest.raises(ValueError, match="source"):
            TEFConfig.from_dict({"dispersion": {"vectors": {"phishing": {"shape_r": 5.0}}}})


class TestConfig:
    """5. The dispersion block survives a round trip and resolves correctly."""

    def test_round_trip(self):
        cfg = TEFConfig.from_dict({"dispersion": {"timescale": "month",
                                                  "vectors": {"phishing": {"shape_r": 9.0, "source": "x"}}}})
        again = TEFConfig.from_dict(cfg.to_dict())
        assert again.to_dict() == cfg.to_dict()
        assert again.dispersion_for("vectors", "phishing") == cfg.dispersion_for("vectors", "phishing")

    def test_defaults(self):
        cfg = TEFConfig.from_dict({})
        expl = cfg.dispersion_for("vectors", "exploitation")
        assert expl.shape_r == pytest.approx(22.5) and expl.timescale == "month" and expl.basis == "detrended"
        assert cfg.dispersion_for("scenarios", "ransomware").shape_r == pytest.approx(113.7)
        for vec in ("credential", "phishing", "supply_chain"):
            assert cfg.dispersion_for("vectors", vec).is_poisson
        assert cfg.dispersion_for("scenarios", "bec").is_poisson

    def test_raw_basis_switches_to_raw_fit(self):
        cfg = TEFConfig.from_dict({"dispersion": {"basis": "raw"}})
        d = cfg.dispersion_for("vectors", "exploitation")
        assert d.basis == "raw" and d.shape_r == pytest.approx(10.5)

    def test_bad_kind(self):
        with pytest.raises(ValueError):
            TEFConfig.from_dict({}).dispersion_for("sectors", "x")


class TestOutput:
    """6. The result carries the dispersion; the report line appears only when a shape is set."""

    def test_to_dict_fields(self):
        r = TEFEngine(config=TEFConfig.from_dict({})).estimate(_profile())
        disp = r.to_dict()["analysis"]["dispersion"]
        assert disp["total"]["shape_r_month"] == pytest.approx(113.7)
        assert disp["total"]["vmr_at_median"] == pytest.approx(1 + r.total_positioned_median / (12 * 113.7))
        assert disp["vectors"]["exploitation"]["annual_shape"] == pytest.approx(12 * 22.5)
        assert disp["vectors"]["credential"]["shape_r_month"] is None

    def test_report_line_only_when_set(self):
        r = TEFEngine(config=TEFConfig.from_dict({})).estimate(_profile())
        assert "DISPERSION" in r.full_report()
        off = TEFConfig.from_dict({"dispersion": {"vectors": {"exploitation": None},
                                                  "scenarios": {"ransomware": None}}})
        assert "DISPERSION" not in TEFEngine(config=off).estimate(_profile()).full_report()

    def test_scenario_without_fit_is_poisson(self):
        r = TEFEngine(scenario=BECScenario(), config=TEFConfig.from_dict({})).estimate(_profile())
        assert r.total_dispersion.is_poisson

    def test_dispersion_never_changes_the_rate(self):
        on = TEFEngine(config=TEFConfig.from_dict({})).estimate(_profile())
        off = TEFEngine(config=TEFConfig.from_dict({"dispersion": {"vectors": {"exploitation": None},
                                                                   "scenarios": {"ransomware": None}}})).estimate(_profile())
        assert on.total_positioned_median == off.total_positioned_median
        assert on.lognormal == off.lognormal

class TestFairRiskEngineHandoff:
    """7. The inputs printed for fair-risk-engine rebuild this lognormal and carry the total annual shape."""

    def test_percentiles_rebuild_the_lognormal(self):
        """fair-risk-engine fits mu = ln P50, sigma = (ln P90 - ln P10) / (2 z_0.9)."""
        r = TEFEngine(config=TEFConfig.from_dict({})).estimate(_profile())
        inputs = r.fair_risk_engine_inputs()
        z90 = stats.norm.ppf(0.9)
        assert inputs["tef_model"] == "lognormal"
        assert np.log(inputs["tef_p50"]) == pytest.approx(r.lognormal.mu)
        assert (np.log(inputs["tef_p90"]) - np.log(inputs["tef_p10"])) / (2 * z90) == pytest.approx(
            r.lognormal.sigma, rel=1e-4)
        assert inputs["tef_p10"] < r.total_positioned_median < inputs["tef_p90"]

    def test_dispersion_is_the_total_annual_shape(self):
        r = TEFEngine(config=TEFConfig.from_dict({})).estimate(_profile())
        assert r.fair_risk_engine_inputs()["tef_dispersion"] == pytest.approx(12 * 113.7)
        raw = r.fair_risk_engine_inputs(basis="raw")["tef_dispersion"]
        assert raw == pytest.approx(r.total_dispersion.as_raw().annual_shape)

    def test_poisson_scenario_has_no_dispersion(self):
        r = TEFEngine(scenario=BECScenario(), config=TEFConfig.from_dict({})).estimate(_profile())
        assert r.fair_risk_engine_inputs()["tef_dispersion"] is None
        assert "tef_dispersion=None" in r.full_report()

    def test_report_prints_the_handoff(self):
        r = TEFEngine(config=TEFConfig.from_dict({})).estimate(_profile())
        assert "For fair-risk-engine: tef_model='lognormal'" in r.full_report()


class TestPERTDistribution:
    def test_basic_pert(self):
        r = PERTRange(0.01, 0.05, 0.10)
        dist = pert_distribution(r)
        assert dist is not None
        # Mean should be close to PERT mean: (a + 4b + c) / 6
        expected_mean = (0.01 + 4 * 0.05 + 0.10) / 6
        assert abs(dist.mean() - expected_mean) < 0.01

    def test_pert_bounds(self):
        r = PERTRange(0.001, 0.01, 0.05)
        dist = pert_distribution(r)
        samples = dist.rvs(size=10_000, random_state=42)
        assert samples.min() >= r.low - 1e-10
        assert samples.max() <= r.high + 1e-10

    def test_pert_invalid_range(self):
        with pytest.raises(ValueError, match="low < high"):
            pert_distribution(PERTRange(0.05, 0.03, 0.01))

    def test_pert_symmetric_range(self):
        # Mode at the midpoint (b == mu) previously raised ZeroDivisionError.
        r = PERTRange(0.5, 0.75, 1.0)
        dist = pert_distribution(r)
        expected_mean = (0.5 + 4 * 0.75 + 1.0) / 6
        assert abs(dist.mean() - expected_mean) < 0.01
        # Symmetric: alpha == beta, so the distribution is centered on the mode.
        assert abs(dist.median() - 0.75) < 0.01


class TestLognormalParams:
    def test_from_median_and_range(self):
        lp = LognormalParams.from_median_and_range(
            median=0.02, low=0.005, high=0.10
        )
        assert abs(lp.median - 0.02) < 0.005
        assert lp.sigma >= 0.1  # Minimum sigma

class TestDampening:
    def test_cap_enforced(self):
        dampened = dampen_composite(100.0, k=0.9, max_cap=5.0)
        assert dampened == 5.0

    def test_formula(self):
        # Dampened = 1 + (Raw - 1) * k
        raw, k = 2.5, 0.7
        expected = 1.0 + (raw - 1.0) * k
        assert abs(dampen_composite(raw, k) - expected) < 1e-10

    def test_below_one_input(self):
        # If raw < 1, dampening should bring closer to 1 (not further)
        dampened = dampen_composite(0.5, k=0.7)
        assert dampened < 1.0
        assert dampened > 0.5  # Pulled toward 1
