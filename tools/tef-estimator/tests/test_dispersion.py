"""Tests for the dispersion feature (Gamma-mixed rate, negative binomial counts)."""

import numpy as np
import pytest
from scipy import stats

from tef_estimator.config import TEFConfig
from tef_estimator.data.common import Geography, RemoteAccessType, RevenueBand, Sector
from tef_estimator.data.scenarios.bec import BECScenario
from tef_estimator.distributions import POISSON, DispersionParams, sample_annual_counts
from tef_estimator.engine import TEFEngine
from tef_estimator.profile import OrganizationProfile

from tests.fft_oracle import CompoundLoss, negbin_pgf, poisson_pgf


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
        assert expl.shape_r == pytest.approx(21.6) and expl.timescale == "month" and expl.basis == "detrended"
        assert cfg.dispersion_for("scenarios", "ransomware").shape_r == pytest.approx(129.7)
        for vec in ("credential", "phishing", "supply_chain"):
            assert cfg.dispersion_for("vectors", vec).is_poisson
        assert cfg.dispersion_for("scenarios", "bec").is_poisson

    def test_raw_basis_switches_to_raw_fit(self):
        cfg = TEFConfig.from_dict({"dispersion": {"basis": "raw"}})
        d = cfg.dispersion_for("vectors", "exploitation")
        assert d.basis == "raw" and d.shape_r == pytest.approx(13.3)

    def test_bad_kind(self):
        with pytest.raises(ValueError):
            TEFConfig.from_dict({}).dispersion_for("sectors", "x")


class TestOutput:
    """6. The result carries the dispersion; the report line appears only when a shape is set."""

    def test_to_dict_fields(self):
        r = TEFEngine(config=TEFConfig.from_dict({})).estimate(_profile())
        disp = r.to_dict()["analysis"]["dispersion"]
        assert disp["total"]["shape_r_month"] == pytest.approx(129.7)
        assert disp["total"]["vmr_at_median"] == pytest.approx(1 + r.total_positioned_median / (12 * 129.7))
        assert disp["vectors"]["exploitation"]["annual_shape"] == pytest.approx(12 * 21.6)
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

    def test_result_sampler_mean(self):
        r = TEFEngine(config=TEFConfig.from_dict({})).estimate(_profile())
        counts = r.sample_annual_counts(size=400_000, rng=np.random.default_rng(5))
        assert counts.mean() == pytest.approx(r.lognormal.mean, rel=0.03)


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
        assert r.fair_risk_engine_inputs()["tef_dispersion"] == pytest.approx(12 * 129.7)
        raw = r.fair_risk_engine_inputs(basis="raw")["tef_dispersion"]
        assert raw == pytest.approx(r.total_dispersion.as_raw().annual_shape)

    def test_poisson_scenario_has_no_dispersion(self):
        r = TEFEngine(scenario=BECScenario(), config=TEFConfig.from_dict({})).estimate(_profile())
        assert r.fair_risk_engine_inputs()["tef_dispersion"] is None
        assert "tef_dispersion=None" in r.full_report()

    def test_report_prints_the_handoff(self):
        r = TEFEngine(config=TEFConfig.from_dict({})).estimate(_profile())
        assert "For fair-risk-engine: tef_model='lognormal'" in r.full_report()


def _fft_annual_loss_quantile(rate, shape, q, median=300e3, p95=4e6, n=1 << 18, ceiling=600e6):
    """Closed-form annual loss quantile: Poisson or Gamma-mixed Poisson frequency, lognormal severity."""
    sigma = np.log(p95 / median) / stats.norm.ppf(0.95)
    pgf = poisson_pgf(rate) if shape is None else negbin_pgf(rate, shape)
    oracle = CompoundLoss(lambda x: stats.lognorm.cdf(x, s=sigma, scale=median), pgf, h=ceiling / n, n=n)
    assert oracle.severity_tail < 1e-5
    return oracle.quantile(q)


class TestLossTailCrossCheck:
    """8. Exact FFT annual loss against the sampler (FFT vs MC within ~1%)."""

    @pytest.mark.parametrize("rate", [1.0, 5.0, 50.0])
    def test_p99_matches_fft(self, rate):
        shape = 2.2
        d = DispersionParams(shape, timescale="year", source="test")
        rng = np.random.default_rng(int(rate))
        counts = sample_annual_counts(np.full(200_000, rate), d, rng)
        sigma = np.log(4e6 / 300e3) / stats.norm.ppf(0.95)
        losses = np.zeros(counts.size)
        idx = np.repeat(np.arange(counts.size), counts)
        np.add.at(losses, idx, rng.lognormal(np.log(300e3), sigma, size=idx.size))
        mc = np.quantile(losses, 0.99)
        exact = _fft_annual_loss_quantile(rate, shape, 0.99)
        assert mc == pytest.approx(exact, rel=0.02)

    def test_fft_poisson_limit(self):
        assert _fft_annual_loss_quantile(5.0, 1e9, 0.99) == pytest.approx(
            _fft_annual_loss_quantile(5.0, None, 0.99), rel=0.001)
