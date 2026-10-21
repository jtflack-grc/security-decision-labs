"""Tests for Bühlmann credibility blending."""

import json
import pytest
from pathlib import Path

from tef_estimator.credibility import (
    BlendResult,
    CredibilityBlender,
    OrgTelemetry,
    VectorObservation,
)
from tef_estimator.data.common import (
    Geography,
    RemoteAccessType,
    RevenueBand,
    Sector,
)
from tef_estimator.engine import TEFEngine
from tef_estimator.profile import OrganizationProfile


class TestVectorObservation:
    def test_valid_observation(self):
        obs = VectorObservation(
            vector="credential",
            annualized_frequency=0.05,
            observation_periods=4,
            detection_coverage=0.8,
        )
        assert obs.vector == "credential"
        assert obs.detection_coverage == 0.8

    def test_invalid_vector_name(self):
        with pytest.raises(ValueError, match="must be one of"):
            VectorObservation(
                vector="insider",
                annualized_frequency=0.01,
                observation_periods=4,
            )

    def test_negative_frequency(self):
        with pytest.raises(ValueError, match="annualized_frequency"):
            VectorObservation(
                vector="exploitation",
                annualized_frequency=-0.01,
                observation_periods=4,
            )

    def test_zero_observation_periods(self):
        with pytest.raises(ValueError, match="observation_periods"):
            VectorObservation(
                vector="phishing",
                annualized_frequency=0.01,
                observation_periods=0,
            )

    def test_zero_detection_coverage(self):
        with pytest.raises(ValueError, match="detection_coverage"):
            VectorObservation(
                vector="phishing",
                annualized_frequency=0.01,
                observation_periods=4,
                detection_coverage=0.0,
            )

    def test_default_detection_coverage(self):
        obs = VectorObservation(
            vector="exploitation",
            annualized_frequency=0.01,
            observation_periods=4,
        )
        assert obs.detection_coverage == 1.0


class TestOrgTelemetry:
    def test_get_existing_vector(self):
        telem = OrgTelemetry(observations=[
            VectorObservation(vector="credential", annualized_frequency=0.05, observation_periods=4),
            VectorObservation(vector="phishing", annualized_frequency=0.10, observation_periods=4),
        ])
        assert telem.get("credential") is not None
        assert telem.get("credential").annualized_frequency == 0.05

    def test_get_missing_vector(self):
        telem = OrgTelemetry(observations=[
            VectorObservation(vector="credential", annualized_frequency=0.05, observation_periods=4),
        ])
        assert telem.get("exploitation") is None


class TestCredibilityBlender:
    def test_blend_basic(self):
        blender = CredibilityBlender()
        obs = VectorObservation(
            vector="exploitation",
            annualized_frequency=0.01,
            observation_periods=6,
            detection_coverage=1.0,
        )
        result = blender.blend(prior=0.005, obs=obs)

        assert isinstance(result, BlendResult)
        assert result.prior == 0.005
        assert result.adjusted_observed == 0.01
        # Z = 6 / (6 + 6.0) = 0.5 (exploitation k=6, asserted)
        assert abs(result.credibility_z - 6.0 / 12.0) < 0.01
        # blended = Z * 0.01 + (1-Z) * 0.005
        expected_z = 6.0 / 12.0
        expected_blend = expected_z * 0.01 + (1 - expected_z) * 0.005
        assert abs(result.blended - expected_blend) < 0.0001

    def test_credibility_increases_with_periods(self):
        blender = CredibilityBlender()
        obs_short = VectorObservation(
            vector="credential", annualized_frequency=0.05,
            observation_periods=2, detection_coverage=1.0,
        )
        obs_long = VectorObservation(
            vector="credential", annualized_frequency=0.05,
            observation_periods=12, detection_coverage=1.0,
        )
        r_short = blender.blend(prior=0.01, obs=obs_short)
        r_long = blender.blend(prior=0.01, obs=obs_long)

        assert r_short.credibility_z < r_long.credibility_z
        # More periods → blended closer to observed
        assert abs(r_long.blended - 0.05) < abs(r_short.blended - 0.05)

    def test_detection_coverage_adjusts_observation(self):
        blender = CredibilityBlender()
        obs = VectorObservation(
            vector="phishing",
            annualized_frequency=0.06,
            observation_periods=4,
            detection_coverage=0.6,
        )
        result = blender.blend(prior=0.05, obs=obs)

        # adjusted = 0.06 / 0.6 = 0.10
        assert abs(result.adjusted_observed - 0.10) < 0.001
        # effective_n = 4 * 0.6 = 2.4; Z = 2.4 / (2.4 + 10) = 0.1935
        assert result.effective_n == pytest.approx(2.4, abs=0.01)
        assert result.credibility_z < 0.25

    def test_supply_chain_low_credibility(self):
        blender = CredibilityBlender()
        obs = VectorObservation(
            vector="supply_chain",
            annualized_frequency=0.0,
            observation_periods=4,
            detection_coverage=0.5,
        )
        result = blender.blend(prior=0.005, obs=obs)

        # effective_n = 4 * 0.5 = 2.0; Z = 2.0 / (2.0 + 40) = 0.048
        assert result.credibility_z < 0.06
        # blended should barely move from prior
        assert abs(result.blended - 0.005) < 0.001

    def test_k_override(self):
        blender = CredibilityBlender(k_overrides={"exploitation": 2.0})
        obs = VectorObservation(
            vector="exploitation",
            annualized_frequency=0.02,
            observation_periods=4,
            detection_coverage=1.0,
        )
        result = blender.blend(prior=0.005, obs=obs)

        # Z = 4 / (4 + 2) = 0.667 (much higher than default k=6)
        assert result.credibility_z > 0.6

    def test_blend_vectors_multi(self):
        blender = CredibilityBlender()
        telem = OrgTelemetry(observations=[
            VectorObservation(vector="credential", annualized_frequency=0.03, observation_periods=8),
            VectorObservation(vector="phishing", annualized_frequency=0.08, observation_periods=8),
        ])
        priors = {
            "exploitation": 0.003,
            "credential": 0.006,
            "phishing": 0.002,
            "supply_chain": 0.001,
        }
        results = blender.blend_vectors(priors, telem)

        assert "credential" in results
        assert "phishing" in results
        assert "exploitation" not in results
        assert "supply_chain" not in results

    def test_zero_observed_frequency(self):
        blender = CredibilityBlender()
        obs = VectorObservation(
            vector="exploitation",
            annualized_frequency=0.0,
            observation_periods=8,
            detection_coverage=1.0,
        )
        result = blender.blend(prior=0.005, obs=obs)

        # Z = 8 / (8 + 6) = 0.571
        # blended = 0.571 * 0 + 0.429 * 0.005 = 0.002145
        assert result.blended < result.prior
        assert result.blended > 0  # prior prevents full zero


class TestEngineWithCredibility:
    def _make_profile(self, **overrides):
        defaults = dict(
            sector=Sector.MANUFACTURING,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
            remote_access=[RemoteAccessType.FORTINET],
            employee_count=2000,
        )
        defaults.update(overrides)
        return OrganizationProfile(**defaults)

    def test_estimate_without_telemetry(self):
        engine = TEFEngine()
        profile = self._make_profile()
        result = engine.estimate(profile)
        assert not result.has_credibility_data
        for v in result.vectors:
            assert v.credibility_z is None

    def test_estimate_with_telemetry(self):
        engine = TEFEngine()
        telem = OrgTelemetry(observations=[
            VectorObservation(
                vector="credential",
                annualized_frequency=0.02,
                observation_periods=8,
                detection_coverage=0.7,
            ),
        ])
        profile = self._make_profile(telemetry=telem)
        result = engine.estimate(profile)

        assert result.has_credibility_data
        cred_vec = next(v for v in result.vectors if v.vector_name.lower() == "credential")
        assert cred_vec.credibility_z is not None
        assert cred_vec.prior_median is not None
        assert cred_vec.observed_frequency is not None

    def test_telemetry_shifts_estimate(self):
        engine = TEFEngine()
        profile_base = self._make_profile()
        result_base = engine.estimate(profile_base)

        high_telem = OrgTelemetry(observations=[
            VectorObservation(
                vector="credential",
                annualized_frequency=0.10,
                observation_periods=12,
                detection_coverage=0.9,
            ),
        ])
        profile_high = self._make_profile(telemetry=high_telem)
        result_high = engine.estimate(profile_high)

        # Higher observed frequency should increase the total
        assert result_high.total_positioned_median > result_base.total_positioned_median

    def test_floor_enforced_after_blending(self):
        engine = TEFEngine()
        low_telem = OrgTelemetry(observations=[
            VectorObservation(
                vector="exploitation",
                annualized_frequency=0.0,
                observation_periods=20,
                detection_coverage=1.0,
            ),
            VectorObservation(
                vector="credential",
                annualized_frequency=0.0,
                observation_periods=20,
                detection_coverage=1.0,
            ),
            VectorObservation(
                vector="phishing",
                annualized_frequency=0.0,
                observation_periods=20,
                detection_coverage=1.0,
            ),
            VectorObservation(
                vector="supply_chain",
                annualized_frequency=0.0,
                observation_periods=20,
                detection_coverage=1.0,
            ),
        ])
        profile = self._make_profile(telemetry=low_telem)
        result = engine.estimate(profile)

        # Even with all-zero observations, floor should prevent zero TEF
        assert result.total_positioned_median > 0

    def test_credibility_text_output(self):
        engine = TEFEngine()
        telem = OrgTelemetry(observations=[
            VectorObservation(
                vector="exploitation",
                annualized_frequency=0.005,
                observation_periods=4,
            ),
        ])
        profile = self._make_profile(telemetry=telem)
        result = engine.estimate(profile)

        text = result.credibility_text()
        assert "CREDIBILITY ADJUSTMENT" in text
        assert "Z=" in text
        assert "prior:" in text
        assert "blended:" in text

    def test_json_output_includes_credibility(self):
        engine = TEFEngine()
        telem = OrgTelemetry(observations=[
            VectorObservation(
                vector="credential",
                annualized_frequency=0.02,
                observation_periods=6,
            ),
        ])
        profile = self._make_profile(telemetry=telem)
        result = engine.estimate(profile)

        d = result.to_dict()
        cred_data = d["analysis"]["credibility"]
        assert cred_data is not None
        assert len(cred_data) == 1
        assert cred_data[0]["vector"] == "Credential"
        assert cred_data[0]["credibility_z"] is not None


class TestPosteriorBandContraction:
    """Gamma-inspired posterior band contraction."""

    def _make_profile(self, **overrides):
        defaults = dict(
            sector=Sector.MANUFACTURING,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
            remote_access=[RemoteAccessType.FORTINET],
            employee_count=2000,
        )
        defaults.update(overrides)
        return OrganizationProfile(**defaults)

    def test_band_contracts_with_more_data(self):
        engine = TEFEngine()
        profile_base = self._make_profile()
        result_base = engine.estimate(profile_base)
        base_cred = next(v for v in result_base.vectors if v.vector_name.lower() == "credential")
        base_spread = base_cred.positioned_high / max(base_cred.positioned_low, 1e-10)

        long_telem = OrgTelemetry(observations=[
            VectorObservation(
                vector="credential",
                annualized_frequency=0.10,
                observation_periods=40,
                detection_coverage=0.9,
            ),
        ])
        profile_long = self._make_profile(telemetry=long_telem)
        result_long = engine.estimate(profile_long)
        long_cred = next(v for v in result_long.vectors if v.vector_name.lower() == "credential")
        long_spread = long_cred.positioned_high / max(long_cred.positioned_low, 1e-10)

        assert long_spread < base_spread

    def test_more_periods_tighter_band(self):
        engine = TEFEngine()

        short_telem = OrgTelemetry(observations=[
            VectorObservation(
                vector="credential",
                annualized_frequency=0.05,
                observation_periods=4,
                detection_coverage=0.8,
            ),
        ])
        long_telem = OrgTelemetry(observations=[
            VectorObservation(
                vector="credential",
                annualized_frequency=0.05,
                observation_periods=20,
                detection_coverage=0.8,
            ),
        ])
        result_short = engine.estimate(self._make_profile(telemetry=short_telem))
        result_long = engine.estimate(self._make_profile(telemetry=long_telem))

        short_cred = next(v for v in result_short.vectors if v.vector_name.lower() == "credential")
        long_cred = next(v for v in result_long.vectors if v.vector_name.lower() == "credential")

        short_spread = short_cred.positioned_high / max(short_cred.positioned_low, 1e-10)
        long_spread = long_cred.positioned_high / max(long_cred.positioned_low, 1e-10)

        assert long_spread < short_spread

    def test_band_ordering_preserved(self):
        engine = TEFEngine()
        telem = OrgTelemetry(observations=[
            VectorObservation(
                vector="exploitation",
                annualized_frequency=0.02,
                observation_periods=8,
                detection_coverage=0.7,
            ),
        ])
        result = engine.estimate(self._make_profile(telemetry=telem))
        expl = next(v for v in result.vectors if v.vector_name.lower() == "exploitation")

        assert expl.positioned_low <= expl.positioned_median <= expl.positioned_high

    def test_supply_chain_telemetry_applied(self):
        """Regression: supply chain name had space/underscore mismatch."""
        engine = TEFEngine()
        profile_base = self._make_profile()
        result_base = engine.estimate(profile_base)
        sc_base = next(v for v in result_base.vectors if "supply" in v.vector_name.lower())

        telem = OrgTelemetry(observations=[
            VectorObservation(
                vector="supply_chain",
                annualized_frequency=0.5,
                observation_periods=20,
                detection_coverage=1.0,
            ),
        ])
        profile_telem = self._make_profile(telemetry=telem)
        result_telem = engine.estimate(profile_telem)
        sc_telem = next(v for v in result_telem.vectors if "supply" in v.vector_name.lower())

        assert sc_telem.credibility_z is not None
        assert sc_telem.positioned_median != sc_base.positioned_median

    def test_extreme_input_warning(self):
        """Extreme observed rate triggers a credibility warning."""
        engine = TEFEngine()
        telem = OrgTelemetry(observations=[
            VectorObservation(
                vector="exploitation",
                annualized_frequency=5.0,
                observation_periods=20,
                detection_coverage=1.0,
            ),
        ])
        profile = self._make_profile(telemetry=telem)
        result = engine.estimate(profile)

        cred_warnings = [w for w in result.warnings if "Credibility warning" in w]
        assert len(cred_warnings) >= 1
        assert "Exploitation" in cred_warnings[0]

    def test_zero_rate_sigma_invariance(self):
        """Zero observed rate produces N=0, so sigma_post = sigma_prior exactly."""
        import math
        engine = TEFEngine()
        profile_base = self._make_profile()
        result_base = engine.estimate(profile_base)
        cred_base = next(v for v in result_base.vectors if v.vector_name.lower() == "credential")
        sigma_prior = (math.log(cred_base.positioned_high)
                       - math.log(max(cred_base.positioned_low, 1e-10))) / (2 * 1.645)

        zero_telem = OrgTelemetry(observations=[
            VectorObservation(
                vector="credential",
                annualized_frequency=0.0,
                observation_periods=20,
                detection_coverage=1.0,
            ),
        ])
        profile_zero = self._make_profile(telemetry=zero_telem)
        result_zero = engine.estimate(profile_zero)
        cred_zero = next(v for v in result_zero.vectors if v.vector_name.lower() == "credential")

        # sigma_post should equal sigma_prior since N=0.
        # The output band may be narrower due to floor enforcement clipping
        # positioned_low upward, but the underlying sigma is preserved.
        # Recover sigma from positioned_high (not clipped by floor):
        mu_post = math.log(cred_zero.positioned_median)
        sigma_from_high = (math.log(cred_zero.positioned_high) - mu_post) / 1.645

        assert abs(sigma_from_high - sigma_prior) / sigma_prior < 0.01

    def test_contraction_table_values(self):
        """Verify documented contraction rates match engine output."""
        import math
        engine = TEFEngine()
        profile_base = self._make_profile()
        result_base = engine.estimate(profile_base)
        cred_base = next(v for v in result_base.vectors if v.vector_name.lower() == "credential")
        sigma_prior = (math.log(cred_base.positioned_high)
                       - math.log(max(cred_base.positioned_low, 1e-10))) / (2 * 1.645)

        # Contraction values band hardening (eff_n capped at 5.0):
        # 20Q and 8Q produce identical contraction because both are capped at eff_n=5
        expected = [(4, 0.05, 0.04), (8, 0.05, 0.047), (20, 0.05, 0.047), (40, 0.10, 0.087)]
        for quarters, rate, expected_contraction in expected:
            telem = OrgTelemetry(observations=[
                VectorObservation(
                    vector="credential",
                    annualized_frequency=rate,
                    observation_periods=quarters,
                    detection_coverage=1.0,
                ),
            ])
            result = engine.estimate(self._make_profile(telemetry=telem))
            cred = next(v for v in result.vectors if v.vector_name.lower() == "credential")
            sigma_post = (math.log(cred.positioned_high)
                          - math.log(max(cred.positioned_low, 1e-10))) / (2 * 1.645)
            actual = 1 - sigma_post / sigma_prior
            assert abs(actual - expected_contraction) < 0.02, (
                f"{quarters}Q rate={rate}: expected {expected_contraction:.0%}, got {actual:.0%}"
            )

    def test_duplicate_vector_observation_rejected(self):
        """Duplicate vector names in OrgTelemetry raise ValueError."""
        import pytest
        with pytest.raises(ValueError, match="Duplicate"):
            OrgTelemetry(observations=[
                VectorObservation(vector="credential", annualized_frequency=0.05,
                                  observation_periods=4, detection_coverage=1.0),
                VectorObservation(vector="credential", annualized_frequency=0.10,
                                  observation_periods=8, detection_coverage=1.0),
            ])


class TestTelemetryFileLoading:
    def test_load_telemetry_from_json(self, tmp_path):
        data = {
            "observations": [
                {
                    "vector": "credential",
                    "annualized_frequency": 0.03,
                    "observation_periods": 6,
                    "detection_coverage": 0.75,
                },
                {
                    "vector": "phishing",
                    "annualized_frequency": 0.08,
                    "observation_periods": 6,
                    "detection_coverage": 0.9,
                },
            ]
        }
        f = tmp_path / "telemetry.json"
        f.write_text(json.dumps(data))

        from tef_estimator.cli import _load_telemetry
        telem = _load_telemetry(f)

        assert len(telem.observations) == 2
        assert telem.get("credential").annualized_frequency == 0.03
        assert telem.get("phishing").detection_coverage == 0.9
