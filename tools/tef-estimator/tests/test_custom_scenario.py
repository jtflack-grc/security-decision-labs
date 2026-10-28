"""Custom scenarios: validation, defaults, engine runs, templates, consensus triangulation."""

import json
from pathlib import Path

import pytest

from tef_estimator.data.common import (
    Geography,
    PERTRange,
    RevenueBand,
    Sector,
)
from tef_estimator.data.scenarios.base import ScenarioDefinition
from tef_estimator.data.scenarios.custom import (
    generate_template,
    load_custom_scenario,
)
from tef_estimator.engine import TEFEngine
from tef_estimator.profile import OrganizationProfile
from tef_estimator.triangulation import extract_anchors, triangulate

VALID_SCENARIO = {
    "scenario_name": "Data Exfiltration",
    "scenario_slug": "data_exfil",
    "vector_proportions": {
        "exploitation": [0.10, 0.20, 0.30],
        "credential": [0.30, 0.40, 0.50],
        "phishing": [0.15, 0.25, 0.35],
        "supply_chain": [0.05, 0.15, 0.20],
    },
    "base_rate": {
        "consensus": [0.005, 0.015, 0.04],
    },
    "overall_share": 0.10,
}


def _write_scenario(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(data))
    return path


class TestCustomScenarioValidation:
    def test_valid_scenario(self, tmp_path):
        path = _write_scenario(tmp_path, VALID_SCENARIO)
        s = load_custom_scenario(path)
        assert s.scenario_name == "Data Exfiltration"
        assert s.scenario_slug == "data_exfil"

    def test_missing_required_field(self, tmp_path):
        bad = dict(VALID_SCENARIO)
        del bad["vector_proportions"]
        path = _write_scenario(tmp_path, bad)
        with pytest.raises(ValueError, match="missing required"):
            load_custom_scenario(path)

    def test_unknown_vector(self, tmp_path):
        bad = dict(VALID_SCENARIO)
        bad["vector_proportions"] = dict(VALID_SCENARIO["vector_proportions"])
        bad["vector_proportions"]["insider"] = [0.1, 0.2, 0.3]
        path = _write_scenario(tmp_path, bad)
        with pytest.raises(ValueError, match="Unknown vectors"):
            load_custom_scenario(path)

    def test_proportions_dont_sum(self, tmp_path):
        bad = dict(VALID_SCENARIO)
        bad["vector_proportions"] = {
            "exploitation": [0.5, 0.6, 0.7],
            "credential": [0.5, 0.6, 0.7],
        }
        path = _write_scenario(tmp_path, bad)
        with pytest.raises(ValueError, match="sum to"):
            load_custom_scenario(path)

    def test_missing_consensus(self, tmp_path):
        bad = dict(VALID_SCENARIO)
        bad["base_rate"] = {"anchor_1": [0.01, 0.02, 0.03]}
        path = _write_scenario(tmp_path, bad)
        with pytest.raises(ValueError, match="consensus"):
            load_custom_scenario(path)


class TestCustomScenarioProtocol:
    @pytest.fixture
    def scenario(self, tmp_path):
        path = _write_scenario(tmp_path, VALID_SCENARIO)
        return load_custom_scenario(path)

    def test_implements_protocol(self, scenario):
        assert isinstance(scenario, ScenarioDefinition)

    def test_sector_shares_default_to_none(self, scenario):
        shares = scenario.sector_shares
        for sector in Sector:
            assert shares[sector] is None

    def test_revenue_shares_default_to_overall(self, scenario):
        shares = scenario.revenue_shares
        for band in RevenueBand:
            assert shares[band] == scenario.overall_share

class TestCustomScenarioWithOptionalFields:
    def test_with_sector_shares(self, tmp_path):
        data = dict(VALID_SCENARIO)
        data["sector_shares"] = {"manufacturing": 0.15, "financial": 0.20}
        path = _write_scenario(tmp_path, data)
        s = load_custom_scenario(path)

        assert s.sector_shares[Sector.MANUFACTURING] == 0.15
        assert s.sector_shares[Sector.FINANCIAL] == 0.20
        assert s.sector_shares[Sector.EDUCATION] is None

    def test_with_revenue_shares(self, tmp_path):
        data = dict(VALID_SCENARIO)
        data["revenue_shares"] = {"100m_1b": 0.12, "1b_10b": 0.15}
        path = _write_scenario(tmp_path, data)
        s = load_custom_scenario(path)

        assert s.revenue_shares[RevenueBand.R_100M_1B] == 0.12
        assert s.revenue_shares[RevenueBand.UNDER_10M] == 0.10  # falls back to overall_share

    def test_with_additional_anchors(self, tmp_path):
        data = dict(VALID_SCENARIO)
        data["base_rate"] = {
            "anchor_1": [0.01, 0.02, 0.03],
            "anchor_2": [0.005, 0.015, 0.05],
            "consensus": [0.005, 0.015, 0.04],
        }
        path = _write_scenario(tmp_path, data)
        s = load_custom_scenario(path)

        br = s.base_rate_triangulation
        assert len(br) == 3


class TestCustomScenarioEngine:
    def test_engine_runs_with_custom_scenario(self, tmp_path):
        path = _write_scenario(tmp_path, VALID_SCENARIO)
        scenario = load_custom_scenario(path)

        engine = TEFEngine(scenario=scenario)
        profile = OrganizationProfile(
            sector=Sector.MANUFACTURING,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
        )
        result = engine.estimate(profile)

        assert result.total_positioned_median > 0
        assert result.scenario_name == "Data Exfiltration"
        assert len(result.vectors) == 4

    def test_engine_honors_active_vectors(self, tmp_path):
        # A scenario that declares only two vectors must produce two estimates.
        data = dict(VALID_SCENARIO)
        data["vector_proportions"] = {
            "credential": [0.5, 0.6, 0.7],
            "phishing": [0.3, 0.4, 0.5],
        }
        path = _write_scenario(tmp_path, data)
        scenario = load_custom_scenario(path)

        engine = TEFEngine(scenario=scenario)
        profile = OrganizationProfile(
            sector=Sector.MANUFACTURING,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
        )
        result = engine.estimate(profile)

        assert [v.vector_name for v in result.vectors] == ["Credential", "Phishing"]

    def test_sensitivity_with_custom_scenario(self, tmp_path):
        path = _write_scenario(tmp_path, VALID_SCENARIO)
        scenario = load_custom_scenario(path)

        engine = TEFEngine(scenario=scenario)
        profile = OrganizationProfile(
            sector=Sector.FINANCIAL,
            revenue_band=RevenueBand.R_1B_10B,
            geography=Geography.US,
        )
        result = engine.sensitivity(profile)
        assert result.baseline_median > 0
        assert len(result.entries) >= 2


class TestTemplate:
    def test_template_runs_in_engine(self, tmp_path):
        path = tmp_path / "template.json"
        generate_template(path)
        scenario = load_custom_scenario(path)

        engine = TEFEngine(scenario=scenario)
        profile = OrganizationProfile(
            sector=Sector.INFORMATION,
            revenue_band=RevenueBand.R_10M_100M,
            geography=Geography.US,
        )
        result = engine.estimate(profile)
        assert result.total_positioned_median > 0


class TestTriangulate:
    def test_suggested_low_is_min_of_anchor_lows(self):
        anchors = {
            "a": PERTRange(0.003, 0.005, 0.007),
            "b": PERTRange(0.005, 0.015, 0.08),
            "c": PERTRange(0.006, 0.012, 0.015),
        }
        result = triangulate(anchors)
        assert result.suggested.low == 0.003

    def test_suggested_mode_is_mean_of_anchor_modes(self):
        anchors = {
            "a": PERTRange(0.003, 0.005, 0.007),
            "b": PERTRange(0.005, 0.015, 0.08),
            "c": PERTRange(0.006, 0.012, 0.015),
        }
        result = triangulate(anchors)
        expected = round((0.005 + 0.015 + 0.012) / 3, 4)
        assert result.suggested.mode == expected

    def test_suggested_high_capped_at_max_anchor_high(self):
        anchors = {
            "a": PERTRange(0.01, 0.02, 0.03),
            "b": PERTRange(0.01, 0.02, 0.03),
            "c": PERTRange(0.01, 0.02, 0.03),
        }
        result = triangulate(anchors)
        assert result.suggested.high <= 0.03

    def test_convergent_anchors(self):
        anchors = {
            "a": PERTRange(0.003, 0.005, 0.007),
            "b": PERTRange(0.005, 0.015, 0.08),
            "c": PERTRange(0.006, 0.012, 0.015),
        }
        result = triangulate(anchors)
        assert result.is_convergent is True
        assert result.convergence_ratio == 3.0

    def test_divergent_anchors(self):
        anchors = {
            "a": PERTRange(0.001, 0.001, 0.002),
            "b": PERTRange(0.05, 0.10, 0.20),
            "c": PERTRange(0.001, 0.015, 0.03),
        }
        result = triangulate(anchors)
        assert result.is_convergent is False
        assert result.convergence_ratio > 10.0

    def test_large_deviation_produces_warning(self):
        anchors = {
            "a": PERTRange(0.01, 0.02, 0.03),
            "b": PERTRange(0.01, 0.02, 0.03),
        }
        bad_consensus = PERTRange(0.001, 0.001, 0.003)
        result = triangulate(anchors, actual_consensus=bad_consensus)
        warning_lines = [v for v in result.validation if "WARNING" in v]
        assert len(warning_lines) == 1

class TestExtractAnchors:
    def test_separates_consensus_from_anchors(self):
        tri = {
            "operational_tempo": PERTRange(0.003, 0.005, 0.007),
            "iris_back_calculation": PERTRange(0.005, 0.015, 0.08),
            "consensus": PERTRange(0.003, 0.010, 0.025),
        }
        anchors, consensus = extract_anchors(tri)
        assert "consensus" not in anchors
        assert len(anchors) == 2
        assert consensus == PERTRange(0.003, 0.010, 0.025)

class TestScenarioTriangulation:
    """Built-in scenarios take their base rate from one population (base_rate.py);
    triangulation applies to custom scenarios with a consensus only."""

    def test_builtin_scenarios_have_no_consensus(self):
        from tef_estimator.data.scenarios import SCENARIO_CLASSES
        for slug, cls in SCENARIO_CLASSES.items():
            scenario = cls()
            assert "consensus" not in scenario.base_rate_triangulation, slug
            assert scenario.base_rate_lef, slug
