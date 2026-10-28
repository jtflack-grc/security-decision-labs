"""Estimate engine: positioning, vectors, floors, compare, sensitivity, reports, profile validation, vector shares, pinned medians."""

import pytest

from tef_estimator.data.common import (
    Geography,
    RemoteAccessType,
    RevenueBand,
    Sector,
)
from tef_estimator.data.loader import normalized_proportions
from tef_estimator.data.scenarios.bec import BECScenario
from tef_estimator.data.scenarios.exfiltration import ExfiltrationScenario
from tef_estimator.data.scenarios.ransomware import RansomwareScenario
from tef_estimator.data.scenarios.web_app import WebAppScenario
from tef_estimator.engine import TEFEngine
from tef_estimator.profile import OrganizationProfile
from tef_estimator.vectors.credential import CredentialVector
from tef_estimator.vectors.exploitation import ExploitationVector
from tef_estimator.vectors.phishing import PhishingVector
from tef_estimator.vectors.supply_chain import SupplyChainVector

@pytest.fixture
def engine():
    return TEFEngine()


def _make_profile(**overrides):
    defaults = dict(
        sector=Sector.MANUFACTURING,
        revenue_band=RevenueBand.R_100M_1B,
        geography=Geography.US,
        remote_access=[RemoteAccessType.FORTINET],
        employee_count=2000,
    )
    defaults.update(overrides)
    return OrganizationProfile(**defaults)


class TestEstimate:
    def test_high_risk_manufacturing(self, engine):
        profile = _make_profile()
        result = engine.estimate(profile)
        assert result.total_positioned_median > 0
        assert result.total_positioned_low <= result.total_positioned_median
        assert result.total_positioned_median <= result.total_positioned_high
        # Implied annual loss (x susceptibility mode 0.17) inside IRIS's
        # $100M-1B bracket, 1.20%-9.83%
        assert 0.012 < result.total_positioned_median * 0.17 < 0.0983

    def test_minimal_input(self, engine):
        """Engine works with just sector, revenue, geography."""
        profile = OrganizationProfile(
            sector=Sector.EDUCATION,
            revenue_band=RevenueBand.R_10M_100M,
            geography=Geography.WESTERN_EUROPE,
        )
        result = engine.estimate(profile)
        assert result.total_positioned_median > 0

    def test_custom_base_rate(self):
        engine = TEFEngine()
        profile = _make_profile(custom_base_rate=0.9)
        result = engine.estimate(profile)
        # Higher base rate -> higher estimate
        default_result = engine.estimate(_make_profile())
        assert result.total_positioned_median > default_result.total_positioned_median

    def test_floor_enforced(self, engine):
        profile = _make_profile()
        result = engine.estimate(profile)
        assert result.total_positioned_median >= result.total_floor

class TestCompare:
    def test_vpn_removal_reduces(self, engine):
        with_vpn = _make_profile(remote_access=[RemoteAccessType.FORTINET])
        no_vpn = _make_profile(remote_access=[RemoteAccessType.NONE])
        diff = engine.compare(with_vpn, no_vpn)
        assert diff.total_delta < 0  # Removing VPN should reduce TEF

class TestSensitivity:
    def test_base_rate_dominates(self, engine):
        profile = _make_profile()
        sens = engine.sensitivity(profile)
        assert len(sens.entries) >= 3
        # Base rate should be the first (highest range)
        assert sens.entries[0].parameter == "base_rate"
        assert sens.entries[0].range_multiple > 1.0

class TestThreeTierOutput:
    def test_full_report(self, engine):
        result = engine.estimate(_make_profile())
        text = result.full_report()
        assert "THREAT EVENT FREQUENCY ESTIMATE" in text
        assert "CALCULATION TRACES" in text
        assert "DATA SOURCES" in text
        assert "BASE RATE DERIVATION" in text

    def test_to_markdown(self, engine):
        result = engine.estimate(_make_profile())
        md = result.to_markdown()
        assert md.startswith("# Ransomware TEF Estimate")
        assert "## Vector Breakdown" in md
        assert "## Distribution Parameters" in md
        assert "## Calculation Traces" in md
        assert "## Data Sources" in md
        assert "## Base Rate Derivation" in md


@pytest.fixture
def scenario():
    return RansomwareScenario()


@pytest.fixture
def base_rate(scenario):
    from tef_estimator.engine import TEFEngine
    return TEFEngine(scenario=scenario).base_rate_for(RevenueBand.R_100M_1B)


@pytest.fixture
def manufacturing_profile():
    return OrganizationProfile(
        sector=Sector.MANUFACTURING,
        revenue_band=RevenueBand.R_100M_1B,
        geography=Geography.US,
        remote_access=[RemoteAccessType.FORTINET],
        employee_count=2000,
    )


@pytest.fixture
def minimal_profile():
    return OrganizationProfile(
        sector=Sector.FINANCIAL,
        revenue_band=RevenueBand.R_10M_100M,
        geography=Geography.US,
    )


class TestExploitationVector:
    def test_floor_respected(self, manufacturing_profile, base_rate, scenario):
        vec = ExploitationVector()
        est = vec.estimate(manufacturing_profile, base_rate, scenario)
        assert est.positioned_low >= est.floor

    def test_vpn_increases_estimate(self, base_rate, scenario):
        no_vpn = OrganizationProfile(
            sector=Sector.MANUFACTURING,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
        )
        with_vpn = OrganizationProfile(
            sector=Sector.MANUFACTURING,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
            remote_access=[RemoteAccessType.FORTINET],
        )
        vec = ExploitationVector()
        est_no = vec.estimate(no_vpn, base_rate, scenario)
        est_yes = vec.estimate(with_vpn, base_rate, scenario)
        assert est_yes.positioned_median > est_no.positioned_median


class TestCredentialVector:
    def test_no_remote_reduces(self, base_rate, scenario):
        with_vpn = OrganizationProfile(
            sector=Sector.MANUFACTURING,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
            remote_access=[RemoteAccessType.FORTINET],
        )
        no_remote = OrganizationProfile(
            sector=Sector.MANUFACTURING,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
            remote_access=[RemoteAccessType.NONE],
        )
        vec = CredentialVector()
        est_vpn = vec.estimate(with_vpn, base_rate, scenario)
        est_none = vec.estimate(no_remote, base_rate, scenario)
        assert est_none.positioned_median < est_vpn.positioned_median


class TestPhishingVector:
    def test_large_email_footprint_increases(self, base_rate, scenario):
        small_co = OrganizationProfile(
            sector=Sector.MANUFACTURING,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
            employee_count=30,
        )
        large_co = OrganizationProfile(
            sector=Sector.MANUFACTURING,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
            employee_count=5000,
        )
        vec = PhishingVector()
        est_small = vec.estimate(small_co, base_rate, scenario)
        est_large = vec.estimate(large_co, base_rate, scenario)
        assert est_large.positioned_median > est_small.positioned_median

class TestSupplyChainVector:
    def test_supply_chain_provider_increases(self, base_rate, scenario):
        base = OrganizationProfile(
            sector=Sector.MANUFACTURING,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
        )
        provider = OrganizationProfile(
            sector=Sector.MANUFACTURING,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
            supply_chain_provider=True,
        )
        vec = SupplyChainVector()
        est_base = vec.estimate(base, base_rate, scenario)
        est_provider = vec.estimate(provider, base_rate, scenario)
        assert est_provider.positioned_median > est_base.positioned_median


PROFILE = dict(sector=Sector.MANUFACTURING, revenue_band=RevenueBand.R_100M_1B,
               geography=Geography.US, remote_access=[RemoteAccessType.FORTINET])


@pytest.mark.parametrize("cls,median", [
    (RansomwareScenario, 0.43723),
    (ExfiltrationScenario, 0.23001),
    (BECScenario, 0.10230),
    (WebAppScenario, 0.05879),
])
def test_reference_median(cls, median):
    r = TEFEngine(scenario=cls()).estimate(OrganizationProfile(**PROFILE))
    assert r.total_positioned_median == pytest.approx(median, abs=5e-6)


@pytest.mark.parametrize("cls", [ExfiltrationScenario, WebAppScenario])
def test_sector_multiplier_applied_once_without_scenario_data(cls):
    from tef_estimator.data.common import SECTOR_DATA
    scenario = cls()
    for sector in Sector:
        assert scenario.sector_shares.get(sector) is None
        assert scenario.adjusted_sector_multiplier(sector) == SECTOR_DATA[sector].all_incident_multiplier


SCENARIOS = [RansomwareScenario, BECScenario, ExfiltrationScenario, WebAppScenario]


def test_helper_scales_all_three_points():
    out = normalized_proportions({"a": [0.1, 0.475, 0.6], "b": [0.3, 0.475, 0.5], "_note": "x"})
    assert set(out) == {"a", "b"}
    assert sum(m for _, m, _ in out.values()) == pytest.approx(1.0)
    assert out["a"] == pytest.approx((0.1 / 0.95, 0.5, 0.6 / 0.95))


def test_helper_rejects_zero_total():
    with pytest.raises(ValueError):
        normalized_proportions({"a": [0, 0, 0]})


@pytest.mark.parametrize("cls", SCENARIOS)
def test_builtin_modes_sum_to_one(cls):
    assert sum(v.mode for v in cls().vector_proportions.values()) == pytest.approx(1.0)


def test_custom_scenario_normalized(tmp_path):
    import json

    from tef_estimator.data.scenarios.custom import CustomScenario, generate_template
    path = tmp_path / "s.json"
    generate_template(path)
    data = json.loads(path.read_text())
    for k in ("exploitation", "credential", "phishing", "supply_chain"):
        data["vector_proportions"][k] = [x * 0.9 for x in data["vector_proportions"][k]]
    vp = CustomScenario(data).vector_proportions
    assert sum(v.mode for v in vp.values()) == pytest.approx(1.0)


def _profile_with(**overrides):
    defaults = dict(
        sector=Sector.MANUFACTURING,
        revenue_band=RevenueBand.R_100M_1B,
        geography=Geography.US,
    )
    defaults.update(overrides)
    return OrganizationProfile(**defaults)


class TestVPNDetection:
    def test_vulnerable_vendor(self):
        for vendor in [RemoteAccessType.FORTINET, RemoteAccessType.CISCO,
                       RemoteAccessType.PALO_ALTO, RemoteAccessType.SONICWALL]:
            p = _profile_with(remote_access=[vendor])
            assert p.has_vulnerable_vpn_vendor is True

    def test_other_vpn_not_vulnerable(self):
        p = _profile_with(remote_access=[RemoteAccessType.OTHER_VPN])
        assert p.has_vpn is True
        assert p.has_vulnerable_vpn_vendor is False


class TestEmployeeBands:
    def test_large_email_footprint(self):
        p = _profile_with(employee_count=5000)
        assert p.has_large_email_footprint is True

    def test_small_no_large_email(self):
        p = _profile_with(employee_count=100)
        assert p.has_large_email_footprint is False


class TestCloudPrimary:
    def test_no_remote_no_edge_is_cloud(self):
        p = _profile_with(
            remote_access=[RemoteAccessType.NONE],
            edge_vendors=[],
        )
        assert p.is_cloud_primary is True

class TestValidation:
    def test_negative_employee_count_raises(self):
        import pytest
        with pytest.raises(ValueError, match="non-negative"):
            _profile_with(employee_count=-1)

    def test_absurd_employee_count_raises(self):
        import pytest
        with pytest.raises(ValueError, match="exceeds 10M"):
            _profile_with(employee_count=99_000_000)

    def test_base_rate_zero_raises(self):
        import pytest
        with pytest.raises(ValueError, match="must be positive"):
            _profile_with(custom_base_rate=0.0)

    def test_base_rate_negative_raises(self):
        import pytest
        with pytest.raises(ValueError, match="must be positive"):
            _profile_with(custom_base_rate=-0.5)

    def test_base_rate_over_one_accepted(self):
        # TEF is a rate: more than one attempt a year is valid
        assert _profile_with(custom_base_rate=1.5).custom_base_rate == 1.5
