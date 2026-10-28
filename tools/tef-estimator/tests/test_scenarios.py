"""Built-in scenarios and reference data: base-rate recipes, sector adjustment, data completeness."""

import pytest

from tef_estimator.data.common import (
    GEO_MULTIPLIERS,
    REVENUE_BAND_DATA,
    SECTOR_DATA,
    DampeningConfig,
    Geography,
    PERTRange,
    RevenueBand,
    Sector,
)
from tef_estimator.data.scenarios.bec import BECScenario
from tef_estimator.data.scenarios.ransomware import RansomwareScenario

class TestRansomwareScenario:
    def setup_method(self):
        self.scenario = RansomwareScenario()

    def test_adjusted_multiplier_composition(self):
        """Verify: adjusted = common_mult * (sector_share / overall_share)."""
        from tef_estimator.data.common import SECTOR_DATA
        sector = Sector.MANUFACTURING
        common_mult = SECTOR_DATA[sector].all_incident_multiplier
        share = self.scenario.sector_shares.get(sector)
        expected = common_mult * (share / self.scenario.overall_share)
        actual = self.scenario.adjusted_sector_multiplier(sector)
        assert abs(actual - expected) < 1e-6

    def test_revenue_is_in_the_tiered_base_rate(self):
        # The base rate is set per revenue tier, so no revenue multiplier on top
        r = self.scenario.adjusted_revenue_multiplier_range(RevenueBand.R_100M_1B)
        assert r == PERTRange(1.0, 1.0, 1.0)

class TestExfiltrationAndWebAppBaseRate:
    def test_exfiltration_underreporting_from_ic3_ransomware_capture(self):
        # IC3 ransomware complaints ÷ US ransomware victims = the IC3 filing rate
        from tef_estimator.data.scenarios.exfiltration import ExfiltrationScenario
        rw = RansomwareScenario().base_rate_lef
        ic3_ransomware = 3611
        low, mode, high = (rw["n_us"] * u / ic3_ransomware for u in rw["underreporting"])
        ex = ExfiltrationScenario().base_rate_lef
        # Low and mode measured; high = half the lowest ransomware filing rate (judgment)
        assert ex["underreporting"] == [round(low, 2), round(mode, 2), round(2 * high, 2)]
        firms = {name: t["us_firms"] for name, t in ex["tiers"].items()}
        assert firms == {name: t["us_firms"] for name, t in rw["tiers"].items()}

    def test_exfiltration_gradient_above_1b(self):
        # From $1B the measured $100M–1B rate scales by IRIS's all-incident revenue multipliers
        from tef_estimator.base_rate import scenario_lef
        from tef_estimator.data.common import REVENUE_BAND_DATA
        from tef_estimator.data.scenarios.exfiltration import ExfiltrationScenario
        ex = ExfiltrationScenario()
        ref = scenario_lef(ex, RevenueBand.R_100M_1B).mode
        for band in (RevenueBand.R_1B_10B, RevenueBand.R_10B_100B, RevenueBand.OVER_100B):
            ratio = REVENUE_BAND_DATA[band].all_incident_multiplier / REVENUE_BAND_DATA[RevenueBand.R_100M_1B].all_incident_multiplier
            assert scenario_lef(ex, band).mode == pytest.approx(ref * ratio)

    def test_web_app_is_a_share_of_exfiltration(self):
        from tef_estimator.base_rate import scenario_lef
        from tef_estimator.data.scenarios.exfiltration import ExfiltrationScenario
        from tef_estimator.data.scenarios.web_app import WebAppScenario
        web = WebAppScenario()
        share = web.base_rate_lef["share"]
        for band in RevenueBand:
            ex, wa = scenario_lef(ExfiltrationScenario(), band), scenario_lef(web, band)
            assert wa.low == pytest.approx(ex.low * share[0])
            assert wa.mode == pytest.approx(ex.mode * share[1])
            assert wa.high == pytest.approx(ex.high * share[2])

    def test_revenue_is_in_the_tiered_base_rate(self):
        from tef_estimator.data.scenarios.exfiltration import ExfiltrationScenario
        from tef_estimator.data.scenarios.web_app import WebAppScenario
        for scenario in (ExfiltrationScenario(), WebAppScenario()):
            assert scenario.adjusted_revenue_multiplier_range(RevenueBand.R_1B_10B) == PERTRange(1.0, 1.0, 1.0)


class TestBECScenario:
    def setup_method(self):
        self.scenario = BECScenario()

    def test_base_rate_higher_than_ransomware_for_smaller_firms(self):
        from tef_estimator.engine import TEFEngine
        band = RevenueBand.R_10M_100M
        bec = TEFEngine(scenario=self.scenario).base_rate_for(band)
        rw = TEFEngine(scenario=RansomwareScenario()).base_rate_for(band)
        assert bec.mode > rw.mode

class TestBECEstimation:
    def test_bec_tef_higher_than_ransomware(self):
        from tef_estimator.data.common import Geography, RemoteAccessType
        from tef_estimator.engine import TEFEngine
        from tef_estimator.profile import OrganizationProfile

        profile = OrganizationProfile(
            sector=Sector.FINANCIAL,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
            remote_access=[RemoteAccessType.NONE],
        )
        bec_result = TEFEngine(scenario=BECScenario()).estimate(profile)
        rw_result = TEFEngine(scenario=RansomwareScenario()).estimate(profile)
        assert bec_result.total_positioned_median > rw_result.total_positioned_median


class TestSectorData:
    def test_all_sectors_populated(self):
        for sector in Sector:
            assert sector in SECTOR_DATA, f"Missing sector: {sector}"

    def test_multipliers_positive(self):
        for sector, data in SECTOR_DATA.items():
            assert data.all_incident_multiplier > 0, f"{sector} has non-positive multiplier"

class TestRevenueBandData:
    def test_all_bands_populated(self):
        for band in RevenueBand:
            assert band in REVENUE_BAND_DATA, f"Missing band: {band}"

    def test_multipliers_positive(self):
        for band, data in REVENUE_BAND_DATA.items():
            assert data.all_incident_multiplier > 0


class TestGeoMultipliers:
    def test_all_geos_populated(self):
        for geo in Geography:
            assert geo in GEO_MULTIPLIERS, f"Missing geo: {geo}"

class TestDampeningConfig:
    def test_source_citations_not_empty(self):
        d = DampeningConfig()
        assert d.factor_k_source, "factor_k_source should have a citation"
        assert d.vector_k_source, "vector_k_source should have a citation"
        assert d.max_composite_source, "max_composite_source should have a citation"

class TestRansomwareData:
    def setup_method(self):
        self.scenario = RansomwareScenario()

    def test_base_rate_tiers_cover_every_band(self):
        tiers = self.scenario.base_rate_lef["tiers"].values()
        covered = [b for t in tiers for b in t["bands"]]
        assert sorted(covered) == sorted(b.value for b in RevenueBand)
