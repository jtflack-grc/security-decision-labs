"""Exploitation and credential ceilings: derivation, audit checks, never caps."""

import math

import pytest

from tef_estimator.config import TEFConfig
from tef_estimator.data.common import Geography, RemoteAccessType, RevenueBand, Sector
from tef_estimator.data.scenarios.bec import BECScenario
from tef_estimator.data.scenarios.ransomware import RansomwareScenario
from tef_estimator.engine import TEFEngine
from tef_estimator.profile import OrganizationProfile
from tef_estimator.vectors.exploitation import derived_exploitation_ceiling, exposure_class

SOURCES = {22: 21747, 23: 21620, 443: 18863, 445: 6072, 3389: 2992, 8080: 14840, 8443: 4861}


def _profile(**kw):
    base = dict(sector=Sector.MANUFACTURING, revenue_band=RevenueBand.R_100M_1B,
                geography=Geography.US, remote_access=[RemoteAccessType.NONE])
    return OrganizationProfile(**{**base, **kw})


def _expected(scanning, ports, suspicious=0.35):
    contact = sum(SOURCES[p] for p in ports)
    return (contact * (scanning["grn_malicious_rate"].mode + 0.5 * suspicious)
            / math.exp(scanning["campaign_ip_ratio_lognormal_mu"]) * 365
            * scanning["ransomware_proportion_of_scanning"].mode
            * scanning["poa_ransomware"].high)


def _cfg(**over):
    d = TEFConfig.from_dict({}).exploitation_ceiling_derivation
    d = {**d, "dshield_snapshot": {**d["dshield_snapshot"], "unique_sources": SOURCES}, **over}
    return d


class TestExposureClass:
    @pytest.mark.parametrize("remote,expected", [
        ([RemoteAccessType.FORTINET], "vpn"),
        ([RemoteAccessType.RDP], "rdp"),
        ([RemoteAccessType.FORTINET, RemoteAccessType.RDP], "vpn+rdp"),
        ([RemoteAccessType.NONE], "web"),
    ])
    def test_classes(self, remote, expected):
        assert exposure_class(_profile(remote_access=remote)) == expected


class TestDerivation:
    def test_ransomware_vpn_matches_formula(self):
        scanning = RansomwareScenario().exploitation_scanning
        ceiling, exposure, detail = derived_exploitation_ceiling(
            _profile(remote_access=[RemoteAccessType.FORTINET]), scanning, _cfg())
        assert exposure == "vpn"
        assert ceiling == pytest.approx(_expected(scanning, [443, 8443]))
        assert "443, 8443" in detail and "2026-10-23" in detail

    def test_worked_example_reproduced(self):
        # 30,000 sources/day × 0.45 ÷ 55 × 365 × 0.40 × 0.9 ≈ 32,000/yr
        scanning = {"grn_malicious_rate": 0.275, "campaign_ip_ratio_lognormal_mu": math.log(55),
                    "ransomware_proportion_of_scanning": 0.40, "poa_ransomware": 0.9}
        cfg = _cfg(dshield_snapshot={"unique_sources": {443: 30000}}, ports={"vpn": [443]})
        ceiling, _, _ = derived_exploitation_ceiling(
            _profile(remote_access=[RemoteAccessType.FORTINET]), scanning, cfg)
        assert ceiling == pytest.approx(32_245, rel=0.01)

    def test_vpn_and_rdp_union_of_ports(self):
        scanning = RansomwareScenario().exploitation_scanning
        ceiling, exposure, _ = derived_exploitation_ceiling(
            _profile(remote_access=[RemoteAccessType.FORTINET, RemoteAccessType.RDP]), scanning, _cfg())
        assert exposure == "vpn+rdp"
        assert ceiling == pytest.approx(_expected(scanning, [443, 3389, 8443]))

    def test_scenario_share_used(self):
        rw = RansomwareScenario().exploitation_scanning
        bec = BECScenario().exploitation_scanning
        p = _profile()
        c_rw, _, _ = derived_exploitation_ceiling(p, rw, _cfg())
        c_bec, _, _ = derived_exploitation_ceiling(p, bec, _cfg())
        assert c_bec < c_rw

    def test_missing_port_data_falls_back(self):
        cfg = _cfg(dshield_snapshot={"unique_sources": {443: 1000}})
        assert derived_exploitation_ceiling(_profile(), RansomwareScenario().exploitation_scanning, cfg) is None

    def test_missing_scanning_input_falls_back(self):
        assert derived_exploitation_ceiling(_profile(), {"grn_malicious_rate": 0.28}, _cfg()) is None


class TestEngine:
    def test_bundled_snapshot_gives_derived_ceiling(self):
        r = TEFEngine().estimate(_profile())
        expl = next(v for v in r.vectors if v.telemetry_key == "exploitation")
        assert expl.ceiling > 1000  # the 0.01 assumption is gone for cloud-primary
        assert any("campaign contact frequency" in step.source for step in expl.trace.steps)

    def test_ceiling_never_moves_positioned_values(self):
        frozen = TEFEngine().estimate(_profile())
        no_data = TEFEngine(config=TEFConfig.from_dict(
            {"exploitation_ceiling_derivation": {"dshield_snapshot": None}})).estimate(_profile())
        assert frozen.total_positioned_median == no_data.total_positioned_median
        assert frozen.total_positioned_high == no_data.total_positioned_high


class TestAuditChecks:
    def test_each_vector_checked_against_its_ceiling(self):
        r = TEFEngine().estimate(_profile())
        lines = [c for c in r.validation_checks if "ceiling" in c and "Positioned" not in c]
        assert len(lines) == len(r.vectors)
        expl = next(c for c in lines if "Exploitation" in c)
        assert expl.startswith("Exploitation median <= ceiling")

    def test_above_ceiling_is_reported(self):
        from tef_estimator.data.scenarios.exfiltration import ExfiltrationScenario
        p = _profile(sector=Sector.EDUCATION, revenue_band=RevenueBand.R_100M_1B,
                     remote_access=[RemoteAccessType.FORTINET])
        r = TEFEngine(scenario=ExfiltrationScenario()).estimate(p)
        assert any(c.startswith("ABOVE CEILING: Phishing") for c in r.validation_checks)


class TestCeilingNeverCaps:
    def test_ceiling_below_median_is_reported_not_applied(self):
        # 0.007 sources/day on each port: the ceiling falls below the median
        tiny = {"exploitation_ceiling_derivation": {"dshield_snapshot": {
            "date": "2026-10-23", "unique_sources": {p: 0.007 for p in (443, 445, 3389, 8080, 8443)}}}}
        r = TEFEngine(config=TEFConfig.from_dict(tiny)).estimate(_profile())
        bundled = TEFEngine().estimate(_profile())
        expl = next(v for v in r.vectors if v.telemetry_key == "exploitation")
        assert expl.positioned_median > expl.ceiling
        assert r.total_positioned_median == bundled.total_positioned_median
        assert any(c.startswith("ABOVE CEILING: Exploitation") for c in r.validation_checks)


class TestCredentialCeiling:
    def test_bec_tempo_from_ic3(self):
        from tef_estimator.data.scenarios.bec import BECScenario
        t = BECScenario().credential_tempo
        assert t["global_campaigns_per_month"].mode == pytest.approx(21489 * 7.5 / 12, abs=1)
        assert t["addressable_population"].low == 6_000_000

    def test_bec_ceiling_geography_relative_to_us(self):
        # IC3 counts US victims: a US firm gets geography 1.0, others their ratio to the US
        from tef_estimator.data.common import GEO_MULTIPLIERS, Geography
        from tef_estimator.data.scenarios.bec import BECScenario

        def ceiling(geo):
            r = TEFEngine(scenario=BECScenario()).estimate(_profile(geography=geo))
            v = next(v for v in r.vectors if v.telemetry_key == "credential")
            return v.ceiling, next(s for s in v.trace.steps if s.label.startswith("Ceiling")).source

        us, note = ceiling(Geography.US)
        assert "geography 1.00" in note
        eu, _ = ceiling(Geography.WESTERN_EUROPE)
        ratio = GEO_MULTIPLIERS[Geography.WESTERN_EUROPE].mode / GEO_MULTIPLIERS[Geography.US].mode
        assert eu == pytest.approx(us * ratio)

    def test_exfiltration_tempo_from_netdiligence_ratio(self):
        from tef_estimator.data.scenarios.exfiltration import ExfiltrationScenario
        t = ExfiltrationScenario().credential_tempo
        assert t["global_campaigns_per_month"].high == pytest.approx(3000 * 0.15 / 0.26, abs=1)

    def test_ransomware_credential_ceiling_counts_attempts(self):
        # campaign counts are claimed victims (successes); ÷ susceptibility low → attempts
        r = TEFEngine().estimate(_profile())
        cred = next(v for v in r.vectors if v.telemetry_key == "credential")
        tempo = RansomwareScenario().credential_tempo
        from tef_estimator.base_rate import tier_concentration
        sector = RansomwareScenario().adjusted_sector_multiplier(Sector.MANUFACTURING)
        tier = tier_concentration(RansomwareScenario(), RevenueBand.R_100M_1B)
        expected = (tempo["global_campaigns_per_month"].high * tempo["credential_proportion"].high
                    * 12 / tempo["addressable_population"].low * sector * 1.2 * tier / 0.10)
        assert cred.ceiling == pytest.approx(expected)
        assert cred.positioned_median <= cred.ceiling
        assert "÷ susceptibility 0.10" in next(
            s.source for s in cred.trace.steps if s.label.startswith("Ceiling"))

    def test_credential_ceiling_has_profile_adjustments(self):
        us = TEFEngine().estimate(_profile())
        other = TEFEngine().estimate(_profile(geography=Geography.OTHER))
        c_us = next(v for v in us.vectors if v.telemetry_key == "credential").ceiling
        c_other = next(v for v in other.vectors if v.telemetry_key == "credential").ceiling
        assert c_us / c_other == pytest.approx(1.2 / 0.8)  # susceptibility cancels
