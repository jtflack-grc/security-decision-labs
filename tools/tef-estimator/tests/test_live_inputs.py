"""Live inputs: dispersion refit, live ransomware base rate, input modes, watch re-estimation."""

import pytest

from tef_estimator.config import TEFConfig, get_config
from tef_estimator.data.common import Geography, RemoteAccessType, RevenueBand, Sector
from tef_estimator.data.scenarios.bec import BECScenario
from tef_estimator.dispersion_fit import moments_shape, month_range, nb2_shape
from tef_estimator.engine import TEFEngine
from tef_estimator.profile import OrganizationProfile
from tef_estimator.telemetry.db import TelemetryDB
from tef_estimator.telemetry.derive import _days_in_month, live_dispersion_config, live_tempo_anchor

# CISA KEV new entries per month, Jan 2023 - May 2026: the series behind the
# bundled exploitation shape (config.yaml dispersion.vectors.exploitation).
KEV_2023_05_TO_2026_09 = [
    19, 24, 16, 8, 19, 18, 18, 11, 21, 9, 10, 10, 14, 9, 14, 19, 25, 17, 22, 16,
    14, 27, 32, 15, 24, 20, 20, 15, 16, 31, 11, 20, 17, 28, 26, 31, 21, 23, 26, 31,
    43,
]


def _profile():
    return OrganizationProfile(
        sector=Sector.MANUFACTURING,
        revenue_band=RevenueBand.R_100M_1B,
        geography=Geography.US,
        remote_access=[RemoteAccessType.FORTINET],
        employee_count=2000,
    )


def _kev_db(monthly: dict[str, int], collected_on: str) -> TelemetryDB:
    """In-memory DB with KEV catalog rows spread over the given months."""
    db = TelemetryDB(db_path=None)
    db.initialize()
    conn = db.connect()
    cursor = conn.cursor()
    ts = f"{collected_on}T08:00:00+00:00"
    n = 0
    for month, count in monthly.items():
        for i in range(count):
            n += 1
            db.insert_observation(
                cursor, "cisa_kev", "vulnerability_catalog",
                f"{month}-{(i % 28) + 1:02d}", f"kev_CVE-2099-{n:05d}", 1.0,
                "binary", ts, f"h{n}",
            )
    conn.commit()
    conn.close()
    return db


class TestShapeFits:
    def test_detrended_reproduces_bundled(self):
        bundled = get_config().dispersion["vectors"]["exploitation"]["shape_r"]
        fit = nb2_shape(KEV_2023_05_TO_2026_09, trend=True)
        assert fit.converged
        assert round(fit.shape_r, 1) == bundled

    def test_moments_reproduces_bundled_raw(self):
        bundled = get_config().dispersion["vectors"]["exploitation"]["raw_shape_r"]
        assert round(moments_shape(KEV_2023_05_TO_2026_09), 1) == bundled

    def test_underdispersed_is_poisson(self):
        assert moments_shape([10, 10, 10, 10, 10]) is None

    def test_rejects_short_and_zero_series(self):
        with pytest.raises(ValueError):
            nb2_shape([1, 2])
        with pytest.raises(ValueError):
            nb2_shape([0, 0, 0, 0])

class TestLiveDispersion:
    def test_refit_on_frozen_series_matches_bundled(self):
        months = month_range("2023-05", "2026-09")
        db = _kev_db(dict(zip(months, KEV_2023_05_TO_2026_09)), collected_on="2026-10-24")

        cfg, fits = live_dispersion_config(db)
        fit = fits[0]
        assert fit.status == "fitted"
        assert fit.window == ("2023-05", "2026-09")
        assert fit.shape_r == 22.5
        assert fit.raw_shape_r == 10.5

        entry = cfg.dispersion["vectors"]["exploitation"]
        assert "Live fit on the telemetry DB" in entry["source"]
        assert "2023-05 to 2026-09" in entry["source"]
        assert "collected through 2026-10-24" in entry["source"]

    def test_window_never_before_earliest_month(self):
        months = month_range("2021-11", "2026-05")
        db = _kev_db({m: 15 + (i % 7) for i, m in enumerate(months)}, collected_on="2026-06-15")
        _, fits = live_dispersion_config(db)
        assert fits[0].window[0] == "2023-01"

    def test_base_config_not_mutated(self):
        months = month_range("2023-05", "2026-09")
        db = _kev_db(dict(zip(months, [c * 2 for c in KEV_2023_05_TO_2026_09])),
                     collected_on="2026-10-24")
        base = TEFConfig.from_dict({})
        before = base.dispersion["vectors"]["exploitation"]["shape_r"]
        live_dispersion_config(db, base)
        assert base.dispersion["vectors"]["exploitation"]["shape_r"] == before

    def test_fallback_without_data(self):
        db = TelemetryDB(db_path=None)
        db.initialize()
        cfg, fits = live_dispersion_config(db)
        assert fits[0].status == "fallback"
        assert cfg.dispersion["vectors"]["exploitation"] == \
            get_config().dispersion["vectors"]["exploitation"]

    def test_fallback_on_short_window(self):
        months = month_range("2025-06", "2026-05")
        db = _kev_db({m: 20 for m in months}, collected_on="2026-06-15")
        _, fits = live_dispersion_config(db)
        assert fits[0].status == "fallback"
        assert "needs" in fits[0].reason

    def test_fallback_outside_bounds(self):
        months = month_range("2023-05", "2026-09")
        db = _kev_db(dict(zip(months, KEV_2023_05_TO_2026_09)), collected_on="2026-10-24")
        base = TEFConfig.from_dict({"dispersion": {"live": {"shape_bounds": [100.0, 1000.0]}}})
        cfg, fits = live_dispersion_config(db, base)
        assert fits[0].status == "fallback"
        assert cfg.dispersion["vectors"]["exploitation"]["shape_r"] == 22.5


class TestLiveDispersionInEngine:
    def test_frozen_default_unchanged(self):
        result = TEFEngine().estimate(_profile())
        assert result.dispersion["vectors"]["exploitation"].shape_r == 22.5

    def test_live_moves_shape_not_mean(self):
        months = month_range("2023-05", "2026-09")
        bursty = [c if i % 6 else c * 3 for i, c in enumerate(KEV_2023_05_TO_2026_09)]
        db = _kev_db(dict(zip(months, bursty)), collected_on="2026-10-24")
        cfg, fits = live_dispersion_config(db)
        assert fits[0].status == "fitted"
        assert fits[0].shape_r < 22.5

        frozen = TEFEngine().estimate(_profile())
        live = TEFEngine(config=cfg).estimate(_profile())

        assert live.dispersion["vectors"]["exploitation"].shape_r == fits[0].shape_r
        # Dispersion changes the variance around the rate, never the rate
        assert live.total_positioned_median == frozen.total_positioned_median
        assert live.total_positioned_low == frozen.total_positioned_low
        assert live.total_positioned_high == frozen.total_positioned_high


class TestWatchReEstimation:
    def _signal_cycle(self, monkeypatch, db, live, profiles=None):
        from tef_estimator.telemetry import watch
        from tef_estimator.telemetry.compare import CompareResult, Signal

        monkeypatch.setattr(watch, "run_due_collections", lambda db, **kw: [
            {"source": "cisa_kev", "status": "completed", "records_inserted": 1},
        ])
        sig = Signal("cisa_kev", "kev_additions_7d_avg", 0.2, 1.5, 6.5, "up", 1.3, "abs_delta")
        monkeypatch.setattr(watch, "compare", lambda db, **kw: CompareResult([sig], 1, 0.2))
        wp = watch.WatchProfile(name="mfg", profile_kwargs={
            "sector": Sector.MANUFACTURING, "revenue_band": RevenueBand.R_100M_1B,
            "geography": Geography.US, "remote_access": [RemoteAccessType.FORTINET],
            "employee_count": 2000,
        })
        return watch.run_once(db, profiles=profiles or [wp], live=live)

    def test_re_estimation_produces_estimate(self, monkeypatch):
        db = TelemetryDB(db_path=None)
        db.initialize()
        result = self._signal_cycle(monkeypatch, db, live=False)
        entry = result.re_estimated[0]
        assert "error" not in entry
        assert entry["inputs"] == "frozen"
        assert entry["tef_median"] == TEFEngine().estimate(_profile()).total_positioned_median

    def test_each_profile_uses_its_scenario(self, monkeypatch):
        from tef_estimator.data.scenarios.bec import BECScenario
        from tef_estimator.telemetry.watch import WatchProfile

        base = {"sector": "manufacturing", "revenue_band": "100m_1b",
                "geography": "us", "remote_access": ["fortinet"], "employee_count": 2000}
        profiles = [WatchProfile.from_dict({"name": "rw", **base}),
                    WatchProfile.from_dict({"name": "bec", "scenario": "bec", **base})]
        db = TelemetryDB(db_path=None)
        db.initialize()
        result = self._signal_cycle(monkeypatch, db, live=False, profiles=profiles)
        by_name = {e["profile"]: e for e in result.re_estimated}
        assert "error" not in by_name["bec"]
        bec = TEFEngine(scenario=BECScenario()).estimate(_profile())
        assert by_name["bec"]["tef_median"] == bec.total_positioned_median
        assert by_name["bec"]["tef_median"] != by_name["rw"]["tef_median"]

    def test_re_estimation_reports_live_shapes(self, monkeypatch):
        months = month_range("2023-05", "2026-09")
        db = _kev_db(dict(zip(months, KEV_2023_05_TO_2026_09)), collected_on="2026-10-24")
        result = self._signal_cycle(monkeypatch, db, live=True)
        entry = result.re_estimated[0]
        assert "error" not in entry
        assert entry["inputs"] == "live"
        # No ransomware attack-date series in this DB: bundled value kept (None = not refitted)
        assert entry["live_dispersion"] == {"vectors/exploitation": 22.5,
                                            "scenarios/ransomware": None}


class TestInputMode:
    def test_default_is_frozen(self):
        assert TEFConfig.from_dict({}).telemetry_inputs == "frozen"

    def test_invalid_mode_rejected(self):
        with pytest.raises(ValueError):
            TEFConfig.from_dict({"telemetry_inputs": "sometimes"})

    def test_mode_round_trips(self):
        cfg = TEFConfig.from_dict({"telemetry_inputs": "live"})
        assert TEFConfig.from_dict(cfg.to_dict()).telemetry_inputs == "live"

    def test_flag_overrides_config(self):
        from tef_estimator.telemetry.derive import use_live
        live_cfg = TEFConfig.from_dict({"telemetry_inputs": "live"})
        frozen_cfg = TEFConfig.from_dict({})
        assert use_live(live_cfg) is True
        assert use_live(frozen_cfg) is False
        assert use_live(live_cfg, False) is False
        assert use_live(frozen_cfg, True) is True


class TestWatchProfiles:
    def test_from_dict_converts_enums(self):
        from tef_estimator.telemetry.watch import WatchProfile
        wp = WatchProfile.from_dict({
            "name": "plant", "scenario": "exfiltration", "sector": "manufacturing",
            "revenue_band": "100m_1b", "geography": "western_europe",
            "remote_access": ["fortinet"], "employee_count": 2000,
        })
        assert wp.scenario_name == "exfiltration"
        profile = OrganizationProfile(**wp.profile_kwargs)
        assert profile.sector is Sector.MANUFACTURING
        assert profile.geography is Geography.WESTERN_EUROPE
        assert profile.remote_access == [RemoteAccessType.FORTINET]

    def test_unknown_scenario_rejected(self):
        from tef_estimator.telemetry.watch import WatchProfile
        with pytest.raises(ValueError, match="unknown scenario"):
            WatchProfile.from_dict({"name": "x", "scenario": "insider", "sector": "manufacturing",
                                    "revenue_band": "100m_1b", "geography": "us"})

    def test_load_file(self, tmp_path):
        import json

        from tef_estimator.telemetry.watch import load_watch_profiles
        path = tmp_path / "profiles.json"
        entry = {"name": "a", "sector": "manufacturing", "revenue_band": "100m_1b", "geography": "us"}
        path.write_text(json.dumps([entry]))
        assert [p.name for p in load_watch_profiles(path)] == ["a"]

        path.write_text(json.dumps([entry, entry]))
        with pytest.raises(ValueError, match="unique"):
            load_watch_profiles(path)

        path.write_text(json.dumps(entry))
        with pytest.raises(ValueError, match="JSON list"):
            load_watch_profiles(path)


WINDOW = month_range("2025-06", "2026-05")  # collected 2026-08-15: Jun, Jul censored


def _rw_profile():
    return OrganizationProfile(sector=Sector.MANUFACTURING, revenue_band=RevenueBand.R_100M_1B,
                               geography=Geography.US, remote_access=[RemoteAccessType.FORTINET])


def _db(n_us_year, unknown_share=0.0, us_share_known=0.45, filling=("2026-06", "2026-07")):
    """Daily rows whose window sums give N_US = n_us_year after pro-rata allocation."""
    known_year = n_us_year / us_share_known / (1 + unknown_share / (1 - unknown_share))
    us_year = known_year * us_share_known
    total_year = known_year / (1 - unknown_share)
    db = TelemetryDB(db_path=None)
    db.initialize()
    conn = db.connect()
    cursor = conn.cursor()
    for month in WINDOW + list(filling):
        n = _days_in_month(month)
        for day in range(1, n + 1):
            date = f"{month}-{day:02d}"
            for metric, yearly in (("daily_victim_count_by_attack", total_year),
                                   ("daily_victim_count_by_attack_us", us_year),
                                   ("daily_victim_count_by_attack_known_country", known_year)):
                db.upsert_observation(cursor, "ransomware_live", "ransomware_activity", date,
                                      metric, yearly / 12 / n, "count",
                                      "2026-08-15T08:00:00+00:00", "h")
    conn.commit()
    conn.close()
    return db


def _fit(db):
    cfg = TEFConfig.from_dict({})
    conn = db.connect()
    try:
        fit = live_tempo_anchor(conn.cursor(), cfg)
    finally:
        conn.close()
    return cfg, fit



def _shares(result):
    return [v.positioned_median / result.total_positioned_median for v in result.vectors]

class TestTempoAnchor:
    def test_identity_on_published_input(self):
        cfg, fit = _fit(_db(3971))
        assert fit.status == "fitted"
        assert fit.window == ("2025-06", "2026-05")
        assert cfg.live_base_rate["ransomware"]["n_us"] == pytest.approx(3971, rel=1e-9)
        assert (TEFEngine(config=cfg).base_rate_for(RevenueBand.R_100M_1B)
                == pytest.approx(TEFEngine().base_rate_for(RevenueBand.R_100M_1B), rel=1e-9))

    @pytest.mark.parametrize("n_us", [7942, 2100])  # 2x and 0.53x the bundled count: inside the bounds
    def test_base_rate_scales_with_victims(self, n_us):
        cfg, _ = _fit(_db(n_us))
        live = TEFEngine(config=cfg).base_rate_for(RevenueBand.R_10M_100M)
        frozen = TEFEngine().base_rate_for(RevenueBand.R_10M_100M)
        assert live.mode / frozen.mode == pytest.approx(n_us / 3971, rel=1e-6)

    def test_unknown_countries_allocated_pro_rata(self):
        cfg, fit = _fit(_db(3971, unknown_share=0.053))
        assert "N_US 3,971" in fit.detail

    @pytest.mark.parametrize("n_us", [1600, 10000])
    def test_outside_bounds_keeps_bundled(self, n_us):
        cfg, fit = _fit(_db(n_us))
        assert fit.status == "fallback" and "outside" in fit.reason
        assert "ransomware" not in cfg.live_base_rate

    def test_incomplete_month_keeps_bundled(self):
        db = _db(4000)
        conn = db.connect()
        conn.execute("DELETE FROM raw_observations WHERE observation_date LIKE '2026-03-%' "
                     "AND CAST(substr(observation_date, 9, 2) AS INTEGER) > 10")
        conn.commit()
        conn.close()
        _, fit = _fit(db)
        assert fit.status == "fallback" and "2026-03" in fit.reason

    def test_no_data(self):
        db = TelemetryDB(db_path=None)
        db.initialize()
        _, fit = _fit(db)
        assert fit.status == "fallback"


class TestEngineUsesLiveBaseRate:
    def test_frozen_unchanged(self):
        band = RevenueBand.R_100M_1B
        assert TEFEngine().base_rate_for(band) == TEFEngine(config=TEFConfig.from_dict({})).base_rate_for(band)

    def test_live_moves_ransomware_not_shares(self):
        cfg, _ = _fit(_db(7942))
        frozen = TEFEngine().estimate(_rw_profile())
        live = TEFEngine(config=cfg).estimate(_rw_profile())
        assert live.total_positioned_median > frozen.total_positioned_median
        assert _shares(live) == pytest.approx(_shares(frozen), rel=0.05)

    def test_other_scenarios_unaffected(self):
        cfg, _ = _fit(_db(7942))
        assert (TEFEngine(scenario=BECScenario(), config=cfg).estimate(_rw_profile()).total_positioned_median
                == TEFEngine(scenario=BECScenario()).estimate(_rw_profile()).total_positioned_median)


class TestInputProvenanceInReports:
    def test_frozen_reports_say_frozen(self):
        r = TEFEngine().estimate(_rw_profile())
        assert r.input_provenance[0].startswith("Inputs: frozen")
        for text in (r.full_report(), r.to_markdown(), r.fair_risk_engine_text()):
            assert "frozen" in text
        assert r.to_dict()["inputs"] == r.input_provenance

    def test_live_reports_carry_data_date(self):
        from tef_estimator.telemetry.derive import live_config
        cfg, _ = live_config(_db(4000))
        r = TEFEngine(config=cfg).estimate(_rw_profile())
        assert r.input_provenance[0] == "Inputs: live, telemetry data through 2026-08-15"
        assert any(line.startswith("Ransomware base rate: N_US 4,000") for line in r.input_provenance)
        assert "telemetry data through 2026-08-15" in r.fair_risk_engine_text()
        assert "Ransomware base rate" in r.full_report()

    def test_base_rate_derivation_in_reports(self):
        r = TEFEngine().estimate(_rw_profile())
        for text in (r.full_report(), r.to_markdown()):
            assert "3,971 US events/yr" in text
            assert "susceptibility" in text
