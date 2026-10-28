"""CLI, UI inputs and refresh commands."""

from __future__ import annotations

import json
from datetime import date, timedelta

import pytest
from typer.testing import CliRunner

from tef_estimator import ui
from tef_estimator.cli import app
from tef_estimator.config import TEFConfig, get_config
from tef_estimator.dispersion_fit import month_range
from tef_estimator.refresh.validators import bundled_editions, check_freshness, due_after_months
from tef_estimator.telemetry import db as telemetry_db
from tef_estimator.telemetry.db import TelemetryDB
from tests.test_live_inputs import KEV_2023_05_TO_2026_09

runner = CliRunner()


class TestEstimate:
    def test_default_output(self):
        result = runner.invoke(app, [
            "estimate",
            "--sector", "manufacturing",
            "--revenue", "100m_1b",
            "--geo", "us",
            "--remote-access", "fortinet",
            "--employees", "2000",
        ])
        assert result.exit_code == 0, result.output
        assert "VECTOR BREAKDOWN" in result.output

    def test_json_output(self):
        result = runner.invoke(app, [
            "estimate",
            "--sector", "financial",
            "--revenue", "1b_10b",
            "--geo", "us",
            "--json",
        ])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "summary" in data
        assert "analysis" in data
        assert "audit" in data

class TestExplain:
    def test_explain_runs(self):
        result = runner.invoke(app, [
            "explain",
            "--sector", "manufacturing",
            "--revenue", "100m_1b",
            "--geo", "us",
        ])
        assert result.exit_code == 0, result.output
        assert "THREAT EVENT FREQUENCY ESTIMATE" in result.output


class TestCompare:
    def test_compare_runs(self):
        result = runner.invoke(app, [
            "compare",
            "--sector", "manufacturing",
            "--revenue", "100m_1b",
            "--geo", "us",
            "--b-sector", "financial",
        ])
        assert result.exit_code == 0, result.output
        assert "PROFILE COMPARISON" in result.output

class TestSensitivity:
    def test_sensitivity_runs(self):
        result = runner.invoke(app, [
            "sensitivity",
            "--sector", "manufacturing",
            "--revenue", "100m_1b",
            "--geo", "us",
        ])
        assert result.exit_code == 0, result.output
        assert "SENSITIVITY ANALYSIS" in result.output

class TestDataCommands:
    def test_show_multipliers(self):
        result = runner.invoke(app, ["data", "multipliers"])
        assert result.exit_code == 0, result.output

    def test_show_base_rate(self):
        result = runner.invoke(app, ["data", "base-rate"])
        assert result.exit_code == 0, result.output

    def test_show_vectors(self):
        result = runner.invoke(app, ["data", "vectors"])
        assert result.exit_code == 0, result.output


pytest.importorskip("nicegui")




def _state(inputs="frozen"):
    return {
        "sector": "manufacturing",
        "revenue_band": "100m_1b",
        "geography": "us",
        "remote_access": ["fortinet"],
        "employees": 2000,
        "critical_infra": False,
        "supply_chain": False,
        "recent_ma": False,
        "base_rate_override": None,
        "scenario": "ransomware",
        "inputs": inputs,
    }


def _config_state():
    cfg = get_config()
    return {
        "susc_low": cfg.susceptibility_prior.low,
        "susc_mode": cfg.susceptibility_prior.mode,
        "susc_high": cfg.susceptibility_prior.high,
        "factor_k": cfg.dampening.factor_k,
        "vector_k": cfg.dampening.vector_k,
        "max_composite": cfg.dampening.max_composite,
        "cred_exploitation": cfg.credibility_k.exploitation,
        "cred_credential": cfg.credibility_k.credential,
        "cred_phishing": cfg.credibility_k.phishing,
        "cred_supply_chain": cfg.credibility_k.supply_chain,
    }


def _kev_file_db(path, monthly, collected_on):
    db = TelemetryDB(db_path=path)
    db.initialize()
    conn = db.connect()
    cursor = conn.cursor()
    n = 0
    for month, count in monthly.items():
        for i in range(count):
            n += 1
            db.insert_observation(cursor, "cisa_kev", "vulnerability_catalog",
                                  f"{month}-{(i % 28) + 1:02d}", f"kev_CVE-2099-{n:05d}",
                                  1.0, "binary", f"{collected_on}T08:00:00+00:00", f"h{n}")
    conn.commit()
    conn.close()


class TestAppConstruction:
    def test_app_constructs(self):
        app = ui.TEFEstimatorApp()
        assert app.state["inputs"] == get_config().telemetry_inputs


class TestUserConfigHonored:
    def test_config_beyond_sliders_reaches_engine(self, monkeypatch):
        custom = TEFConfig.from_dict({"dispersion": {"vectors": {
            "exploitation": {"shape_r": 50.0, "source": "test override"}}}})
        monkeypatch.setattr(ui, "get_config", lambda: custom)
        out = ui._run_estimate(_state(), _config_state())
        assert out["error"] is None
        assert out["result"].dispersion["vectors"]["exploitation"].shape_r == 50.0


class TestInputModes:
    def test_frozen(self):
        out = ui._run_estimate(_state("frozen"), _config_state())
        assert out["inputs"]["mode"] == "frozen"
        assert out["result"].dispersion["vectors"]["exploitation"].shape_r == 22.5
        assert ui._inputs_lines(out["inputs"])[0].startswith("Inputs: frozen")

    def test_live_uses_collected_data(self, monkeypatch, tmp_path):
        path = tmp_path / "telemetry.db"
        months = month_range("2023-05", "2026-09")
        bursty = [c if i % 6 else c * 3 for i, c in enumerate(KEV_2023_05_TO_2026_09)]
        _kev_file_db(path, dict(zip(months, bursty)), collected_on="2026-10-24")
        monkeypatch.setattr(telemetry_db, "DEFAULT_DB_PATH", path)

        frozen = ui._run_estimate(_state("frozen"), _config_state())
        live = ui._run_estimate(_state("live"), _config_state())
        assert live["error"] is None
        assert live["inputs"]["mode"] == "live"
        live_r = live["result"].dispersion["vectors"]["exploitation"].shape_r
        assert live_r < 22.5
        assert live["result"].total_positioned_median == frozen["result"].total_positioned_median

        lines = ui._inputs_lines(live["inputs"])
        assert lines[0] == "Inputs: live, telemetry data through 2026-10-24"
        assert any(line.startswith(f"Exploitation dispersion r {live_r:g}") for line in lines)
        assert any("Ransomware dispersion: bundled value kept" in line for line in lines)

    def test_live_without_db_falls_back(self, monkeypatch, tmp_path):
        monkeypatch.setattr(telemetry_db, "DEFAULT_DB_PATH", tmp_path / "missing.db")
        out = ui._run_estimate(_state("live"), _config_state())
        assert out["inputs"]["mode"] == "frozen"
        assert "No telemetry database" in out["inputs"]["note"]


def test_due_after_own_cycle_plus_grace():
    assert due_after_months(12) == 15
    assert due_after_months(3) == 5


def test_nothing_due_within_cycles():
    # Extracted May-Jul 2026; Beazley (quarterly) is due after 5 months
    assert check_freshness(today=date(2026, 9, 30)) == []


def test_quarterly_source_flagged_before_annual_ones():
    msgs = check_freshness(today=date(2026, 5, 24) + timedelta(days=6 * 31))
    assert any(m.startswith("Beazley Q3 2025:") for m in msgs)
    assert not any(m.startswith("IRIS 2025:") for m in msgs)


def test_annual_source_flagged_after_15_months():
    msgs = check_freshness(today=date(2026, 5, 24) + timedelta(days=16 * 31))
    assert any(m.startswith("IRIS 2025:") and "check for a newer edition" in m for m in msgs)


def test_bundled_editions_named():
    assert bundled_editions() == ["IRIS 2025", "At-Bay 2025", "Beazley Q3 2025"]


def test_estimates_carry_no_freshness_warnings_but_name_editions():
    from tef_estimator.data.common import Geography, RevenueBand, Sector
    from tef_estimator.engine import TEFEngine
    from tef_estimator.profile import OrganizationProfile
    r = TEFEngine().estimate(OrganizationProfile(sector=Sector.MANUFACTURING,
                                                 revenue_band=RevenueBand.R_100M_1B,
                                                 geography=Geography.US))
    assert not any("newer edition" in w or "days old" in w for w in r.warnings)
    assert "IRIS 2025, At-Bay 2025, Beazley Q3 2025, DShield 2026-10-23" in r.input_provenance[0]
