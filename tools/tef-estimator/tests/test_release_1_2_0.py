"""Direct tests for the 1.2.0 features that shipped without them."""

import importlib.metadata
import importlib.util
import json
import math
from pathlib import Path

import numpy as np
import pytest
import yaml

import tef_estimator
from tef_estimator.config import TEFConfig
from tef_estimator.credibility import OrgTelemetry, VectorObservation
from tef_estimator.data.common import Geography, RemoteAccessType, RevenueBand, Sector
from tef_estimator.data.scenarios import ExfiltrationScenario, RansomwareScenario, WebAppScenario
from tef_estimator.distributions import LognormalParams
from tef_estimator.engine import TEFEngine
from tef_estimator.profile import OrganizationProfile

REPO = Path(__file__).resolve().parent.parent


def _profile(**overrides):
    d = dict(sector=Sector.MANUFACTURING, revenue_band=RevenueBand.R_100M_1B, geography=Geography.US,
             remote_access=[RemoteAccessType.FORTINET], employee_count=2000)
    d.update(overrides)
    return OrganizationProfile(**d)


def _telemetry():
    return OrgTelemetry(observations=[
        VectorObservation(vector="exploitation", annualized_frequency=0.5, observation_periods=8, detection_coverage=0.5),
    ])


class TestBandHardening:
    """Binding limits show up in validation_checks."""

    def test_band_floor_binds(self):
        cfg = TEFConfig.from_dict({"band_hardening": {"min_sigma_ratio": 0.99}})
        r = TEFEngine(config=cfg).estimate(_profile(telemetry=_telemetry()))
        assert any(c.startswith("Band hardening:") and "band floor bound" in c for c in r.validation_checks)
        assert any("band floor bound" in w for w in r.warnings)

    def test_coverage_cap_binds(self):
        cfg = TEFConfig.from_dict({"band_hardening": {"coverage_leverage_cap": 0.5}})
        r = TEFEngine(config=cfg).estimate(_profile(telemetry=_telemetry()))
        assert any(c.startswith("Band hardening:") and "coverage-leverage cap" in c for c in r.validation_checks)

    def test_no_entry_when_not_binding(self):
        cfg = TEFConfig.from_dict({"band_hardening": {"min_sigma_ratio": 0.0, "coverage_leverage_cap": 1e6}})
        r = TEFEngine(config=cfg).estimate(_profile(telemetry=_telemetry()))
        assert not any(c.startswith("Band hardening:") for c in r.validation_checks)

    def test_floor_keeps_band_width(self):
        cfg = TEFConfig.from_dict({"band_hardening": {"min_sigma_ratio": 0.99}})
        prior = TEFEngine(config=cfg).estimate(_profile())
        post = TEFEngine(config=cfg).estimate(_profile(telemetry=_telemetry()))
        width = lambda v: math.log(v.positioned_high / v.positioned_low)
        assert width(post.vectors[0]) >= 0.99 * width(prior.vectors[0]) - 1e-9

    def test_coverage_does_not_narrow_the_band(self):
        """Same detected events at lower coverage must not contract the band more (cap on periods)."""
        width = lambda v: math.log(v.positioned_high / v.positioned_low)
        widths = []
        for coverage in (1.0, 0.5, 0.25):
            telem = OrgTelemetry(observations=[VectorObservation(
                vector="credential", annualized_frequency=0.05, observation_periods=20,
                detection_coverage=coverage)])
            r = TEFEngine().estimate(_profile(telemetry=telem))
            widths.append(width(next(v for v in r.vectors if v.telemetry_key == "credential")))
        assert widths == pytest.approx([widths[0]] * 3, rel=1e-9)


class TestFentonWilkinson:
    """Moments match the sum exactly; the median beats the naive median sum."""

    def test_against_monte_carlo_sum(self):
        comps = [LognormalParams(math.log(m), s) for m, s in [(0.02, 0.6), (0.05, 0.8), (0.01, 1.0), (0.004, 0.5)]]
        fw = LognormalParams.fenton_wilkinson(comps)
        rng = np.random.default_rng(0)
        total = sum(c.sample(size=400_000, rng=rng) for c in comps)
        assert fw.mean == pytest.approx(total.mean(), rel=0.01)
        assert fw.median == pytest.approx(np.median(total), rel=0.05)
        naive = sum(c.median for c in comps)
        assert abs(fw.median - np.median(total)) < abs(naive - np.median(total))

    def test_single_component_unchanged(self):
        c = LognormalParams(-3.0, 0.7)
        assert LognormalParams.fenton_wilkinson([c]) == c

    def test_engine_lognormal_is_centred_on_the_headline(self):
        """The total lognormal's median is the positioned total, not a sum of independent vectors."""
        for profile in (_profile(), _profile(remote_access=[]), _profile(sector=Sector.FINANCIAL)):
            r = TEFEngine().estimate(profile)
            assert r.lognormal.median == pytest.approx(r.total_positioned_median, rel=1e-5)


class TestKSweep:
    """Per-vector credibility k sweep: present with telemetry, and it actually moves the output."""

    def test_sweep_entries_with_telemetry(self):
        sens = TEFEngine().sensitivity(_profile(telemetry=_telemetry()))
        entries = {e.parameter: e for e in sens.entries if e.parameter.startswith("credibility_k_")}
        assert set(entries) == {"credibility_k_exploitation"}
        e = entries["credibility_k_exploitation"]
        assert e.output_low != e.output_high  # regression: the sweep used to be a no-op

    def test_no_sweep_without_telemetry(self):
        sens = TEFEngine().sensitivity(_profile())
        assert not any(e.parameter.startswith("credibility_k_") for e in sens.entries)

    def test_ranges_come_from_config(self):
        cfg = TEFConfig.from_dict({"k_sensitivity": {"exploitation": [1.0, 32.0, 200.0]}})
        wide = TEFEngine(config=cfg).sensitivity(_profile(telemetry=_telemetry()))
        narrow = TEFEngine().sensitivity(_profile(telemetry=_telemetry()))
        pick = lambda s: next(e for e in s.entries if e.parameter == "credibility_k_exploitation")
        assert pick(wide).range_multiple > pick(narrow).range_multiple


class TestExploitationCeilings:
    """Config-driven ceilings by attack-surface class."""

    CFG = {"exploitation_ceilings": {"edge_device": 111.0, "cloud_primary": 0.022, "default": 0.33}}

    @pytest.mark.parametrize("overrides,expected", [
        (dict(remote_access=[RemoteAccessType.FORTINET]), 111.0),
        (dict(remote_access=[RemoteAccessType.RDP]), 111.0),
        (dict(remote_access=[RemoteAccessType.NONE]), 0.022),
        (dict(remote_access=[RemoteAccessType.NONE], edge_vendors=[RemoteAccessType.CITRIX]), 0.33),
    ])
    def test_ceiling_by_class(self, overrides, expected):
        r = TEFEngine(config=TEFConfig.from_dict(self.CFG)).estimate(_profile(**overrides))
        expl = next(v for v in r.vectors if v.telemetry_key == "exploitation")
        assert expl.ceiling == pytest.approx(expected)


class TestConfigModule:
    """TEFConfig: from_yaml and a lossless round trip."""

    def test_from_yaml(self, tmp_path):
        p = tmp_path / "cfg.yaml"
        p.write_text(yaml.safe_dump({"dampening": {"vector_k": 0.5}, "dispersion": {"timescale": "year"}}))
        cfg = TEFConfig.from_yaml(p)
        assert cfg.dampening.vector_k == 0.5
        assert cfg.dampening.factor_k == TEFConfig.from_dict({}).dampening.factor_k
        assert cfg.dispersion_for("vectors", "exploitation").timescale == "year"

    def test_empty_yaml_is_defaults(self, tmp_path):
        p = tmp_path / "empty.yaml"
        p.write_text("")
        assert TEFConfig.from_yaml(p).to_dict() == TEFConfig.from_dict({}).to_dict()

    def test_round_trip_keeps_k_sensitivity(self):
        cfg = TEFConfig.from_dict({"k_sensitivity": {"phishing": [2.0, 10.0, 12.0]}})
        assert TEFConfig.from_dict(cfg.to_dict()).k_sensitivity["phishing"] == [2.0, 10.0, 12.0]


class TestVersion:
    """GUI version (issue #2): follows the running code, not hardcoded."""

    def test_version_matches_pyproject(self):
        # In a source tree, the tree's own pyproject wins — even over the
        # metadata of an older or stale install shadowing it.
        text = (REPO / "pyproject.toml").read_text()
        assert f'version = "{tef_estimator.__version__}"' in text

    def test_version_falls_back_to_metadata_without_pyproject(self, monkeypatch, tmp_path):
        # Wheel installs have no pyproject above the package.
        monkeypatch.setattr(tef_estimator, "__file__", str(tmp_path / "x" / "y" / "z" / "__init__.py"))
        assert tef_estimator._resolve_version() == importlib.metadata.version("tef-estimator")

    def test_version_unknown_without_pyproject_or_metadata(self, monkeypatch, tmp_path):
        monkeypatch.setattr(tef_estimator, "__file__", str(tmp_path / "x" / "y" / "z" / "__init__.py"))
        monkeypatch.setattr(
            tef_estimator,
            "_package_version",
            lambda name: (_ for _ in ()).throw(importlib.metadata.PackageNotFoundError()),
        )
        assert tef_estimator._resolve_version() == "0+unknown"

    def test_ui_has_no_version_literal(self):
        src = (REPO / "src" / "tef_estimator" / "ui.py").read_text()
        assert "__version__" in src
        assert f'"{tef_estimator.__version__}"' not in src


class TestNewScenarios:
    """Exfiltration and web-app scenarios run end to end."""

    @pytest.mark.parametrize("scenario_cls,slug", [(ExfiltrationScenario, "exfiltration"), (WebAppScenario, "web_app")])
    def test_runs(self, scenario_cls, slug):
        s = scenario_cls()
        assert s.scenario_slug == slug
        r = TEFEngine(scenario=s).estimate(_profile())
        assert 0 < r.total_positioned_low <= r.total_positioned_median <= r.total_positioned_high
        assert r.total_dispersion.is_poisson  # no public series fitted for these yet

    @pytest.mark.parametrize("scenario_cls", [ExfiltrationScenario, WebAppScenario])
    def test_differs_from_ransomware(self, scenario_cls):
        a = TEFEngine(scenario=scenario_cls()).estimate(_profile())
        b = TEFEngine(scenario=RansomwareScenario()).estimate(_profile())
        assert a.total_positioned_median != b.total_positioned_median


@pytest.mark.skipif(not (REPO / "scripts" / "refresh_reference_data.py").exists(),
                    reason="maintainer-only script, not shipped in the public repo")
class TestRefreshScript:
    """scripts/refresh_reference_data.py: whitelist filtering, dry run writes nothing."""

    @pytest.fixture
    def script(self, tmp_path, monkeypatch):
        spec = importlib.util.spec_from_file_location("refresh_reference_data", REPO / "scripts" / "refresh_reference_data.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        dst = tmp_path / "reference"
        dst.mkdir()
        (dst / "iris.json").write_text(json.dumps({"floor_anchors": {"a": 1}, "keep": True}))
        monkeypatch.setattr(mod, "ESTIMATOR_DATA", dst)
        src = tmp_path / "substrata"
        src.mkdir()
        (src / "iris.json").write_text(json.dumps({"floor_anchors": {"a": 2}, "private_field": 9}))
        return mod, src, dst

    def test_dry_run_writes_nothing(self, script, capsys):
        mod, src, dst = script
        before = (dst / "iris.json").read_text()
        assert mod.refresh(src, dry_run=True) == 0
        assert (dst / "iris.json").read_text() == before
        out = capsys.readouterr().out
        assert "1 change(s)" in out and "private_field" in out

    def test_write_keeps_only_whitelisted(self, script):
        mod, src, dst = script
        mod.refresh(src, dry_run=False)
        data = json.loads((dst / "iris.json").read_text())
        assert data["floor_anchors"] == {"a": 2}
        assert data["keep"] is True
        assert "private_field" not in data
        assert data["_provenance"].startswith("Refreshed from Substrata")

    def test_missing_dir(self, tmp_path):
        spec = importlib.util.spec_from_file_location("rrd", REPO / "scripts" / "refresh_reference_data.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.refresh(tmp_path / "nope") == 1


class TestNewScenariosInCliAndUi:
    """Exfiltration and web-app scenarios are selectable in the CLI and the UI."""

    @pytest.mark.parametrize("slug", ["exfiltration", "web_app"])
    def test_cli_json(self, slug):
        from typer.testing import CliRunner
        from tef_estimator.cli import app
        res = CliRunner().invoke(app, ["estimate", "--scenario", slug, "--sector", "healthcare",
                                       "--revenue", "100m_1b", "--geo", "us", "--json"])
        assert res.exit_code == 0, res.output
        d = json.loads(res.output)
        assert d["scenario"] in ("data exfiltration", "web application exploitation")
        assert d["analysis"]["dispersion"]["total"]["shape_r_month"] is None

    def test_ui_lists_them(self):
        from tef_estimator import ui
        assert {"exfiltration", "web_app"} <= set(ui.BUILTIN_SCENARIOS)
        assert {"exfiltration", "web_app"} <= set(ui._all_scenario_options())
