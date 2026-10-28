"""
CLI interface for the TEF estimator.

Usage examples:
    tef-estimator estimate --sector manufacturing --revenue 100m_1b --geo us
    tef-estimator explain --sector manufacturing --revenue 100m_1b --geo us
    tef-estimator compare --sector manufacturing --revenue 100m_1b --geo us ...
    tef-estimator sensitivity --sector manufacturing --revenue 100m_1b --geo us
    tef-estimator data multipliers
    tef-estimator data base-rate
    tef-estimator data vectors
    tef-estimator data peer-grid --rebuild
    tef-estimator refresh snapshot | check | full
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path

try:
    import typer
    from rich.console import Console
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from tef_estimator.data.common import (
    Geography,
    RemoteAccessType,
    RevenueBand,
    Sector,
)
from tef_estimator.data.loader import PEER_GRID_DIR
from tef_estimator.data.scenarios.bec import BECScenario
from tef_estimator.data.scenarios.exfiltration import ExfiltrationScenario
from tef_estimator.data.scenarios.web_app import WebAppScenario
from tef_estimator.data.scenarios.ransomware import RansomwareScenario
from tef_estimator.config import get_config
from tef_estimator.engine import TEFEngine
from tef_estimator.profile import OrganizationProfile


class ScenarioChoice(str, Enum):
    RANSOMWARE = "ransomware"
    BEC = "bec"
    EXFILTRATION = "exfiltration"
    WEB_APP = "web_app"
    CUSTOM = "custom"


SCENARIO_MAP = {
    ScenarioChoice.RANSOMWARE: RansomwareScenario,
    ScenarioChoice.BEC: BECScenario,
    ScenarioChoice.EXFILTRATION: ExfiltrationScenario,
    ScenarioChoice.WEB_APP: WebAppScenario,
}

PEER_GRID_PATH = PEER_GRID_DIR / "ransomware.json"


def _resolve_scenario(choice: ScenarioChoice, scenario_file: Path | None = None):
    if choice == ScenarioChoice.CUSTOM:
        if scenario_file is None:
            print("Error: --scenario custom requires --scenario-file <path>")
            raise typer.Exit(1)
        from tef_estimator.data.scenarios.custom import load_custom_scenario
        return load_custom_scenario(scenario_file)
    return SCENARIO_MAP[choice]()

app = typer.Typer(
    name="tef-estimator",
    help="Data-grounded FAIR Threat Event Frequency estimation.",
    no_args_is_help=True,
)
data_app = typer.Typer(help="Inspect embedded empirical data.")
app.add_typer(data_app, name="data")
refresh_app = typer.Typer(help="Data refresh pipeline.")
app.add_typer(refresh_app, name="refresh")
scenario_app = typer.Typer(help="Custom scenario management.")
app.add_typer(scenario_app, name="scenario")

console = Console() if HAS_RICH else None


def _build_profile(
    sector: Sector,
    revenue: RevenueBand,
    geo: Geography,
    remote_access: list[RemoteAccessType],
    employees: int | None = None,
    critical_infra: bool = False,
    supply_chain: bool = False,
    recent_ma: bool = False,
    base_rate: float | None = None,
    telemetry_file: Path | None = None,
) -> OrganizationProfile:
    telemetry = None
    if telemetry_file is not None:
        telemetry = _load_telemetry(telemetry_file)

    return OrganizationProfile(
        sector=sector,
        revenue_band=revenue,
        geography=geo,
        remote_access=remote_access,
        employee_count=employees,
        critical_infrastructure=critical_infra,
        supply_chain_provider=supply_chain,
        recent_ma=recent_ma,
        custom_base_rate=base_rate,
        telemetry=telemetry,
    )


def _load_telemetry(path: Path):
    """Load telemetry observations from a JSON file.

    Expected format::

        {
          "observations": [
            {
              "vector": "exploitation",
              "annualized_frequency": 0.004,
              "observation_periods": 4,
              "detection_coverage": 0.8
            }
          ]
        }
    """
    from tef_estimator.credibility import OrgTelemetry, VectorObservation

    with open(path) as f:
        data = json.load(f)

    observations = [
        VectorObservation(**obs)
        for obs in data["observations"]
    ]
    return OrgTelemetry(observations=observations)


def _live_option():
    return typer.Option(
        None, "--live/--frozen",
        help="Derive inputs from the telemetry DB (--live) or use bundled values only "
             "(--frozen). Default: config telemetry_inputs (frozen)",
    )


def _telemetry_db_option():
    return typer.Option(
        None, "--telemetry-db", help="Telemetry database for --live (default ~/.tef-estimator/telemetry.db)"
    )


def _engine_config(live: bool | None, telemetry_db: Path | None):
    """The engine config for the input mode: None (bundled) when frozen, else
    the live-derived config, with each live input's outcome on stderr."""
    from tef_estimator.telemetry.derive import use_live
    if not use_live(get_config(), live):
        return None
    from tef_estimator.telemetry.db import DEFAULT_DB_PATH, TelemetryDB
    from tef_estimator.telemetry.derive import live_config
    db_file = telemetry_db or DEFAULT_DB_PATH
    if not db_file.exists():
        typer.echo(f"Telemetry database not found: {db_file}", err=True)
        raise typer.Exit(1)
    config, fits = live_config(TelemetryDB(db_path=db_file))
    for f in fits:
        what = (f"Live {f.name} base rate" if f.kind == "base_rate"
                else f"Live dispersion {f.kind}/{f.name}")
        if f.status != "fitted":
            typer.echo(f"{what}: bundled kept ({f.reason})", err=True)
        elif f.kind == "base_rate":
            typer.echo(f"{what}: {f.detail}", err=True)
        else:
            typer.echo(
                f"{what}: r={f.shape_r} "
                f"(bundled {f.bundled_shape_r}), {f.window[0]}..{f.window[1]}, "
                f"data through {f.last_collected}",
                err=True,
            )
    return config


@app.command()
def estimate(
    sector: Sector = typer.Option(..., help="Industry sector"),
    revenue: RevenueBand = typer.Option(..., help="Annual revenue band"),
    geo: Geography = typer.Option(..., help="Primary geography"),
    remote_access: list[RemoteAccessType] = typer.Option(
        [RemoteAccessType.NONE], help="Remote access types exposed"
    ),
    employees: int = typer.Option(None, help="Approximate employee count"),
    critical_infra: bool = typer.Option(False, help="Critical infrastructure?"),
    supply_chain: bool = typer.Option(False, help="Significant supply chain role?"),
    recent_ma: bool = typer.Option(False, help="M&A in last 18 months?"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
    base_rate: float = typer.Option(None, help="Override base rate (TEF, events per year)"),
    brief: bool = typer.Option(False, "--brief", help="Tier 1 summary only"),
    full: bool = typer.Option(False, "--full", help="Tier 3 full audit trail"),
    scenario: ScenarioChoice = typer.Option(
        ScenarioChoice.RANSOMWARE, help="Threat scenario (ransomware, bec, exfiltration, web_app, custom)"
    ),
    telemetry: Path = typer.Option(
        None, "--telemetry", help="JSON file with org-specific vector observations for Bühlmann blending"
    ),
    scenario_file: Path = typer.Option(
        None, "--scenario-file", help="JSON file defining a custom scenario (use with --scenario custom)"
    ),
    output: Path = typer.Option(
        None, "--output", "-o", help="Write markdown report to file"
    ),
    live: bool = _live_option(),
    telemetry_db: Path = _telemetry_db_option(),
):
    """Estimate TEF for an organization profile."""
    profile = _build_profile(
        sector, revenue, geo, remote_access, employees,
        critical_infra, supply_chain, recent_ma, base_rate,
        telemetry_file=telemetry,
    )

    scenario_obj = _resolve_scenario(scenario, scenario_file)
    engine = TEFEngine(scenario=scenario_obj, config=_engine_config(live, telemetry_db))
    result = engine.estimate(profile)

    _apply_peer_grid(result, profile.revenue_band, scenario_obj.scenario_slug)

    if output is not None:
        output.write_text(result.to_markdown())
        print(f"Report written to {output}")
    elif output_json:
        print(json.dumps(result.to_dict(), indent=2))
    elif brief:
        print(result.brief_report())
    elif full:
        print(result.full_report())
    else:
        # Default: Tier 2 (analysis-level)
        print(result.brief_report())
        print()
        print(result.distribution_text())
        if result.has_credibility_data:
            print()
            print(result.credibility_text())


@app.command()
def explain(
    sector: Sector = typer.Option(..., help="Industry sector"),
    revenue: RevenueBand = typer.Option(..., help="Annual revenue band"),
    geo: Geography = typer.Option(..., help="Primary geography"),
    remote_access: list[RemoteAccessType] = typer.Option(
        [RemoteAccessType.NONE], help="Remote access types exposed"
    ),
    employees: int = typer.Option(None, help="Approximate employee count"),
    critical_infra: bool = typer.Option(False, help="Critical infrastructure?"),
    supply_chain: bool = typer.Option(False, help="Significant supply chain role?"),
    recent_ma: bool = typer.Option(False, help="M&A in last 18 months?"),
    base_rate: float = typer.Option(None, help="Override base rate"),
    scenario: ScenarioChoice = typer.Option(
        ScenarioChoice.RANSOMWARE, help="Threat scenario (ransomware, bec, exfiltration, web_app, custom)"
    ),
    scenario_file: Path = typer.Option(
        None, "--scenario-file", help="JSON file for custom scenario"
    ),
    output: Path = typer.Option(
        None, "--output", "-o", help="Write markdown report to file"
    ),
    live: bool = _live_option(),
    telemetry_db: Path = _telemetry_db_option(),
):
    """Print the full calculation trace for every vector."""
    profile = _build_profile(
        sector, revenue, geo, remote_access, employees,
        critical_infra, supply_chain, recent_ma, base_rate,
    )

    scenario_obj = _resolve_scenario(scenario, scenario_file)
    engine = TEFEngine(scenario=scenario_obj, config=_engine_config(live, telemetry_db))
    result = engine.estimate(profile)

    if output is not None:
        output.write_text(result.to_markdown())
        print(f"Report written to {output}")
    else:
        print(result.full_report())


@app.command()
def compare(
    # Profile A
    sector: Sector = typer.Option(..., help="Profile A: sector"),
    revenue: RevenueBand = typer.Option(..., help="Profile A: revenue band"),
    geo: Geography = typer.Option(..., help="Profile A: geography"),
    remote_access: list[RemoteAccessType] = typer.Option(
        [RemoteAccessType.NONE], help="Profile A: remote access"
    ),
    employees: int = typer.Option(None, help="Profile A: employees"),
    # Profile B
    b_sector: Sector = typer.Option(None, "--b-sector", help="Profile B: sector (default=same as A)"),
    b_revenue: RevenueBand = typer.Option(None, "--b-revenue", help="Profile B: revenue band"),
    b_geo: Geography = typer.Option(None, "--b-geo", help="Profile B: geography"),
    b_remote_access: list[RemoteAccessType] = typer.Option(
        None, "--b-remote-access", help="Profile B: remote access"
    ),
    b_employees: int = typer.Option(None, "--b-employees", help="Profile B: employees"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
    scenario: ScenarioChoice = typer.Option(
        ScenarioChoice.RANSOMWARE, help="Threat scenario (ransomware, bec, exfiltration, web_app, custom)"
    ),
    scenario_file: Path = typer.Option(
        None, "--scenario-file", help="JSON file for custom scenario"
    ),
    live: bool = _live_option(),
    telemetry_db: Path = _telemetry_db_option(),
):
    """Compare TEF estimates for two profiles."""
    profile_a = _build_profile(sector, revenue, geo, remote_access, employees)
    profile_b = _build_profile(
        b_sector or sector,
        b_revenue or revenue,
        b_geo or geo,
        b_remote_access if b_remote_access is not None else remote_access,
        b_employees if b_employees is not None else employees,
    )

    scenario_obj = _resolve_scenario(scenario, scenario_file)
    engine = TEFEngine(scenario=scenario_obj, config=_engine_config(live, telemetry_db))
    diff = engine.compare(profile_a, profile_b)

    if output_json:
        print(json.dumps(diff.to_dict(), indent=2))
    else:
        print(diff.render_text())


@app.command()
def sensitivity(
    sector: Sector = typer.Option(..., help="Industry sector"),
    revenue: RevenueBand = typer.Option(..., help="Annual revenue band"),
    geo: Geography = typer.Option(..., help="Primary geography"),
    remote_access: list[RemoteAccessType] = typer.Option(
        [RemoteAccessType.NONE], help="Remote access types exposed"
    ),
    employees: int = typer.Option(None, help="Approximate employee count"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
    scenario: ScenarioChoice = typer.Option(
        ScenarioChoice.RANSOMWARE, help="Threat scenario (ransomware, bec, exfiltration, web_app, custom)"
    ),
    scenario_file: Path = typer.Option(
        None, "--scenario-file", help="JSON file for custom scenario"
    ),
    live: bool = _live_option(),
    telemetry_db: Path = _telemetry_db_option(),
):
    """Rank input parameters by contribution to output variance."""
    profile = _build_profile(sector, revenue, geo, remote_access, employees)

    scenario_obj = _resolve_scenario(scenario, scenario_file)
    engine = TEFEngine(scenario=scenario_obj, config=_engine_config(live, telemetry_db))
    result = engine.sensitivity(profile)

    if output_json:
        print(json.dumps(result.tornado_data, indent=2))
    else:
        print(result.render_text())


# --- Data inspection commands ---

@data_app.command("multipliers")
def show_multipliers(
    scenario: ScenarioChoice = typer.Option(
        ScenarioChoice.RANSOMWARE, help="Threat scenario"
    ),
):
    """Show all sector and revenue band multipliers with sources."""
    scenario_obj = SCENARIO_MAP[scenario]()

    if HAS_RICH:
        table = Table(title=f"Sector Multipliers (IRIS 2025 + {scenario_obj.scenario_name})")
        table.add_column("Sector", style="bold")
        table.add_column("All-Incident", justify="right")
        table.add_column("Adjusted", justify="right", style="cyan")

        from tef_estimator.data.common import SECTOR_DATA
        for s in sorted(SECTOR_DATA.keys(), key=lambda s: -scenario_obj.adjusted_sector_multiplier(s)):
            data = SECTOR_DATA[s]
            adj = scenario_obj.adjusted_sector_multiplier(s)
            table.add_row(
                s.value.replace("_", " ").title(),
                f"{data.all_incident_multiplier:.2f}x",
                f"{adj:.2f}x",
            )
        console.print(table)

        rev_table = Table(title=f"\nRevenue Band Multipliers (IRIS 2025 + {scenario_obj.scenario_name})")
        rev_table.add_column("Revenue Band", style="bold")
        rev_table.add_column("All-Incident", justify="right")
        rev_table.add_column("Adjusted", justify="right", style="cyan")

        from tef_estimator.data.common import REVENUE_BAND_DATA
        for band, data in REVENUE_BAND_DATA.items():
            adj = scenario_obj.adjusted_revenue_multiplier(band)
            rev_table.add_row(
                band.value.replace("_", "-"),
                f"{data.all_incident_multiplier:.2f}x",
                f"{adj:.2f}x",
            )
        console.print(rev_table)
    else:
        from tef_estimator.data.common import SECTOR_DATA
        print("Sector Multipliers")
        print("-" * 50)
        for s in sorted(SECTOR_DATA.keys(), key=lambda s: -scenario_obj.adjusted_sector_multiplier(s)):
            data = SECTOR_DATA[s]
            adj = scenario_obj.adjusted_sector_multiplier(s)
            print(f"  {s.value:<20} All: {data.all_incident_multiplier:.2f}x  Adj: {adj:.2f}x")


@data_app.command("base-rate")
def show_base_rate(
    scenario: ScenarioChoice = typer.Option(
        ScenarioChoice.RANSOMWARE, help="Threat scenario"
    ),
):
    """Show the scenario's base rate: per revenue band, with its derivation."""
    scenario_obj = SCENARIO_MAP[scenario]()
    engine = TEFEngine(scenario=scenario_obj)
    rows = []
    for band in RevenueBand:
        br = engine.base_rate_for(band)
        rows.append((band.value, br))
    if HAS_RICH:
        table = Table(title=f"Base rate (TEF, events per year), {scenario_obj.scenario_name}")
        table.add_column("Revenue band", style="bold")
        table.add_column("Low", justify="right")
        table.add_column("Mode", justify="right", style="cyan")
        table.add_column("High", justify="right")
        for band, br in rows:
            table.add_row(band, f"{br.low:.3g}", f"{br.mode:.3g}", f"{br.high:.3g}")
        console.print(table)
    else:
        for band, br in rows:
            print(f"{band}: low={br.low:.4f}, mode={br.mode:.4f}, high={br.high:.4f}")
    for line in engine.base_rate_derivation(RevenueBand.R_100M_1B, engine.base_rate_for(RevenueBand.R_100M_1B)):
        print(f"$100M–1B: {line}")


@data_app.command("vectors")
def show_vectors(
    scenario: ScenarioChoice = typer.Option(
        ScenarioChoice.RANSOMWARE, help="Threat scenario"
    ),
):
    """Show initial access vector proportions."""
    scenario_obj = SCENARIO_MAP[scenario]()

    if HAS_RICH:
        table = Table(title=f"{scenario_obj.scenario_name} Initial Access Vector Proportions")
        table.add_column("Vector", style="bold")
        table.add_column("Low", justify="right")
        table.add_column("Mode", justify="right", style="cyan")
        table.add_column("High", justify="right")

        for name, pert in scenario_obj.vector_proportions.items():
            table.add_row(
                name.replace("_", " ").title(),
                f"{pert.low:.0%}",
                f"{pert.mode:.0%}",
                f"{pert.high:.0%}",
            )
        console.print(table)
    else:
        for name, pert in scenario_obj.vector_proportions.items():
            print(f"{name}: {pert.low:.0%} - {pert.mode:.0%} - {pert.high:.0%}")


@data_app.command("peer-grid")
def show_peer_grid(
    rebuild: bool = typer.Option(False, "--rebuild", help="Rebuild the peer grid"),
):
    """Show the ransomware peer grid, or rebuild the grids of all built-in scenarios."""
    from tef_estimator.peer import build_grid, save_grid, load_grid

    if rebuild:
        from tef_estimator.data.scenarios import SCENARIO_CLASSES
        for slug, cls in SCENARIO_CLASSES.items():
            path = PEER_GRID_DIR / f"{slug}.json"
            print(f"Building {slug} peer grid (all sector x revenue x geo combos)...")
            grid = build_grid(TEFEngine(scenario=cls()))
            save_grid(grid, path)
            print(f"Saved to {path}")
            for band, values in grid.items():
                print(f"  {band}: {len(values)} estimates, "
                      f"range {min(values):.5f} - {max(values):.5f}")
    else:
        grid = load_grid(PEER_GRID_PATH)
        if grid is None:
            print(f"No peer grid found at {PEER_GRID_PATH}. Run with --rebuild to create one.")
            return
        for band, values in grid.items():
            print(f"  {band}: {len(values)} estimates, "
                  f"range {min(values):.5f} - {max(values):.5f}")


# --- Refresh pipeline ---

@refresh_app.command("snapshot")
def refresh_snapshot():
    """Print the steps to update the bundled reference data (fetches nothing)."""
    from tef_estimator.refresh import run_snapshot_refresh
    run_snapshot_refresh()


@refresh_app.command("check")
def refresh_check():
    """Validate data directories and report stale/missing."""
    from tef_estimator.refresh import run_check
    run_check()


@refresh_app.command("full")
def refresh_full():
    """Full refresh: snapshot + check."""
    from tef_estimator.refresh import run_snapshot_refresh, run_check
    run_snapshot_refresh()
    run_check()


# --- Helpers ---

def _apply_peer_grid(result, revenue_band: RevenueBand, scenario_slug: str = "ransomware") -> None:
    """Try to load peer grid and apply percentile to result."""
    grid_path = PEER_GRID_DIR / f"{scenario_slug}.json"
    if not grid_path.exists():
        return
    from tef_estimator.peer import load_grid, compute_and_set_percentile
    grid = load_grid(grid_path)
    if grid is not None:
        compute_and_set_percentile(result, revenue_band, grid)


@scenario_app.command("template")
def scenario_template(
    output: Path = typer.Argument("custom_scenario.json", help="Output file path"),
):
    """Generate a template custom scenario JSON file."""
    from tef_estimator.data.scenarios.custom import generate_template
    generate_template(output)
    print(f"Template written to {output}")
    print("Edit the file, then use: tef-estimator estimate --scenario custom --scenario-file <path>")


@scenario_app.command("validate")
def scenario_validate(
    path: Path = typer.Argument(..., help="Path to custom scenario JSON"),
):
    """Validate a custom scenario definition file."""
    from tef_estimator.data.scenarios.custom import load_custom_scenario
    try:
        s = load_custom_scenario(path)
        print(f"Valid scenario: {s.scenario_name} ({s.scenario_slug})")
        print(f"  Active vectors: {', '.join(s.active_vectors)}")
        vp = s.vector_proportions
        for name, pert in vp.items():
            print(f"    {name}: {pert.low:.0%} - {pert.mode:.0%} - {pert.high:.0%}")
        br = s.base_rate_triangulation
        consensus = br.get("consensus")
        if consensus:
            print(f"  Base rate consensus: {consensus.low:.3f} - {consensus.mode:.3f} - {consensus.high:.3f}")
        print(f"  Overall share: {s.overall_share:.0%}")
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        print(f"Validation failed: {e}")
        raise typer.Exit(1)


@app.command()
def ui(
    port: int = typer.Option(8080, help="Port to run the web UI on"),
    reload: bool = typer.Option(False, help="Enable hot reload for development"),
):
    """Launch the NiceGUI web interface."""
    try:
        from tef_estimator.ui import launch
    except ImportError:
        print("NiceGUI not installed. Install with: pip install tef-estimator[ui]")
        raise typer.Exit(1)
    launch(port=port, reload=reload)


try:
    from tef_estimator.telemetry.cli import app as telemetry_app
    app.add_typer(telemetry_app, name="telemetry")
except ImportError:
    pass


if __name__ == "__main__":
    app()
