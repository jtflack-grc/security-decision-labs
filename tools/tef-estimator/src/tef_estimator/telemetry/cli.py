"""Telemetry CLI subgroup: tef-estimator telemetry <command>."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from tef_estimator.telemetry import _check_requests

_check_requests()

app = typer.Typer(help="Continuous telemetry monitoring for TEF estimation.")
console = Console()


def _db_from_path(db_path: Path | None):
    from tef_estimator.telemetry.db import TelemetryDB, DEFAULT_DB_PATH
    return TelemetryDB(db_path or DEFAULT_DB_PATH)


@app.command()
def init(
    db_path: Path = typer.Option(None, "--db-path", help="Custom database path"),
):
    """Initialize the telemetry database."""
    db = _db_from_path(db_path)
    db.initialize()
    console.print(f"[green]Database initialized at {db.db_path}[/green]")


@app.command()
def collect(
    source: str = typer.Option(None, "--source", help="Run only this collector"),
    force: bool = typer.Option(False, "--force", help="Ignore cadence schedule"),
    db_path: Path = typer.Option(None, "--db-path", help="Custom database path"),
):
    """Run telemetry collectors (all or a specific source), then integrate new data."""
    from tef_estimator.telemetry.scheduler import run_due_collections
    db = _db_from_path(db_path)
    results = run_due_collections(db, force=force, source_filter=source)

    table = Table(title="Collection Results")
    table.add_column("Source", style="bold")
    table.add_column("Status")
    table.add_column("Inserted", justify="right")
    table.add_column("Skipped", justify="right")

    for r in results:
        status_style = "green" if r.get("status") == "completed" else "red"
        table.add_row(
            r.get("source", "?"),
            f"[{status_style}]{r.get('status', '?')}[/{status_style}]",
            str(r.get("records_inserted", "")),
            str(r.get("records_skipped", "")),
        )

    console.print(table)


@app.command()
def integrate(
    source: str = typer.Option(None, "--source", help="Integrate only this source"),
    db_path: Path = typer.Option(None, "--db-path", help="Custom database path"),
):
    """Rebuild the daily series and rolling averages from stored data (no downloads).

    Collection integrates only when it brings new data; run this after an
    upgrade that changes integration, so the stored data is reprocessed.
    """
    from tef_estimator.telemetry.integrator import run_integration
    db = _db_from_path(db_path)
    result = run_integration(db, source_filter=source)

    table = Table(title="Integration Results")
    table.add_column("Source", style="bold")
    table.add_column("Rows written", justify="right")
    for r in result["per_source"]:
        written = r.get("inserted", 0) + r.get("derived_series", {}).get("inserted", 0)
        table.add_row(r["source"], str(written))
    console.print(table)


@app.command()
def status(
    db_path: Path = typer.Option(None, "--db-path", help="Custom database path"),
):
    """Show source health status."""
    db = _db_from_path(db_path)
    conn = db.connect()
    health = db.get_source_health(conn)
    conn.close()

    table = Table(title="Source Health")
    table.add_column("Source", style="bold")
    table.add_column("Last Success")
    table.add_column("Failures", justify="right")
    table.add_column("Stale?")
    table.add_column("Notes")

    for h in health:
        stale_style = "red" if h.staleness_flag else "green"
        table.add_row(
            h.source_id,
            h.last_success or "never",
            str(h.consecutive_failures),
            f"[{stale_style}]{'yes' if h.staleness_flag else 'no'}[/{stale_style}]",
            (h.notes or "")[:60],
        )

    console.print(table)


@app.command()
def baseline(
    db_path: Path = typer.Option(None, "--db-path", help="Custom database path"),
):
    """Snapshot current rolling averages as baseline for comparison."""
    from tef_estimator.telemetry.compare import snapshot_baseline
    db = _db_from_path(db_path)
    bl = snapshot_baseline(db)
    total = sum(len(v) for v in bl.values())
    console.print(
        f"[green]Baseline saved: {total} metrics across {len(bl)} sources[/green]"
    )


@app.command("compare")
def compare_cmd(
    threshold: float = typer.Option(0.20, "--threshold", help="Signal threshold (0.0-1.0)"),
    db_path: Path = typer.Option(None, "--db-path", help="Custom database path"),
):
    """Compare current data against baseline and report signals."""
    from tef_estimator.telemetry.compare import compare
    db = _db_from_path(db_path)
    result = compare(db, threshold=threshold)

    if result.new_metrics:
        console.print(
            f"[yellow]{len(result.new_metrics)} new metric(s) baselined, "
            f"not yet comparable: {', '.join(result.new_metrics)}[/yellow]"
        )
    if result.missing_metrics:
        console.print(
            f"[red]{len(result.missing_metrics)} baseline metric(s) missing from "
            f"current data (collector stopped?): {', '.join(result.missing_metrics)}[/red]"
        )

    if not result.has_signals:
        console.print(
            f"[green]No signals detected ({result.metrics_checked} metrics checked, "
            f"threshold={result.threshold:.0%})[/green]"
        )
        return

    table = Table(title=f"Signals Detected (threshold={result.threshold:.0%})")
    table.add_column("Source", style="bold")
    table.add_column("Metric")
    table.add_column("Baseline", justify="right")
    table.add_column("Current", justify="right")
    table.add_column("Change", justify="right")
    table.add_column("Direction")

    for s in result.signals:
        change_style = "red" if s.direction == "up" else "cyan"
        table.add_row(
            s.source_id,
            s.metric_name,
            f"{s.baseline_value:.2f}",
            f"{s.current_value:.2f}",
            f"[{change_style}]{s.pct_change:+.1%}[/{change_style}]",
            s.direction,
        )

    console.print(table)


@app.command()
def watch(
    interval: int = typer.Option(60, "--interval", help="Minutes between cycles"),
    threshold: float = typer.Option(0.20, "--threshold", help="Signal threshold"),
    db_path: Path = typer.Option(None, "--db-path", help="Custom database path"),
    max_cycles: int = typer.Option(None, "--max-cycles", help="Stop after N cycles"),
    profiles_file: Path = typer.Option(
        None, "--profiles",
        help="JSON list of watched profiles to re-estimate when signals fire",
    ),
    live: bool = typer.Option(
        None, "--live/--frozen",
        help="Re-estimate with telemetry-derived inputs (--live) or bundled values "
             "only (--frozen). Default: config telemetry_inputs (frozen)",
    ),
):
    """Run continuous monitoring (collect → compare → re-estimate loop)."""
    from tef_estimator.telemetry.watch import load_watch_profiles, watch_loop
    db = _db_from_path(db_path)
    profiles = load_watch_profiles(profiles_file) if profiles_file else None
    console.print(
        f"[bold]Starting watch mode[/bold] "
        f"(interval={interval}m, threshold={threshold:.0%}, "
        f"{len(profiles) if profiles else 'no'} watched profile(s))"
    )
    if not profiles:
        console.print(
            "[yellow]No --profiles given: signals are reported, nothing is re-estimated.[/yellow]"
        )
    watch_loop(
        db,
        interval_minutes=interval,
        threshold=threshold,
        max_cycles=max_cycles,
        profiles=profiles,
        live=live,
    )
