"""Watch mode: continuous monitoring with re-estimation on signal.

Pipeline: check schedule → collect due sources → integrate →
compare against baseline → re-estimate watched profiles if signals fire.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tef_estimator.data.scenarios import SCENARIO_CLASSES
from tef_estimator.telemetry.compare import CompareResult, compare
from tef_estimator.telemetry.db import TelemetryDB
from tef_estimator.telemetry.scheduler import run_due_collections

log = logging.getLogger(__name__)

# Profile-file keys that hold enum values, mapped to OrganizationProfile fields
_ENUM_FIELDS = {
    "sector": "Sector",
    "revenue_band": "RevenueBand",
    "geography": "Geography",
}
_ENUM_LIST_FIELDS = {
    "remote_access": "RemoteAccessType",
    "edge_vendors": "RemoteAccessType",
}


@dataclass
class WatchProfile:
    """A profile to re-estimate when signals are detected."""
    name: str
    profile_kwargs: dict[str, Any]
    scenario_name: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> WatchProfile:
        """Build from a profiles-file entry: enum fields given by value.

        ``{"name": "plant-eu", "scenario": "ransomware", "sector": "manufacturing",
        "revenue_band": "100m_1b", "geography": "western_europe",
        "remote_access": ["fortinet"], "employee_count": 2000}``
        """
        from tef_estimator.data import common

        d = dict(d)
        name = d.pop("name")
        scenario = d.pop("scenario", None)
        if scenario is not None and scenario not in SCENARIO_CLASSES:
            raise ValueError(f"profile {name!r}: unknown scenario {scenario!r}")
        kwargs: dict[str, Any] = {}
        for key, value in d.items():
            if key in _ENUM_FIELDS:
                kwargs[key] = getattr(common, _ENUM_FIELDS[key])(value)
            elif key in _ENUM_LIST_FIELDS:
                enum = getattr(common, _ENUM_LIST_FIELDS[key])
                kwargs[key] = [enum(v) for v in value]
            else:
                kwargs[key] = value
        return cls(name=name, profile_kwargs=kwargs, scenario_name=scenario)


def load_watch_profiles(path: Path) -> list[WatchProfile]:
    """Read a JSON list of watched profiles (see WatchProfile.from_dict)."""
    entries = json.loads(Path(path).read_text())
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected a JSON list of profiles")
    profiles = [WatchProfile.from_dict(e) for e in entries]
    names = [p.name for p in profiles]
    if len(set(names)) != len(names):
        raise ValueError(f"{path}: profile names must be unique")
    return profiles


@dataclass
class WatchCycleResult:
    collection_results: list[dict[str, Any]]
    compare_result: CompareResult | None
    re_estimated: list[dict[str, Any]] = field(default_factory=list)

    @property
    def had_signals(self) -> bool:
        return self.compare_result is not None and self.compare_result.has_signals


def run_once(
    db: TelemetryDB,
    *,
    profiles: list[WatchProfile] | None = None,
    threshold: float = 0.20,
    force: bool = False,
    baseline_dir: Path | None = None,
    state_dir: Path | None = None,
    live: bool | None = None,
) -> WatchCycleResult:
    """Execute one full watch cycle.

    1. Run due collectors + integrate
    2. Compare against baseline
    3. If signals, re-estimate any watched profiles, each under its own
       scenario, with live-derived inputs when live mode is on (``live``,
       else config ``telemetry_inputs``)
    """
    from tef_estimator.config import get_config
    from tef_estimator.engine import TEFEngine
    from tef_estimator.profile import OrganizationProfile
    from tef_estimator.telemetry.derive import live_config, use_live

    kwargs: dict[str, Any] = {"force": force}
    if state_dir:
        kwargs["state_dir"] = state_dir
    collection_results = run_due_collections(db, **kwargs)

    any_new_data = any(
        r.get("status") == "completed" and r.get("records_inserted", 0) > 0
        for r in collection_results
        if r.get("source") != "integrator"
    )

    compare_result = None
    re_estimated: list[dict[str, Any]] = []

    if any_new_data:
        compare_kwargs: dict[str, Any] = {"threshold": threshold}
        if baseline_dir:
            compare_kwargs["baseline_dir"] = baseline_dir
        compare_result = compare(db, **compare_kwargs)

        if compare_result.has_signals and profiles:
            log.info("Signals detected — re-estimating %d profile(s)", len(profiles))
            config = None
            is_live = use_live(get_config(), live)
            live_fits: dict[str, float | None] = {}
            if is_live:
                config, fits = live_config(db)
                live_fits = {f"{f.kind}/{f.name}": f.shape_r for f in fits
                             if f.kind in ("vectors", "scenarios")}
            for wp in profiles:
                try:
                    profile = OrganizationProfile(**wp.profile_kwargs)
                    slug = wp.scenario_name or "ransomware"
                    engine = TEFEngine(scenario=SCENARIO_CLASSES[slug](), config=config)
                    result = engine.estimate(profile)
                    entry = {
                        "profile": wp.name,
                        "scenario": result.scenario_name,
                        "tef_median": result.total_positioned_median,
                        "signals_count": len(compare_result.signals),
                        "inputs": "live" if is_live else "frozen",
                    }
                    if is_live:
                        entry["live_dispersion"] = live_fits
                        entry["live_base_rate"] = (config.live_base_rate or {}).get(slug)
                    re_estimated.append(entry)
                    log.info(
                        "  %s: TEF median = %.4f",
                        wp.name, result.total_positioned_median,
                    )
                except Exception as e:
                    log.error("  Re-estimation failed for %s: %s", wp.name, e)
                    re_estimated.append({
                        "profile": wp.name,
                        "error": str(e),
                    })
    else:
        log.info("No new data — skipping compare")

    return WatchCycleResult(
        collection_results=collection_results,
        compare_result=compare_result,
        re_estimated=re_estimated,
    )


def watch_loop(
    db: TelemetryDB,
    *,
    interval_minutes: int = 60,
    profiles: list[WatchProfile] | None = None,
    threshold: float = 0.20,
    baseline_dir: Path | None = None,
    state_dir: Path | None = None,
    max_cycles: int | None = None,
    live: bool | None = None,
) -> None:
    """Run the watch cycle repeatedly."""
    cycle = 0
    while True:
        cycle += 1
        log.info("=== Watch cycle %d ===", cycle)

        try:
            result = run_once(
                db,
                profiles=profiles,
                threshold=threshold,
                baseline_dir=baseline_dir,
                state_dir=state_dir,
                live=live,
            )

            if result.had_signals:
                log.info(
                    "Cycle %d: %d signal(s), %d re-estimation(s)",
                    cycle,
                    len(result.compare_result.signals),
                    len(result.re_estimated),
                )
            else:
                log.info("Cycle %d: no signals", cycle)

        except Exception as e:
            log.error("Cycle %d failed: %s", cycle, e)

        if max_cycles and cycle >= max_cycles:
            log.info("Reached max_cycles=%d, stopping", max_cycles)
            break

        log.info("Sleeping %d minutes...", interval_minutes)
        time.sleep(interval_minutes * 60)
