"""Estimate inputs derived from the telemetry database.

Live dispersion: refits the NB2 shape r of a published dispersion default on
the collected series, using the same recipe as the bundled value (monthly
counts, trailing window, linear trend for the detrended basis). The result is
a new TEFConfig; the bundled config is never mutated, and every refit records
its window and data vintage in the shape's source citation.

The shape describes when attacks happen, so each series is timed by the date
closest to the attack: KEV by the date a CVE entered the catalog, ransomware by
the victim's attack date (not the date the leak post was discovered, which adds
crawler and batch-posting timing). Attack-date months keep filling for weeks as
late postings arrive, so the most recent months are left out (censor_months).
"""

from __future__ import annotations

import calendar
import logging
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from tef_estimator.config import TEFConfig, get_config
from tef_estimator.data.scenarios import SCENARIO_CLASSES
from tef_estimator.dispersion_fit import moments_shape, month_range, nb2_shape, shift_month
from tef_estimator.telemetry.db import TelemetryDB

log = logging.getLogger(__name__)

# (kind, name) -> how to read the series; window settings live in config.yaml
# dispersion.live.series.<name>. "rows": one row per event (count rows);
# "sum": one row per day holding a count (sum values).
LIVE_DISPERSION_SERIES = {
    ("vectors", "exploitation"): {
        "source_id": "cisa_kev",
        "metric_like": "kev_CVE-%",
        "aggregate": "rows",
        "label": "CISA KEV new entries per month",
    },
    ("scenarios", "ransomware"): {
        "source_id": "ransomware_live",
        "metric_like": "daily_victim_count_by_attack",
        "aggregate": "sum",
        "label": "ransomware.live victims per month by attack date",
    },
}


@dataclass(frozen=True)
class LiveFit:
    kind: str
    name: str
    status: str  # "fitted" or "fallback"
    reason: str = ""
    shape_r: float | None = None
    raw_shape_r: float | None = None
    bundled_shape_r: float | None = None
    window: tuple[str, str] | None = None
    last_collected: str | None = None
    detail: str = ""


def _monthly_counts(cursor, spec: dict) -> tuple[Counter, dict[str, int], str | None]:
    """(counts per month, days with a row per month, latest collection date)."""
    value = "1" if spec["aggregate"] == "rows" else "metric_value"
    cursor.execute(
        f"""SELECT substr(observation_date, 1, 7), SUM({value}),
                   COUNT(DISTINCT observation_date), MAX(date(collection_timestamp))
            FROM raw_observations
            WHERE source_id = ? AND metric_name LIKE ?
            GROUP BY substr(observation_date, 1, 7)""",
        (spec["source_id"], spec["metric_like"]),
    )
    rows = cursor.fetchall()
    counts = Counter({month: total for month, total, _, _ in rows})
    days = {month: n for month, _, n, _ in rows}
    return counts, days, max((c for *_, c in rows if c), default=None)


def _days_in_month(month: str) -> int:
    year, mon = map(int, month.split("-"))
    return calendar.monthrange(year, mon)[1]


def _window(counts: Counter, last_collected: str, series_cfg: dict,
            earliest: str | None = None) -> tuple[str, str, list[str]]:
    """(start, end, months): the trailing window of complete, uncensored months.

    It ends at the last complete month before the latest collection, minus the
    months still filling with late reports. Months before the series' first
    observation are missing data, not zero counts.
    """
    end = shift_month(last_collected[:7], -1 - series_cfg.get("censor_months", 0))
    floors = [shift_month(end, -(series_cfg["window_months"] - 1)), min(counts)]
    if earliest:
        floors.append(earliest)
    start = max(floors)
    return start, end, (month_range(start, end) if start <= end else [])


def _partial_months(months: list[str], days: dict[str, int], series_cfg: dict) -> list[str]:
    """Window months with rows on fewer than min_day_coverage of their days.

    A daily-count series has a row on (nearly) every day; a month with far
    fewer days was not fully collected, and would read as a quiet one.
    """
    min_cov = series_cfg.get("min_day_coverage")
    if not min_cov:
        return []
    return [m for m in months if days.get(m, 0) < min_cov * _days_in_month(m)]


def _fit_one(cursor, kind: str, name: str, spec: dict, live_cfg: dict,
             bundled: dict | None) -> LiveFit:
    bundled_r = (bundled or {}).get("shape_r")
    series_cfg = (live_cfg.get("series") or {}).get(name)
    if not series_cfg:
        return LiveFit(kind, name, "fallback", f"no dispersion.live.series.{name} config",
                       bundled_shape_r=bundled_r)

    counts, days, last_collected = _monthly_counts(cursor, spec)
    if last_collected is None or not counts:
        return LiveFit(kind, name, "fallback", "no collected data",
                       bundled_shape_r=bundled_r)

    start, end, months = _window(counts, last_collected, series_cfg,
                                 series_cfg.get("earliest_month"))
    if len(months) < series_cfg["min_months"]:
        return LiveFit(kind, name, "fallback",
                       f"window {start}..{end} has {len(months)} months, "
                       f"needs {series_cfg['min_months']}",
                       bundled_shape_r=bundled_r, last_collected=last_collected)

    partial = _partial_months(months, days, series_cfg)
    if partial:
        return LiveFit(kind, name, "fallback",
                       f"incomplete month(s) in window: {', '.join(partial)}",
                       bundled_shape_r=bundled_r, window=(start, end),
                       last_collected=last_collected)

    ys = [counts.get(m, 0) for m in months]
    try:
        detrended = nb2_shape(ys, trend=True)
        raw_r = moments_shape(ys)
    except ValueError as e:
        return LiveFit(kind, name, "fallback", str(e),
                       bundled_shape_r=bundled_r, last_collected=last_collected)

    lo, hi = live_cfg["shape_bounds"]
    if not detrended.converged or not lo <= detrended.shape_r <= hi:
        return LiveFit(kind, name, "fallback",
                       f"detrended fit outside bounds [{lo}, {hi}] or not converged "
                       f"(r={detrended.shape_r:.1f})",
                       bundled_shape_r=bundled_r, window=(start, end),
                       last_collected=last_collected)
    if raw_r is not None and not lo <= raw_r <= hi:
        raw_r = None
        log.info("Live %s/%s raw shape outside bounds; raw basis falls back to detrended",
                 kind, name)

    if bundled_r and abs(detrended.shape_r / bundled_r - 1) > live_cfg["warn_rel_change"]:
        log.warning("Live %s/%s shape r=%.1f differs from bundled %.1f by more than %.0f%%",
                    kind, name, detrended.shape_r, bundled_r,
                    live_cfg["warn_rel_change"] * 100)

    return LiveFit(kind, name, "fitted",
                   shape_r=round(detrended.shape_r, 1),
                   raw_shape_r=round(raw_r, 1) if raw_r is not None else None,
                   bundled_shape_r=bundled_r,
                   window=(start, end),
                   last_collected=last_collected)


def _sum_months(cursor, source_id: str, metric: str, months: list[str]) -> float:
    cursor.execute(
        """SELECT COALESCE(SUM(metric_value), 0) FROM raw_observations
           WHERE source_id = ? AND metric_name = ?
             AND substr(observation_date, 1, 7) BETWEEN ? AND ?""",
        (source_id, metric, months[0], months[-1]),
    )
    return float(cursor.fetchone()[0])


def live_tempo_anchor(cursor, cfg: TEFConfig) -> LiveFit:
    """US ransomware events per year from collected victims, for the base rate.

    Sets ``cfg.live_base_rate[scenario] = {"n_us": ...}``; the engine applies the
    scenario's own recipe (base_rate.py) to it, as it does to the bundled count.
    """
    recipe = cfg.tempo_anchor or {}
    slug = recipe.get("scenario", "ransomware")
    series_cfg = ((cfg.dispersion or {}).get("live") or {}).get("series", {}).get(slug)
    if not recipe or not series_cfg:
        return LiveFit("base_rate", slug, "fallback", "no tempo_anchor / window config")

    spec = LIVE_DISPERSION_SERIES[("scenarios", slug)]
    counts, days, last_collected = _monthly_counts(cursor, spec)
    if last_collected is None or not counts:
        return LiveFit("base_rate", slug, "fallback", "no collected data")
    start, end, months = _window(counts, last_collected, series_cfg)
    if len(months) < series_cfg["window_months"]:
        return LiveFit("base_rate", slug, "fallback",
                       f"window {start}..{end} has {len(months)} months, needs "
                       f"{series_cfg['window_months']}", last_collected=last_collected)
    partial = _partial_months(months, days, series_cfg)
    if partial:
        return LiveFit("base_rate", slug, "fallback",
                       f"incomplete month(s) in window: {', '.join(partial)}",
                       window=(start, end), last_collected=last_collected)

    metric = spec["metric_like"]
    total, us, known = (_sum_months(cursor, spec["source_id"], m, months)
                        for m in (metric, f"{metric}_us", f"{metric}_known_country"))
    if known <= 0:
        return LiveFit("base_rate", slug, "fallback", "no victims with a country in the window",
                       window=(start, end), last_collected=last_collected)
    n_us = us + (total - known) * us / known

    reference = SCENARIO_CLASSES[slug]().base_rate_lef["n_us"]
    lo_b, hi_b = recipe["bounds"]
    ratio = n_us / reference
    if not lo_b <= ratio <= hi_b:
        return LiveFit("base_rate", slug, "fallback",
                       f"N_US {n_us:,.0f} is {ratio:.2f}× the bundled {reference:,}, "
                       f"outside [{lo_b}, {hi_b}]", window=(start, end), last_collected=last_collected)

    cfg.live_base_rate[slug] = {"n_us": n_us}
    return LiveFit(
        "base_rate", slug, "fitted", window=(start, end), last_collected=last_collected,
        detail=(f"N_US {n_us:,.0f} US victims/yr by attack date, {start} to {end} "
                f"(bundled {reference:,}); base rate scales by {ratio:.2f}"),
    )


def use_live(config: TEFConfig, override: bool | None = None) -> bool:
    """Resolve the input mode: an explicit --live/--frozen wins over config."""
    if override is not None:
        return override
    return config.telemetry_inputs == "live"


def live_config(
    db: TelemetryDB,
    base: TEFConfig | None = None,
) -> tuple[TEFConfig, list[LiveFit]]:
    """Return a copy of ``base`` with every live-derivable input derived from ``db``.

    The single entry point for live mode; each derivation keeps the bundled
    value when it cannot run and says why in the returned list.
    """
    cfg, fits = live_dispersion_config(db, base)

    conn = db.connect()
    try:
        fits.append(live_tempo_anchor(conn.cursor(), cfg))
    finally:
        conn.close()
    cfg.input_provenance = input_lines(fits)
    return cfg, fits


def live_dispersion_config(
    db: TelemetryDB,
    base: TEFConfig | None = None,
) -> tuple[TEFConfig, list[LiveFit]]:
    """Return a copy of ``base`` with dispersion shapes refitted on the telemetry DB.

    Shapes that cannot be refitted keep their bundled values; the returned
    LiveFit list says which, and why.
    """
    base = base or get_config()
    live_cfg = (base.dispersion or {}).get("live") or {}
    cfg = TEFConfig.from_dict(base.to_dict())
    fits: list[LiveFit] = []

    conn = db.connect()
    try:
        cursor = conn.cursor()
        for (kind, name), spec in LIVE_DISPERSION_SERIES.items():
            bundled = (cfg.dispersion.get(kind) or {}).get(name)
            fit = _fit_one(cursor, kind, name, spec, live_cfg, bundled)
            fits.append(fit)
            if fit.status != "fitted":
                log.info("Live dispersion %s/%s: fallback to bundled (%s)", kind, name, fit.reason)
                continue
            entry = dict(bundled or {})
            entry.update({
                "shape_r": fit.shape_r,
                "raw_shape_r": fit.raw_shape_r,
                "source": (
                    f"Live fit on the telemetry DB: {spec['label']}, "
                    f"{fit.window[0]} to {fit.window[1]} (linear trend), "
                    f"data collected through {fit.last_collected}"
                    + (f"; bundled default {fit.bundled_shape_r}" if fit.bundled_shape_r else "")
                    + f". Fitted {datetime.now().date().isoformat()}."
                ),
            })
            cfg.dispersion.setdefault(kind, {})[name] = entry
    finally:
        conn.close()

    return cfg, fits


def input_lines(fits: list[LiveFit]) -> list[str]:
    """Plain-language provenance of live inputs, one line per item (reports, UI)."""
    fitted = [f for f in fits if f.status == "fitted"]
    through = max((f.last_collected for f in fitted if f.last_collected), default=None)
    lines = ["Inputs: live, telemetry data" + (f" through {through}" if through else "")]
    names = {"base_rate": "base rate"}
    for f in fits:
        what = f"{f.name.replace('_', ' ').title()} {names.get(f.kind, 'dispersion')}"
        if f.status != "fitted":
            lines.append(f"{what}: bundled value kept ({f.reason})")
        elif f.kind in names:
            lines.append(f"{what}: {f.detail}")
        else:
            lines.append(f"{what} r {f.shape_r:g} (bundled {f.bundled_shape_r:g}), "
                         f"fitted on {f.window[0]} to {f.window[1]}")
    return lines
