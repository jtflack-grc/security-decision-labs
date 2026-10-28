"""Threshold-based change detection against a stored baseline.

After integration, compare current 7-day rolling averages against a
snapshot baseline. Emit signals when deviation exceeds the threshold.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tef_estimator.telemetry.db import TelemetryDB
from tef_estimator.telemetry.integrator import is_monitored, is_sparse

log = logging.getLogger(__name__)

DEFAULT_THRESHOLD = 0.20
DEFAULT_BASELINE_DIR = Path.home() / ".tef-estimator"

# Sparse count series (daily additions derived from event catalogs,
# integrator.is_sparse) sit near zero, where a percentage test misfires: any
# activity after a quiet baseline is +-100%. They are tested on absolute change.
DEFAULT_SPARSE_MIN_DELTA = 1.0
# With enough history, a sparse series signals when its current value is above
# its own SPARSE_QUANTILE of the trailing SPARSE_HISTORY_DAYS; the absolute
# delta rule is the fallback for a short history
SPARSE_QUANTILE = 0.95
SPARSE_HISTORY_DAYS = 90
SPARSE_MIN_HISTORY_DAYS = 60
# A metric whose last complete day lags the newest source's by more than this
# counts as missing (its collector has likely stopped)
DEFAULT_MAX_STALE_DAYS = 3


@dataclass(frozen=True)
class Signal:
    source_id: str
    metric_name: str
    baseline_value: float
    current_value: float
    pct_change: float
    direction: str
    abs_change: float = 0.0
    test: str = "pct"


@dataclass
class CompareResult:
    signals: list[Signal]
    metrics_checked: int
    threshold: float
    new_metrics: list[str] = field(default_factory=list)
    missing_metrics: list[str] = field(default_factory=list)

    @property
    def has_signals(self) -> bool:
        return len(self.signals) > 0


def _baseline_path(baseline_dir: Path) -> Path:
    return baseline_dir / "telemetry_baseline.json"


def _trailing_quantile(cursor: sqlite3.Cursor, source_id: str, metric_name: str,
                       as_of: str | None) -> float | None:
    """The metric's SPARSE_QUANTILE over its trailing history, or None if too short.

    History: the SPARSE_HISTORY_DAYS before the current week (the week itself
    would compare a wave with itself).
    """
    as_of_day = datetime.strptime(as_of, "%Y-%m-%d") if as_of else datetime.now(timezone.utc).replace(tzinfo=None)
    end = (as_of_day - timedelta(days=8)).strftime("%Y-%m-%d")
    start = (as_of_day - timedelta(days=8 + SPARSE_HISTORY_DAYS)).strftime("%Y-%m-%d")
    cursor.execute(
        """SELECT value FROM time_series
           WHERE source_id = ? AND metric_name = ? AND series_date BETWEEN ? AND ?
           ORDER BY value""",
        (source_id, metric_name, start, end),
    )
    values = [row[0] for row in cursor.fetchall()]
    if len(values) < SPARSE_MIN_HISTORY_DAYS:
        return None
    return values[int(SPARSE_QUANTILE * (len(values) - 1))]


def _latest_complete(
    cursor: sqlite3.Cursor,
    as_of: str | None,
    max_stale_days: int,
) -> tuple[dict[str, dict[str, float]], list[str]]:
    """Each 7-day average on its own last complete day.

    The current day (UTC, or ``as_of``) is left out: it is still being
    collected, and its partial counts pull the average down. Each metric uses
    its own latest day, so sources collected on different days are all
    compared; a metric whose latest day lags the newest one by more than
    ``max_stale_days`` is returned as stale instead.
    """
    as_of = as_of or datetime.now(timezone.utc).date().isoformat()
    cursor.execute(
        """SELECT t.source_id, t.metric_name, t.value, t.series_date
           FROM time_series t
           JOIN (SELECT source_id, metric_name, MAX(series_date) AS d
                 FROM time_series
                 WHERE metric_name LIKE '%_7d_avg' AND series_date < ?
                 GROUP BY source_id, metric_name) m
             ON t.source_id = m.source_id AND t.metric_name = m.metric_name
            AND t.series_date = m.d""",
        (as_of,),
    )
    rows = cursor.fetchall()
    if not rows:
        return {}, []
    newest = max(datetime.strptime(r[3], "%Y-%m-%d") for r in rows)
    cutoff = (newest - timedelta(days=max_stale_days)).strftime("%Y-%m-%d")

    current: dict[str, dict[str, float]] = {}
    stale: list[str] = []
    for source_id, metric_name, value, day in rows:
        if not is_monitored(source_id, metric_name):
            continue
        if day < cutoff:
            stale.append(f"{source_id}/{metric_name}")
            continue
        current.setdefault(source_id, {})[metric_name] = value
    return current, stale


def snapshot_baseline(
    db: TelemetryDB,
    *,
    baseline_dir: Path = DEFAULT_BASELINE_DIR,
    as_of: str | None = None,
    max_stale_days: int = DEFAULT_MAX_STALE_DAYS,
) -> dict[str, dict[str, float]]:
    """Save each 7-day rolling average on its last complete day as the baseline."""
    conn = db.connect()
    cursor = conn.cursor()
    baseline, stale = _latest_complete(cursor, as_of, max_stale_days)
    conn.close()
    if stale:
        log.warning("Not baselined (stale): %s", ", ".join(stale))

    baseline_dir.mkdir(parents=True, exist_ok=True)
    path = _baseline_path(baseline_dir)
    path.write_text(json.dumps(baseline, indent=2))

    total = sum(len(v) for v in baseline.values())
    log.info("Baseline saved: %d metrics across %d sources → %s",
             total, len(baseline), path)

    return baseline


def load_baseline(
    baseline_dir: Path = DEFAULT_BASELINE_DIR,
) -> dict[str, dict[str, float]] | None:
    path = _baseline_path(baseline_dir)
    if not path.exists():
        return None
    return json.loads(path.read_text())


def compare(
    db: TelemetryDB,
    *,
    threshold: float = DEFAULT_THRESHOLD,
    baseline_dir: Path = DEFAULT_BASELINE_DIR,
    sparse_min_delta: float = DEFAULT_SPARSE_MIN_DELTA,
    as_of: str | None = None,
    max_stale_days: int = DEFAULT_MAX_STALE_DAYS,
) -> CompareResult:
    """Compare current rolling averages against the stored baseline.

    Metrics present in current data but not in the baseline are appended to
    the baseline file and reported as new (never silently skipped); baseline
    metrics missing from current data are reported as missing, since a dead
    collector is itself a signal. Sparse additions series are tested on
    absolute change (``sparse_min_delta``) instead of percentage.
    """
    baseline = load_baseline(baseline_dir)
    if baseline is None:
        log.warning("No baseline found — run 'tef-estimator telemetry baseline' first")
        return CompareResult(signals=[], metrics_checked=0, threshold=threshold)

    # A baseline from an earlier version can hold metrics that are no longer
    # monitored (the ransomware.live group census): drop them, once, and say so
    retired = [f"{s}/{m}" for s, ms in baseline.items() for m in ms if not is_monitored(s, m)]
    if retired:
        baseline = {s: {m: v for m, v in ms.items() if is_monitored(s, m)}
                    for s, ms in baseline.items()}
        baseline = {s: ms for s, ms in baseline.items() if ms}
        log.info("%d metric(s) no longer monitored, removed from the baseline", len(retired))

    conn = db.connect()
    cursor = conn.cursor()
    current, _stale = _latest_complete(cursor, as_of, max_stale_days)
    trailing = {
        (s, m): _trailing_quantile(cursor, s, m, as_of)
        for s, ms in current.items() for m in ms if is_sparse(s, m)
    }
    conn.close()

    signals: list[Signal] = []
    metrics_checked = 0
    missing_metrics: list[str] = []

    for source_id, baseline_metrics in baseline.items():
        current_metrics = current.get(source_id, {})
        for metric_name, base_val in baseline_metrics.items():
            cur_val = current_metrics.get(metric_name)
            if cur_val is None:
                missing_metrics.append(f"{source_id}/{metric_name}")
                log.warning(
                    "Baseline metric %s/%s missing from current data — "
                    "its collector or integration may have stopped",
                    source_id, metric_name,
                )
                continue

            metrics_checked += 1
            delta = cur_val - base_val

            if is_sparse(source_id, metric_name):
                q = trailing.get((source_id, metric_name))
                if q is not None:
                    # High against the series' own recent history, not a snapshot
                    if cur_val <= q:
                        continue
                    base_val, delta = q, cur_val - q
                    pct = delta / q if q >= 1e-9 else 1.0
                    test = f"above_trailing_p{int(SPARSE_QUANTILE * 100)}"
                else:
                    if abs(delta) < sparse_min_delta:
                        continue
                    pct = delta / abs(base_val) if abs(base_val) >= 1e-9 else 1.0
                    test = "abs_delta"
            else:
                if abs(base_val) < 1e-9:
                    if abs(cur_val) > 1e-9:
                        pct = 1.0
                    else:
                        continue
                else:
                    pct = delta / abs(base_val)
                if abs(pct) < threshold:
                    continue
                test = "pct"

            signals.append(Signal(
                source_id=source_id,
                metric_name=metric_name,
                baseline_value=base_val,
                current_value=cur_val,
                pct_change=pct,
                direction="up" if delta > 0 else "down",
                abs_change=delta,
                test=test,
            ))

    new_metrics: list[str] = []
    for source_id, current_metrics in current.items():
        base_metrics = baseline.setdefault(source_id, {})
        for metric_name, cur_val in current_metrics.items():
            if metric_name not in base_metrics:
                base_metrics[metric_name] = cur_val
                new_metrics.append(f"{source_id}/{metric_name}")

    if new_metrics or retired:
        _baseline_path(baseline_dir).write_text(json.dumps(baseline, indent=2))
    if new_metrics:
        log.info(
            "%d new metric(s) baselined, not yet comparable: %s",
            len(new_metrics), ", ".join(new_metrics),
        )

    if signals:
        log.warning("%d signal(s) detected (threshold=%.0f%%)", len(signals), threshold * 100)
        for s in signals:
            log.warning(
                "  %s/%s: %.2f → %.2f (%+.1f%%)",
                s.source_id, s.metric_name,
                s.baseline_value, s.current_value, s.pct_change * 100,
            )
    else:
        log.info("No signals detected (%d metrics checked)", metrics_checked)

    return CompareResult(
        signals=signals,
        metrics_checked=metrics_checked,
        threshold=threshold,
        new_metrics=new_metrics,
        missing_metrics=missing_metrics,
    )
