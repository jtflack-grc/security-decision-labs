"""Cadence-based scheduling for telemetry collection and integration.

Replaces coordinator.py subprocess dispatch with direct function calls.
Tracks last-run timestamps in a JSON state file alongside the database.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tef_estimator.telemetry.collectors import get_all_collectors
from tef_estimator.telemetry.db import TelemetryDB
from tef_estimator.telemetry.integrator import run_integration

log = logging.getLogger(__name__)

DEFAULT_STATE_DIR = Path.home() / ".tef-estimator"


def _state_path(state_dir: Path) -> Path:
    return state_dir / "scheduler_state.json"


def load_state(state_dir: Path = DEFAULT_STATE_DIR) -> dict[str, Any]:
    path = _state_path(state_dir)
    if path.exists():
        return json.loads(path.read_text())
    return {}


def save_state(state: dict[str, Any], state_dir: Path = DEFAULT_STATE_DIR) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    _state_path(state_dir).write_text(json.dumps(state, indent=2))


def is_due(
    source_id: str,
    cadence_days: int,
    state: dict[str, Any],
    *,
    force: bool = False,
) -> tuple[bool, str]:
    if force:
        return True, "forced"

    last_run = state.get(source_id, {}).get("last_success")
    if not last_run:
        return True, "never run"

    try:
        last_dt = datetime.fromisoformat(last_run)
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - last_dt).total_seconds() / 86400

        if age_days >= cadence_days:
            return True, f"last run {age_days:.1f}d ago (cadence: {cadence_days}d)"
        return False, f"last run {age_days:.1f}d ago (cadence: {cadence_days}d)"
    except (ValueError, TypeError):
        return True, "invalid last_run timestamp"


def run_due_collections(
    db: TelemetryDB,
    *,
    force: bool = False,
    source_filter: str | None = None,
    state_dir: Path = DEFAULT_STATE_DIR,
) -> list[dict[str, Any]]:
    """Run collectors that are due according to cadence, then integrate."""
    state = load_state(state_dir)
    collectors = get_all_collectors()
    results = []

    for collector in collectors:
        sid = collector.SOURCE_ID
        if source_filter and sid != source_filter:
            continue

        due, reason = is_due(sid, collector.CADENCE_DAYS, state, force=force)
        if not due:
            log.info("Skipping %s: %s", sid, reason)
            results.append({"source": sid, "status": "skipped", "reason": reason})
            continue

        log.info("Running %s: %s", sid, reason)
        try:
            summary = collector.collect(db, force=force)
            results.append(summary)

            if summary.get("status") == "completed":
                state[sid] = {
                    "last_success": datetime.now(timezone.utc).isoformat(),
                    "last_status": "success",
                }
            else:
                state[sid] = {
                    "last_success": state.get(sid, {}).get("last_success"),
                    "last_attempt": datetime.now(timezone.utc).isoformat(),
                    "last_status": "failed",
                }
        except Exception as e:
            log.error("Collector %s failed: %s", sid, e)
            results.append({
                "source": sid,
                "status": "failed",
                "error": str(e),
            })
            state[sid] = {
                "last_success": state.get(sid, {}).get("last_success"),
                "last_attempt": datetime.now(timezone.utc).isoformat(),
                "last_status": "failed",
            }

        save_state(state, state_dir)

    any_collected = any(
        r.get("status") == "completed" and r.get("records_inserted", 0) > 0
        for r in results
    )
    if any_collected:
        log.info("New data collected — running integration")
        integration = run_integration(db, source_filter=source_filter)
        results.append({"source": "integrator", **integration})
        state["integrator"] = {
            "last_success": datetime.now(timezone.utc).isoformat(),
            "last_status": "success",
        }
        save_state(state, state_dir)
    else:
        log.info("No new data — skipping integration")

    return results
