"""
Data staleness validation.

Checks that bundled reference data and scenario files are present
and within acceptable freshness thresholds.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path

from tef_estimator.data.loader import (
    REFERENCE_DIR,
    SCENARIOS_DIR,
    PEER_GRID_DIR,
)


REFERENCE_SOURCES = [
    "iris", "at_bay", "beazley", "common",
]

DEFAULT_CADENCE_MONTHS = 12
DAYS_PER_MONTH = 30.44


def _metadata(path: Path) -> dict:
    try:
        with open(path) as f:
            return json.load(f).get("_metadata", {})
    except (json.JSONDecodeError, OSError):
        return {}


def _extract_date(path: Path) -> date | None:
    """Read extracted_date from a JSON file's _metadata."""
    raw = _metadata(path).get("extracted_date")
    try:
        return date.fromisoformat(raw) if raw else None
    except ValueError:
        return None


def due_after_months(cadence_months: int) -> int:
    """A source is due for a check after its own cycle plus a grace period."""
    return cadence_months + max(2, cadence_months // 4)


def bundled_editions() -> list[str]:
    """Editions of the bundled reference sources, e.g. ["IRIS 2025", ...]."""
    editions = []
    for source in REFERENCE_SOURCES:
        edition = _metadata(REFERENCE_DIR / source / "extracted.json").get("edition")
        if edition:
            editions.append(edition)
    return editions


def check_freshness(today: date | None = None) -> list[str]:
    """Data files that are past their own update cycle.

    Each file's _metadata gives cadence_months (annual reports 12, quarterly
    3; scenario files are reviewed per release, 12). A file is flagged once
    its extraction is older than the cycle plus a grace period, meaning a
    newer edition may exist. Empty list: nothing is due.
    """
    today = today or date.today()
    files = [(source, REFERENCE_DIR / source / "extracted.json") for source in REFERENCE_SOURCES]
    files += [(f"scenario {p.stem}", p) for p in sorted(SCENARIOS_DIR.glob("*.json"))]

    warnings: list[str] = []
    for name, path in files:
        if not path.exists():
            continue
        meta = _metadata(path)
        label = meta.get("edition") or name
        extracted = _extract_date(path)
        if extracted is None:
            warnings.append(f"{label}: no extracted_date, age unknown")
            continue
        cadence = meta.get("cadence_months", DEFAULT_CADENCE_MONTHS)
        due = due_after_months(cadence)
        months = (today - extracted).days / DAYS_PER_MONTH
        if months > due:
            warnings.append(
                f"{label}: extracted {extracted.isoformat()}, {months:.0f} months ago "
                f"(updates every {cadence} months); check for a newer edition"
            )
    return warnings


def run_check() -> dict[str, str]:
    """Validate data sources and report status."""
    results = {}
    print("Data validation report:")
    print("=" * 60)

    print(f"  Reference data: {REFERENCE_DIR}")
    print()

    for source in REFERENCE_SOURCES:
        path = REFERENCE_DIR / source / "extracted.json"
        if not path.exists():
            status = "missing"
            age_str = ""
        else:
            status = "present"
            extracted = _extract_date(path)
            if extracted:
                age = (date.today() - extracted).days
                age_str = f" ({age}d old, extracted {extracted.isoformat()})"
            else:
                age_str = " (no date)"
        results[f"ref_{source}"] = status
        icon = "+" if status == "present" else "X"
        print(f"  [{icon}] {source.replace('_', ' ').title()} reference: {status}{age_str}")

    print()

    for scenario in sorted(p.stem for p in SCENARIOS_DIR.glob("*.json")):
        path = SCENARIOS_DIR / f"{scenario}.json"
        if path.exists():
            results[f"scenario_{scenario}"] = "present"
            extracted = _extract_date(path)
            age_str = ""
            if extracted:
                age = (date.today() - extracted).days
                age_str = f" ({age}d old)"
            print(f"  [+] Scenario {scenario}: present{age_str}")
        else:
            results[f"scenario_{scenario}"] = "missing"
            print(f"  [X] Scenario {scenario}: missing")

    print()

    grid_path = PEER_GRID_DIR / "ransomware.json"
    if grid_path.exists():
        results["peer_grid"] = "present"
        print("  [+] Peer grid: present")
    else:
        results["peer_grid"] = "missing"
        print("  [X] Peer grid: missing (run: tef-estimator data peer-grid --rebuild)")

    print()

    freshness_warnings = check_freshness()
    if freshness_warnings:
        print("FRESHNESS WARNINGS:")
        for w in freshness_warnings:
            print(f"  ! {w}")
        print()

    pkg_data = Path(__file__).resolve().parent.parent / "data"
    log_path = pkg_data / "refresh_log.json"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = {
        "timestamp": datetime.now().isoformat(),
        "results": results,
    }
    log_path.write_text(json.dumps(log, indent=2))
    print(f"Validation log saved to {log_path}")

    return results
