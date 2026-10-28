"""
Load empirical reference data from bundled JSON files.

All data ships with the package under data/reference/, data/scenarios/,
and data/peer_grid/.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_PKG_DATA = Path(__file__).resolve().parent

REFERENCE_DIR = _PKG_DATA / "reference"
SCENARIOS_DIR = _PKG_DATA / "scenarios"
PEER_GRID_DIR = _PKG_DATA / "peer_grid"


def load_reference(source: str) -> dict[str, Any]:
    """Load extracted.json for a given reference source."""
    path = REFERENCE_DIR / source / "extracted.json"
    if not path.exists():
        available = [
            d.name for d in sorted(REFERENCE_DIR.iterdir()) if d.is_dir()
        ]
        raise FileNotFoundError(
            f"Missing data for source '{source}'.\n"
            f"Checked: {path}\n"
            f"Available: {', '.join(available)}"
        )
    with open(path) as f:
        return json.load(f)


def load_scenario(name: str) -> dict[str, Any]:
    """Load a scenario JSON file from data/scenarios/."""
    path = SCENARIOS_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"Missing scenario file: {path}\n"
            f"Available: {', '.join(f.stem for f in sorted(SCENARIOS_DIR.glob('*.json')))}"
        )
    with open(path) as f:
        return json.load(f)


def load_all_references() -> dict[str, dict[str, Any]]:
    """Load all reference data files."""
    sources: dict[str, dict[str, Any]] = {}
    for source_dir in sorted(REFERENCE_DIR.iterdir()):
        if source_dir.is_dir():
            extracted = source_dir / "extracted.json"
            if extracted.exists():
                with open(extracted) as f:
                    sources[source_dir.name] = json.load(f)
    return sources


def pert_from_list(values: list[float]) -> tuple[float, float, float]:
    """Convert a [low, mode, high] JSON list to a 3-tuple."""
    if len(values) != 3:
        raise ValueError(f"PERT range requires exactly 3 values, got {len(values)}: {values}")
    return (values[0], values[1], values[2])


def normalized_proportions(raw: dict[str, Any]) -> dict[str, tuple[float, float, float]]:
    """Vector proportions scaled so their modes sum to 1.

    The four vectors carry the scenario's whole base rate. Source
    triangulations can leave a remainder (other or unattributed initial
    access, e.g. modes summing to 0.95); it is allocated to the vectors in
    proportion, by scaling low, mode and high of each vector by 1 / (sum of
    modes). The extracted values in the data files stay as published.
    """
    parsed = {k: pert_from_list(v) for k, v in raw.items() if not k.startswith("_")}
    total = sum(mode for _, mode, _ in parsed.values())
    if total <= 0:
        raise ValueError("vector proportion modes must sum to a positive number")
    return {k: (lo / total, mode / total, hi / total) for k, (lo, mode, hi) in parsed.items()}
