"""
Data refresh guidance.

Reference data ships with the package. To update it, replace the JSON
files under data/reference/ with newer extractions.
"""

from __future__ import annotations


def run_snapshot_refresh() -> None:
    """Print instructions for updating reference data."""
    print("Reference data is bundled with the package.")
    print()
    print("To update, replace the extracted.json files in:")
    print("  src/tef_estimator/data/reference/<source>/extracted.json")
    print()
    print("Sources: iris, at_bay, beazley, common")
    print()
    print("Then rebuild the peer grid:")
    print("  tef-estimator data peer-grid --rebuild")
