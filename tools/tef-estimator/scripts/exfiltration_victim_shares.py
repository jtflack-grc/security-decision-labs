"""
Exfiltration victim shares by revenue tier, from VCDB US data-disclosure incidents.

The exfiltration base rate divides US events (FBI IC3 data-breach complaints) among
revenue tiers by each tier's share of victims, then by US firms in the tier (Census
SUSB 2022). IC3 gives no victim sizes; this script takes them from VCDB: US victims,
external actor, confirmed data disclosure, ransomware excluded. VCDB employee classes
are split log-uniformly at the tier boundaries (40, 300, 2,500 employees, the SUSB
bands whose average receipts per firm cross $10M, $100M and $1B).

Usage:
    python scripts/exfiltration_victim_shares.py --vcdb DIR --susb PATH/us_state_naics_detailedsizes_2022.xlsx
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
import math
from pathlib import Path

from dampening_k_check import ET, XLSX_NS, susb_band_low, zipfile

TIERS = ["under_10m", "10m_100m", "100m_1b", "1b_plus"]
BOUNDS = [40, 300, 2500]  # employees: first SUSB band of the next revenue tier
VCDB_CLASSES = {  # employee_count -> (low, high) employees
    "1 to 10": (1, 10), "11 to 100": (11, 100), "101 to 1000": (101, 1000),
    "1001 to 10000": (1001, 10000), "10001 to 25000": (10001, 25000),
    "25001 to 50000": (25001, 50000), "50001 to 100000": (50001, 100000),
    "Over 100000": (100001, 1000000),
}
WINDOWS = {"2010–2024": (2010, 2024), "2013–2022": (2013, 2022)}


def split(lo: int, hi: int) -> list[float]:
    """Share of a class [lo, hi] in each tier, log-uniform within the class."""
    edges = [1] + BOUNDS + [10 ** 9]
    span = math.log(hi + 1) - math.log(lo)
    out = []
    for a, b in zip(edges, edges[1:]):
        x, y = max(lo, a), min(hi + 1, b)
        out.append((math.log(y) - math.log(x)) / span if y > x else 0.0)
    return out


def tier_of_band(band: str) -> str | None:
    lo = susb_band_low(band)
    return None if lo is None else TIERS[sum(lo >= b for b in BOUNDS)]


def susb_firms_by_tier(path: Path) -> dict[str, int]:
    z = zipfile.ZipFile(path)
    strings = ["".join(t.text or "" for t in si.iter(XLSX_NS + "t"))
               for si in ET.fromstring(z.read("xl/sharedStrings.xml")).iter(XLSX_NS + "si")]
    sheet = sorted(n for n in z.namelist() if n.startswith("xl/worksheets/sheet"))[0]
    firms, seen = collections.Counter(), set()
    for _, el in ET.iterparse(z.open(sheet)):
        if el.tag != XLSX_NS + "row":
            continue
        v = []
        for c in el.iter(XLSX_NS + "c"):
            x = c.find(XLSX_NS + "v")
            v.append((strings[int(x.text)] if c.get("t") == "s" else x.text) if x is not None else "")
        el.clear()
        # US rows (state 00), all industries ("--"), each size band once
        if len(v) > 5 and v[0] == "00" and v[2] == "--" and v[4] not in seen and ":" in (v[4] or ""):
            seen.add(v[4])
            tier = tier_of_band(v[4])
            if tier:
                firms[tier] += int(v[5])
    return dict(firms)


def is_exfiltration(d: dict) -> bool:
    disclosure = d.get("attribute", {}).get("confidentiality", {}).get("data_disclosure")
    malware = [x.lower() for x in d.get("action", {}).get("malware", {}).get("variety", [])]
    return (disclosure == "Yes" and "external" in d.get("actor", {})
            and not any("ransomware" in x for x in malware))


def victim_shares(vcdb_dir: Path, years: tuple[int, int]) -> tuple[list[float], int]:
    counts = [0.0] * len(TIERS)
    n = 0
    for f in glob.glob(str(vcdb_dir / "**" / "*.json"), recursive=True):
        try:
            d = json.loads(Path(f).read_text())
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(d, dict):
            continue
        vic = d.get("victim", {})
        if isinstance(vic, list):  # a few incidents list several victims: take the first
            vic = vic[0] if vic else {}
        year = d.get("timeline", {}).get("incident", {}).get("year")
        size = vic.get("employee_count")
        cls = VCDB_CLASSES.get(size) if isinstance(size, str) else None
        if ("US" not in (vic.get("country") or []) or not cls or not year
                or not years[0] <= year <= years[1] or not is_exfiltration(d)):
            continue
        n += 1
        for i, s in enumerate(split(*cls)):
            counts[i] += s
    return [c / n for c in counts], n


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vcdb", type=Path, required=True)
    ap.add_argument("--susb", type=Path, required=True)
    args = ap.parse_args()

    firms = susb_firms_by_tier(args.susb)
    total = sum(firms.values())
    print(f"US firms (Census SUSB 2022): {total:,}\n")
    print("| Window | Incidents | " + " | ".join(TIERS) + " |")
    print("|---|---|" + "---|" * len(TIERS))
    print("| US firms | | " + " | ".join(f"{firms[t]:,}" for t in TIERS) + " |")
    print("| share of firms | | " + " | ".join(f"{firms[t] / total:.4f}" for t in TIERS) + " |")
    for name, years in WINDOWS.items():
        shares, n = victim_shares(args.vcdb, years)
        print(f"| victim share {name} | {n:,} | " + " | ".join(f"{s:.3f}" for s in shares) + " |")
        print(f"| relative rate {name} | | "
              + " | ".join(f"{s / (firms[t] / total):.2f}" for s, t in zip(shares, TIERS)) + " |")


if __name__ == "__main__":
    main()
