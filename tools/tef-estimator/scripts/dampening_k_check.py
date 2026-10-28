"""
How much do sector and size overlap?  Evidence for the within-vector dampening default.

The tool multiplies a sector multiplier m_s and a size multiplier m_z, then keeps
a share k of the combined deviation from 1:  composite = 1 + (m_s * m_z - 1) * k.
k = 1 treats the multipliers as independent; k < 1 assumes they partly measure the
same thing (large firms cluster in some sectors). This script runs the three checks
documented in docs/dampening-k.md:

  A. StatCan 22-10-0076: share of Canadian enterprises hit, by industry x size
     together. Fit k by least squares on r(s,z) = 1 + (m_s * m_z - 1) * k.
  B. VCDB US incidents by industry x size, divided by Census SUSB 2022 firms in
     the same cells. Same fit.
  C. Ransomware profiles: implied annual loss (TEF median x susceptibility mode)
     inside IRIS's per-tier bracket, at k = 0.70 and k = 1.0.

Usage:
    python scripts/dampening_k_check.py --statcan PATH/22100076.csv \
        --vcdb DIR --susb PATH/us_state_naics_detailedsizes_2022.xlsx

Each check runs only when its inputs are given (C needs none). Sources:
  StatCan table 22-10-0076-01 (CSV download), VCDB JSON (github.com/vz-risk/VCDB),
  Census SUSB 2022 "U.S. & states, NAICS, detailed employment sizes" (xlsx).
"""

from __future__ import annotations

import argparse
import collections
import csv
import glob
import itertools
import json
import re
import statistics
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from pathlib import Path

ASSERTED_K = 0.70


@dataclass
class Fit:
    k: float
    cells: int
    r2: float
    err_asserted: float    # squared error at k = 0.70, relative to the best k
    err_independent: float  # same at k = 1.0


def fit_k(xs: list[float], ys: list[float], ws: list[float] | None = None) -> Fit:
    """Least squares through the origin: y = k x, x = m_s m_z - 1, y = r - 1."""
    ws = ws or [1.0] * len(xs)
    k = sum(w * x * y for x, y, w in zip(xs, ys, ws)) / sum(w * x * x for x, w in zip(xs, ws))

    def sse(kk):
        return sum(w * (y - kk * x) ** 2 for x, y, w in zip(xs, ys, ws))

    r2 = 1 - sse(k) / sum(w * y * y for y, w in zip(ys, ws))
    return Fit(k, len(xs), r2, sse(ASSERTED_K) / sse(k), sse(1.0) / sse(k))


# --- A. StatCan 22-10-0076 ---------------------------------------------------

SC_IND = "North American Industry Classification System (NAICS)"
SC_SIZE = "Size of enterprise"
SC_INC = "Cyber security incidents"
SC_SIZES = ["Small size enterprises", "Medium size enterprises", "Large size enterprises"]
SC_ALL_IND, SC_ALL_SIZE = "Private sector", "Total, all enterprises"
SC_SERIES = {
    "any incident": "Business was not impacted by any cyber security incidents",
    "theft of money or ransom": "Incidents to steal money or demand ransom payment",
    "theft of personal or financial information": "Incidents to steal personal or financial information",
}
SC_YEARS = ("2017", "2019", "2021", "2023")
SC_SUPPRESSED = ("D", "E", "F", "x", "..")  # quality D-F and suppressed cells dropped


def statcan_fit(rows: list[dict], year: str, incident: str) -> Fit | None:
    cell = {}
    for r in rows:
        if r["REF_DATE"] != year or r[SC_INC] != incident or not r["VALUE"] or r["STATUS"] in SC_SUPPRESSED:
            continue
        v = float(r["VALUE"])
        cell[(r[SC_IND], r[SC_SIZE])] = 100 - v if incident.startswith("Business was not") else v
    p = cell.get((SC_ALL_IND, SC_ALL_SIZE))
    if not p:
        return None
    xs, ys = [], []
    for ind in {i for (i, _) in cell if re.search(r"\[\d{2}(-\d{2})?\]$", i)}:  # 2-digit NAICS
        for size in SC_SIZES:
            ps, pz, psz = cell.get((ind, SC_ALL_SIZE)), cell.get((SC_ALL_IND, size)), cell.get((ind, size))
            if None in (ps, pz, psz):
                continue
            xs.append(ps / p * pz / p - 1)
            ys.append(psz / p - 1)
    return fit_k(xs, ys) if len(xs) >= 10 else None


def check_statcan(path: Path) -> None:
    rows = list(csv.DictReader(path.open(encoding="utf-8-sig")))
    print("## A. StatCan 22-10-0076: share of enterprises impacted, industry x size\n")
    print("| Incident type | Year | k | Cells | R² | Error at k=0.70 | Error at k=1.0 |")
    print("|---|---|---|---|---|---|---|")
    for label, incident in SC_SERIES.items():
        for year in SC_YEARS:
            f = statcan_fit(rows, year, incident)
            if f:
                print(f"| {label} | {year} | {f.k:.2f} | {f.cells} | {f.r2:.2f} | "
                      f"×{f.err_asserted:.2f} | ×{f.err_independent:.2f} |")
    print("\nError columns: squared error relative to the best-fitting k (×1.00 = as good as the best).\n")


# --- B. VCDB US incidents / Census SUSB firms ---------------------------------

VCDB_SIZE = {
    "1 to 10": "1-10", "11 to 100": "11-100", "101 to 1000": "101-1000",
    "1001 to 10000": "1001+", "10001 to 25000": "1001+", "25001 to 50000": "1001+",
    "50001 to 100000": "1001+", "Over 100000": "1001+",
}
SIZE_CLASSES = ["1-10", "11-100", "101-1000", "1001+"]
VCDB_YEARS = (2010, 2024)
MIN_INCIDENTS = 5
WORKING_RANGE = (0.2, 5.0)  # composite range the tool can produce (max_composite 5)
XLSX_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def naics2(code: str) -> str:
    c = code[:2]
    return {"31": "31-33", "32": "31-33", "33": "31-33", "44": "44-45", "45": "44-45",
            "48": "48-49", "49": "48-49"}.get(c, c)


SUSB_SUBTOTALS = ("01", "06", "19")  # Total, <20, <500: sums of other bands


def susb_band_low(band: str) -> int | None:
    """Lowest employee count of a SUSB size band ('03: 5-9 employees' -> 5, '02: <5' -> 0);
    None for the subtotal bands."""
    code, label = (s.strip() for s in band.split(":", 1))
    if code in SUSB_SUBTOTALS:
        return None
    return 0 if label.startswith("<") else int(re.match(r"[\d,]+", label).group(0).replace(",", ""))


def susb_size_class(band: str) -> str | None:
    """'03: 5-9 employees' -> '1-10' etc.; subtotal bands return None."""
    lo = susb_band_low(band)
    if lo is None:
        return None
    return "1-10" if lo < 10 else "11-100" if lo < 100 else "101-1000" if lo < 1000 else "1001+"


def susb_firms(path: Path) -> collections.Counter:
    """US firms by 2-digit NAICS x size class, from the SUSB detailed-sizes xlsx."""
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
        # US rows (state 00), 2-digit NAICS, size bands other than the total
        if len(v) > 5 and v[0] == "00" and re.fullmatch(r"\d\d(-\d\d)?", v[2] or ""):
            if (v[2], v[4]) in seen:
                continue
            seen.add((v[2], v[4]))
            cls = susb_size_class(v[4])
            if cls:
                firms[(v[2], cls)] += int(v[5])
    return firms


def vcdb_incidents(vcdb_dir: Path) -> collections.Counter:
    """US VCDB incidents by 2-digit NAICS x size class."""
    inc = collections.Counter()
    for f in glob.glob(str(vcdb_dir / "**" / "*.json"), recursive=True):
        try:
            d = json.loads(Path(f).read_text())
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(d, dict):
            continue
        vic = d.get("victim", {})
        year = d.get("timeline", {}).get("incident", {}).get("year")
        if "US" not in (vic.get("country") or []) or not year or not VCDB_YEARS[0] <= year <= VCDB_YEARS[1]:
            continue
        cls, ind = VCDB_SIZE.get(vic.get("employee_count")), vic.get("industry") or ""
        if cls and re.match(r"\d\d", ind):
            inc[(naics2(ind), cls)] += 1
    return inc


def check_vcdb(vcdb_dir: Path, susb: Path) -> None:
    firms, inc = susb_firms(susb), vcdb_incidents(vcdb_dir)
    cells = [c for c in inc if firms.get(c)]
    p = sum(inc[c] for c in cells) / sum(firms[c] for c in cells)
    ind_n, ind_f, sz_n, sz_f = (collections.Counter() for _ in range(4))
    for (i, s) in cells:
        ind_n[i] += inc[(i, s)]
        ind_f[i] += firms[(i, s)]
        sz_n[s] += inc[(i, s)]
        sz_f[s] += firms[(i, s)]

    print("## B. VCDB US incidents ÷ Census SUSB 2022 firms, industry x size\n")
    print(f"{sum(inc[c] for c in cells):,} US incidents {VCDB_YEARS[0]}–{VCDB_YEARS[1]} matched to "
          f"{sum(firms[c] for c in cells):,} firms; {len(ind_n)} industries, {len(cells)} cells.\n")
    print("| Size (employees) | Incidents | Rate relative to average |")
    print("|---|---|---|")
    for s in SIZE_CLASSES:
        print(f"| {s} | {sz_n[s]:,} | {sz_n[s] / sz_f[s] / p:.2f} |")

    print(f"\n| Cells | Weighting | k | Cells used (≥ {MIN_INCIDENTS} incidents) | Error at k=0.70 | Error at k=1.0 |")
    print("|---|---|---|---|---|---|")
    for (lo, hi), label in [(WORKING_RANGE, f"composite {WORKING_RANGE[0]}–{WORKING_RANGE[1]:g}"),
                            ((0, float("inf")), "all")]:
        for weighted in (False, True):
            xs, ys, ws = [], [], []
            for (i, s) in cells:
                if inc[(i, s)] < MIN_INCIDENTS:
                    continue
                raw = (ind_n[i] / ind_f[i] / p) * (sz_n[s] / sz_f[s] / p)
                if lo <= raw <= hi:
                    xs.append(raw - 1)
                    ys.append(inc[(i, s)] / firms[(i, s)] / p - 1)
                    ws.append(inc[(i, s)] if weighted else 1)
            f = fit_k(xs, ys, ws)
            print(f"| {label} | {'by incident count' if weighted else 'none'} | {f.k:.2f} | {f.cells} | "
                  f"×{f.err_asserted:.2f} | ×{f.err_independent:.2f} |")
    print()


# --- C. IRIS bracket check ----------------------------------------------------

# IRIS Ransomware Spotlight, upper bound per revenue tier (events ÷ organizations
# with any past incident). Lower bounds come from the scenario's floor_lef.
IRIS_UPPER = {"10m_100m": 0.1132, "100m_1b": 0.0983, "1b_10b": 0.0948,
              "10b_100b": 0.0970, "over_100b": 0.1289}


def check_iris() -> None:
    from tef_estimator.config import TEFConfig
    from tef_estimator.data.common import Geography, RemoteAccessType, RevenueBand, Sector
    from tef_estimator.data.scenarios.ransomware import RansomwareScenario
    from tef_estimator.engine import TEFEngine
    from tef_estimator.profile import OrganizationProfile

    scenario = RansomwareScenario()
    s_mode = scenario.base_rate_triangulation["susceptibility_prior"].mode
    remote = [[RemoteAccessType.NONE], [RemoteAccessType.FORTINET], [RemoteAccessType.RDP],
              [RemoteAccessType.FORTINET, RemoteAccessType.RDP]]
    bands = [b for b in RevenueBand if b.value in IRIS_UPPER]
    profiles = list(itertools.product(Sector, Geography, remote))

    print("## C. Ransomware: implied annual loss inside IRIS's bracket\n")
    print(f"Per tier, {len(profiles)} profiles (every sector × geography × 4 remote-access setups); "
          f"implied loss = TEF median × ransomware susceptibility mode {s_mode}. "
          f"Bracket = IRIS lower bound (floor_lef) to IRIS upper bound.\n")
    print("| Tier | k | Inside | Below | Above | Median TEF per year |")
    print("|---|---|---|---|---|---|")
    summary = collections.defaultdict(lambda: [0, 0])  # k -> [inside, total] for $10M–$10B
    for band in bands:
        lo, hi = scenario.floor_lef[band.value], IRIS_UPPER[band.value]
        for k in (ASSERTED_K, 1.0):
            engine = TEFEngine(scenario=scenario, config=TEFConfig.from_dict({"dampening": {"factor_k": k}}))
            tefs = [engine.estimate(OrganizationProfile(sector=s, revenue_band=band, geography=g, remote_access=r))
                    .total_positioned_median for s, g, r in profiles]
            below = sum(t * s_mode < lo for t in tefs)
            above = sum(t * s_mode > hi for t in tefs)
            inside, n = len(tefs) - below - above, len(tefs)
            if band.value in ("10m_100m", "100m_1b", "1b_10b"):
                summary[k][0] += inside
                summary[k][1] += n
            print(f"| {band.value} | {k:.2f} | {inside / n:.0%} | {below / n:.0%} | {above / n:.0%} | "
                  f"{statistics.median(tefs):.3f} |")
    print()
    for k, (inside, n) in summary.items():
        print(f"$10M–$10B, k = {k:.2f}: {inside / n:.0%} inside ({inside}/{n})")
    print()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--statcan", type=Path, help="StatCan 22-10-0076 CSV (22100076.csv)")
    ap.add_argument("--vcdb", type=Path, help="VCDB checkout or its data/json directory")
    ap.add_argument("--susb", type=Path, help="Census SUSB 2022 detailed employment sizes xlsx")
    args = ap.parse_args()

    if args.statcan:
        check_statcan(args.statcan)
    if args.vcdb and args.susb:
        check_vcdb(args.vcdb, args.susb)
    check_iris()


if __name__ == "__main__":
    main()
