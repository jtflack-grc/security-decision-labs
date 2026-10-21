"""
How long does a rate shock last?  Evidence for the dispersion timescale default.

The dispersion shape r is fitted on monthly counts. Whether one month's shock
is independent of the next decides how r carries over to a year:
independent months -> annual shape 12 r; a shock that persists -> annual shape r.
This script runs the two checks documented in docs/dispersion-timescale.md:

  A. Autocorrelation of the detrended monthly residuals (lags 1-3, Ljung-Box).
  B. Aggregation test: fit the shape on monthly and on quarterly counts.
     Independent monthly shocks give r_quarter / r_month ~ 3; a shock that
     persists through the quarter gives ~ 1.

Usage:
    python scripts/dispersion_timescale_check.py --kev PATH/kev.json [--ransomware-dir DIR]

kev.json is the CISA KEV catalogue (known_exploited_vulnerabilities.json).
--ransomware-dir holds ransomware.live monthly caches rl_YYYY-MM.json (as written
by the companion notebook). Needs numpy, pandas, scipy, statsmodels
(not package dependencies: pip install pandas statsmodels).
"""

from __future__ import annotations

import argparse
import json
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import statsmodels.api as sm
from scipy import stats

warnings.filterwarnings("ignore")

LAGS = (1, 2, 3)
WINDOWS = {
    "Jun 2025-May 2026 (blog window)": ("2025-06", "2026-05"),
    "Jan 2024-May 2026": ("2024-01", "2026-05"),
    "Jan 2023-May 2026 (excludes 2022 back-fill)": ("2023-01", "2026-05"),
    "Jan 2022-May 2026": ("2022-01", "2026-05"),
}


def design(n: int, trend: str) -> np.ndarray:
    t = np.arange(n) / max(n - 1, 1)
    cols = [t] if trend == "linear" else [t, t ** 2]
    return sm.add_constant(np.column_stack(cols))


def nb_fit(y: np.ndarray, trend: str):
    """NB2 regression with a time trend. Returns (fitted means, alpha)."""
    X = design(len(y), trend)
    res = sm.NegativeBinomial(y, X, loglike_method="nb2").fit(disp=0, maxiter=500)
    beta, alpha = res.params[:-1], max(res.params[-1], 1e-10)
    return np.exp(X @ beta), alpha


def residual_acf(y: np.ndarray, trend: str) -> dict:
    mu, alpha = nb_fit(y, trend)
    res = (y - mu) / np.sqrt(mu + alpha * mu ** 2)          # Pearson residuals under NB2
    res = res - res.mean()
    n = len(res)
    acf = [float(np.sum(res[k:] * res[:-k]) / np.sum(res ** 2)) for k in LAGS]
    q = n * (n + 2) * sum(a ** 2 / (n - k) for a, k in zip(acf, LAGS))
    return {"n": n, "r_month": 1 / alpha, "acf": acf, "band": 1.96 / np.sqrt(n),
            "ljung_box_p": float(stats.chi2.sf(q, len(LAGS)))}


def aggregation_ratio(monthly: pd.Series, trend: str) -> dict:
    """Shape on monthly vs quarterly counts (full quarters only)."""
    q = monthly.groupby(monthly.index.asfreq("Q")).agg(["sum", "size"])
    q = q[q["size"] == 3]["sum"]
    _, a_m = nb_fit(monthly.values.astype(float), trend)
    _, a_q = nb_fit(q.values.astype(float), trend)
    r_m, r_q = 1 / a_m, 1 / a_q
    return {"quarters": len(q), "r_month": r_m, "r_quarter": r_q, "ratio": r_q / r_m}


def monthly_counts(dates: pd.Series, start: str, end: str) -> pd.Series:
    months = pd.period_range(start, end, freq="M")
    return dates.dt.to_period("M").value_counts().reindex(months, fill_value=0).sort_index()


def fmt(x: float) -> str:
    return "∞" if not np.isfinite(x) or x > 1e6 else f"{x:.1f}"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kev", type=Path, required=True)
    ap.add_argument("--ransomware-dir", type=Path)
    args = ap.parse_args()

    kev_json = json.loads(args.kev.read_text())
    kev = pd.DataFrame(kev_json["vulnerabilities"])
    added = pd.to_datetime(kev["dateAdded"])
    rw = added[kev["knownRansomwareCampaignUse"] == "Known"]
    print(f"KEV catalogue {kev_json.get('catalogVersion')} ({kev_json.get('count')} entries)\n")

    series = {"KEV new entries": added, "KEV ransomware-associated": rw}

    print("## A. Autocorrelation of detrended monthly residuals\n")
    print("| Series | Window | Trend | n | r (month) | ACF lag 1, 2, 3 | ±95% band | Ljung-Box p |")
    print("|---|---|---|---|---|---|---|---|")
    for name, dates in series.items():
        for wname, (s, e) in WINDOWS.items():
            y = monthly_counts(dates, s, e).values.astype(float)
            for trend in ("linear", "quadratic"):
                a = residual_acf(y, trend)
                acf = ", ".join(f"{v:+.2f}" for v in a["acf"])
                print(f"| {name} | {wname} | {trend} | {a['n']} | {fmt(a['r_month'])} | {acf} | "
                      f"±{a['band']:.2f} | {a['ljung_box_p']:.2f} |")
    if args.ransomware_dir:
        files = sorted(args.ransomware_dir.glob("rl_*.json"))
        if files:
            y = np.array([len(json.loads(f.read_text())) for f in files], dtype=float)
            a = residual_acf(y, "linear")
            acf = ", ".join(f"{v:+.2f}" for v in a["acf"])
            print(f"| Ransomware leak-site postings | {files[0].stem[3:]} to {files[-1].stem[3:]} | linear | "
                  f"{a['n']} | {fmt(a['r_month'])} | {acf} | ±{a['band']:.2f} | {a['ljung_box_p']:.2f} |")

    print("\n## B. Aggregation test: shape on monthly vs quarterly counts\n")
    print("Independent monthly shocks: r_quarter / r_month ≈ 3. Shock persists through the quarter: ≈ 1.\n")
    print("| Series | Window | Trend | Quarters | r (month) | r (quarter) | Ratio |")
    print("|---|---|---|---|---|---|---|")
    for name, dates in series.items():
        for wname, (s, e) in list(WINDOWS.items())[1:]:          # 12 months = 4 quarters: too few
            m = monthly_counts(dates, s, e)
            for trend in ("linear", "quadratic"):
                b = aggregation_ratio(m, trend)
                print(f"| {name} | {wname} | {trend} | {b['quarters']} | {fmt(b['r_month'])} | "
                      f"{fmt(b['r_quarter'])} | {fmt(b['ratio'])} |")


if __name__ == "__main__":
    main()
