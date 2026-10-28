# Within-vector dampening: how much do sector and size overlap?

Analysis note to verify the default `dampening.factor_k: 0.70` in `config.yaml`.

Analysis run 2026-10-26 on the following data sources · StatCan 22-10-0076 (survey years 2017–2023) · VCDB (US incidents 2010–2024) · Census SUSB 2022.

**Reproduce:**
```bash
python scripts/dampening_k_check.py --statcan PATH/22100076.csv \
    --vcdb PATH/VCDB --susb PATH/us_state_naics_detailedsizes_2022.xlsx
```
Standard library only for checks A and B; check C runs the estimator. Each check runs only when its inputs are given (C needs none).

| Input | Where to get it |
|---|---|
| `22100076.csv` | Statistics Canada table 22-10-0076-01, full-table CSV download |
| VCDB | github.com/vz-risk/VCDB (the JSON incident files) |
| `us_state_naics_detailedsizes_2022.xlsx` | Census Statistics of US Businesses 2022, "U.S. & states, NAICS, detailed employment sizes" |

---

## 1. The question

Each vector multiplies the base rate by a sector multiplier m_s and a size multiplier m_z (plus technology, geography). Both come from marginal data: incidents by sector, incidents by size. If large firms cluster in high-rate sectors, part of each multiplier measures the same thing, and their product over-counts. The tool keeps a share k of the combined deviation from 1:

```
composite = 1 + (m_s × m_z − 1) × k        (capped at max_composite 5)
```

k = 1: the multipliers are independent. k < 1: they overlap. k = 0.70 was set by judgment. Testing it needs data with sector **and** size together, on firm counts.

## 2. Data

| Check | What a cell is | Population | Cells |
|---|---|---|---|
| A. StatCan 22-10-0076 | Share of enterprises impacted, 2-digit NAICS × small / medium / large | Canadian enterprises, survey (self-reported) | 50–57 per year, quality A–C only |
| B. VCDB ÷ Census SUSB | US VCDB incidents ÷ US firms, 2-digit NAICS × 1–10 / 11–100 / 101–1,000 / 1,001+ employees | US firms; incidents publicly reported | 70 matched, 56 with ≥ 5 incidents |
| C. IRIS bracket | One ransomware estimate per profile | The tool's own output | 320 profiles per revenue tier |

## 3. Method

**A and B.** Observed relative rate r(s,z) = p(s,z) / p; marginal multipliers m_s = p(s) / p, m_z = p(z) / p, all from the same table. Fit r − 1 = k (m_s m_z − 1) by least squares through the origin. Error columns compare the squared error at k = 0.70 and k = 1.0 with the best k (×1.00 = as good as the best). B also fits only cells whose composite falls in the tool's working range (0.2–5) and weights by incident count as a variant.

**C.** For every sector × geography × remote-access setup (4) in each revenue tier, implied annual loss = TEF median × ransomware susceptibility mode (0.17). Count how often it falls inside IRIS's bracket: lower bound (`floor_lef`) to upper bound (IRIS Ransomware Spotlight), at k = 0.70 and k = 1.0.

## 4. Results

Per-series fits, cell counts and the per-tier IRIS check: printed by the reproduce script above.

1. **The two data sets disagree on the level.** StatCan puts k at 0.69–0.75 (2023, all three incident types). VCDB ÷ Census in the tool's working range puts it at 0.86–0.96. Together: k between about 0.7 and 1.0.
2. **The spread is wide** (0.29–1.30). StatCan 2021 is the outlier year (0.94–1.30, with the lowest R²); VCDB over all cells swings from 0.29 to 0.80 with weighting, because a few very large-firm cells dominate.
3. **On fit alone, 0.70 and 1.0 are close.** StatCan: 0.70 within 5% of the best in 9 of 12 series, 1.0 in 3 of 12. VCDB's working range: 1.0 slightly better (×1.00 vs ×1.08 unweighted; ×1.03 vs ×1.04 weighted).
4. **IRIS agrees.** With k = 0.70, 95% of $10M–$10B profiles imply a loss inside IRIS's bracket, against 89% at k = 1.0. Dampening mostly moves low-multiplier profiles up from below the floor (a composite under 1 is shrunk toward 1 too).
5. **Above `$10B`, k doesn't matter.** Most profiles fall below IRIS's lower bound with either k: the base rate is flat from `$100M` (IRIS finds ransomware about equally likely from `$100M` to `$100B`) while IRIS's floor keeps rising. The estimate is held at the floor there; this is a base-rate limit, not a dampening one.

## 5. Decision

**Keep `factor_k: 0.70`.** The data put k between about 0.7 and 1.0, so 0.70 is at the low end of that range: StatCan supports it, VCDB favours less dampening. The IRIS check (§4, item 4) favours 0.70 over 1.0. Sensitivity analysis sweeps it (`k_sensitivity`).

## 6. Limitations

Sector × size only; technology and geography get the same k by assumption. StatCan is Canadian and self-reported; VCDB counts publicly reported incidents, so large firms are over-represented. Cells are coarse and weighting changes the fit. Re-run when StatCan publishes a new survey year (every two years).
