# Dispersion timescale: how long does a rate shock last?

Analysis note for tef-estimator 1.2.0. It sets the default of `dispersion.timescale` in `config.yaml`.
Analysis run 2026-10-17 · KEV catalogue version 2026.10.15 (1,746 entries) · ransomware.live monthly caches Jun 2025–May 2026.

**Reproduce:**
```bash
python scripts/dispersion_timescale_check.py --kev data_cache/kev.json --ransomware-dir data_cache
```
This needs pandas, scipy and statsmodels, which aren't package dependencies. The caches are the ones the companion notebook writes: https://gist.github.com/lauravoicu/5089edfa1673202af60add2f8272247b. KEV revises its history, so a later catalogue can give slightly different numbers.

---

## 1. The question

The dispersion shape r is the Gamma shape of a shared shock on the event rate. It is fitted on **monthly** counts. To use it for an **annual** count, we need to know how long a shock lasts:

| If… | then the annual rate multiplier is… | annual shape |
|---|---|---|
| each month gets its own, independent shock (`month`) | the mean of 12 independent Gamma(r) shocks = Gamma(12r) | 12 r |
| one shock lasts the whole year (`year`) | a single Gamma(r) shock | r |

The choice changes the extra variance about twelvefold, so it is a setting, and its default needs evidence.

**The rule, set before the analysis:** if month-to-month residuals show no carry-over, the default is `month`, with `year` as the cautious alternative. If they do show carry-over, the default is `year`.

## 2. Data

| Series | What a count is | Source | Windows used |
|---|---|---|---|
| KEV new entries | CVEs added to CISA's Known Exploited Vulnerabilities catalogue per month, by `dateAdded` | CISA KEV JSON feed | 4 windows, Jan 2022–May 2026 |
| KEV ransomware-associated | Same, filtered to `knownRansomwareCampaignUse == "Known"` | CISA KEV JSON feed | same |
| Ransomware leak-site postings | Victims posted per month, by attack date | ransomware.live `/v2/victims/YYYY/MM` | Jun 2025–May 2026 only (no longer cache) |

Nov–Dec 2021 is dropped: that is when the catalogue was first loaded. **2022 is kept in one window and excluded in the others.** It was still a back-fill year, with CISA adding older exploited CVEs in large batches (for example, the March 2022 additions), so its month-to-month pattern reflects how the catalogue was curated, not how exploitation arrived.

Caveats that apply throughout:
- KEV counts **vulnerabilities** CISA newly added to the catalog, not attacks; `dateAdded` is the listing date, not when exploitation began.
- Leak-site postings come in batches.
- All three series are population-level. They show the shared part of burstiness, not one organization's own.

## 3. Method

**Detrending.** Every series is fitted with an NB2 negative binomial regression, log link, with a time trend: linear, and quadratic as a robustness check. The detrended shape is r = 1/α. Without the trend, growth would show up as fake dispersion; that is the trap described in the blog.

**Check A: autocorrelation.**
- Take the Pearson residuals under the NB2 fit, (y − μ̂)/√(μ̂ + α μ̂²).
- Compute their lag-1 to lag-3 autocorrelation, compared against the ±1.96/√n band.
- Test the lags jointly with Ljung-Box.

Persistent shocks show up as positive autocorrelation.

**Check B: aggregation.** This one tests the question directly. Fit r on monthly counts, and again on quarterly counts (full quarters only).

| If shocks are… | quarterly count VMR | so r_quarter / r_month ≈ |
|---|---|---|
| independent by month | 1 + m/r (same as monthly) | 3 |
| persistent through the quarter | 1 + 3m/r | 1 |

Here m is the monthly mean. The 12-month window has only 4 quarters, so check B is not run on it.

## 4. Results

### A. Autocorrelation of detrended monthly residuals

| Series | Window | Trend | n | r (month) | ACF lag 1, 2, 3 | ±95% band | Ljung-Box p |
|---|---|---|---|---|---|---|---|
| KEV new entries | Jun 2025–May 2026 (blog) | linear | 12 | 46.4 | −0.39, +0.02, −0.26 | ±0.57 | 0.31 |
| KEV new entries | Jun 2025–May 2026 (blog) | quadratic | 12 | 48.9 | −0.44, +0.02, −0.27 | ±0.57 | 0.22 |
| KEV new entries | Jan 2024–May 2026 | linear | 29 | 25.1 | −0.01, +0.01, −0.07 | ±0.36 | 0.98 |
| KEV new entries | Jan 2024–May 2026 | quadratic | 29 | 26.4 | −0.05, −0.03, −0.12 | ±0.36 | 0.89 |
| KEV new entries | Jan 2023–May 2026 | linear | 41 | 21.6 | +0.07, +0.02, −0.02 | ±0.31 | 0.97 |
| KEV new entries | Jan 2023–May 2026 | quadratic | 41 | 22.0 | +0.05, +0.00, −0.03 | ±0.31 | 0.99 |
| KEV new entries | Jan 2022–May 2026 | linear | 53 | 2.4 | +0.19, **+0.31**, +0.16 | ±0.27 | **0.03** |
| KEV new entries | Jan 2022–May 2026 | quadratic | 53 | 3.9 | +0.07, +0.17, +0.13 | ±0.27 | 0.40 |
| KEV ransomware-assoc. | Jun 2025–May 2026 (blog) | linear | 12 | 7.6 | −0.30, −0.05, +0.17 | ±0.57 | 0.58 |
| KEV ransomware-assoc. | Jun 2025–May 2026 (blog) | quadratic | 12 | 10.0 | −0.58, −0.01, +0.26 | ±0.57 | 0.10 |
| KEV ransomware-assoc. | Jan 2024–May 2026 | linear | 29 | 15.3 | +0.07, +0.14, +0.02 | ±0.36 | 0.83 |
| KEV ransomware-assoc. | Jan 2024–May 2026 | quadratic | 29 | 26.9 | +0.07, +0.23, +0.12 | ±0.36 | 0.49 |
| KEV ransomware-assoc. | Jan 2023–May 2026 | linear | 41 | 16.4 | −0.08, +0.16, −0.01 | ±0.31 | 0.70 |
| KEV ransomware-assoc. | Jan 2023–May 2026 | quadratic | 41 | 16.9 | −0.09, +0.18, +0.01 | ±0.31 | 0.62 |
| KEV ransomware-assoc. | Jan 2022–May 2026 | linear | 53 | 2.7 | +0.09, +0.17, +0.04 | ±0.27 | 0.55 |
| KEV ransomware-assoc. | Jan 2022–May 2026 | quadratic | 53 | 3.6 | −0.03, +0.15, +0.02 | ±0.27 | 0.71 |
| Ransomware postings | Jun 2025–May 2026 | linear | 12 | 129.7 | +0.19, −0.00, −0.35 | ±0.57 | 0.42 |

### B. Shape on monthly vs quarterly counts

| Series | Window | Trend | Quarters | r (month) | r (quarter) | Ratio (≈3 independent, ≈1 persistent) |
|---|---|---|---|---|---|---|
| KEV new entries | Jan 2024–May 2026 | linear | 9 | 25.1 | 109.4 | 4.4 |
| KEV new entries | Jan 2024–May 2026 | quadratic | 9 | 26.4 | 210.9 | 8.0 |
| KEV new entries | Jan 2023–May 2026 | linear | 13 | 21.6 | 78.2 | **3.6** |
| KEV new entries | Jan 2023–May 2026 | quadratic | 13 | 22.0 | 82.2 | **3.7** |
| KEV new entries | Jan 2022–May 2026 | linear | 17 | 2.4 | 3.5 | 1.4 |
| KEV new entries | Jan 2022–May 2026 | quadratic | 17 | 3.9 | 8.1 | 2.1 |
| KEV ransomware-assoc. | Jan 2024–May 2026 | linear | 9 | 15.3 | 195.9 | 12.8 |
| KEV ransomware-assoc. | Jan 2024–May 2026 | quadratic | 9 | 26.9 | 181.2 | 6.7 |
| KEV ransomware-assoc. | Jan 2023–May 2026 | linear | 13 | 16.4 | 26,066 | (no quarterly overdispersion) |
| KEV ransomware-assoc. | Jan 2023–May 2026 | quadratic | 13 | 16.9 | ∞ | (no quarterly overdispersion) |
| KEV ransomware-assoc. | Jan 2022–May 2026 | linear | 17 | 2.7 | 6.5 | 2.4 |
| KEV ransomware-assoc. | Jan 2022–May 2026 | quadratic | 17 | 3.6 | 10.6 | 2.9 |

## 5. Reading the results

1. **No month-to-month carry-over without 2022.** In every KEV window from 2023 or 2024 onwards, with either trend, the residual autocorrelations sit well inside the band and Ljung-Box gives p = 0.89–0.99.
2. **The one significant result is an artifact.** Jan 2022–May 2026 with a linear trend gives p = 0.03, but it disappears with a quadratic trend (p = 0.40). The same window also gives a very low monthly r (2.4 against ~22 without 2022). Both are the signature of a regime the linear trend can't follow: the 2022 back-fill followed by steady curation. Neither is a sign of persistent threat shocks.
3. **Aggregation agrees with independence.** For KEV new entries without 2022, the quarterly shape is 3.6–4.4 times the monthly one with a linear trend, close to the 3 that independent months predict. It is 8.0 with the quadratic trend on the 9-quarter window, noisy but on the same side. A lasting shock would give about 1. Ratios above 3 suggest, if anything, a little mean reversion (a busy month followed by a quieter one). With 9–13 quarters that can't be told apart from noise.
4. **KEV ransomware-associated is too sparse to decide.** Its quarterly fits are unstable: two show no quarterly overdispersion at all, so the ratio is unbounded. It is used for neither direction.
5. **Ransomware postings:** 12 months only, with no detectable carry-over (p = 0.42) but little power. There is no longer series to test.
6. **The 12-month blog window has little power everywhere** (±0.57 band). It can't settle the question on its own, which is why the longer KEV history was needed.

## 6. Decision

**Default `dispersion.timescale: month`**, giving annual shape = 12 r. This follows the rule set in §1: the evidence shows no carry-over once the back-fill artifact is removed, and the aggregation test points to independent months.

`year` (annual shape = r) stays available as the **cautious alternative**. Use it for sensitivity analysis, or where you have reason to expect long campaigns. The two settings bracket the effect.

What the choice does, at r = 21.6 (KEV default, monthly) and 5 events a year:

| Setting | Annual shape | VMR = 1 + λ/shape |
|---|---|---|
| `month` (default) | 259.2 | 1.019 |
| `year` | 21.6 | 1.231 |

Neither setting changes any TEF estimate. It only changes the variance of simulated counts.

## 7. Side finding: the level of r depends on the window

KEV new entries:
- **12-month blog window:** r ≈ 46.
- **Longer windows without 2022:** r ≈ 22–26, i.e. more dispersion.

**Decision (2026-10-19): the default uses the longer window**, r = 21.6 (Jan 2023–May 2026, linear trend), with the raw fit on the same window (13.3, method of moments) as the sensitivity bound. It rests on 41 months instead of 12, and it is the window this timescale analysis rests on. The published 12-month fit (46.4, raw 23.0; blog and notebook, run 2026-10-16) stays documented here. At `month`, annual shape 12 × 21.6 ≈ 259: the effect is still small for one organization.

## 8. Limitations

- **Population-level series only.** They show the burstiness organizations share. One organization's own burstiness, and the differences between organizations (credibility k), are invisible here.
- **KEV counts vulnerabilities, not attacks.** Applying its timing to the exploitation vector assumes exploitation waves track catalogue additions.
- **Short series.** 9–13 quarters for check B, 12 months for ransomware postings. Tests with low power can miss modest persistence.
- **Trend form matters**, as the 2022 window shows. Two trend forms were tried, not a full search.
- **Re-run when the data refreshes.** Re-run the script after each quarterly data refresh. If carry-over appears in a window without the back-fill, revisit the default.
