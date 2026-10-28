# Dispersion timescale: how long does a rate shock last?

Analysis note to verify the default of `dispersion.timescale` in `config.yaml`.

Analysis run 2026-10-17 on the following data sources · KEV catalogue version 2026.10.15 (1,746 entries) · ransomware.live monthly caches Jun 2025–May 2026.

**Reproduce:**
```bash
python scripts/dispersion_timescale_check.py --kev data_cache/kev.json --ransomware-dir data_cache
```
Needs pandas, scipy and statsmodels (not package dependencies) and the caches written by the companion notebook: https://gist.github.com/lauravoicu/5089edfa1673202af60add2f8272247b. KEV revises its history, so a later catalogue can differ slightly.

---

## 1. The question

The dispersion shape r (Gamma shape of a shared shock on the event rate) is fitted on **monthly** counts. Applying it to an **annual** count requires knowing how long a shock lasts:

| If… | then the annual rate multiplier is… | annual shape |
|---|---|---|
| each month gets its own, independent shock (`month`) | the mean of 12 independent Gamma(r) shocks = Gamma(12r) | 12 r |
| one shock lasts the whole year (`year`) | a single Gamma(r) shock | r |

The choice changes the extra variance about twelvefold, so its default needs evidence.

**Rule, set before the analysis:** no month-to-month carry-over in the residuals → default `month`, with `year` as the cautious alternative; carry-over → default `year`.

## 2. Data

| Series | What a count is | Source | Windows used |
|---|---|---|---|
| KEV new entries | CVEs added to CISA's Known Exploited Vulnerabilities catalogue per month, by `dateAdded` | CISA KEV JSON feed | 4 windows, Jan 2022–May 2026 |
| KEV ransomware-associated | Same, filtered to `knownRansomwareCampaignUse == "Known"` | CISA KEV JSON feed | same |
| Ransomware leak-site postings | Victims posted per month, by attack date | ransomware.live `/v2/victims/YYYY/MM` | Jun 2025–May 2026 only (no longer cache) |

Nov–Dec 2021 (the catalogue's initial load) is dropped. **2022 is kept in one window only**: CISA was still back-filling older exploited CVEs in large batches (e.g. March 2022), so its monthly pattern reflects curation, not exploitation. `dateAdded` is the listing date, not when exploitation began; leak-site postings come in batches (further caveats in §7).

## 3. Method

**Detrending.** NB2 negative binomial regression, log link, linear time trend (quadratic as robustness check); detrended shape r = 1/α. Without the trend, growth would show up as fake dispersion (the trap described in the blog).

**Check A: autocorrelation.** Lag-1 to lag-3 autocorrelation of the NB2 Pearson residuals, (y − μ̂)/√(μ̂ + α μ̂²), against the ±1.96/√n band; Ljung-Box tests the lags jointly. Persistent shocks give positive autocorrelation.

**Check B: aggregation.** Fit r on monthly and on quarterly counts (full quarters only).

| If shocks are… | quarterly count VMR | so r_quarter / r_month ≈ |
|---|---|---|
| independent by month | 1 + m/r (same as monthly) | 3 |
| persistent through the quarter | 1 + 3m/r | 1 |

m is the monthly mean. Not run on the 12-month window (only 4 quarters).

## 4. Results

Per-window autocorrelations, Ljung-Box tests and monthly vs quarterly shapes: printed by the reproduce script above.

1. **No month-to-month carry-over without 2022.** Every KEV window from 2023 or 2024 on, either trend: autocorrelations well inside the band, Ljung-Box p = 0.89–0.99.
2. **The one significant result is an artifact.** Jan 2022–May 2026, linear trend: p = 0.03, gone with a quadratic trend (p = 0.40); monthly r is also very low (2.4 against ~22 without 2022). Both signal a regime the linear trend can't follow (2022 back-fill, then steady curation), not persistent threat shocks.
3. **Aggregation agrees with independence.** KEV new entries without 2022: quarterly shape 3.6–4.4 × monthly with a linear trend, close to the 3 independent months predict; 8.0 with the quadratic trend on 9 quarters, noisy but on the same side. A lasting shock would give about 1. Ratios above 3 hint at slight mean reversion, indistinguishable from noise with 9–13 quarters.
4. **KEV ransomware-associated is too sparse to decide**: unstable quarterly fits (two show no quarterly overdispersion). Not used either way.
5. **Ransomware postings:** no detectable carry-over (p = 0.42), but 12 months give little power, and no longer series exists.
6. **The 12-month blog window has little power everywhere** (±0.57 band), hence the longer KEV history.

## 5. Decision

**Default `dispersion.timescale: month`** (annual shape = 12 r), per the §1 rule: no carry-over once the back-fill artifact is removed, and aggregation points to independent months. `year` (annual shape = r) stays as the **cautious alternative** for sensitivity analysis or expected long campaigns; the two bracket the effect.

At r = 21.6 (KEV default, monthly) and 5 events a year:

| Setting | Annual shape | VMR = 1 + λ/shape |
|---|---|---|
| `month` (default) | 259.2 | 1.019 |
| `year` | 21.6 | 1.231 |

Neither setting changes any TEF estimate, only the variance of simulated counts.

## 6. Side finding: the level of r depends on the window

KEV new entries: r ≈ 46 on the 12-month blog window, about 22–26 (more dispersion) on longer windows without 2022. The default uses the longer window, the one this analysis rests on; the release refit on May 2023–Sep 2026 gives the shipped r = 22.5.

## 7. Limitations

Population-level series only: one organization's own burstiness is invisible. KEV counts catalogue additions, not attacks, so applying its timing assumes exploitation waves track them. The series are short (low power against modest persistence), and only two trend forms were tried. Re-run after each quarterly data refresh; if carry-over appears without the back-fill, revisit the default.
