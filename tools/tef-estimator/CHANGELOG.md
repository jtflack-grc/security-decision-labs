# Changelog

## [1.2.0] - 2026-10-21

### Added
- **Dispersion: burstiness of the rate over time** — `DispersionParams` and `sample_annual_counts()` in `distributions.py`. The model is a Gamma-mixed **rate**, so annual counts are negative binomial with VMR = 1 + λ/r. It is not a model of inter-arrival times. It is separate from credibility k: k = how rates differ between organizations; r = how one organization's rate is shaken in time by shared shocks.
  - Defaults in `config.yaml` → `dispersion` are set only where a public series supports them: exploitation vector r = 21.6 (CISA KEV new entries, Jan 2023–May 2026, 41 months, 2022 back-fill excluded); ransomware scenario total r = 129.7 (Ransomware.live, Jun 2025–May 2026). Both are detrended monthly fits (linear trend), with the raw fits (13.3 / 34.9) kept as the sensitivity bound. KEV uses the longer window because the timescale analysis rests on it and 12 months has little power; the 12-month fit (46.4, raw 23.0) is documented in `docs/dispersion-timescale.md`. Credential, phishing, supply chain and the other scenarios stay Poisson.
  - `dispersion.timescale` sets how long a shock lasts: `month` (default; independent monthly shocks, annual shape = 12 r) or `year` (cautious alternative; annual shape = r). Evidence: KEV residuals show no month-to-month carry-over once the 2022 back-fill is excluded, and quarterly shapes are 3.6–4.4× the monthly ones. Full analysis in `docs/dispersion-timescale.md`, reproducible with the new `scripts/dispersion_timescale_check.py`.
  - Output: `TEFResult.dispersion`, `total_dispersion`, `sample_annual_counts()`; `to_dict()["analysis"]["dispersion"]` (shape, timescale, annual shape, basis, source, VMR at the median); a DISPERSION block in `full_report()`; a Dispersion panel in the UI (shape, annual shape, VMR at your rate, basis, with each fitted series' source shown under the table).
  - **Dispersion itself changes no estimate**: every positioned median, band and lognormal is identical with and without it (24-case snapshot across ransomware, BEC, exfiltration and web-app scenarios, with and without telemetry). Other 1.2.0 changes do move estimates: see **Changed (estimates move)**.
  - **Hand-off to fair-risk-engine:** `TEFResult.fair_risk_engine_inputs(basis="detrended")` returns the `FAIRInputs` fields for fair-risk-engine (1.1.0): `tef_model='lognormal'`, `tef_p10/p50/p90` read off this lognormal, and `tef_dispersion` = the total annual shape (None for Poisson); `basis="raw"` gives the trend-included bound. The same line is printed under DISTRIBUTION PARAMETERS in `full_report()` and shown under Distribution Parameters in the UI. The positioned low/high are about P5/P95, so they are not fair-risk-engine's P10/P90; `LognormalParams.p10` and `.p90` added.
- **Data exfiltration scenario** and **web application exploitation scenario** — `ExfiltrationScenario`, `WebAppScenario` (`data/scenarios/exfiltration.*`, `web_app.*`). Selectable in the CLI (`--scenario exfiltration` / `web_app`) and the UI scenario dropdown. No peer grid yet, so no peer percentile; dispersion is Poisson (no fitted series).
- **Per-vector credibility k sweep** — sensitivity analysis sweeps each observed vector's credibility k when telemetry is present, in addition to the base-rate and dampening sweeps.
- **Exploitation vector config-driven ceilings** — `exploitation_ceilings` in `TEFConfig` with per-class ceilings (edge_device, cloud_primary, default) and basis labels.
- **Config module** — `TEFConfig` dataclass with `from_dict()` / `to_dict()` / `from_yaml()` for full config round-tripping, including `BandHardeningParams`, `ExploitationCeilingParams`, `k_sensitivity` and `dispersion`.

- **`LognormalParams.fenton_wilkinson()`** — moment-matched sum of lognormals, tested against a Monte Carlo sum. Not used for the total TEF: it treats the vectors as independent, but they share one base rate, so the total lognormal stays centred on the positioned total (with Fenton-Wilkinson its median was 1.35–1.72× the headline TEF on 24 test profiles).
- **`OrgTelemetry` and `VectorObservation` exported** from `tef_estimator`.
- **`OrganizationProfile.infer_employee_count()`** and `revenue_per_employee` in `config.yaml` (Damodaran revenue per employee by sector): infers headcount from the revenue band when `employee_count` is not given. Not yet called by the engine.

### Changed (estimates move)
Compared with 1.1.4, on 24 profiles (manufacturing, financial, healthcare × two revenue bands × with/without remote access × ransomware/BEC), without telemetry the lognormal moves only through the proportions below (median within 2.3%, σ within 2.7%):
- **Ransomware vector proportions** — exploitation 22 → 26%, credential 52 → 48%, phishing 17 → 15% (modes; DBIR 2026, Mandiant 2026), in `data/reference/beazley/extracted.json`. Ransomware positioned medians move by −1.9 to −2.3%; BEC is unchanged.
- **Band hardening** — `band_hardening.min_sigma_ratio` (0.25) keeps telemetry from narrowing a band below a quarter of its prior σ; `coverage_leverage_cap` (5.0) caps the observation quarters counted for band contraction, so beyond 5 quarters the band stops narrowing. The pseudo-event count is the events actually detected (detected rate × quarters / 4), so detection coverage acts on the band only through that count: lower coverage means fewer detections and less narrowing, never more. Estimates with more than 5 quarters of telemetry move. Config-driven.

### Removed
- **`OrganizationProfile.custom_susceptibility_prior`** (unused; use `config.yaml` → `susceptibility_prior`). Passing it now raises a `TypeError`.

### Changed
- **Version bumped to 1.2.0.**
- **LognormalParams.from_median_and_range** — precision increased from 3 to 6 decimal places.
- **ExploitationVector** — constructor accepts a `config` kwarg for exploitation ceilings.
- **Version never hardcoded** — `tef_estimator.__version__` reports the version of the code actually running: the source tree's own `pyproject.toml` when running from a checkout (including editable installs with stale metadata), otherwise the installed package metadata. The GUI badge uses it (fixes [#2](https://github.com/security-decision-science/security-decision-labs/issues/2)).

### Fixed
- **Per-vector k sweep had no effect** — the credibility blender read the global config instead of the engine's, so the swept k values were ignored and the low and high outputs were identical. The engine now passes its own k values. k entries are ranked by spread (max/min), because a higher k lowers the output.
- **Sensitivity sub-engines ignored a custom config** — base-rate and dampening sweeps built their engines from the global config; they now use the engine's config. Results with the default config are unchanged.
- **Band hardening observability** — a binding `min_sigma_ratio` or `coverage_leverage_cap` now adds a `Band hardening:` entry to `validation_checks`, as well as a warning.
- **k-sensitivity config** — the per-vector credibility-k sweep ranges come only from `config.yaml` (`k_sensitivity`). The hardcoded fallback in `engine.py` was removed.
- **`TEFConfig.to_dict()` dropped `k_sensitivity`** — custom sweep ranges are now kept through a round trip.
- **Compare mode left a stale Profile B card** — switching Compare off in the UI now clears the comparison panel instead of leaving the last rendered result on the page.
- **Web-app overall-share citation** — `web_app.json` cited "web applications involved in ~26% of breaches" and Edgescan exposure for a value of 10%. The 10% is DBIR 2026's Basic Web Application Attacks pattern (10% of breaches, n = 22,625), so the citation now says that. The badge moves from gray (assumption) to amber, because DBIR counts breaches and the field is used as a share of all incidents. The value is unchanged. The scenario's list of sources still needed drops Edgescan and Cobalt (vulnerability prevalence belongs to susceptibility, not TEF; noted in `_susceptibility_note`) and adds the DBIR web-app pattern by industry and the IRIS public-facing-application share by revenue.

### Corrected: credibility k is asserted, not fitted
- **What changed:** the `credibility_k` citations in `config.yaml`, and the k tables in the technical reference (§6 parameter table, §8.3). All four k values are now labelled **asserted (judgment)**, and all four values are unchanged from 1.1.4: exploitation 6, credential 10, phishing 10, supply chain 40. (A draft of this release had raised exploitation k to 32 on the strength of the time-series fit below; with that basis gone, it stays at 6.)
- **Why:** the exploitation k was cited as "fitted" from a negative binomial fit on detrended KEV new entries (r ≈ 18–32), and the credential k as "bounded" by HIBP fits (r ≈ 4.8–6.5). Those fits measure how bursty a rate is *over time*: the dispersion shape r added in this release. k measures how much rates differ *between organizations*, and only cross-organization data (IRIS-type, insurer portfolios) shows that. A global time series can't: organizations that each have a steady rate add up to a Poisson total, however different they are.
- **Why it matters:** k sets the weight on an organization's own telemetry, Z = n / (n + k). For example, 8 quarters at 50% coverage gives Z = 40% at k = 6 and 29% at k = 10. Until k is fitted, that weight is a judgment call, and the docs now say so.
- **Also:** the `k_sensitivity` comment is relabelled as judgment ranges. The exploitation sweep now runs from the asserted 6 up to 32, to show what slower credibility would do.
- **Planned (later release):** fit k from cross-organization data. That is a methods change, and it will move estimates that use telemetry.
- **Unrelated doc fix:** technical reference limitation 7 still described Fenton-Wilkinson as "deferred". It now describes the dependence assumption behind the total lognormal and what Fenton-Wilkinson would give instead.

### Tests
- 317 passed, 0 failures. New: `tests/test_dispersion.py` (35, including the fair-risk-engine hand-off, an exact scipy `nbinom` check and an FFT closed form of the annual loss checked against simulation) and `tests/test_release_1_2_0.py` (33: band hardening incl. coverage not narrowing the band, the total lognormal centred on the headline, Fenton-Wilkinson, k sweep, ceilings, config, version resolution order, new scenarios incl. CLI/UI, refresh script).

---

## [1.1.4] - 2026-07-01

### Changed
- **Packaging only:** version and PyPI project URLs (Homepage, Documentation, Issues point to `security-decision-labs`). The code is identical to 1.1.3. Published on PyPI; the source was not committed.

---

## [1.1.3] - 2026-06-17

### Fixed
- **Pseudo-event count inflated 4× by unit mismatch** — `N = adjusted_observed × effective_n` mixed annualized frequency (per year) with observation periods (quarters), inflating the pseudo-event count by 4×. Corrected to `N = adjusted_observed × effective_n / 4` so N represents actual expected events. Contraction rates now: 1yr/0.05 = 4%, 2yr/0.05 = 8%, 5yr/0.05 = 16%, 10yr/0.10 = 38%.
- **Duplicate vector observations silently dropped** — `OrgTelemetry` now validates that no two observations share the same vector name; raises `ValueError` on duplicates.
- **Trace divergence** — credibility blend and band contraction now emit trace steps, making the full estimation chain visible in the audit trail.
- **OrgTelemetry mutation** — `observations` list is frozen to a tuple in `__post_init__` to prevent post-construction mutation.
- **Dead code removed** — deleted unused `obs_periods` variable in `result.py`, orphaned `apply_peer_percentile()` function in `peer.py`, and unused `dampen_composite` import in `engine.py`.
- **Percentage vs percentage-point in compare mode** — delta displays now correctly use "pp" (percentage points) instead of "%" throughout engine (`compare()` explanation and `CompareResult.render_text()`), result, UI, and user-guide examples.
- **Ceiling validation asymmetry** — ceiling breach now emits a FAIL message like the floor check, instead of silently passing.
- **Stale ransomware consensus in docs** — TECHNICAL_GUIDE.md and python-api.md referenced old `PERT(0.003, 0.010, 0.025)` consensus; corrected to actual `PERT(0.01, 0.03, 0.10)` from `ransomware.json`.
- **Sensitivity sweep ignored custom_base_rate** — when a profile had `custom_base_rate` set, the sensitivity analysis swept the scenario's default PERT range instead; the custom rate's `estimate()` override silently produced identical results for all sweeps (range_multiple=1.0). Now sweeps the custom rate's implied PERT range.
- **Detection coverage amplification unwarned** — low detection coverage (e.g. 1%) amplifies `adjusted_observed` by up to 100× with no warning, since the existing `n_events` check only guards band contraction. Added a warning when `adjusted_observed > 50× prior`.
- **Partial telemetry share distortion unwarned** — providing telemetry for fewer than all 4 vectors shifts vector share proportions without explanation. Added a warning listing covered and uncovered vectors.
- **`annual_probability_pct` displayed >100% for high-frequency TEF** — when telemetry pushes TEF above 1.0 events/year, the label now shows frequency format (e.g. "2.1/yr") instead of an incoherent "209%".

### Changed
- **Renamed `positioned_mode` → `positioned_median`** throughout (dataclass fields, engine, result, UI, docs, tests). The value is the lognormal median (exp(μ)), not the statistical mode — the old name was semantically misleading. Also renamed `prior_mode` → `prior_median`, `enforce_floor()` → `enforce_bounds()`, `baseline_mode` → `baseline_median`, and remaining `total_mode` local variables.
- **Version bumped to 1.1.3** in `pyproject.toml`, `__init__.py`, and `technical-reference.md` header.
- **Peer percentile caveats** — peer context now always notes "tech-neutral peers" (grid excludes technology multipliers); additionally notes telemetry exclusion when org-specific telemetry is present.
- **Renamed `mean_recurrence_years` → `median_recurrence_years`** — the value is `1/median`, not `1/mean`; old name retained as alias for backwards compatibility.
- **Sensitivity analysis telemetry caveat** — when telemetry is present, sensitivity output notes that credibility parameters (k, detection coverage) are additional sources of uncertainty not varied. Displayed in CLI, UI, and text output.
- **Band recentering at telemetry boundary documented** — §8.6 Limitations now explains the ~5% endpoint shift when telemetry is first provided, caused by switching from PERT geometric-mean centering to estimate centering.
- **§8.6 expanded to 9 limitations** — added: prior shape α conservative (sigma_prior overstatement from PERT support bounds), aggregate lognormal understates median ~20% (Fenton-Wilkinson deferred), sensitivity analysis omits credibility parameters, dampening-before-blending interaction documented as intentional design.
- **3 new tests** — zero-rate sigma invariance, contraction table verification, duplicate observation rejection. 241 total passing.

## [1.1.2] - 2026-06-17

### Fixed
- **Supply chain telemetry silently ignored** — `v.vector_name.lower()` produced "supply chain" (space) but `VectorObservation` expects "supply_chain" (underscore). Supply chain credibility blending now works correctly.
- **Documentation contraction rate table** — §8.6 table used a hypothetical α_pert≈2.04 instead of the actual α_pert≈0.30 from the credential vector's PERT range. Recomputed from real engine output.

### Added
- **Extreme input warning** — engine warns when observed pseudo-events N > 10× the prior shape α_pert, indicating the posterior is dominated by the observation and the band may be overconfidently narrow.
- **Limitation section** (§8.6) — documents lognormal approximation errors at low α, detection coverage cancellation in band contraction, zero-event band invariance, and two-model nature of the k / α_pert parameterization.
- **2 new tests** — supply chain telemetry regression test, extreme input warning test. 238 total passing.

### Changed
- **Softened "Gamma-Poisson" framing** — reframed as "Gamma-inspired" throughout docs (tech-ref, README, user-guide, python-api, credibility.py docstring) to accurately reflect the two-parameter pragmatic approach rather than implying a single coherent Bayesian model.

## [1.1.1] - 2026-06-17

### Changed
- **Gamma-inspired posterior band contraction** — Credibility blending now derives the positioned band from Gamma-Poisson posterior mechanics instead of ratio-scaling the prior PERT. The Bühlmann mean (point estimate) is unchanged; the uncertainty band now contracts monotonically with observation volume. Fits a Gamma prior shape α to the PERT's log-spread, updates with observed pseudo-events N = adjusted_observed × effective_n / 4 [corrected in 1.1.3], then derives σ_post = √(ln(1 + 1/(α + N))). At zero telemetry the band is identical to the prior; with evidence, σ_post < σ_prior. See `docs/technical-reference.md` §8.6 for derivation.
- **3 new tests** — Posterior band contracts with data, more periods produce a tighter band, low/mode/high ordering preserved after contraction. 236 total passing.

## [1.1.0] - 2026-06-13

### Added
- **Continuous telemetry monitoring** — new `tef_estimator.telemetry` subpackage with 7 collectors (DShield port scans, CISA KEV catalog, Ransomware.live victims, GreyNoise IP classifications, annual report edition monitor, IRIS reference data importer, vector benchmarks importer), SQLite persistence, rolling average integration, baseline comparison with configurable thresholds, and watch mode for continuous monitoring with automatic re-estimation.
- **IRIS reference data collector** — imports sector multipliers, revenue multipliers, floor anchors, and ransomware shares from bundled `data/reference/iris/extracted.json` into the telemetry DB. Hash-based skip prevents duplicate imports.
- **Vector benchmarks collector** — imports initial access vector proportions from bundled `data/reference/vectors/initial_access_vectors.json` (38 records from 8 sources: DBIR 2025/2026 (Verizon), Unit42 IR 2025/2026, Mandiant M-Trends 2026, CrowdStrike GTR 2026, Beazley Q3 2025, IBM CODB 2025) into the telemetry DB. Hash-based skip prevents duplicate imports.
- **`tef-estimator telemetry` CLI subgroup** — 6 commands: `init`, `collect`, `status`, `baseline`, `compare`, `watch`. Optional dependency via `pip install tef-estimator[telemetry]`.
- **Cadence-based scheduler** — tracks last-run timestamps per source; collectors only run when due (daily/weekly/quarterly). `--force` overrides schedule.
- **Change detection** — `compare` module snapshots 7-day rolling averages as baseline, signals when metrics deviate beyond threshold (default 20%).
- **Watch mode** — `tef-estimator telemetry watch` runs the full pipeline (collect → integrate → compare → re-estimate) on a configurable interval.
- **28 new tests** — TelemetryDB, integrator (gap detection, rolling averages, dedup), compare (baseline snapshot, signal detection, threshold), scheduler (cadence logic, state persistence). 246 total passing.

### Changed
- **`pyproject.toml`** — added `telemetry = ["requests>=2.25"]` optional dependency; updated `all` extra to include telemetry.

## [1.0.2] - 2026-06-10

### Added
- **Data freshness warnings** — `check_freshness()` in `tef_estimator.refresh.validators` reads `extracted_date` from each bundled reference source and scenario file, warns at >90 days, flags "consider refreshing" at >180 days. Freshness warnings appear in estimation output and in `tef-estimator refresh check`.
- **Markdown report export** — `TEFResult.to_markdown()` generates a structured markdown report with tables, traces, and source citations. CLI: `tef-estimator estimate --output report.md` or `tef-estimator explain -o report.md`.
- **`--output` / `-o` flag** on `estimate` and `explain` CLI commands for file export.
- **5 new tests** — freshness thresholds (4) and markdown export (1). 218 total passing.

### Fixed
- **`DATA_ROOT` import error** — `cli.py` and `ui.py` imported removed `DATA_ROOT`; replaced with `PEER_GRID_DIR` export from `loader.py`.
- **`test_refresh.py` broken tests** — replaced 500+ lines of dead tests (testing removed fetcher functions) with tests for the actual data refresh validation.

### Removed
- **All FAIR-CAM control mapping claims** — removed from README, FAIR_NOTICE, CHANGELOG, TECHNICAL_GUIDE, docs (cli-reference, user-guide, python-api, technical-reference), result.py docstrings, scenario JSON templates, and UI. No empirical data backs control-to-vector mappings; this is a downstream activity.

### Changed
- **`tef-estimator refresh check`** now shows per-source data age (e.g. "17d old, extracted 2026-05-24") and a freshness warnings section.

## [1.0.1] - 2026-05-27

### Added
- **VERIS empirical dampening support** — `scripts/compute_dampening.py` analyses 10,037 VERIS VCDB incidents. Cross-vector k=0.85 empirically supported by pairwise co-occurrence lift analysis (bimodal structure: exploitation↔credential substitutes at lift~0.2, credential↔phishing complements at lift=8.29). Pairwise lifts with bootstrap 95% CIs stored in `extracted.json` under `veris_pairwise_lifts`.
- **Snapshot data populated** — first refresh cycle: CISA KEV (1,606 vulns), EPSS (335K CVEs), DShield (4 ports, 91 days), Ransomware.live (victims), Shodan (exposed service counts).
- **4 new dampening tests** — validate JSON loading, VERIS citation, pairwise lift data integrity.
- **Technical reference §6.2.1** — full derivation methodology section with lift table and limitations.

### Fixed
- **DShield summary parser** — API returns dict with numeric-string keys + metadata, not a list. Parser now handles both formats correctly.
- **Stale `tef-estimator` directory** removed (leftover from rename).

### Changed
- **`extracted.json` dampening_config** — `vector_k_source` updated from judgment to VERIS VCDB citation; `factor_k_source` updated to explain why judgment-based (needs population denominators unavailable in VCDB).
- **SPECIFICATION.md updated** — §5.5 dampening (empirical), §8.6 UI (NiceGUI not Streamlit), §10 tests (implemented, 247 passing), §12 limitations (dampening supported), §13 roadmap (pruned to future-only).

## [1.0.0] - 2026-05-25

### Added
- **NiceGUI web interface** — `tef-estimator ui` launches a browser-based UI with sidebar profile inputs, live Tier 1+2 display, vector breakdown chart, tornado sensitivity chart, and compare mode. Install with `pip install tef-estimator[ui]`.

### Changed
- **Version 1.0.0** — all v1 blockers complete: two scenarios, comprehensive docs, web UI, input validation, peer grids, packaging.
- **Development status** upgraded from Alpha to Beta.

## [0.3.0] - 2026-05-24

### Added
- **BEC scenario** — Business Email Compromise as second threat scenario (`--scenario bec`). Phishing-dominant (65%).
- **Three-anchor consensus formalization** — `tef_estimator.triangulation` module computes suggested consensus from independent anchors, performs convergence validation, and includes deviation checks in the audit trail.
- **VERIS dampening empirical support** — analysis of 10,037 VCDB incidents validates k=0.85. Credential x phishing lift=8.3 (strong complements), exploitation independent (lift~0.2).
- **Refresh pipeline** — automated fetchers for DShield, CISA KEV, EPSS, Ransomware.live via `tef-estimator refresh`.
- **Peer percentile grid** — pre-computed TEF across all sector/revenue/geo combinations for relative positioning.
- **PyPI packaging** — data files bundled inside wheel; `pip install tef-estimator` works standalone.
- **Comprehensive documentation** — user guide, CLI reference, Python API reference, data sources guide, interpretation guide.
- **Input validation** — OrganizationProfile rejects invalid employee counts and base rate overrides with clear error messages.

### Fixed
- **Vector share normalization** — shares now use raw (pre-dampening) total as denominator, preventing >100% share sums.
- **Scenario-aware peer grid** — peer percentile now looks for scenario-specific grid file instead of always using ransomware.

### Changed
- **Scenario-aware CLI** — `estimate`, `explain`, `compare`, `sensitivity`, and data commands accept `--scenario` flag.
- **Directory renamed** from `tef-estimator` to `tef-estimator` (single z).

## [0.2.0] - 2026-05-24

### Added
- Four vector engines (exploitation, credential, phishing, supply chain) with independent floor/ceiling/positioning.
- Cross-vector dampening (k=0.85) and within-vector dampening (k=0.70).
- Three-tier output (summary, analysis, audit) with calculation traces.
- CLI commands: estimate, explain, compare, sensitivity.
- Data inspection commands: multipliers, base-rate, vectors.
- IRIS 2025 sector/revenue multipliers loaded from JSON.
- Beazley Q3 2025 vector proportions loaded from JSON.

## [0.1.0] - 2026-05-24

### Added
- Initial project structure and specification.
- Organization profile with sector, revenue band, geography, technology exposure.
- Base rate triangulation methodology (three anchors).
