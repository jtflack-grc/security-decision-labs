# Changelog

## [1.3.0] - 2026-10-28

Method details: [technical reference](docs/technical-reference.md) §3 (vectors and ceilings), §8.7–8.9 (dispersion, live inputs).

### What moves
- **Ransomware base rate: one population, per revenue tier** (US leak-site victims × under-reporting ÷ US firms ÷ susceptibility); IRIS is the floor only. Reference profile (manufacturing, $100M–1B, Fortinet) 0.064 → 0.437 per year; small firms down to ×0.06.
- **BEC base rate: one population** (FBI IC3 complaints × reporting multiplier ÷ US firms). Median ×1.3.
- **Exfiltration base rate: one population, per revenue tier** (FBI IC3 data-breach complaints), replacing the anchored consensus. Reference profile 0.025 → 0.230 per year.
- **Web app base rate: exfiltration × web-app share of breaches** (judgment), replacing the consensus. Reference profile 0.046 → 0.059 per year.
- **Floors per scenario;** before, every scenario used the ransomware figure.
- **Geography relative to the US** for all scenarios (their base rates are US counts).
- **IRIS ransomware sector shares corrected:** ransomware estimates move ×0.51 (hospitality) to ×1.41 (agriculture) by sector; the "Other" sector ×0.95 in all scenarios.
- **Ransomware and exfiltration +5.3%:** vector shares now sum to 100% (were 95%).
- **Exfiltration and web app: sector multiplier applied once** (was twice); −37% to +23% by sector.
- **Dispersion r refit at release:** exploitation 21.6 → 22.5, ransomware 129.7 → 113.7.

### New
- **Live inputs** (`--live` / `--frozen` on `estimate`, `explain`, `compare`, `sensitivity`; UI switch; frozen default): dispersion and the ransomware base rate follow collected data.
- **Exploitation ceiling from DShield** scanning sources on the exposed ports (bundled snapshot), with one GreyNoise malicious rate for all scenarios.
- **Credential ceiling campaign counts** for BEC (FBI IC3) and exfiltration (NetDiligence).
- **Peer grids for exfiltration and web app**; `data peer-grid --rebuild` rebuilds all four.
- **Per-vector ceiling checks** in the audit trail: sanity checks, never caps.
- **Shift detection for every source**, on the last complete day; new and missing metrics reported.
- **KEV additions series:** signals above its own 90-day 95th percentile (catches the Oct 2026 wave).
- **Ransomware.live attack dates** from the monthly API (cached; first collection ~16 min).
- **Within-vector dampening 0.70 checked on data:** k for sector × size between about 0.7 and 1.0; IRIS favours 0.70 ([dampening-k.md](docs/dampening-k.md)).
- `telemetry watch --profiles FILE`; `telemetry integrate`.
- **Daily collection on macOS:** launchd template in `scripts/launchd/`.

### Fixed
- IRIS's 0.465% is already the ransomware lower bound; it was multiplied by the 31.7% ransomware share again (0.147%).
- The old ransomware base rate divided leak-site victims by all 6M US businesses, mostly micro firms: about 10x too low for firms over $10M.
- Coalition's 3.70x "market correction" contradicted NAIC's own figures (1.14% claims per policy vs Coalition 1.48%); dropped with the three-anchor consensus.
- `watch` re-estimation always failed, and ignored each profile's scenario.
- UI ignored `~/.tef-estimator/config.yaml`.
- **Collection:** day counts no longer freeze at their first collection; DShield resumes from the last stored day (first run 90 days); `collect --force` reprocesses and integrates; ransomware.live refetches only months still filling.
- **Shift detection:** `compare` skips the partial current day and no longer flags sources collected on other days as missing; the 380 gang-census series (noise) are no longer compared.
- Credential ceiling lacked sector and geography adjustments, and counted successes instead of attempts.
- An interrupted ransomware.live cache write stopped every later collection.
- **KEV additions series:** quiet days no longer end it early (`compare` reported KEV missing); averages near the window start cover full windows.
- Audit trail: the aggregate "Positioned <= Ceiling" check summed ceilings in different units; replaced by the per-vector checks.
- Docs said telemetry re-estimates TEF and `refresh` fetches data; neither was true.
- Freshness warnings for every source past 90 days, even with no newer edition: estimates now name their editions; `refresh check` uses each source's cycle.
- `pert_distribution` crashed on symmetric ranges.
- The engine ignored a custom scenario's `active_vectors`.

### Changed
- TEF is reported as events per year (with the chance of at least one attempt), not as an annual probability; JSON `annual_probability_pct` replaced by `tef_text` and `chance_at_least_one`.
- `--base-rate` / `custom_base_rate` accept any positive rate (was capped at 1); UI inputs likewise.
- Triangulation check runs for custom scenarios only; no built-in scenario has a consensus base rate.
- Peer percentiles read "71st", not "71th".
- BEC credential ceiling: geography relative to the US (its IC3 count is US-only); worldwide counts keep the absolute factor. Sanity check only.
- Coalition is no longer loaded or named on the Inputs line; `COALITION_BIAS_CORRECTION` removed from `tef_estimator.data`; its reference file is no longer shipped.
- GreyNoise collector removed: it queried three fixed reference IPs and fed nothing. The ceiling's malicious rate comes from GreyNoise's published reports, unchanged.
- The plain-language summary uses each scenario's own wording (`output_templates.one_sentence`, now with `{recurrence}`, `{low}`, `{high}`); custom files with other placeholders fall back to a generic sentence.

### Internal
- `CredibilityBlender` takes `vector_k` explicitly; `DampeningConfig` defaults no longer monkey-patched.

## [1.2.0] - 2026-10-21

### What moves
- **Ransomware vector shares:** exploitation 22 → 26%, credential 52 → 48%, phishing 17 → 15% (DBIR 2026, Mandiant 2026). Ransomware medians −2%; BEC unchanged.
- **Band hardening:** bands no longer narrow below ¼ of prior σ or beyond 5 quarters of data; moves only estimates with >5 quarters of telemetry.

### New
- **Dispersion:** negative-binomial counts for simulation; r = 21.6 exploitation (CISA KEV), 129.7 ransomware (ransomware.live), else Poisson; no estimate changes ([dispersion-timescale.md](docs/dispersion-timescale.md)).
- **Hand-off to fair-risk-engine:** `fair_risk_engine_inputs()` gives the P10/P50/P90 and dispersion it expects.
- **Scenarios:** data exfiltration and web-application exploitation (early; thinner data than ransomware).
- **Sensitivity:** sweeps each observed vector's credibility k.
- **Config:** exploitation ceilings by attack surface; full `TEFConfig` round trip.
- **API:** `OrgTelemetry` and `VectorObservation` exported; `LognormalParams.p10` / `.p90`.

### Fixed
- The per-vector k sweep had no effect.
- Sensitivity sweeps ignored a custom config.
- `to_dict()` dropped `k_sensitivity`.
- Compare mode left a stale Profile B card.
- Web-app share citation corrected (DBIR 2026 basic web-app pattern, 10%); value unchanged.
- The UI showed a hardcoded version ([#2](https://github.com/security-decision-science/security-decision-labs/issues/2)).

### Corrected
- **Credibility k is judgment, not fitted:** the cited time-series fits measure burstiness, not between-organization differences. Values unchanged (6 / 10 / 10 / 40).

### Removed
- `OrganizationProfile.custom_susceptibility_prior` (use `config.yaml`).

## [1.1.4] - 2026-07-01
- Packaging only: PyPI project URLs. Code identical to 1.1.3.

## [1.1.3] - 2026-06-17

### Fixed
- **Telemetry over-counted events 4×** (yearly rates multiplied by quarters), so bands narrowed too fast.
- Duplicate vector observations were silently dropped; now rejected.
- A custom base rate was ignored by the sensitivity sweep.
- Compare mode showed percentage-point deltas as "%".
- TEF above 1 event/yr showed as ">100%"; now "2.1/yr".
- New warnings: very low detection coverage, partial telemetry, and a ceiling breach (as for the floor).

### Changed
- `positioned_mode` renamed `positioned_median` (it is the lognormal median), and related names.
- Peer percentile notes that peers are technology-neutral.

## [1.1.2] - 2026-06-17

### Fixed
- Supply-chain telemetry was silently ignored (name mismatch).

### New
- Warning when telemetry dominates the prior so much that the band may be overconfident.

## [1.1.1] - 2026-06-17

### Changed
- **Telemetry narrows the uncertainty band** as observations accumulate (Gamma-inspired update); the point estimate is unchanged.

## [1.1.0] - 2026-06-13

### New
- **Telemetry monitoring** (`pip install tef-estimator[telemetry]`): 7 collectors (DShield, CISA KEV, ransomware.live, GreyNoise, annual-report monitor, IRIS and IR-report importers), local database, rolling averages, baseline comparison.
- `watch` mode (its re-estimation did not work until 1.3.0).
- `tef-estimator telemetry` commands: `init`, `collect`, `status`, `baseline`, `compare`, `watch`.

## [1.0.2] - 2026-06-10

### New
- Data-freshness warnings (90 / 180 days) in estimates and `refresh check`.
- Markdown report export (`--output`).

### Removed
- All FAIR-CAM control-mapping claims: no empirical data supports them.

### Fixed
- An import error in the CLI and UI.

## [1.0.1] - 2026-05-27

### New
- **Cross-vector dampening k = 0.85 supported by data:** co-occurrence analysis of 10,037 VERIS incidents.

### Fixed
- DShield response parsing.

## [1.0.0] - 2026-05-25

### New
- **Web interface** (`tef-estimator ui`, `pip install tef-estimator[ui]`).

## [0.3.0] - 2026-05-24

### New
- **BEC scenario.**
- **Three-anchor consensus** made explicit, with a convergence check in the audit trail.
- Peer percentile; PyPI packaging; documentation; input validation.
- `refresh` fetchers for DShield, KEV, EPSS and ransomware.live (later removed; `refresh` now prints the update steps).

### Fixed
- Vector shares could sum to more than 100%.
- The peer percentile ignored the scenario.

## [0.2.0] - 2026-05-24

### New
- Four vector engines with their own floor, ceiling and positioning; cross-vector and within-vector dampening; three-tier output with calculation traces; CLI.

## [0.1.0] - 2026-05-24

### New
- Project structure, organization profile, three-anchor base rate.
