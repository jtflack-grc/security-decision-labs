# API Reference

## CLI

Entry point: `tef-estimator` (`pip install tef-estimator`; `tef-estimator --help`).

### estimate

Estimate TEF for an organization profile.

| Flag | Default | Description |
|------|---------|-------------|
| `--sector` | required | Industry sector ([Sector](#sector)) |
| `--revenue` | required | Annual revenue band ([Revenue Band](#revenue-band)) |
| `--geo` | required | Primary geography ([Geography](#geography)) |
| `--remote-access` | `none` | Exposed remote access types (repeatable) |
| `--employees` | None | Approximate employee count |
| `--critical-infra`, `--supply-chain`, `--recent-ma` (each with `--no-` form) | False | Critical infrastructure; significant supply chain role; M&A in last 18 months |
| `--base-rate` | None | Override the base rate (TEF, events per year; used as PERT(0.5×, 1×, 2×)) |
| `--scenario` | `ransomware` | `ransomware`, `bec`, `exfiltration`, `web_app`, `custom` |
| `--scenario-file` | None | Custom scenario JSON (with `--scenario custom`) |
| `--telemetry` | None | Org vector observations JSON, for Bühlmann blending |
| `--json`, `--brief`, `--full`, `--output` / `-o` PATH | off | Output mode, see below |
| `--live` / `--frozen` | config `telemetry_inputs` (`frozen`) | Live derives the dispersion shapes and the ransomware base rate's US victim count from the telemetry DB (one stderr line per input); frozen uses bundled values. [User guide](user-guide.md#telemetry-inputs-frozen-and-live) |
| `--telemetry-db` | `~/.tef-estimator/telemetry.db` | Telemetry database for `--live` (exits if missing) |

#### Output Modes

- **Default (Tier 2):** summary, distribution parameters, per-vector breakdown.
- **`--brief` (Tier 1):** one slide: vector bar, one-sentence interpretation.
- **`--full` (Tier 3):** audit trail: calculation traces, validation checks, base-rate derivation, data sources.
- **`--json`:** all three tiers. **`--output file.md`:** markdown report (summary tables, traces, sources).

```bash
tef-estimator estimate --sector manufacturing --revenue 100m_1b --geo us \
    --remote-access fortinet --employees 2000
tef-estimator estimate --sector financial --revenue 100m_1b --geo us --scenario bec --json
tef-estimator estimate --sector manufacturing --revenue 100m_1b --geo us --full -o report.md
```

### explain

Print every vector's calculation trace (like `estimate --full`, focused on the arithmetic). Always Tier 3, or markdown with `--output`.

Flags: as `estimate`, minus `--json`, `--brief`, `--full`, `--telemetry`.

```bash
tef-estimator explain --sector manufacturing --revenue 100m_1b --geo us
```

### compare

Compare TEF per vector for two profiles ("what if").

- Profile A: `--sector`, `--revenue`, `--geo`, `--remote-access`, `--employees`.
- Profile B: `--b-sector`, `--b-revenue`, `--b-geo`, `--b-remote-access`, `--b-employees`; each defaults to A's value.
- Both: `--scenario`, `--scenario-file`, `--json`, `--live` / `--frozen`, `--telemetry-db`.

```bash
# Impact of removing VPN exposure
tef-estimator compare --sector manufacturing --revenue 100m_1b --geo us \
    --remote-access fortinet --b-remote-access none
```

### sensitivity

Rank inputs by contribution to output variance (each varied across its PERT range, others at mode).

Flags: as `estimate`, minus `--critical-infra`, `--supply-chain`, `--recent-ma`, `--base-rate`, `--telemetry`, `--brief`, `--full`, `--output`.

```bash
tef-estimator sensitivity --sector manufacturing --revenue 100m_1b --geo us
```

```
SENSITIVITY ANALYSIS
============================================================
Baseline TEF: 0.27133 per year

Parameter                 Low          High            Range
------------------------------------------------------------
base_rate                 0.14006    0.55288    3.9x
vector_k                  0.22345    0.31921    1.4x
factor_k                  0.26239    0.28473    1.1x
```

`Range` = high/low output ratio; the top row is the input most worth refining.

### data

Inspect embedded data. `multipliers`, `base-rate` and `vectors` take `--scenario` (default `ransomware`).

| Subcommand | Shows |
|------------|-------|
| `data multipliers` | Sector and revenue multipliers, with sources |
| `data base-rate` | Base rate (TEF, events per year) per revenue band, with the derivation for $100M–1B |
| `data vectors` | Initial access vector proportions (PERT ranges) |
| `data peer-grid [--rebuild]` | Ransomware peer percentile grid (TEF for every sector/revenue/geography combination); `--rebuild` rebuilds the grids of all four built-in scenarios (a few seconds) |

```bash
tef-estimator data base-rate --scenario bec
```

### refresh

Reference data ships with the package; to update it, replace the `extracted.json` files under `src/tef_estimator/data/reference/`.

| Subcommand | Does |
|------------|------|
| `refresh check` | Each bundled source's edition and age; flags one past its cycle plus grace (`cadence_months` metadata: annual after 15 months, quarterly after 5). Estimates name editions rather than warn on freshness |
| `refresh snapshot` | Prints the update steps; fetches nothing (snapshots change only with a release). For current data use `telemetry collect` and live inputs |
| `refresh full` | `snapshot`, then `check` |

### scenario

```bash
tef-estimator scenario template [OUTPUT]   # starter JSON (default: custom_scenario.json)
tef-estimator scenario validate PATH       # check a scenario file before use
tef-estimator estimate --scenario custom --scenario-file PATH
```

### telemetry

Requires `pip install tef-estimator[telemetry]`. Every subcommand takes `--db-path PATH` (default `~/.tef-estimator/telemetry.db`).

| Subcommand | Does |
|------------|------|
| `telemetry init` | Create the SQLite database |
| `telemetry collect` | Run due collectors, then integrate new data |
| `telemetry integrate [--source ID]` | Rebuild daily series and rolling averages from stored data, no downloads (collection integrates only when it brings new data). Run after an upgrade that changes integration (e.g. to build the KEV additions series from earlier KEV data) |
| `telemetry status` | Per source: last success, consecutive failures, staleness flag, notes |
| `telemetry baseline` | Snapshot current 7-day rolling averages to `~/.tef-estimator/telemetry_baseline.json`; run after the initial collection |
| `telemetry compare` | Compare current rolling averages with the baseline; report signals |
| `telemetry watch` | Loop: collect due sources, integrate, compare, re-estimate watched profiles on signals |

#### telemetry collect

| Flag | Description |
|------|-------------|
| `--source ID` | Run only this collector |
| `--force` | Ignore cadence and reprocess unchanged downloads (otherwise skipped by CISA KEV, Ransomware.live, IRIS, vector benchmarks); Ransomware.live refetches only the months still filling (settled months come from the cache) |

- Cadence: DShield, CISA KEV, Ransomware.live daily; annual reports, IRIS reference, vector benchmarks weekly.
- DShield fills each port's daily series up to today; the first run backfills 90 days.
- Ransomware.live fetches attack dates from its monthly API at one request a minute: first run ~16 minutes, later 2–3.

#### telemetry compare

`--threshold` (default 0.20, range 0.0–1.0). Also lists **new metrics** (added to the baseline, compared from the next run) and **missing metrics** (usually a stopped collector). Sparse daily counts (`*_additions`) signal on an absolute change of at least 1.0/day (`sparse_min_delta`), not a percentage.

#### telemetry watch

| Flag | Default | Description |
|------|---------|-------------|
| `--interval` | 60 | Minutes between cycles |
| `--threshold` | 0.20 | Signal threshold |
| `--max-cycles` | forever | Stop after N cycles |
| `--profiles` | None | JSON list of profiles to re-estimate on signals; without it, signals are only reported |
| `--live` / `--frozen` | config `telemetry_inputs` | Input mode for re-estimates; each records its mode |

Profiles file: enum fields take CLI values; `scenario` is optional (default `ransomware`), per profile; names must be unique.

```json
[
  {"name": "plant-eu", "scenario": "ransomware", "sector": "manufacturing",
   "revenue_band": "100m_1b", "geography": "western_europe",
   "remote_access": ["fortinet"], "employee_count": 2000},
  {"name": "finance-us", "scenario": "bec", "sector": "financial",
   "revenue_band": "1b_10b", "geography": "us"}
]
```

#### Typical Workflow

```bash
tef-estimator telemetry init
tef-estimator telemetry collect --force
tef-estimator telemetry status
tef-estimator telemetry baseline
tef-estimator telemetry compare                              # later
tef-estimator telemetry watch --profiles profiles.json --live  # or continuously
```

### ui

NiceGUI web interface. Requires `pip install tef-estimator[ui]`.

Flags: `--port` (default 8080), `--reload` / `--no-reload` (hot reload for development; default off).

| Tab | Contents |
|-----|----------|
| Estimate | Profile sidebar; built-in and custom scenarios (`~/.tef-estimator/scenarios/`); live Tier 1; expandable Tier 2 with sensitivity tornado; compare mode |
| Telemetry (`[telemetry]`) | Status cards for 6 sources; (force-)collect, source filter; threshold, baseline/compare, signal table; 7-day rolling average chart |
| Scenarios | Builder (name, slug, 4 vectors × low/mode/high, base rate, overall share) with live sum check (~1.0); save/load JSON, preview, manage saved |

### Enum Values

CLI values are lowercase; Python members (`tef_estimator.data.common`) are the uppercase form, e.g. `Sector.MANUFACTURING`, `Geography.WESTERN_EUROPE`.

#### Sector

`manufacturing`, `financial`, `healthcare`, `education`, `professional`, `information`, `public`, `retail`, `trade`, `entertainment`, `administrative`, `real_estate`, `transportation`, `hospitality`, `construction`, `mining`, `utilities`, `agriculture`, `management`, `other`

#### Revenue Band

`under_10m`, `10m_100m`, `100m_1b`, `1b_10b`, `10b_100b`, `over_100b`

Python: `UNDER_10M`, `R_10M_100M`, `R_100M_1B`, `R_1B_10B`, `R_10B_100B`, `OVER_100B`.

#### Geography

`us`, `western_europe`, `asia_pacific`, `other`

#### Remote Access Type

`none`, `fortinet`, `palo_alto`, `cisco`, `sonicwall`, `citrix`, `other_vpn`, `rdp`

Fortinet, Cisco, Palo Alto and SonicWall (history of critical vulnerabilities) get elevated multipliers for both exploitation and credential vectors.

## Python API

Install from [PyPI](https://pypi.org/project/tef-estimator/): `pip install tef-estimator`.

### Quick Start

See the [README](../README.md#python-api). `result.to_dict()` returns all tiers as JSON-ready dicts.

### OrganizationProfile

`tef_estimator.profile`. Engine input describing the assessed organization (6–9 questions, 2–3 minutes).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sector`, `revenue_band`, `geography` | `Sector`, `RevenueBand`, `Geography` | required | NAICS-aligned sector; revenue band; primary geography |
| `remote_access` | `list[RemoteAccessType]` | `[NONE]` | Internet-exposed remote access types |
| `employee_count` | `int \| None` | `None` | Approximate headcount; >=1000 = large email footprint |
| `edge_vendors` | `list[RemoteAccessType]` | `[]` | Edge device vendors (exploitation vector) |
| `critical_infrastructure`, `supply_chain_provider`, `recent_ma` | `bool` | `False` | Critical infrastructure; significant supply chain role (elevates supply chain vector); M&A in last 18 months |
| `custom_base_rate` | `float \| None` | `None` | Override the base rate (TEF, events per year, > 0; used as PERT(0.5×, 1×, 2×)) |
| `telemetry` | `OrgTelemetry \| None` | `None` | Org vector observations (`tef_estimator.credibility`) for Bühlmann blending |

| Property (`bool` unless noted) | True when |
|----------|-------------|
| `has_vpn` / `has_rdp` | Any VPN remote access / RDP exposed |
| `has_no_remote_access` | `remote_access` is `[NONE]` |
| `has_vulnerable_vpn_vendor` | Fortinet, Cisco, Palo Alto or SonicWall |
| `has_large_email_footprint` | `employee_count >= 1000` |
| `is_cloud_primary` | No remote access and no edge vendors |
| `employee_band_label` (`str`) | `"<50"`, `"50–500"`, `"500–5,000"`, `"5,000–50,000"`, `"50,000+"` or `"unknown"` |

`summary()` returns one line, e.g. `"Financial | 1B–10B | Western Europe | VPN: cisco, rdp | ~5,000 employees"`.

### TEFEngine

`tef_estimator.engine`. Runs the scenario's active vector engines (all four for built-in scenarios), applies dampening, validates, returns a `TEFResult`.

```python
TEFEngine(
    scenario: ScenarioDefinition | None = None,
    dampening: DampeningConfig | None = None,
    base_rate_override: PERTRange | None = None,
    config: TEFConfig | None = None,
)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `scenario` | `RansomwareScenario()` | Threat scenario |
| `dampening` | From `config` | Dampening coefficients; takes precedence over `config` |
| `base_rate_override` | None (`base_rate_for(band)`) | Base rate PERT override, all revenue bands |
| `config` | `get_config()` | Susceptibility prior, dampening defaults, credibility k; from `config.yaml` |

| Method | Returns | Notes |
|--------|---------|-------|
| `estimate(profile)` | `TEFResult` | With `profile.telemetry`: Bühlmann credibility blending (point estimate) and Gamma-inspired posterior band contraction; see `docs/technical-reference.md` §8 |
| `compare(profile_a, profile_b)` | `CompareResult` | `total_delta` (positive = B higher), `vector_deltas`, `explanation`, `result_a`, `result_b`, `render_text()`, `to_dict()` |
| `base_rate_for(band)` | `PERTRange` | Base rate (TEF) for a revenue band: LEF ÷ susceptibility (built-in scenarios; ransomware live count in live mode) or a custom scenario's consensus |
| `sensitivity(profile)` | `SensitivityResult` | `baseline_median`, `ranked` (list of `(param_name, pert_range, range_multiple)`), `tornado_data`, `render_text()` |

Live inputs (what `--live` does):

```python
from tef_estimator.telemetry.db import TelemetryDB
from tef_estimator.telemetry.derive import live_config

config, fits = live_config(TelemetryDB())  # each fit keeps the bundled value, with a reason, when it cannot run
engine = TEFEngine(config=config)
```

### TEFResult

`tef_estimator.result`. Estimation output: three tiers plus rendering.

| Property | Description |
|----------|-------------|
| `scenario_name` | "Ransomware", "Business Email Compromise", "Data Exfiltration", "Web Application Exploitation" or custom |
| `profile_summary` | Profile description |
| `vectors` | `list[VectorEstimate]` |
| `total_positioned_median` | The main TEF number (events per year); `total_positioned_low` / `_high` are the bounds |
| `total_floor` | Observed-LEF floor for the scenario and revenue tier × adjusted sector multiplier |
| `total_ceiling` | Sum of vector ceilings (mixed units, not a bound; use each vector's `ceiling`). Ceilings are audit-trail sanity checks, never caps |
| `lognormal`, `base_rate`, `dampening` | `LognormalParams`, `PERTRange`, `DampeningConfig` used |
| `base_rate_derivation` | `list[str]`: the base-rate derivation lines of the audit trail |
| `peer_percentile` | `int \| None`, within revenue band peers |
| `tef_text` | `str`, e.g. "0.45 per year (about once every 2.2 years)" |
| `chance_at_least_one` | `float`, 1 − e^(−median): chance of at least one attempt in a year (Poisson) |
| `median_recurrence_years` | 1 / positioned median |
| `dispersion` | `{"total": DispersionParams, "vectors": {key: DispersionParams}}`; `total_dispersion` is the total's (`DispersionParams \| None`); `has_dispersion` = any non-Poisson shape |

| Method | Returns |
|--------|---------|
| `sample_annual_counts(size=10_000, rng=None)` | Annual event counts: lognormal rate, then dispersion shock, then Poisson |
| `fair_risk_engine_inputs(basis="detrended")` | TEF fields for fair-risk-engine's `FAIRInputs`: `tef_model='lognormal'`, `tef_p10`/`tef_p50`/`tef_p90` (from `lognormal`; positioned low/high are ~P5/P95, not P10/P90), `tef_dispersion` (total annual shape, `None` for Poisson). `basis="raw"` = trend-included shape, the sensitivity bound |
| `fair_risk_engine_text()`, `dispersion_text()` | One-line FAIR inputs (also in the UI) / dispersion block, both in `full_report()` |
| `brief_report()`, `full_report()` | Tier 1 (one slide) / Tier 3 (everything) |
| `distribution_text()`, `vector_breakdown_text()` | Tier 2: lognormal + PERT params / per-vector ranges |
| `plain_language_summary()`, `to_markdown()`, `to_dict()` | One paragraph / markdown report with tables / all tiers |

Module helper `recurrence_text(rate)`: a rate in words, e.g. `recurrence_text(0.446)` → "about once every 2.2 years", `recurrence_text(1.6)` → "about 1.6 times a year".

```python
from fair_risk_engine import FAIRCalculator, FAIRInputs
inputs = FAIRInputs(**result.fair_risk_engine_inputs(), susc_p10=20, susc_p50=40, susc_p90=70,
                    response_p10=20_000, response_p50=75_000, response_p90=250_000)
```

#### Three-Tier Access

```python
# Tier 1 (executives)
s = result.summary
s.positioned_median        # 0.446 (events per year)
s.tef_text                 # "0.45 per year (about once every 2.2 years)"
s.chance_at_least_one      # 0.360
s.recurrence_years         # 2.24
s.peer_percentile          # set by the CLI and UI; None from engine.estimate() alone
                           # (tef_estimator.peer.compute_and_set_percentile(result, revenue_band, load_grid(path)))
s.vector_bar               # [{"vector": "Exploitation", "share": 0.28}, ...]
s.one_sentence             # Board-ready plain language
# JSON (to_dict()["summary"]): positioned_median/_low/_high, tef_text, chance_at_least_one,
# recurrence_years, peer_percentile, peer_context, one_sentence, vector_bar

# Tier 2 (analyst)
a = result.analysis
a.lognormal                # LognormalParams(mu=-0.807, sigma=0.786)
a.pert                     # PERTRange(0.121, 0.446, 1.606)
a.vectors                  # List[VectorEstimate]

# Tier 3 (reviewer)
au = result.audit
au.traces, au.validation_checks, au.warnings, au.data_sources, au.base_rate, au.dampening
```

### Scenarios

`tef_estimator.data.scenarios`. Built-ins: `RansomwareScenario`, `BECScenario`, `ExfiltrationScenario`, `WebAppScenario`.

#### ScenarioDefinition Protocol

`tef_estimator.data.scenarios.base.ScenarioDefinition`. A custom scenario is any class satisfying it; the engine runs only `active_vectors`, so a subset is allowed.

| Member | Type |
|--------|------|
| `scenario_name`, `scenario_slug` | `str` (e.g. `"My Threat"`, `"my_threat"`) |
| `active_vectors` | `list[str]` (e.g. `["exploitation", "credential", ...]`) |
| `vector_proportions`, `base_rate_triangulation` | `dict[str, PERTRange]` (`base_rate_triangulation`: `consensus` and/or `susceptibility_prior`) |
| `overall_share` | `float` |
| `sector_shares` / `revenue_shares` | `dict[Sector, float \| None]` / `dict[RevenueBand, float]` |
| `credential_tempo`, `exploitation_scanning` | `dict` |
| `output_templates` | `dict[str, str]` |
| `adjusted_sector_multiplier(sector)`, `adjusted_revenue_multiplier(band)` | method → `float` |

All but the two methods are properties. Optional: `base_rate_lef` and `floor_lef` (dicts, as in `ransomware.json`): a one-population base rate and per-tier floors; without them the engine uses `consensus` and the IRIS all-incident floor × `overall_share`.

#### Built-in Scenarios

```python
from tef_estimator.engine import TEFEngine
from tef_estimator.data.common import RevenueBand, Sector
from tef_estimator.data.scenarios.ransomware import RansomwareScenario
from tef_estimator.data.scenarios.bec import BECScenario

rw, bec = RansomwareScenario(), BECScenario()
TEFEngine(scenario=rw).base_rate_for(RevenueBand.R_100M_1B)   # PERTRange (TEF per year)
bec.vector_proportions["phishing"]                            # PERTRange
rw.adjusted_sector_multiplier(Sector.MANUFACTURING)           # float
```

### Triangulation

`tef_estimator.triangulation`. Consensus check for custom scenarios with a consensus base rate; the built-in scenarios have none.

| Function | Returns | Description |
|----------|---------|-------------|
| `extract_anchors(triangulation)` | `(anchors, consensus)` | Split a scenario's `base_rate_triangulation` into named anchors and the consensus PERT |
| `triangulate(anchors, actual_consensus=None)` | `TriangulationResult` | Suggest a consensus PERT; optionally validate an analyst-set one |

```python
from tef_estimator.data.common import PERTRange
from tef_estimator.triangulation import triangulate, extract_anchors

anchors, consensus = extract_anchors({"consensus": PERTRange(0.008, 0.025, 0.07)})
tri = triangulate(anchors, actual_consensus=consensus)
anchors                   # {} (no independent anchors)
tri.suggested             # PERTRange(0.008, 0.025, 0.07): the analyst consensus
tri.convergence_ratio     # 1.0
tri.is_convergent         # True
tri.validation            # ["No independent anchors provided — using analyst consensus only", "Analyst consensus: PERT(0.0080, 0.0250, 0.0700)"]
```

### TEFConfig

`tef_estimator.config`. All tunable parameters: bundled `config.yaml`, with `~/.tef-estimator/config.yaml` deep-merged on top; the web UI Configuration panel adjusts them at runtime.

```python
from tef_estimator.config import TEFConfig, get_config, SusceptibilityPrior

cfg = get_config()                     # bundled + user overrides
cfg.susceptibility_prior.mode          # 0.20 (scenario priors apply unless you change this)
cfg.dampening.vector_k                 # 0.85
cfg.credibility_k.exploitation         # 6.0 (asserted; technical reference §8.3)

cfg = TEFConfig()
cfg.susceptibility_prior = SusceptibilityPrior(low=0.05, mode=0.10, high=0.15)
engine = TEFEngine(config=cfg)
```

- `TEFConfig.from_yaml(path)`: load a config file; omitted keys fall back to bundled defaults.
- `TEFConfig.dispersion_for(kind, name)`: resolve a configured dispersion entry (`kind` = `"vectors"` or `"scenarios"`).

### DampeningConfig

`tef_estimator.data.common`. Without a `dampening` argument, `TEFEngine` uses `TEFConfig.dampening`. `*_source` fields hold provenance strings, defaulting from bundled reference data.

```python
from tef_estimator.data.common import DampeningConfig

engine = TEFEngine(dampening=DampeningConfig(factor_k=0.60, vector_k=0.90, max_composite=4.0))
```

### PERTRange

`tef_estimator.data.common`. Named tuple `(low, mode, high)`.

```python
PERTRange(low=0.01, mode=0.03, high=0.10).mode  # 0.03
```

### DispersionParams

`tef_estimator.distributions`. Burstiness of the rate over time (Gamma-mixed rate, negative binomial counts); see technical reference §8.7.

| Field | Meaning |
|---|---|
| `shape_r` | Monthly Gamma shape; `None` = Poisson |
| `timescale` | `"month"` (default; independent months, annual shape 12 r) or `"year"` (shock lasts all year; annual shape r) |
| `basis` | `"detrended"` (default) or `"raw"` |
| `source` | Citation, required when `shape_r` is set |
| `raw_shape_r` | Raw fit kept as the sensitivity bound |

```python
import numpy as np
from tef_estimator.distributions import DispersionParams, sample_annual_counts

d = DispersionParams(shape_r=22.5, timescale="year", basis="detrended",
                     source="CISA KEV, May 2023-Sep 2026", raw_shape_r=10.5)
d.annual_shape        # 22.5 ("month" would give 270.0 = 12 r)
d.vmr(5.0)            # 1 + 5/22.5
d.as_raw()            # the raw fit, for sensitivity
sample_annual_counts(np.full(10_000, 0.05), d)   # one count per annual rate
```

### LognormalParams

`tef_estimator.distributions`. Fitted lognormal; the recommended distribution for Monte Carlo.

```python
ln = result.lognormal
ln.mu, ln.sigma   # -0.807, 0.786 (ln-space)
ln.median         # 0.446 (the positioned median)
ln.p5, ln.p95     # 0.122, 1.624
ln.mean           # 0.607 (arithmetic, above the median)
ln.sample(size=10000)  # numpy array of draws
```

### Telemetry

`tef_estimator.telemetry`. Requires `pip install tef-estimator[telemetry]`.

| Module | Key API | Does |
|--------|---------|------|
| `.db` | `TelemetryDB(db_path=...)`: `initialize()` (idempotent), `connect()`, `get_source_health(conn)` | SQLite; default `~/.tef-estimator/telemetry.db`, `None` = in-memory |
| `.collectors` | `collect_all(db)`, `get_all_collectors()` | Six `Collector`s (`SOURCE_ID`, `CADENCE_DAYS`, `collect(db) -> CollectionSummary`) |
| `.integrator` | `run_integration(db, source_filter=None, lookback_days=...)` | Dedup, gap interpolation, 7d/30d rolling averages |
| `.compare` | `snapshot_baseline(db)`, `compare(db, threshold=0.20)` | Baseline of 7d averages; change detection |
| `.scheduler` | `run_due_collections(db, force=False, source_filter=None)` | Due collectors, then integrate |
| `.watch` | `run_once(db, profiles=None, threshold=0.20, live=None)`, `WatchProfile` | One collect → integrate → compare → re-estimate cycle |
| `.derive` | `live_config(db)` | Live-derived `TEFConfig` ([TEFEngine](#tefengine)) |

```python
from tef_estimator.telemetry.db import TelemetryDB
from tef_estimator.telemetry.compare import snapshot_baseline, compare

db = TelemetryDB()
db.initialize()
snapshot_baseline(db)
result = compare(db, threshold=0.20)
for s in result.signals:
    print(f"{s.source_id}/{s.metric_name}: {s.baseline_value:.1f} → {s.current_value:.1f} ({s.pct_change:+.0%})")
```

Collectors and cadence: [telemetry collect](#telemetry-collect). IRIS and vector benchmarks read bundled JSON (`data/reference/iris/extracted.json`, `data/reference/vectors/initial_access_vectors.json`) and insert nothing if the file hash is unchanged; a newly bundled edition yields new values that compare reports as signals.
