# API Reference

## CLI

All commands are available via the `tef-estimator` entry point after installation.

```bash
pip install tef-estimator
tef-estimator --help
```

### estimate

Estimate TEF for an organization profile.

```bash
tef-estimator estimate [OPTIONS]
```

#### Required Options

| Flag | Type | Description |
|------|------|-------------|
| `--sector` | Enum | Industry sector (see Sector values below) |
| `--revenue` | Enum | Annual revenue band (see Revenue Band values below) |
| `--geo` | Enum | Primary geography |

#### Optional Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--remote-access` | List[Enum] | `none` | Remote access types exposed (can specify multiple) |
| `--employees` | int | None | Approximate employee count |
| `--critical-infra` | bool | False | Is this a critical infrastructure organization? |
| `--supply-chain` | bool | False | Significant supply chain provider role? |
| `--recent-ma` | bool | False | Merger or acquisition in last 18 months? |
| `--base-rate` | float | None | Override the triangulated base rate (annual probability) |
| `--scenario` | Enum | `ransomware` | Threat scenario: `ransomware`, `bec`, `exfiltration`, `web_app` or `custom` |
| `--scenario-file` | Path | None | JSON file defining a custom scenario (with `--scenario custom`) |
| `--telemetry` | Path | None | JSON file with your organization's vector observations, for Bühlmann blending |
| `--json` | bool | False | Output as JSON (all three tiers) |
| `--brief` | bool | False | Tier 1 summary only |
| `--full` | bool | False | Tier 3 full audit trail |
| `--output` / `-o` | Path | None | Write markdown report to file |

#### Output Modes

- **Default (Tier 2):** Brief summary + distribution parameters + per-vector breakdown
- **`--brief` (Tier 1):** One-slide summary with vector bar and one-sentence interpretation
- **`--full` (Tier 3):** Complete audit trail with calculation traces, validation checks, triangulation, data sources
- **`--json`:** All three tiers as structured JSON (suitable for programmatic consumption)
- **`--output file.md`:** Write a structured markdown report to file (summary tables, traces, sources)

#### Examples

```bash
# Basic ransomware estimate
tef-estimator estimate --sector manufacturing --revenue 100m_1b --geo us

# With technology exposure
tef-estimator estimate --sector manufacturing --revenue 100m_1b --geo us \
    --remote-access fortinet --employees 2000

# BEC scenario
tef-estimator estimate --sector financial --revenue 100m_1b --geo us --scenario bec

# Override base rate
tef-estimator estimate --sector healthcare --revenue 1b_10b --geo western_europe \
    --base-rate 0.02

# JSON output for programmatic use
tef-estimator estimate --sector manufacturing --revenue 100m_1b --geo us --json

# Full audit trail
tef-estimator estimate --sector manufacturing --revenue 100m_1b --geo us --full

# Export to markdown file
tef-estimator estimate --sector manufacturing --revenue 100m_1b --geo us -o report.md
```

### explain

Print the full calculation trace for every vector. Equivalent to `estimate --full` but focused on the arithmetic.

```bash
tef-estimator explain [OPTIONS]
```

Takes the profile options of `estimate` (`--sector`, `--revenue`, `--geo`, `--remote-access`, `--employees`, `--critical-infra`, `--supply-chain`, `--recent-ma`, `--base-rate`) plus `--scenario`, `--scenario-file` and `--output` / `-o`; it has no `--json`, `--brief`, `--full` or `--telemetry`. Always outputs Tier 3 (or writes markdown if `--output` is given).

#### Example

```bash
tef-estimator explain --sector manufacturing --revenue 100m_1b --geo us
```

### compare

Compare TEF estimates for two profiles. Useful for "what if" analysis — toggle one factor and see how TEF changes per-vector.

```bash
tef-estimator compare [OPTIONS]
```

#### Profile A Options

`--sector`, `--revenue`, `--geo`, `--remote-access`, `--employees`. Also `--scenario`, `--scenario-file` and `--json`, which apply to both profiles.

#### Profile B Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--b-sector` | Enum | Same as A | Profile B sector |
| `--b-revenue` | Enum | Same as A | Profile B revenue band |
| `--b-geo` | Enum | Same as A | Profile B geography |
| `--b-remote-access` | List[Enum] | Same as A | Profile B remote access |
| `--b-employees` | int | Same as A | Profile B employee count |

Any Profile B option that's not specified defaults to Profile A's value. This means you typically only change one factor.

#### Examples

```bash
# Impact of removing VPN exposure
tef-estimator compare \
    --sector manufacturing --revenue 100m_1b --geo us --remote-access fortinet \
    --b-remote-access none

# Sector comparison
tef-estimator compare \
    --sector manufacturing --revenue 100m_1b --geo us \
    --b-sector financial

# JSON output
tef-estimator compare \
    --sector manufacturing --revenue 100m_1b --geo us --remote-access fortinet \
    --b-remote-access none --json
```

### sensitivity

Rank input parameters by contribution to output variance. Varies each parameter across its PERT range while holding others at mode.

```bash
tef-estimator sensitivity [OPTIONS]
```

Takes `--sector`, `--revenue`, `--geo`, `--remote-access` and `--employees`, plus `--scenario`, `--scenario-file` and `--json`. It has no `--critical-infra`, `--supply-chain`, `--recent-ma`, `--base-rate` or `--telemetry`.

#### Example

```bash
tef-estimator sensitivity --sector manufacturing --revenue 100m_1b --geo us
```

Output:

```
SENSITIVITY ANALYSIS
============================================================
Baseline TEF: 0.03651 (3.65%)

Parameter                 Low          High            Range
------------------------------------------------------------
base_rate                 0.01217    0.12169    10.0x
vector_k                  0.03006    0.04295    1.4x
factor_k                  0.03300    0.04177    1.3x
```

The `Range` column shows how many times the output changes when that parameter moves from low to high. Base rate at 10.0x dominates — refining the base rate is the highest-value data improvement.

### data

Inspect the embedded empirical data. All data subcommands accept `--scenario` (default: `ransomware`).

#### data multipliers

Show sector and revenue band multipliers with source citations.

```bash
tef-estimator data multipliers
tef-estimator data multipliers --scenario bec
```

#### data base-rate

Show the three-anchor base rate triangulation.

```bash
tef-estimator data base-rate
tef-estimator data base-rate --scenario bec
```

#### data vectors

Show initial access vector proportions (PERT ranges).

```bash
tef-estimator data vectors
tef-estimator data vectors --scenario bec
```

#### data peer-grid

Show or rebuild the peer percentile grid. The grid contains TEF estimates for all sector/revenue/geography combinations, used to compute peer percentiles.

```bash
# Show existing grid
tef-estimator data peer-grid

# Rebuild (takes a few seconds)
tef-estimator data peer-grid --rebuild
```

### refresh

Data freshness validation. Reference data ships with the package.

#### refresh check

Validate data freshness by checking the vintage of bundled reference data. Shows per-source age (e.g. "17d old, extracted 2026-05-24"), reports missing sources, and warns when data exceeds 90 days (warning) or 180 days (stale). Freshness warnings also appear automatically in estimation output.

```bash
tef-estimator refresh check
```

To update reference data, replace the `extracted.json` files under `src/tef_estimator/data/reference/`.

#### refresh snapshot

Fetch API data (DShield, KEV, EPSS, Ransomware.live).

#### refresh full

Full refresh: `snapshot`, then `check`.

### scenario

Custom scenario management.

```bash
tef-estimator scenario template [OUTPUT]   # write a starter JSON (default: custom_scenario.json)
tef-estimator scenario validate PATH       # check a scenario file before use
tef-estimator estimate --scenario custom --scenario-file PATH
```

### telemetry

Continuous telemetry monitoring. Requires the `[telemetry]` extra: `pip install tef-estimator[telemetry]`.

#### telemetry init

Initialize the telemetry SQLite database at `~/.tef-estimator/telemetry.db`.

```bash
tef-estimator telemetry init [--db-path PATH]
```

#### telemetry collect

Run telemetry collectors. Without `--force`, only runs sources that are due according to their cadence (DShield/KEV/Ransomware.live/GreyNoise: daily, annual reports/IRIS reference/vector benchmarks: weekly).

```bash
tef-estimator telemetry collect                    # Run due collectors only
tef-estimator telemetry collect --force            # Run all collectors regardless of schedule
tef-estimator telemetry collect --source dshield   # Run only DShield
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--source` | str | None | Run only this collector |
| `--force` | bool | False | Ignore cadence schedule |
| `--db-path` | Path | None | Custom database path |

#### telemetry status

Show health status for all data sources.

```bash
tef-estimator telemetry status
```

Displays: last success timestamp, consecutive failures, staleness flag, and notes for each source.

#### telemetry baseline

Snapshot current 7-day rolling averages as the baseline for future comparisons.

```bash
tef-estimator telemetry baseline
```

Saves to `~/.tef-estimator/telemetry_baseline.json`. Run this after an initial collection cycle to establish the comparison point.

#### telemetry compare

Compare current rolling averages against the stored baseline and report signals.

```bash
tef-estimator telemetry compare                     # Default 20% threshold
tef-estimator telemetry compare --threshold 0.30    # 30% threshold
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--threshold` | float | 0.20 | Signal threshold (0.0-1.0) |
| `--db-path` | Path | None | Custom database path |

#### telemetry watch

Run the full pipeline continuously: collect due sources, integrate, compare against baseline, and re-estimate TEF profiles when signals are detected.

```bash
tef-estimator telemetry watch                        # Default: check every 60 minutes
tef-estimator telemetry watch --interval 30          # Check every 30 minutes
tef-estimator telemetry watch --max-cycles 5         # Stop after 5 cycles
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--interval` | int | 60 | Minutes between cycles |
| `--threshold` | float | 0.20 | Signal threshold |
| `--max-cycles` | int | None | Stop after N cycles (default: run forever) |
| `--db-path` | Path | None | Custom database path |

#### Typical Workflow

```bash
# 1. Initialize the database
tef-estimator telemetry init

# 2. Run initial collection
tef-estimator telemetry collect --force

# 3. Check source health
tef-estimator telemetry status

# 4. Establish baseline
tef-estimator telemetry baseline

# 5. Later: check for changes
tef-estimator telemetry compare

# 6. Or: run continuously
tef-estimator telemetry watch --interval 60
```

### ui

Launch the NiceGUI web interface. Requires the `[ui]` extra: `pip install tef-estimator[ui]`.

```bash
tef-estimator ui [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--port` | int | `8080` | Port to run the web UI on |
| `--reload` | bool | `False` | Enable hot reload for development |

The web UI has three tabs:

**Estimate tab:**
- Sidebar with all profile inputs (sector, revenue, geography, remote access, employees)
- Scenario selector (Ransomware, BEC, Data Exfiltration, Web App Exploitation, plus any custom scenarios from `~/.tef-estimator/scenarios/`)
- Live Tier 1 display: annual probability, recurrence, peer percentile, vector breakdown chart
- Expandable Tier 2: distribution parameters, per-vector breakdown, sensitivity tornado chart
- Compare mode: toggle a second profile panel for side-by-side comparison

**Telemetry tab** (requires `[telemetry]` extra):
- Source health dashboard: status cards for all 7 data sources
- Collection controls: collect/force-collect buttons, source filter dropdown
- Change detection: threshold slider, baseline/compare buttons, signal table
- Collection history: 7-day rolling average time series chart

**Scenarios tab:**
- Custom scenario builder: name, slug, vector proportions (4 vectors x low/mode/high), base rate, overall share
- Live sum indicator for vector proportions (validates ~1.0)
- Save/load JSON, preview estimate with current profile, saved scenario management

### Enum Values

#### Sector

`manufacturing`, `financial`, `healthcare`, `education`, `professional`, `information`, `public`, `retail`, `trade`, `entertainment`, `administrative`, `real_estate`, `transportation`, `hospitality`, `construction`, `mining`, `utilities`, `agriculture`, `management`, `other`

#### Revenue Band

`under_10m`, `10m_100m`, `100m_1b`, `1b_10b`, `10b_100b`, `over_100b`

#### Geography

`us`, `western_europe`, `asia_pacific`, `other`

#### Remote Access Type

`none`, `fortinet`, `palo_alto`, `cisco`, `sonicwall`, `citrix`, `other_vpn`, `rdp`

Note: VPN vendors known to have had critical vulnerabilities (Fortinet, Cisco, Palo Alto, SonicWall) receive elevated multipliers for both exploitation and credential vectors.

## Python API

### Installation

From [PyPI](https://pypi.org/project/tef-estimator/):

```bash
pip install tef-estimator
```

### Quick Start

```python
from tef_estimator.engine import TEFEngine
from tef_estimator.profile import OrganizationProfile
from tef_estimator.data.common import Sector, RevenueBand, Geography, RemoteAccessType
from tef_estimator.data.scenarios.ransomware import RansomwareScenario
from tef_estimator.data.scenarios.bec import BECScenario

profile = OrganizationProfile(
    sector=Sector.MANUFACTURING,
    revenue_band=RevenueBand.R_100M_1B,
    geography=Geography.US,
    remote_access=[RemoteAccessType.FORTINET],
    employee_count=2000,
)

result = TEFEngine(scenario=RansomwareScenario()).estimate(profile)

# Tier 1: Summary
print(result.brief_report())

# Tier 3: Full audit trail
print(result.full_report())

# JSON (all tiers)
import json
print(json.dumps(result.to_dict(), indent=2))
```

### OrganizationProfile

**Module:** `tef_estimator.profile`

The input to the estimation engine. Represents the organization being assessed. Completable in 2-3 minutes with 6-9 questions.

#### Constructor Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `sector` | `Sector` | Yes | — | Industry sector (NAICS-aligned) |
| `revenue_band` | `RevenueBand` | Yes | — | Annual revenue band |
| `geography` | `Geography` | Yes | — | Primary operating geography |
| `remote_access` | `list[RemoteAccessType]` | No | `[NONE]` | Remote access types exposed to the internet |
| `employee_count` | `int \| None` | No | `None` | Approximate employee count. Used for email footprint (>=1000 = large). |
| `edge_vendors` | `list[RemoteAccessType]` | No | `[]` | Edge device vendors (for exploitation vector) |
| `critical_infrastructure` | `bool` | No | `False` | Critical infrastructure designation |
| `supply_chain_provider` | `bool` | No | `False` | Significant supply chain role (elevates supply chain vector) |
| `recent_ma` | `bool` | No | `False` | M&A in last 18 months (integration risk) |
| `custom_base_rate` | `float \| None` | No | `None` | Override the triangulated base rate (annual probability 0-1) |

#### Properties

| Property | Returns | Description |
|----------|---------|-------------|
| `has_vpn` | `bool` | Whether any VPN remote access is configured |
| `has_rdp` | `bool` | Whether RDP is exposed |
| `has_no_remote_access` | `bool` | Whether `remote_access` is `[NONE]` |
| `has_vulnerable_vpn_vendor` | `bool` | Whether VPN vendor has extensive CVE history (Fortinet, Cisco, Palo Alto, SonicWall) |
| `has_large_email_footprint` | `bool` | Whether `employee_count >= 1000` |
| `is_cloud_primary` | `bool` | No remote access and no edge vendors |
| `employee_band_label` | `str` | Human-readable band: "<50", "50-500", "500-5,000", etc. |

#### Usage

```python
profile = OrganizationProfile(
    sector=Sector.FINANCIAL,
    revenue_band=RevenueBand.R_1B_10B,
    geography=Geography.WESTERN_EUROPE,
    remote_access=[RemoteAccessType.CISCO, RemoteAccessType.RDP],
    employee_count=5000,
    supply_chain_provider=True,
)

print(profile.summary())
# "Financial | 1B–10B | Western Europe | VPN: cisco, rdp | ~5,000 employees"

print(profile.has_vulnerable_vpn_vendor)  # True (Cisco)
print(profile.has_large_email_footprint)  # True (5000 >= 1000)
```

### TEFEngine

**Module:** `tef_estimator.engine`

The orchestrator. Takes a profile, runs all four vector engines, applies dampening, performs validation, and produces a `TEFResult`.

#### Constructor

```python
TEFEngine(
    scenario: ScenarioDefinition | None = None,
    dampening: DampeningConfig | None = None,
    base_rate_override: PERTRange | None = None,
    config: TEFConfig | None = None,
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scenario` | `ScenarioDefinition` | `RansomwareScenario()` | Threat scenario to use |
| `dampening` | `DampeningConfig` | From `config` | Override dampening coefficients (takes precedence over `config`) |
| `base_rate_override` | `PERTRange` | Scenario's consensus | Override the base rate PERT |
| `config` | `TEFConfig` | `get_config()` | Configuration for susceptibility prior, dampening defaults, and credibility k. Loaded from `config.yaml` by default. |

#### Methods

##### estimate(profile) -> TEFResult

Run the full TEF estimation.

```python
engine = TEFEngine(scenario=RansomwareScenario())
result = engine.estimate(profile)
```

Returns a `TEFResult` with the complete estimation output. If `profile.telemetry` is provided, the estimation includes Bühlmann credibility blending (point estimate) and Gamma-inspired posterior band contraction (uncertainty narrowing). See `docs/technical-reference.md` §8 for details and limitations.

##### compare(profile_a, profile_b) -> CompareResult

Compare TEF estimates for two profiles. Returns per-vector deltas and a plain-language explanation.

```python
engine = TEFEngine()
diff = engine.compare(profile_a, profile_b)

print(diff.total_delta)        # Float: positive = B is higher
print(diff.vector_deltas)      # Dict[str, float]
print(diff.explanation)        # Human-readable explanation
print(diff.render_text())      # Formatted text output
print(diff.to_dict())          # JSON-serializable dict
```

##### sensitivity(profile) -> SensitivityResult

Rank parameters by contribution to output variance.

```python
result = engine.sensitivity(profile)

print(result.baseline_median)   # Baseline TEF median
print(result.ranked)            # List of (param_name, pert_range, range_multiple)
print(result.tornado_data)      # List of dicts for tornado chart rendering
print(result.render_text())     # Formatted text output
```

### TEFResult

**Module:** `tef_estimator.result`

The complete estimation output. Provides three tiers of access plus rendering methods.

#### Key Properties

| Property | Type | Description |
|----------|------|-------------|
| `scenario_name` | `str` | "Ransomware", "Business Email Compromise", "Data Exfiltration", "Web Application Exploitation" or a custom name |
| `profile_summary` | `str` | Human-readable profile description |
| `vectors` | `list[VectorEstimate]` | Per-vector estimation results |
| `total_positioned_median` | `float` | The main TEF number (annual probability) |
| `total_positioned_low` | `float` | Lower bound |
| `total_positioned_high` | `float` | Upper bound |
| `total_floor` | `float` | IRIS-derived floor |
| `total_ceiling` | `float` | Scanning-derived ceiling |
| `lognormal` | `LognormalParams` | Fitted lognormal distribution |
| `base_rate` | `PERTRange` | Base rate used in estimation |
| `dampening` | `DampeningConfig` | Dampening coefficients used |
| `peer_percentile` | `int \| None` | Percentile within revenue band peers |
| `annual_probability_pct` | `str` | Formatted: "2.1%" |
| `median_recurrence_years` | `float` | 1 / positioned_median |
| `dispersion` | `dict` | `{"total": DispersionParams, "vectors": {key: DispersionParams}}` (1.2.0) |
| `total_dispersion` | `DispersionParams \| None` | Dispersion of the scenario total |
| `has_dispersion` | `bool` | True when any non-Poisson shape is set |

`sample_annual_counts(size=10_000, rng=None)` returns annual event counts: rate from the lognormal, then the dispersion shock, then Poisson. `dispersion_text()` renders the dispersion block shown in `full_report()`.

`fair_risk_engine_inputs(basis="detrended")` returns the TEF fields for fair-risk-engine's `FAIRInputs`: `tef_model='lognormal'`, `tef_p10`, `tef_p50`, `tef_p90` (read off `lognormal`; the positioned low/high are about P5/P95, not P10/P90) and `tef_dispersion` (the total annual shape, `None` for Poisson). `basis="raw"` returns the trend-included shape, the sensitivity bound. `fair_risk_engine_text()` renders the same as one line, printed in `full_report()` and the UI.

```python
from fair_risk_engine import FAIRCalculator, FAIRInputs
inputs = FAIRInputs(**result.fair_risk_engine_inputs(), susc_p10=20, susc_p50=40, susc_p90=70,
                    response_p10=20_000, response_p50=75_000, response_p90=250_000)
```

#### Three-Tier Access

```python
# Tier 1: Summary (for slides and executives)
summary = result.summary
summary.positioned_median      # 0.0621
summary.annual_probability_pct  # "6.2%"
summary.recurrence_years     # 16.1
summary.peer_percentile      # set by the CLI and UI; None from engine.estimate() alone
                             # (call tef_estimator.peer.compute_and_set_percentile(result, revenue_band, load_grid(path)))
summary.vector_bar           # [{"vector": "Exploitation", "share": 0.28}, ...]
summary.one_sentence         # Board-ready plain language

# Tier 2: Analysis (for the analyst)
analysis = result.analysis
analysis.lognormal           # LognormalParams(mu=-2.778, sigma=1.263)
analysis.pert                # PERTRange(0.0077, 0.0621, 0.492)
analysis.vectors             # List[VectorEstimate]

# Tier 3: Audit (for the reviewer/challenger)
audit = result.audit
audit.traces                 # Per-vector calculation traces
audit.validation_checks      # List of consistency checks
audit.warnings               # Contextual warnings
audit.data_sources           # All data sources used
audit.base_rate              # PERTRange used
audit.dampening              # DampeningConfig used
```

#### Rendering Methods

```python
# Tier 1: One slide
result.brief_report()         # -> str

# Tier 2: Distribution + vectors
result.distribution_text()    # -> str (lognormal + PERT params)
result.vector_breakdown_text() # -> str (per-vector ranges)

# Tier 3: Full audit
result.full_report()          # -> str (everything)

# Plain language
result.plain_language_summary()  # -> str (one paragraph)

# Markdown report (for file export)
result.to_markdown()          # -> str (structured markdown with tables)

# JSON
result.to_dict()              # -> dict (all three tiers)
```

### Scenarios

**Module:** `tef_estimator.data.scenarios`

#### ScenarioDefinition Protocol

Every scenario implements this protocol. You can create custom scenarios by providing a class that satisfies these properties.

```python
from tef_estimator.data.scenarios.base import ScenarioDefinition

class MyScenario:
    @property
    def scenario_name(self) -> str: ...         # "My Threat"
    @property
    def scenario_slug(self) -> str: ...         # "my_threat"
    @property
    def active_vectors(self) -> list[str]: ...  # ["exploitation", "credential", ...]
    @property
    def vector_proportions(self) -> dict[str, PERTRange]: ...
    @property
    def base_rate_triangulation(self) -> dict[str, PERTRange]: ...
    @property
    def overall_share(self) -> float: ...
    @property
    def sector_shares(self) -> dict[Sector, float | None]: ...
    @property
    def revenue_shares(self) -> dict[RevenueBand, float]: ...
    @property
    def credential_tempo(self) -> dict: ...
    @property
    def exploitation_scanning(self) -> dict: ...
    @property
    def output_templates(self) -> dict[str, str]: ...
    def adjusted_sector_multiplier(self, sector: Sector) -> float: ...
    def adjusted_revenue_multiplier(self, band: RevenueBand) -> float: ...
```

#### Built-in Scenarios

```python
from tef_estimator.data.scenarios.ransomware import RansomwareScenario
from tef_estimator.data.scenarios.bec import BECScenario

rw = RansomwareScenario()
bec = BECScenario()

# Compare base rates
print(rw.base_rate_triangulation["consensus"])   # PERTRange(0.01, 0.03, 0.10)
print(bec.base_rate_triangulation["consensus"])  # PERTRange(0.04, 0.10, 0.25)

# Compare vector proportions
print(rw.vector_proportions["credential"].mode)  # ~0.48
print(bec.vector_proportions["phishing"].mode)   # ~0.65

# Scenario-adjusted sector multiplier
print(rw.adjusted_sector_multiplier(Sector.MANUFACTURING))  # ~1.66
print(bec.adjusted_sector_multiplier(Sector.FINANCIAL))     # elevated
```

### Triangulation

**Module:** `tef_estimator.triangulation`

Formalizes the three-anchor base rate consensus computation.

#### triangulate(anchors, actual_consensus=None) -> TriangulationResult

Compute a suggested consensus PERT from independent anchors and optionally validate an analyst-set consensus.

```python
from tef_estimator.triangulation import triangulate, extract_anchors

scenario = RansomwareScenario()
anchors, consensus = extract_anchors(scenario.base_rate_triangulation)
result = triangulate(anchors, actual_consensus=consensus)

print(result.suggested)           # PERTRange(0.005, 0.0333, 0.0833)
print(result.convergence_ratio)   # 4.0
print(result.is_convergent)       # True
for line in result.validation:
    print(line)
```

#### extract_anchors(triangulation) -> (anchors, consensus)

Split a scenario's `base_rate_triangulation` dict into the named anchors and the consensus PERT.

### TEFConfig

**Module:** `tef_estimator.config`

Central configuration for all tunable parameters. Defaults are loaded from the bundled `config.yaml`; user overrides from `~/.tef-estimator/config.yaml` are deep-merged on top. The web UI Configuration panel provides runtime adjustment.

```python
from tef_estimator.config import TEFConfig, load_config, get_config

# Load from config.yaml (bundled + user overrides)
cfg = get_config()

# Access parameters
print(cfg.susceptibility_prior.mode)  # 0.20
print(cfg.dampening.vector_k)        # 0.85
print(cfg.credibility_k.exploitation) # 6.0 (asserted; see technical reference §8.3)

# Override programmatically
from tef_estimator.config import SusceptibilityPrior
cfg = TEFConfig()
cfg.susceptibility_prior = SusceptibilityPrior(low=0.05, mode=0.10, high=0.15)

engine = TEFEngine(config=cfg)
```

### DampeningConfig

**Module:** `tef_estimator.data.common`

Operational dampening configuration used within the engine. When no `dampening` is passed to `TEFEngine`, values are read from `TEFConfig.dampening` (which loads from `config.yaml`).

```python
from tef_estimator.data.common import DampeningConfig

# Direct override (takes precedence over config.yaml)
custom = DampeningConfig(
    factor_k=0.60,
    vector_k=0.90,
    max_composite=4.0,
)
engine = TEFEngine(dampening=custom)
```

### PERTRange

**Module:** `tef_estimator.data.common`

A named tuple representing a PERT distribution: `(low, mode, high)`.

```python
from tef_estimator.data.common import PERTRange

base_rate = PERTRange(low=0.01, mode=0.03, high=0.10)
print(base_rate.low)   # 0.01
print(base_rate.mode)  # 0.03
print(base_rate.high)  # 0.10
```

### DispersionParams

*1.2.0.* Burstiness of the rate over time (Gamma-mixed rate, negative binomial counts). See technical reference §8.7.

```python
from tef_estimator.distributions import DispersionParams, sample_annual_counts

d = DispersionParams(shape_r=21.6, timescale="year", basis="detrended",
                     source="CISA KEV, Jan 2023-May 2026", raw_shape_r=13.3)
d.annual_shape        # 21.6 ("month" would give 259.2 = 12 r)
d.vmr(5.0)            # 1 + 5/21.6
d.as_raw()            # the raw fit, for sensitivity
sample_annual_counts(rates, d, rng)   # rates: array of annual rates
```

| Field | Meaning |
|---|---|
| `shape_r` | Monthly Gamma shape; `None` = Poisson |
| `timescale` | `"month"` (default; independent months, annual shape 12 r) or `"year"` (shock lasts all year, annual shape r) |
| `basis` | `"detrended"` or `"raw"` |
| `source` | Citation, required when `shape_r` is set |
| `raw_shape_r` | Raw fit kept as the sensitivity bound |

`TEFConfig.dispersion_for(kind, name)` resolves a configured entry (`kind` = `"vectors"` or `"scenarios"`). `TEFConfig.from_yaml(path)` loads a config file; keys it leaves out fall back to the bundled defaults.

### LognormalParams

**Module:** `tef_estimator.distributions`

Fitted lognormal distribution parameters. The recommended distribution for Monte Carlo sampling.

```python
from tef_estimator.distributions import LognormalParams

ln = result.lognormal
print(ln.mu)      # -2.778 (ln-space mean)
print(ln.sigma)   # 1.263 (ln-space std dev)
print(ln.median)  # 0.062 (the positioned median)
print(ln.p5)      # 0.0078 (5th percentile)
print(ln.p95)     # 0.496 (95th percentile)
print(ln.mean)    # 0.138 (arithmetic mean, higher than median)

# Sample for Monte Carlo
samples = ln.sample(size=10000)  # numpy array of 10,000 draws
```

### Telemetry

**Module:** `tef_estimator.telemetry`

Continuous monitoring layer. Requires `pip install tef-estimator[telemetry]`.

#### TelemetryDB

**Module:** `tef_estimator.telemetry.db`

SQLite persistence for telemetry observations and time series.

```python
from tef_estimator.telemetry.db import TelemetryDB

db = TelemetryDB()          # Default: ~/.tef-estimator/telemetry.db
db = TelemetryDB(db_path=None)  # In-memory (for testing)
db.initialize()             # Create tables (idempotent)

conn = db.connect()
health = db.get_source_health(conn)
conn.close()
```

#### Collectors

**Module:** `tef_estimator.telemetry.collectors`

Seven collectors, each implementing the `Collector` protocol (`SOURCE_ID`, `CADENCE_DAYS`, `collect(db) -> CollectionSummary`).

```python
from tef_estimator.telemetry.collectors import collect_all, get_all_collectors

db = TelemetryDB()
db.initialize()
results = collect_all(db)  # Run all 7 collectors
```

| Collector | Source | Cadence |
|-----------|--------|---------|
| `DShieldCollector` | SANS ISC port scan telemetry | Daily |
| `CISAKEVCollector` | CISA Known Exploited Vulnerabilities | Daily |
| `RansomwareLiveCollector` | Ransomware.live victim data | Daily |
| `GreyNoiseCollector` | GreyNoise Community IP classifications | Daily |
| `AnnualReportCollector` | Annual report edition monitor | Weekly |
| `IRISReferenceCollector` | Bundled IRIS sector/revenue multipliers, floor anchors | Weekly |
| `VectorBenchmarksCollector` | Bundled vector proportions (Verizon, Unit42, Mandiant, Beazley, CrowdStrike, IBM) | Weekly |

The IRIS and vector benchmarks collectors read bundled JSON files (`data/reference/iris/extracted.json` and `data/reference/vectors/initial_access_vectors.json`). They use hash-based skip: if the file hasn't changed since the last import, no new records are inserted. When the reference data is updated with a new edition, running collection again produces new metric values that the compare layer detects as signals.

#### Integrator

**Module:** `tef_estimator.telemetry.integrator`

Transforms raw observations into clean time series with dedup, gap interpolation, and 7d/30d rolling averages.

```python
from tef_estimator.telemetry.integrator import run_integration

result = run_integration(db, lookback_days=90, source_filter="dshield")
print(result["total_inserted"], result["total_gaps_found"])
```

#### Compare

**Module:** `tef_estimator.telemetry.compare`

Threshold-based change detection against a stored baseline.

```python
from tef_estimator.telemetry.compare import snapshot_baseline, compare

snapshot_baseline(db)              # Save current 7d averages
result = compare(db, threshold=0.20)

if result.has_signals:
    for signal in result.signals:
        print(f"{signal.source_id}/{signal.metric_name}: "
              f"{signal.baseline_value:.1f} → {signal.current_value:.1f} "
              f"({signal.pct_change:+.0%})")
```

#### Scheduler

**Module:** `tef_estimator.telemetry.scheduler`

Cadence-based scheduling — runs collectors only when due.

```python
from tef_estimator.telemetry.scheduler import run_due_collections

results = run_due_collections(db, force=False)
```

#### Watch

**Module:** `tef_estimator.telemetry.watch`

Continuous monitoring loop: collect → integrate → compare → re-estimate.

```python
from tef_estimator.telemetry.watch import run_once, WatchProfile

result = run_once(db, threshold=0.20)
if result.had_signals:
    print(f"{len(result.compare_result.signals)} signals detected")
```

### Enums

#### Sector

```python
from tef_estimator.data.common import Sector

Sector.MANUFACTURING
Sector.FINANCIAL
Sector.HEALTHCARE
Sector.EDUCATION
# ... see tef_estimator.data.common for full list
```

#### RevenueBand

```python
from tef_estimator.data.common import RevenueBand

RevenueBand.UNDER_10M
RevenueBand.R_10M_100M
RevenueBand.R_100M_1B
RevenueBand.R_1B_10B
RevenueBand.R_10B_100B
RevenueBand.OVER_100B
```

#### Geography

```python
from tef_estimator.data.common import Geography

Geography.US
Geography.WESTERN_EUROPE
Geography.ASIA_PACIFIC
Geography.OTHER
```

#### RemoteAccessType

```python
from tef_estimator.data.common import RemoteAccessType

RemoteAccessType.NONE
RemoteAccessType.FORTINET
RemoteAccessType.CISCO
RemoteAccessType.PALO_ALTO
RemoteAccessType.CITRIX
RemoteAccessType.SONICWALL
RemoteAccessType.OTHER_VPN
RemoteAccessType.RDP
```
