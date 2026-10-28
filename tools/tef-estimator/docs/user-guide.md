# User Guide

## What This Tool Does

tef-estimator estimates **Threat Event Frequency (TEF)**: how often threat actors *attempt* to attack an organization like yours, not whether attempts succeed (your controls) or what they cost (loss magnitude). TEF is the first input to a FAIR (Factor Analysis of Information Risk) Monte Carlo.

### What TEF Is and Isn't

| Concept | What It Measures | Example |
|---------|-----------------|---------|
| **TEF** (this tool) | How often adversaries *try* | "Ransomware operators attempt to reach organizations like yours about once every 4 years" |
| **Susceptibility** | Probability that an attempt *succeeds* | "Given your controls, there's a 15-25% chance a ransomware attempt succeeds" |
| **LEF** (Loss Event Frequency) | TEF x Susceptibility | "You experience a ransomware loss event roughly once every 20 years" |
| **Loss Magnitude** | Financial impact *if* it happens | "A ransomware event costs $2-8M for your profile" |

### Prerequisites

`pip install tef-estimator` ([PyPI](https://pypi.org/project/tef-estimator/)); **Python 3.10+**. All reference data is bundled; no API keys or accounts.

### Interaction Modes

- **Web UI**: `tef-estimator ui` (needs `pip install tef-estimator[ui]`).
- **CLI**: `tef-estimator estimate ...` ([API Reference](api-reference.md#cli)).
- **Python API**: `TEFEngine(scenario=...).estimate(profile)` ([API Reference](api-reference.md#python-api)).
- **Telemetry monitoring**: `tef-estimator telemetry ...` (needs `pip install tef-estimator[telemetry]`; [API Reference](api-reference.md#telemetry)): collects from 6 sources, detects shifts, re-estimates watched profiles (`telemetry watch --profiles FILE`), and feeds live inputs ([below](#telemetry-inputs-frozen-and-live)).

## How the Estimation Works

### Three-Layer Model

| Layer | Source | Role |
|-------|--------|------|
| **1. Floor** (observed LEF) | Per scenario and revenue tier: IRIS (ransomware, exfiltration, web app), FBI IC3 (BEC) | Minimum (TEF >= LEF); conservative (reported events only) |
| **2. Ceiling** (campaign contact frequency) | Scanning telemetry (DShield, GreyNoise) for exploitation; operational tempo for credential | Audit-trail sanity check; never caps or positions the estimate |
| **3. Positioned estimate** | Base rate x sector, revenue band, technology, geography, other factors | **The number you use**; never below the floor |

### Vector Decomposition

| Vector | What It Represents | Ransomware Share | BEC Share |
|--------|-------------------|:---:|:---:|
| **Exploitation** | Exploiting vulnerabilities on exposed devices | 27.4% | 3% |
| **Credential** | Stolen credentials (initial access brokers, infostealers) | 50.5% | 22% |
| **Phishing** | Email social engineering (malware delivery, credential theft) | 15.8% | 65% |
| **Supply chain** | Compromising a trusted third party | 6.3% | 10% |

Shares are triangulated from public reports (Beazley, DBIR, Mandiant, Unit 42, CrowdStrike) and labelled as judgment: the reports use different categories and mostly cover all incidents, not ransomware alone, so they can't be computed directly. They always sum to 100%: ransomware's sources sum to 95%, so 26% becomes 27.4%. Each vector has its own data, floor, ceiling and positioning. The four cover 95%+ of initial access, and each has its own attack surface, telemetry and controls; finer splits lack calibration data.

### Scenarios

Same computation for every scenario; details in [technical reference §7.1](technical-reference.md#71-built-in-scenarios).

| Scenario | CLI | Dominant vector | Typical TEF, \$100M–\$1B US, no remote access |
|----------|-----|-----------------|-------------------------|
| Ransomware | default | credential (~50%) | financial 0.16, manufacturing 0.27 per year |
| BEC | `--scenario bec` | phishing (~65%) | financial 0.19 per year |
| Data exfiltration | `--scenario exfiltration` | credential (~47%) | financial 0.20, manufacturing 0.16 per year |
| Web application exploitation | `--scenario web_app` | exploitation (~65%) | financial 0.049, manufacturing 0.039 per year |

**Custom scenarios**: your proportions and base rate; zero out or omit vectors (e.g., insider threat: credential and phishing only). Start from `tef-estimator scenario template` or the UI Scenarios tab, check with `scenario validate <path>`, run with `estimate --scenario custom --scenario-file <path>`; fields and validation: [technical reference §7.2](technical-reference.md#72-custom-scenarios).

### Base Rate

Base rate (TEF) = observed loss events per organization-year (LEF) ÷ susceptibility, with events and firms counted on one population (US organizations): ransomware from leak sites, BEC and exfiltration from FBI IC3 complaints, web app as a share of exfiltration. Ransomware, exfiltration and web app are set per revenue tier, so they have no revenue multiplier; BEC keeps it. Geography is relative to the US (US = 1.0). Your estimate's derivation is in the Tier 3 audit trail; inputs per scenario in [technical reference §6.4](technical-reference.md#64-base-rate).

### Cross-Vector Dampening

Vectors share one threat-actor ecosystem, so a raw sum overcounts:

```
Total_TEF = (TEF_exploitation + TEF_credential + TEF_phishing + TEF_supplychain) x vector_k
```

Default k=0.85 (within-vector factor dampening: k=0.70), set in `config.yaml` or the UI; supported by 10,037 VERIS incidents ([technical reference §6.2.1](technical-reference.md)).

### Credibility Blending (Organization-Specific Telemetry)

Your own per-vector observations (WAF/IDS, email gateway, authentication logs) refine the population estimate ([technical reference §8](technical-reference.md)):

- **Weight:** Bühlmann Z = n/(n+k), rising with observation periods and detection coverage. k per vector: `credibility_k` in `config.yaml` (judgment; adjustable in the UI).
- **Band:** narrows with detected events, a few percent at typical rates, with limits in `band_hardening`. Coverage moves the point estimate, not the width.

```python
from tef_estimator.credibility import VectorObservation, OrgTelemetry

telemetry = OrgTelemetry(observations=[
    VectorObservation(
        vector="credential",
        annualized_frequency=0.05,   # Your observed rate
        observation_periods=8,        # 2 years of quarterly data
        detection_coverage=0.8,       # 80% detection coverage
    ),
])

profile = OrganizationProfile(
    sector=Sector.MANUFACTURING,
    revenue_band=RevenueBand.R_100M_1B,
    geography=Geography.US,
    telemetry=telemetry,
)
```

### Dispersion (Burstiness Over Time)

Attack counts are burstier than a fixed rate (campaign waves, mass exploitation). The output's **dispersion shape r** makes simulated counts negative binomial instead of Poisson: same mean, variance λ + λ²/s, s = annual shape (12r at the default monthly timescale). Method: [technical reference §8.7](technical-reference.md).

Defaults (`dispersion` in `config.yaml`): CISA KEV for exploitation, ransomware.live victims for the ransomware total; everything else stays Poisson (stated in the output).

- `config.yaml`: `dispersion.timescale` = `month` (default) or `year` (cautious; about 12× more extra variance; evidence in [dispersion-timescale.md](dispersion-timescale.md)); `dispersion.basis` = `detrended` (default) or `raw` (sensitivity bound).
- For one organization with a few events a year the loss-tail effect is small (a few percent at P99 even in the burstiest case); it matters at high frequencies and for portfolios.
- Simulate with `result.sample_annual_counts()`, or pass the printed fair-risk-engine inputs ([Reading Tier 2](#reading-tier-2-analysis); `result.fair_risk_engine_inputs()`), which use the same count model ([API Reference](api-reference.md#tefresult)). Use those P10/P90, not the positioned low/high (about P5/P95).

### Telemetry Inputs: Frozen and Live

**Frozen** (default): bundled data only, reproducible; use for reports. **Live**: inputs follow your collected data (`tef-estimator telemetry collect`); the output names the data date. Switch with `--live` / `--frozen`, the UI's "Live telemetry inputs" switch, or `telemetry_inputs` in `config.yaml`. Every estimate says which it used: the UI badge ("Frozen inputs" / "Live inputs") and the "Inputs:" line, which in frozen mode names the bundled editions (e.g. IRIS 2025, At-Bay 2025, Beazley Q3 2025, DShield 2026-10-23) and in live mode the data date per input.

| Live input | From | Effect |
|---|---|---|
| Exploitation dispersion r | CISA KEV | spread of simulated counts |
| Ransomware dispersion r | ransomware.live victims by attack date | spread of simulated counts |
| Ransomware base rate | US ransomware.live victims (replaces the bundled count) | frequency, in proportion; bundled count kept outside 0.5–2× |

- Complete months only: a week of news doesn't move it. BEC, exfiltration and web-app frequencies stay bundled: their counts come from the yearly FBI IC3 report, with no monthly series to collect, and a new report means a new release. Exfiltration's under-reporting multiplier is derived from the bundled ransomware count and stays bundled in live mode too.
- **Same numbers as frozen at first:** the bundled values were fitted on the same months, so live and frozen agree until new months complete. Dispersion r changes only the count spread (Dispersion panel, `tef_dispersion`), never the TEF or its range.
- **"Bundled value kept"**: a live input couldn't be derived; the reason is shown.
- **Ceilings** stay on the bundled data and never change the estimate (technical reference §3).
- **First ransomware collection: about 16 minutes** (one API request a minute); later ones 2–3. Nothing collects on its own; for a daily run on macOS, install `scripts/launchd/tef-estimator-collect.plist` (instructions in the file).

## Interpreting the Output

### Reading Tier 1 (Summary)

`--brief` or `result.brief_report()`, for slides. Manufacturing, \$100M–\$1B, US, Fortinet VPN, 2,000 employees:

```
RANSOMWARE TEF ESTIMATE
========================================
TEF: 0.45 per year (about once every 2.2 years)
Chance of at least one attempt in a year: 36%

Peer percentile: 100th (100m-1b (tech-neutral peers))

VECTOR BREAKDOWN:
  Exploitation     28% ###########
  Credential       52% ####################
  Phishing         14% #####
  Supply Chain      5% #
```


- **TEF**: positioned median, a rate in events per year, not a probability. 0.45 = about 45 attempts per 100 such organizations per year.
- **Once every N years**: 1 / TEF (1 / 0.446 = 2.2 years), assuming a constant threat level; not "safe for 2 years".
- **Chance of at least one attempt in a year**: 1 − e^(−TEF) (Poisson); close to TEF for small rates, lower from about 0.5 up (0.45 → 36%). A TEF above 1 per year means more than one attempt a year expected.
- **Peer percentile**: rank in the pre-computed grid for your revenue band.
- **Vector breakdown**: where the threat enters, the most actionable part; raw (pre-dampening) shares, so they sum to 100%.

### Reading Tier 2 (Analysis)

Default CLI output, or the `analysis` property.

```
DISTRIBUTION PARAMETERS (for Monte Carlo):
  Recommended distribution: Lognormal
  mu (ln-space): -0.807
  sigma (ln-space): 0.786
  5th percentile:  0.12247 events/year
  Median:          0.44602 events/year
  95th percentile: 1.62435 events/year

  Alternative: PERT(min=0.12110, mode=0.44602, max=1.60622)

  For fair-risk-engine: tef_model='lognormal', tef_p10=0.16294, tef_p50=0.44602, tef_p90=1.2209, tef_dispersion=1364.4
  (trend-included sensitivity bound: tef_dispersion=555.6)
```

Sample the lognormal directly (mu, sigma) or with `LognormalParams.sample(size)`. The 5th–95th band (here 13x) is dominated by base rate uncertainty. Values above 1 per year mean more than one attempt a year expected. Lognormal is recommended because TEF is right-skewed and the tail matters; PERT is the simpler alternative.

### Reading Tier 3 (Audit)

`--full` or `result.full_report()`, for reviewers.

#### Base Rate Derivation

Manufacturing, \$100M–\$1B, US, no remote access (the full math: [technical reference §2A](technical-reference.md#2a-worked-example-end-to-end-math)):

```
BASE RATE DERIVATION:
  LEF (100m_plus): 3,971 US events/yr × under-reporting 1.33 / 1.46 / 1.75 × victim share 0.257 ÷ 31,035 US firms = 0.0437 / 0.048 / 0.0575 loss events per year
  ÷ susceptibility 0.3 / 0.17 / 0.1 = base rate (TEF) 0.146 / 0.282 / 0.575 per year
```

Custom scenarios print their consensus PERT instead, and open the validation checks with a triangulation check.

#### Validation Checks

```
  + Floor <= Positioned: 0.01989 <= 0.27133
  + Exploitation median <= ceiling: 0.08595 <= 25834
  + Credential median <= ceiling: 0.14212 <= 4.395
  + ABOVE CEILING: Phishing median 0.06510 > ceiling 0.05
  + Supply Chain median <= ceiling: 0.02604 <= 0.0318
  + At susceptibility 5%: implied LEF = 0.01357 (1.1x observed floor)
  + At susceptibility 15%: implied LEF = 0.04070 (3.4x observed floor)
  + At susceptibility 30%: implied LEF = 0.08140 (6.8x observed floor)
  + Exploitation vector: 27% of total TEF
  + Credential vector: 45% of total TEF
  + Phishing vector: 20% of total TEF
  + Supply Chain vector: 8% of total TEF
```

One check per vector ceiling (reported, never enforced; the phishing ceiling is an assumption), plus implied LEF (loss events per year) vs the observed floor; below 1x at a plausible susceptibility would mean the estimate is too low. Vector shares are of the summed vectors, before cross-vector dampening.

#### Warnings

Each warning names the condition behind it; the full list: [technical reference §10.3](technical-reference.md#103-contextual-warnings).

### What Peer Percentile Does and Doesn't Mean

Your rank among peer profiles in your revenue band; boards grasp relative position better than raw rates:

> "Your positioned TEF of 0.27 per year is at the 90th percentile across all mid-market profiles." (90% of comparable organizations face lower TEF.)

- **Means:** a high percentile reflects elevated risk factors (e.g., vulnerable VPN vendor, high-target sector).
- **Not** a score, a grade, or a breach prediction: it ranks *attempt frequency*; *risk* depends on controls and loss exposure.
- **Peers are tech-neutral:** every sector × region profile in your revenue band (80 per band), run without technology inputs (no VPN vendor, no RDP). Any remote access you enter ranks you higher, so a Fortinet profile lands near the top. The UI badge explains this on hover.

**No percentile showing?** Build the peer grid for your scenario:

```bash
tef-estimator data peer-grid --rebuild
```

### Downstream Usage

1. Estimate TEF for your scenario.
2. Take the lognormal mu/sigma from Tier 2 (plus the dispersion shape if you simulate event counts).
3. Assess susceptibility per vector, not as one blended number (e.g., strong patching, weak credential controls), starting with the dominant vector (for ransomware usually credential, about half the TEF).
4. LEF = TEF distribution x susceptibility distribution; combine with loss magnitude for the full risk distribution.

### Common Questions

**Why is BEC TEF higher than ransomware for small firms?** Any company that processes invoices is a target, while ransomware victims concentrate in larger firms: under \$10M the ransomware base rate is 0.0013 per year (mode), BEC's 0.145 before the revenue multiplier. From \$100M up the two are similar (financial \$100M–\$1B US: 0.19 vs 0.16 per year). Out-of-band verification keeps BEC susceptibility low regardless.

**My estimate seems too low / too high.** `tef-estimator explain` traces the calculation; `tef-estimator sensitivity` shows the biggest drivers. If internal incident data contradicts it, override with `--base-rate` (used as PERT(0.5×, 1×, 2×)).

**How often should I refresh?** Quarterly. Replace the `extracted.json` files under `src/tef_estimator/data/reference/` (`tef-estimator refresh snapshot` prints the steps; `refresh check` validates freshness). IRIS, Beazley, At-Bay update annually; DShield/KEV/Ransomware.live snapshots each release. Live mode follows your collected data.

**A scenario not listed?** Define a custom scenario JSON (see [Scenarios](#scenarios)) or implement the `ScenarioDefinition` protocol.

**I disagree with a multiplier.** `--full` shows every multiplier with its source. Overrides: base rate via `--base-rate`; dampening, susceptibility prior and credibility k via the UI Configuration panel or `~/.tef-estimator/config.yaml`; vector proportions via a modified scenario.
