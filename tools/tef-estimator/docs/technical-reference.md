# TEF Estimator Technical Reference

Version 1.3.0

Modules, design decisions, data sources, parameter choices, and provenance of the TEF estimation engine.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Estimation Pipeline](#2-estimation-pipeline)
3. [Vector Methodology](#3-vector-methodology)
4. [Data Layer](#4-data-layer)
5. [Data Sources and Provenance](#5-data-sources-and-provenance)
6. [Parameter Choices and Rationale](#6-parameter-choices-and-rationale)
7. [Scenario System](#7-scenario-system)
8. [Credibility Blending](#8-credibility-blending)
9. [Output Structure](#9-output-structure)
10. [Validation and Audit Trail](#10-validation-and-audit-trail)

---

## 1. Architecture Overview

### Design Principles

- **Public data sources.** Every empirical number comes from JSON (`data/reference/{source}/extracted.json`, `data/scenarios/`). 
- **Scenario-agnostic engine.** Engine, vectors, dampening, base-rate recipe, floors, and output are identical for every threat type. Scenarios are data implementing `ScenarioDefinition`; the engine runs the vectors in `active_vectors` (all four for built-ins, a subset for custom).
- **Three layers per vector.** Floor (observed LEF lower bound for the scenario and revenue tier; enforced), ceiling (scanning/operational-tempo maximum; sanity check only, never caps), positioned estimate (base rate × profile multipliers; the primary output).
- **Three-tier output.** Summary, analyst workspace, full audit trail (§9.1).

### Module Dependency Graph

```
cli.py / ui.py
    |
    v
engine.py (TEFEngine)
    |
    +---> config.py + config.yaml (TEFConfig: susceptibility, dampening, credibility k)
    +---> vectors/{exploitation,credential,phishing,supply_chain}.py
    |         |
    |         +---> data/common.py (multipliers, enums)
    |         +---> distributions.py (dampening, PERT, lognormal)
    |         +---> trace.py (step-by-step arithmetic)
    |         +---> vectors/base.py (VectorEstimate dataclass)
    |
    +---> credibility.py (Bühlmann blending)
    +---> base_rate.py (base rate, floors, geography, tier concentration)
    +---> triangulation.py (consensus check: custom scenarios)
    +---> peer.py (percentile grid)
    +---> result.py (TEFResult, three-tier output)
    +---> profile.py (OrganizationProfile)
    |
    v
data/loader.py
    |
    +---> data/reference/{iris,beazley,at_bay,common}/extracted.json
    +---> data/scenarios/{ransomware,bec,exfiltration,web_app}.json
    +---> data/scenarios/{ransomware,bec,exfiltration,web_app,custom}.py
```

---

## 2. Estimation Pipeline

### Step-by-Step Flow

For an `OrganizationProfile` and `ScenarioDefinition` (full formula and numbers in §2A):

1. **Base rate**: `TEFEngine.base_rate_for(band)`, a PERT(low, mode, high): LEF ÷ susceptibility on one population (§6.4), or a custom scenario's consensus PERT; or `profile.custom_base_rate` if the analyst overrides.
2. **Vector decomposition**: each vector in `active_vectors` yields a `VectorEstimate` with floor (§6.1), ceiling (§3) and positioned estimate (base rate × vector proportion × dampened multipliers).
3. **Bühlmann credibility blending with Gamma-inspired band contraction** (optional, with `profile.telemetry`): each observed vector's median moves toward the observed rate and its band contracts (§8.4, §8.6). Two separately calibrated parameters (k for the mean, α_pert for the band), not one coherent Bayesian model.
4. **Cross-vector aggregation**: `total = sum(positioned_median) x vector_k` (default 0.85).
5. **Floor enforcement**: `total = max(total, scenario_floor(band) x adjusted_sector_multiplier)`.
6. **Distribution fitting**: `LognormalParams.from_median_and_range(total_median, total_low, total_high)`.
7. **Triangulation validation** (custom scenarios with a consensus only): `triangulate(anchors)`; analyst consensus deviation checked against it.
8. **Result assembly**: `TEFResult` with three tiers, validation checks, warnings, traces.

### Dampening Model

Multipliers are correlated (a large financial-services firm probably already has better controls), so naive multiplication overstates risk for heavily adjusted profiles. Dampened composite = 1 + (raw − 1) × k, capped at `max_composite` (§2A Steps 4–5). Two levels: within-vector `factor_k` compresses sector × revenue × tech × geo; cross-vector `vector_k` compresses the sum of vectors; `max_composite` caps any profile's multiple of the base rate. Values and rationale: §6.2; overrides: Override Mechanisms.

---

## 2A. Worked Example: End-to-End Math

Profile: **manufacturing, \$100M–$1B, US, Fortinet VPN, ransomware scenario** (`tef-estimator explain --sector manufacturing --revenue 100m_1b --geo us --remote-access fortinet`).

### Step 1: Base Rate (One Population: US Organizations)

Base rate = threat events of this type per organization per year in the addressable population (a rate, not a probability), before org-specific adjustment. Events and firms are counted on the same population, the revenue tier's US firms; observed loss events (LEF) convert to attempts as **TEF = LEF ÷ susceptibility** (§6.4).

```
N_US = 3,971 US victims/yr        ransomware.live by attack date, Aug 2025–Jul 2026
                                   (3,762 US among 8,405 with a country; 466 unknown allocated pro rata)
× under-reporting 1.33 / 1.46 / 1.75   Coveware pay rate and "Lone Wolf" share, Q4 2024–Q4 2025
× tier victim share 0.257              $100M and up (Coveware victim sizes)
÷ 31,035 US firms in the tier          Census SUSB 2022
= LEF 0.0437 / 0.048 / 0.0575 loss events per year
÷ susceptibility 0.30 / 0.17 / 0.10
= TEF 0.146 / 0.282 / 0.575 per year    →    PERT(0.1458, 0.2824, 0.5755)
```

The tier covers every band from \$100M up (flat rate, §6.4), so the revenue multiplier is 1.0 for ransomware (Step 3). IRIS sets only the floor (Step 6).

### Step 2: Vector Decomposition

Proportions from IR reports (Beazley, DBIR 2026, Mandiant 2026, Unit42, CrowdStrike; §6.3):

```
credential:    PERT(0.40, 0.48, 0.56)   ← 48% of ransomware initial access
exploitation:  PERT(0.20, 0.26, 0.34)   ← 26%
phishing:      PERT(0.10, 0.15, 0.22)   ← 15%
supply_chain:  PERT(0.04, 0.06, 0.10)   ← 6%
```

Modes sum to 95%; every range is scaled by 1 ÷ 0.95 at load (§6.3):
```
vector_base = base_rate.mode × proportion.mode

credential_base   = 0.28241 × 0.5053 = 0.14269
exploitation_base = 0.28241 × 0.2737 = 0.07729
phishing_base     = 0.28241 × 0.1579 = 0.04459
supply_chain_base = 0.28241 × 0.0632 = 0.01784
```

### Step 3: The Multiplier Stack

**Sector — scenario-adjusted** (`ransomware.py`; formula §6.5):
```
common_mult  = SECTOR_DATA[manufacturing].all_incident_multiplier     # 1.03  (IRIS)
sector_share = scenario.sector_shares[manufacturing]                   # 0.51  (IRIS Ransomware Spotlight)
overall_share = scenario.overall_share                                 # 0.317 (IRIS Ransomware Spotlight)

adjusted_sector = common_mult × (sector_share / overall_share)
                = 1.03 × (0.51 / 0.317)
                = 1.03 × 1.609
                = 1.657
```
Near-average all-incident rate (1.03×), but 51% of manufacturing incidents are ransomware vs. 31.7% overall.

**Revenue:** 1.0. The base rate is set per revenue tier, so a multiplier on top would count revenue twice (§6.6).

**Tech** (`at_bay/extracted.json`):
```
Fortinet = vulnerable VPN vendor
→ TECH_MULTIPLIERS["vpn_vulnerable_vendor"] = PERT(1.2, 1.4, 1.6)
```
From At-Bay 2025 and Beazley; the range is judgment, since the reports give proportions, not relative risks.

**Geography:** US = 1.0. The base rate counts US events over US firms, so geography is relative to the US (other regions: `GEO_MULTIPLIERS` ÷ the US mode 1.2; `common/extracted.json`).

### Step 4: Why Dampening Is Needed

```
raw_composite = sector × revenue × tech × geo
              = 1.657 × 1.0 × 1.4 × 1.0
              = 2.320
```

Full independence fails: **confounding** (manufacturing skews mid-market, which the IRIS sector multiplier already partly reflects), **diminishing marginal impact** (manufacturing implies OT/SCADA exposure, so VPN risk is partly in the sector data), **ceiling effects** (attacker capacity is finite). The insurance-pricing answer is **credibility-weighted compression**: keep each multiplier's direction, dampen their interaction.

### Step 5: The `dampen_composite` Function

```
dampened = 1.0 + (raw_composite - 1.0) × k
         capped at max_composite = 5.0

raw = 2.320,  k = 0.70 (factor_k, from config.yaml)
dampened = 1.0 + 1.320 × 0.70 = 1.924
```

### Step 6: Positioned Vector Estimate

Exploitation:
```
positioned_median = vector_base × dampened_composite
                  = 0.07729 × 1.924
                  = 0.14871 per year

floor = scenario_floor(100m_1b) × exploitation_proportion × adjusted_sector
      = 0.012 × 0.2737 × 1.657
      = 0.00544 per year
```

The floor (IRIS Ransomware Spotlight lower bound for \$100M–\$1B, §6.1) doesn't bind. Each vector runs this with its own tech multipliers: credential 0.27454, phishing 0.06510, supply chain 0.02604.

### Step 7: Cross-Vector Aggregation

```
dampened_total = Σ(positioned_median) × vector_k     # 0.85 default
               = 0.51439 × 0.85 = 0.43723
```

Compresses the sum because credential and phishing are strongly correlated (VERIS lift = 8.29, §6.2.1).

### Step 8: Floor Enforcement

```
total_floor  = 0.012 (IRIS RW, $100M–1B) × adjusted_sector 1.657 = 0.01989
total_median = max(total_median, total_floor)
```

Total median (0.437 per year) >> floor (0.0199): doesn't bind.

### Step 9: Lognormal Output

```
μ = ln(median) = ln(0.43723) = -0.827

σ_low  = (μ - ln(low)) / 1.645        # low targets ~5th percentile
σ_high = (ln(high) - μ) / 1.645       # high targets ~95th percentile
σ = mean(σ_low, σ_high)               # averaged for robustness, floored at 0.1   → 0.779
```

Median 0.437 per year; P5 ≈ positioned low (0.120; lognormal 0.122); P95 ≈ positioned high (1.56; lognormal 1.57). Values above 1 per year mean more than one attempt a year expected.

Centred on the positioned total, not the Fenton-Wilkinson sum of vector lognormals, which assumes independent vectors; they share one base rate (Limitations).

### The Complete Formula

```
base_rate = LEF(tier) ÷ susceptibility                           [built-in scenarios; consensus PERT for custom]

For each vector v ∈ {exploitation, credential, phishing, supply_chain}:

    vector_base_v = base_rate × vector_proportion_v

    raw_composite_v = ∏(sector_mult, revenue_mult, tech_mult, geo_mult)

    dampened_v = 1 + (raw_composite_v - 1) × factor_k           [within-vector compression]

    positioned_v = vector_base_v × dampened_v

    positioned_v = max(positioned_v, floor_v)                    [observed-LEF floor]


TEF_total = (Σ positioned_v) × vector_k                         [cross-vector compression]

TEF_total = max(TEF_total, scenario_floor(tier) × sector_adjustment)    [aggregate floor]

Output: Lognormal(μ = ln(TEF_total), σ = f(range))
```

### Verified Output for This Profile

- **TEF positioned median: 0.437 per year** (about once every 2.3 years; chance of at least one attempt in a year 1 − e^(−0.437) = 35%)
- Shares (pre-dampening): credential ~53%, exploitation ~29%, phishing ~13%, supply chain ~5%
- Sensitivity: base rate 3.9× range vs 1.4× for each dampening coefficient (`tef-estimator sensitivity`, same profile)

---

## 3. Vector Methodology

Shared formula (§2); per-vector threat model, ceiling, and tech multipliers below.

- **Floor:** scenario floor for the revenue tier (§6.1) × vector proportion × adjusted sector multiplier.
- **Multipliers:** sector and revenue (scenario-adjusted IRIS; none for revenue in ransomware, §6.6), technology (per vector), geography (relative to the US for ransomware and BEC).
- **Ceilings:** sanity checks only. The audit trail compares each vector's median with its ceiling (§10.2); the ceiling never caps the estimate.

| Vector | Threat model | Ceiling | Tech multipliers (§5.2) |
|---|---|---|---|
| Exploitation | Public-facing app/device vulnerability exploitation | Campaign contact frequency, DShield snapshot (below) | `vpn_vulnerable_vendor`, `rdp_exposed`, `cloud_primary_no_edge` (protective) |
| Credential | Stolen/purchased VPN/RDP/SSO credentials from Initial Access Brokers; invisible to scanning | Operational tempo (below) | `vpn_vulnerable_vendor`, non-vulnerable VPN, `rdp_exposed`, `no_remote_access` (protective) |
| Phishing | Email social engineering delivering loaders; volume measurable, campaign initiation not | Fixed bound from Proofpoint campaign volume (assumption) | `large_email_footprint` (≥1000 employees); small-organization reduction |
| Supply chain | Third-party/vendor compromise; not directly observable | IRIS overall upper bound × a fixed share (assumption) | supply chain provider flag |

Shares per scenario: `vector_proportions` (§6.3).

Phishing: employee count acts through Probability of Action (more recipients, more chance one takes the bait per campaign).

### Exploitation ceiling

Since 1.3.0: campaign contact frequency on the ports the profile exposes.

ceiling/yr = S × (m + 0.5 s) ÷ c × 365 × p × a

| Symbol | Meaning |
|---|---|
| S | DShield daily unique source IPs on the exposed ports, 30-day average, summed over ports (upper bound: an IP scanning two ports counts twice, which suits a maximum) |
| m | GreyNoise malicious rate (mode); same for every scenario, since it describes scanning |
| s | Suspicious rate (judgment: GreyNoise does not publish it) |
| c | Campaign-to-IP ratio, lognormal median exp(μ) (judgment) |
| p | Scenario's share of malicious scanning (mode) |
| a | Probability of action, high end, as fits a ceiling |

- **Exposed ports** (`exploitation_ceiling_derivation`, `config.yaml`): VPN vendor 443/8443; RDP 3389 (both: union); no remote access 443/8080 (public-facing apps); otherwise 443/445/8080.
- **Source:** bundled DShield snapshot only; live mode does not recompute it. Without the snapshot, the assumed `exploitation_ceilings` apply.

### Credential ceiling

```
ceiling = campaigns × credential proportion × 12 ÷ addressable population
          × sector and geography adjustments × tier victim concentration ÷ low-end susceptibility
```

The adjustments match positioning, so like is compared with like; the tier concentration (tier victim share ÷ tier share of firms) puts the ceiling on the base rate's population; dividing by susceptibility turns claimed victims (successes) into attempts. Tight, because each credential campaign targets a specific organization, unlike scanning.

Campaign inputs (`credential_tempo`, `_derivation` in each scenario file): ransomware — ransomware.live, Recorded Future; BEC — FBI IC3 2024 complaints × under-reporting, US businesses; exfiltration — ransomware campaigns × NetDiligence 2025 hacker/ransomware claims ratio; web app — judgment.

---

## 4. Data Layer

### Directory Structure

```
data/
  reference/
    iris/ beazley/ at_bay/ common/   extracted.json per source
    vectors/initial_access_vectors.json   IR-report vector records (telemetry benchmarks)
  scenarios/
    {ransomware,bec,exfiltration,web_app}.json   scenario parameters, incl. base_rate_lef, floor_lef
  peer_grid/
    {ransomware,bec,exfiltration,web_app}.json   peer percentile grids (data peer-grid --rebuild)
```

### JSON Convention

`_metadata` at the top (source, access URL, extracted_date, extracted_by); `_citation` on every data section (figure/table/page); `_note` for context. `_`-prefixed keys are dropped at load.

---

## 5. Data Sources and Provenance

Which source sets which number. The exact citation (figure, table, page) sits next to each value in the data files: `data/reference/*/extracted.json` and `data/scenarios/*.json`. Reference files extracted 2026-05-24; IRIS figures re-verified against the PDFs 2026-10-26.

### 5.1 Sources

| Source | Sets |
|---|---|
| Ransomware.live, victims by attack date (Aug 2025–Jul 2026) | Ransomware US events per year; ransomware dispersion |
| Coveware, Q4 2024–Q4 2025 | Ransomware under-reporting; victim share per revenue tier |
| Census SUSB 2022 | US firms per revenue tier |
| FBI IC3 2025 | BEC and exfiltration base rates; BEC floor and credential ceiling; exfiltration under-reporting (via IC3 ransomware complaints) |
| VERIS VCDB | Exfiltration victim share per tier; cross-vector dampening (`vector_k`); `factor_k` check |
| Sophos State of Ransomware 2022–2025 | Ransomware susceptibility |
| Cyentia IRIS 2025 + Ransomware Spotlight | Sector and revenue multipliers; ransomware sector shares; ransomware floor; exfiltration revenue gradient from \$1B; supply-chain ceiling |
| Cyentia IRIS 2022 | Exfiltration and web-app floors |
| DBIR 2025/2026, Unit 42, Mandiant M-Trends, CrowdStrike, Beazley, IBM CODB | Vector proportions (judgment); scenario shares of all incidents |
| Proofpoint Human Factor 2025, Cofense 2026 | BEC vector proportions (with IC3 and DBIR) |
| FBI IC3 2024, Coalition 2025 | BEC revenue shares (judgment) |
| DBIR 2026, BakerHostetler DSIR 2025, VCDB | Web-app share of breaches (judgment) |
| At-Bay 2025, Beazley Q3 2025 | Technology multipliers |
| DShield (SANS ISC), snapshot 2026-10-23 | Exploitation ceiling |
| GreyNoise 2025/2026 reports | Exploitation ceiling (malicious scanning rate) |
| Recorded Future | Ransomware credential ceiling (campaign tempo) |
| NetDiligence 2025 | Exfiltration credential ceiling |
| CISA KEV | Exploitation dispersion |
| Statistics Canada 22-10-0076 | `factor_k` check |

### 5.2 Technology Multipliers

From At-Bay 2025 (VPN) and Beazley Q3 2025 (RDP). Values, citations and rationale: `data/reference/at_bay/extracted.json`, loaded as `TECH_MULTIPLIERS`.

### 5.3 Judgment Multipliers

Geography and profile multipliers; no public source measures them yet. Values: `data/reference/common/extracted.json` (`geo_multipliers`, `profile_multipliers`).

---

## 6. Parameter Choices and Rationale

Values sit in the data files (`data/scenarios/*.json`, `data/reference/*/extracted.json`) and `config.yaml`; this section gives the formulas and why. Worked numbers for one profile: §2A.

### 6.1 Floors

Observed LEF lower bound per scenario and revenue tier (`base_rate.scenario_floor`); no TEF below what is observed. Total floor = floor × adjusted sector multiplier; vector floor additionally × vector proportion. One role per source: what sets the base rate never sets the floor (except BEC, which has one source).

| Scenario | Floor |
|---|---|
| Ransomware | IRIS Ransomware Spotlight, lower bound of P(≥1 event) per year per tier |
| BEC | FBI IC3 complaints ÷ US firms (reported losses only), all tiers |
| Exfiltration, web app | IRIS 2022 all-incident lower bound of P(≥1 event) per tier × the scenario's overall share |

IRIS probabilities are used as rates (close at these levels). IRIS has no model under \$10M, so that tier has no floor. The IRIS upper bound feeds only the supply-chain ceiling (§3).

### 6.2 Dampening Parameters

| Parameter | Value | Source | Rationale |
|-----------|-------|--------|-----------|
| `factor_k` | 0.70 | Judgment; checked on StatCan and VCDB ÷ Census (§6.2.2) | Keeps 70% of deviation from 1.0; not derivable from VERIS alone (§6.2.1) |
| `vector_k` | 0.85 | VERIS VCDB | §6.2.1 |
| `max_composite` | 5.0 | Judgment | IRIS's lower and upper bounds are about 22× apart; 5× differentiates without runaway stacking |

#### 6.2.1 VERIS Cross-Vector Dampening Derivation

`scripts/compute_dampening.py` on the VERIS Community Database. For each vector pair:

```
lift = P(A ∩ B) / (P(A) × P(B))
```

P(X) = marginal probability of vector X among incidents. Lift > 1: complements; < 1: substitutes. k = 1/lift, bounded [0.5, 1.0]. The structure is **bimodal**: exploitation substitutes for credential and phishing (attackers use one or the other, k = 1.0); credential complements phishing and supply chain (phishing is a credential theft mechanism, k = 0.5).

- **vector_k = 0.85:** one median can't represent a bimodal structure; 0.85 dampens credential-phishing without over-dampening the exploitation pairs. `veris_pairwise_lifts` is stored for pair-specific dampening (Open Question 5).
- **factor_k stays judgment:** it needs P(incident | sector=X AND size=Y) / [P(incident | sector=X) × P(incident | size=Y) / P(incident)]. VERIS has incidents per sector×size, not organizations per bucket; within-incident lift conflates risk interaction with population correlation (financial institutions tend to be large). §6.2.2 adds firm denominators.
- **Ransomware:** almost all ransomware incidents with mapped vectors are single-vector, so cross-vector dampening matters less here.

#### 6.2.2 factor_k Check: Sector × Size

Model r(s,z) = 1 + (m_s·m_z − 1)·k (sector multiplier m_s, size multiplier m_z), k fitted by least squares on StatCan 22-10-0076 (share of Canadian enterprises impacted, NAICS × enterprise size, four survey years, three incident types) and on VCDB US incidents ÷ Census SUSB firms (NAICS × employee class).

- StatCan puts k for sector × size at about 0.7–0.75, VCDB ÷ Census at 0.86–0.96 in the working range: together about 0.7–1.0, with 0.70 at the low end. They cover only sector × size, not technology or geography. VCDB counts publicly reported incidents only.
- Fits per series, IRIS bracket check by tier and limitations: [dampening-k.md](dampening-k.md), `scripts/dampening_k_check.py`.

### 6.3 Vector Proportions (Ransomware)

**Judgment**, triangulated from Beazley, DBIR, Unit 42, Mandiant, CrowdStrike and Sophos; ranges cover where the sources disagree. They can't be computed: most reports give initial access across all incident types, not ransomware alone, and each uses its own categories. Computing them would need per-case ransomware root-cause data under one taxonomy, which no public source provides.

**Normalization.** At load, `loader.normalized_proportions` scales each vector's low, mode, high by 1 ÷ (sum of modes) so the vectors carry the whole base rate; data files keep extracted values. Custom scenarios: validated on the raw sum (0.85–1.15), then normalized.

### 6.4 Base Rate

One population per scenario (US organizations): the events and the firms they are divided by are counted on the same population, so no source's coverage gap is mixed into another's. TEF = LEF ÷ susceptibility (`base_rate.py`; `base_rate_lef` in the scenario file). Live mode: §8.9.

**Ransomware**, per revenue tier:

LEF = n_us × under-reporting × tier victim share ÷ US firms in the tier

| Input | Source |
|---|---|
| n_us | ransomware.live US victims by attack date, last 12 complete months |
| Under-reporting | 1 ÷ ((1 − pay rate) × (1 − share by actors without leak sites)), Coveware |
| Tier | Census SUSB size bands mapped to revenue tiers by average receipts per firm: under \$10M / \$10M–100M / \$100M and up |
| US firms | Census SUSB 2022 |
| Victim share | Coveware victim sizes |
| Susceptibility | §6.4.1 |

- **\$100M and up is flat** at the measured \$100M–1B values (IRIS: "organizations from \$100M to \$100B are pretty much all equally likely to be hit by ransomware"). Measured directly, \$1B+ came out above IRIS's upper bound (Coveware's caseload over-represents large victims).

**BEC**, one tier: LEF = FBI IC3 BEC complaints × reporting multiplier (judgment, labelled) ÷ US firms. The revenue multiplier still applies (§6.6).

**Exfiltration**, per revenue tier, same US firm counts as ransomware: LEF = FBI IC3 data-breach complaints × under-reporting × tier victim share ÷ US firms in the tier.
- **Under-reporting:** low and mode = 1 ÷ IC3's filing rate, measured on ransomware (IC3 ransomware complaints ÷ US ransomware victims from the recipe above). High (judgment, labelled): data-breach victims file half as often as ransomware victims at their lowest rate, since breaches go to regulators and the people affected rather than the FBI. Check: IC3's data-breach count already exceeds ITRC's publicly notified US cyberattack compromises.
- **Victim shares from VCDB** (IC3 gives no victim sizes): US incidents with an external actor and confirmed data disclosure, ransomware excluded, employee classes split log-uniformly (`scripts/exfiltration_victim_shares.py`).
- **From \$1B: IRIS revenue gradient.** VCDB comes from public reports, which over-represent large victims: measured directly, its largest class lands above IRIS 2022's all-incident upper bounds, as Coveware did for ransomware. So each tier from \$1B = the \$100M–1B rate × IRIS's all-incident revenue multiplier relative to \$100M–1B.

**Web app** = exfiltration LEF × share of breaches through a web application (judgment, labelled; from DBIR 2026, BakerHostetler DSIR 2025 and VCDB). It counts breaches via web applications; defacement, outages and account-takeover fraud without a breach have no US count and are not included.

No revenue multiplier for ransomware, exfiltration or web app: revenue is in the tier (§6.6).

**Geography** is relative to the US for all four (US = 1.0; others = `GEO_MULTIPLIERS` ÷ the US mode).

#### 6.4.1 Population-Level Susceptibility Prior

A **data-preparation parameter**, not an organizational assessment: sources report LEF = TEF × susceptibility, so TEF = LEF ÷ susceptibility for "the average organization with average controls". Org-specific FAIR vulnerability is NOT this; it enters through the multiplier stack.

- **Ransomware:** P(initial access | attempt) (judgment) × P(loss event | access) (Sophos State of Ransomware, share of attacks with data encrypted).
- **BEC, exfiltration, web app:** judgment.

A user-set `susceptibility_prior` (`config.yaml`, UI) replaces the scenario's prior.

### 6.5 Sector Multiplier Adjustment

```
adjusted = common.all_incident_multiplier x (scenario_sector_share / scenario_overall_share)
```

Worked example: §2A Step 3. A null scenario share leaves the all-incident multiplier unchanged. Exfiltration and web app have no scenario-specific sector data (all null).

### 6.6 Revenue Band Adjustment

Same formula, revenue shares, for BEC. Ransomware, exfiltration and web app: 1.0, since their base rate is set per revenue tier (§6.4) and a multiplier on top would count revenue twice.

---

## 7. Scenario System

### 7.1 Built-in Scenarios

Files: `data/scenarios/{name}.py` + `{name}.json`.

| Scenario | Base rate (§6.4) | Sector/revenue data |
|---|---|---|
| **Ransomware** | Leak sites ÷ US firms, per revenue tier | IRIS Ransomware Spotlight sector shares; revenue in the tier |
| **BEC** | FBI IC3 ÷ US firms, one tier | FBI IC3/Verizon sector and revenue shares (IRIS has no BEC data) |
| **Data exfiltration** (`exfiltration`) | FBI IC3 ÷ US firms, per revenue tier | IRIS all-incident sector multiplier; revenue in the tier |
| **Web application exploitation** (`web_app`) | Exfiltration × web-app share of breaches | IRIS all-incident sector multiplier; revenue in the tier |

Vector proportions, overall shares and their sources: each scenario's JSON.

### 7.2 Custom Scenarios

`data/scenarios/custom.py`: scenarios in JSON, no Python. Six required fields:

```json
{
  "scenario_name": "Data Exfiltration",
  "scenario_slug": "data_exfil",
  "vector_proportions": {
    "exploitation": [0.10, 0.20, 0.30],
    "credential": [0.30, 0.40, 0.50],
    "phishing": [0.15, 0.25, 0.35],
    "supply_chain": [0.05, 0.15, 0.20]
  },
  "base_rate": {
    "consensus": [0.005, 0.015, 0.04]
  },
  "overall_share": 0.10
}
```

**Validation:** all 6 fields present; vector names from {exploitation, credential, phishing, supply_chain}, at least one; proportion modes sum to 0.85-1.15; `base_rate` has `consensus`. Optional fields (sector and revenue shares, ceilings inputs, output templates) default to overall_share or the ransomware baseline. `tef-estimator scenario template` writes a JSON that validates and runs.

---

## 8. Credibility Blending

### 8.1 Bühlmann Credibility Theory

`credibility.py`. With org telemetry (e.g. WAF logs of exploitation attempts, email gateway logs of phishing), the engine blends observed frequency with the population prior:
```
blended = Z x adjusted_observed + (1-Z) x prior
Z = effective_n / (effective_n + k)
effective_n = observation_periods x detection_coverage
adjusted_observed = raw_observed / detection_coverage
```

### 8.2 Detection Coverage Adjustment

Two-way: low coverage scales the observation up and shrinks the effective sample size (credibility grows slower).

### 8.3 Per-Vector k Parameters

`credibility_k` in `config.yaml`, asserted per vector: lower where the vector is observable in an organization's own logs, highest for supply chain. k = σ²(process) / σ²(hypothetical means) needs per-vector event counts for many individual organizations, which no public source publishes; time-series fits measure burstiness over time (§8.7), not differences between organizations, so they can't set it.

### 8.4 Engine Integration

After vector estimation, before cross-vector aggregation, for each vector with an observation: blend the median (§8.1), contract the band around the blended value (§8.6), re-apply the floor. Code: `TEFEngine._apply_credibility` in `engine.py`.

### 8.5 Telemetry Input Format

[User guide](user-guide.md#credibility-blending-organization-specific-telemetry) (Python `OrgTelemetry`, or a JSON file for CLI `--telemetry`).

### 8.6 Gamma-Inspired Posterior Band Contraction

The band must narrow with evidence, not just shift. Motivation: with a Gamma(α, β) prior and Poisson observations of N events over exposure n, the posterior mean is (1 − Z) × prior + Z × observed with Z = n/(n + β), which is Bühlmann with β = k. The posterior band follows the Gamma shape, as a lognormal:

```
σ² = ln(1 + 1/α_post),  α_post = α_pert + N
```

α_pert is fitted to the width of the prior PERT band, not taken from k: k sets how fast the **mean** moves, α_pert how fast the **band** narrows. Counted quarters are capped (`band_hardening.coverage_leverage_cap`) and σ_post never falls below `min_sigma_ratio` × σ_prior. The prior is diffuse, so at typical rates the band narrows a few percent; telemetry acts mainly through the mean.

### 8.7 Dispersion (Burstiness Over Time)

Downstream simulations usually draw counts as Poisson; public monthly series are burstier. The estimator exports a dispersion shape r.

**Model.** Each period the rate is λ × a shared shock G ~ Gamma(r, 1/r), so counts are negative binomial: Var[N] = λ + λ²/r. Not credibility k: k is how rates differ *between* organizations, r is how one organization's rate moves in time.

**Defaults** (`dispersion` in `config.yaml`, with series, window and data date): CISA KEV new entries for the exploitation vector, ransomware.live victims by attack date for the ransomware total; every other vector and scenario stays Poisson (no public series). Detrended NB2 fit is the default, method of moments ("raw") the sensitivity bound.

**Timescale.** r is fitted monthly: independent monthly shocks give annual shape 12r (`dispersion.timescale: month`, default); one shock all year gives r (`year`, cautious). Evidence: [dispersion-timescale.md](dispersion-timescale.md).

**When it matters.** For one organization with a few events a year, little: at 5 events a year the annual-loss P99 moves under 1% at the default shapes. It matters for frequent events and portfolios.

**Output.** `TEFResult.dispersion` and `to_dict()["analysis"]["dispersion"]`; `TEFResult.sample_annual_counts()` draws rate uncertainty, then the shock, then a Poisson count. Dispersion never changes the rate estimate.

### 8.8 Live Dispersion Refit

Live mode (`telemetry_inputs: live`, `--live`, or the UI switch) refits both shapes on the collected series with the bundled recipe; frozen mode (default) uses the bundled values. Only shapes move.

- Complete months only; the window ends at the last complete month before the latest collection, minus `censor_months`, and never starts before the first observed month.
- Ransomware uses the attack date (discovery dates add crawling and bulk-posting bursts) and censors the 2 latest months, still filling with late postings.
- Fallback to the bundled value, with the reason in the output: no data, window too short, a month with rows on fewer than `min_day_coverage` of its days, or a fit outside `shape_bounds`.

### 8.9 Live Base Rate (Ransomware)

In live mode the ransomware base rate takes the collected US victim count in place of the bundled n_us; the recipe (§6.4) is unchanged and the base rate scales in proportion. N_US = US victims by attack date over the ransomware dispersion window, with unknown-country victims allocated by the US share of those with a country. Outside `tempo_anchor.bounds` (0.5–2× the bundled count), or with the §8.8 fallbacks, the bundled count is kept. Other scenarios have no live input.

---

## 9. Output Structure

### 9.1 Three-Tier Model

| Tier | Contents |
|---|---|
| **1 Summary** (the slide) | Positioned median, low, high (events per year); `tef_text`; chance of at least one attempt in a year (1 − e^(−median), `chance_at_least_one`); recurrence interval (years); vector share chart data; one-sentence plain-language summary; peer percentile (if grid available) |
| **2 Analysis** (analyst workspace) | Lognormal parameters (mu, sigma, p5, median, p95); PERT range (min, mode, max); per-vector estimates with primary drivers; control priority (top vector's #1 control); credibility summary (if telemetry) |
| **3 Audit** (challenge layer) | Per-vector calculation traces; triangulation validation (consensus scenarios); validation checks (floor/ceiling, implied LEF at different susceptibilities); contextual warnings; all citations; base-rate derivation (`TEFResult.base_rate_derivation`); explicit statement of what the estimate does NOT include |

### 9.2 Output Formats

Text, JSON and markdown rendering, and simulation helpers: [API reference, TEFResult](api-reference.md#tefresult).

### 9.3 Plain Language Summary Template

```
{one_sentence}  ← the scenario's output_templates, e.g. "Based on industry data,
                  threat actors {attempt_verb} organizations matching your profile
                  {recurrence} (range: {low} to {high})."
The primary attack pathway is {dominant_vector}-based
access ({share}% of estimated frequency), driven by {top_driver}. This measures
how often adversaries TRY -- not how often they succeed. Success probability
depends on your controls (assessed separately).
```

Recurrence wording: `recurrence_text` ([API reference](api-reference.md#tefresult)).

---

## 10. Validation and Audit Trail

### 10.1 Base-Rate Derivation and Triangulation Validation

- **Built-in scenarios:** the audit trail prints the derivation (`TEFResult.base_rate_derivation`), as in §2A Step 1.
- **Custom scenarios** (consensus base rate): the analyst consensus is checked against any anchors in the scenario file: modes within 10x (convergence); consensus mode >50% from the suggested mode → "verify override" warning; per-anchor PERT ranges listed.

### 10.2 Internal Consistency Checks

- `Floor <= Positioned`: estimate respects the observed lower bound
- `<vector> median <= ceiling`: each vector against its own ceiling (§3); reported, never enforced; not summed (different units)
- Implied LEF at 5%, 15%, 30% susceptibility vs the observed floor (§6.1)
- Vector shares (should roughly match input proportions)

### 10.3 Contextual Warnings

| Condition | Warning |
|-----------|---------|
| Floor is binding (positioned within 10% of floor) | "IRIS observed LEF is more informative than the base-rate-plus-adjustments approach" |
| Small/mid-market revenue band | "IRIS counts only publicly reported events, which under-counts small and mid-market firms: the observed floor is especially conservative for this cohort." |
| Non-US geography | "IRIS data has a US disclosure bias. Floor is more conservative for non-US firms." |
| Transportation sector | "Low all-incident rate but 84% ransomware loss share. This is a severity signal, not a frequency signal." |
| Always | Dampening coefficient k disclosure |

### 10.4 Calculation Traces

Every arithmetic step, per vector, with its source (`tef-estimator explain`, `--full`); an analyst can substitute a number at any step and trace it downstream. §2A walks through one profile.

### 10.5 What the Estimate Explicitly Excludes

Every full report ends with:
- Susceptibility (probability that an attempt succeeds)
- Loss magnitude (financial impact if it does)
- Control effectiveness (reduces susceptibility)
- Attack surface size effect (enters through susceptibility, not TEF)

---

## Override Mechanisms

### Configuration File (`config.yaml`)

All defaults live in the bundled `config.yaml` (single source of truth; no numeric defaults in Python). Override with `~/.tef-estimator/config.yaml` holding only the changed values:

```yaml
# Override susceptibility prior for a more security-mature population
susceptibility_prior:
  low: 0.05
  mode: 0.10
  high: 0.15

# Adjust dampening
dampening:
  factor_k: 0.60
```

Overrides are deep-merged; omitted keys keep defaults. The UI Configuration panel overrides any parameter for the session.

Every key in the bundled `config.yaml` can be overridden; its comments explain each one.

### In Code

`OrganizationProfile(custom_base_rate=...)` / CLI `--base-rate` (the engine then uses PERT(rate × 0.5, rate, rate × 2.0) instead of `base_rate_for`), `TEFEngine(base_rate_override=PERTRange(...))`, `TEFEngine(dampening=DampeningConfig(...))` or `TEFEngine(config=TEFConfig(...))`: see the [API reference](api-reference.md#python-api).

---

## Adding a New Built-in Scenario

1. Create `src/tef_estimator/data/scenarios/my_scenario.json` like `ransomware.json`. Required: `base_rate_triangulation` with a `consensus` PERT, or a `base_rate_lef` block (plus `susceptibility_prior`) as in `ransomware.json`; optional `floor_lef`; `vector_proportions`, sector/revenue shares, credential tempo, exploitation scanning, output templates.
2. Create `src/tef_estimator/data/scenarios/my_scenario.py` implementing `ScenarioDefinition`.
3. Register in `cli.py`: `ScenarioChoice` enum and `SCENARIO_MAP`.
4. Build the peer grid: `tef-estimator data peer-grid --rebuild`.

No engine changes needed.

---

## Limitations

- **The base rate drives the output** more than any multiplier (`tef-estimator sensitivity`).
- **Judgment inputs, labelled as such:** vector shares, P(access | attempt) in susceptibility, BEC's reporting multiplier, web app's share of breaches, credibility k (fitting it needs per-organization counts no public source publishes), and within-vector dampening (checked for sector × size only, [dampening-k.md](dampening-k.md)).
- **Exfiltration and web app borrow inputs:** IC3's filing rate measured on ransomware, VCDB victim sizes (skewed large) with IRIS's gradient from \$1B; no scenario-specific sector data.
- **Ransomware victim sizes come from Coveware's caseload,** which over-represents large victims; from \$10B the flat \$100M+ rate falls below IRIS's lower bound for most profiles.
- **Floors count reported events only;** the reporting gap varies by cohort.
- **Ceilings are sanity checks;** the phishing and supply-chain ceilings are assumptions, and the phishing ceiling flags nearly every BEC profile.
- **Credibility blending** takes detection coverage as exact and doesn't vary it in sensitivity analysis; band quantiles are approximate and contraction conservative.
- **The aggregate assumes vectors share uncertainty;** independent vectors would give a higher median.
- **Dispersion comes from population series,** which show shared burstiness only; KEV counts catalogue additions, not attacks.
- **TEF is non-stationary:** output is point-in-time; refresh quarterly.
- **It estimates how often adversaries try, not how often they succeed;** success depends on controls, assessed separately.

---

## Open Methodological Questions

1. **Should the base rate PERT be sector-specific from the start?** Currently one population-level rate (per revenue tier for ransomware) adjusted by multipliers. Alternative: sector-specific base rates from insurer claims data, removing one layer of multiplication.

2. **How should the exploitation ceiling be presented?** It is so high (~18,000/year with an exposed VPN, shipped snapshot) that it provides no useful constraint. Currently kept in Tier 3 only. A prior question: is DShield scanning a TEF ceiling, or a contact-frequency ceiling upstream of TEF (a scan is reconnaissance, not yet a threat event)? Until that is settled the ceiling stays a sanity check.

3. **Can P(access | attempt) be measured?** The ransomware susceptibility uses 0.2–0.4 by judgment (§6.4.1); aggregate susceptibility data from real FAIR analyses would calibrate it.

4. **Should compare support more than two profiles?** An N-way comparison ("current → after VPN migration → after MFA rollout") would be more powerful for investment prioritisation.

5. **Should pair-specific dampening replace the single vector_k?** VERIS data shows exploitation pairs need k~1.0 while credential-phishing would need k well below the 0.5 bound (1/lift ≈ 0.12). A 6-element dampening matrix is more accurate but harder to explain in the audit trail.
