# Methodology

Statistical foundations, design rationale, and implementation details for the five-dimension validation framework.

Companion blog post: [Validating LLM-Generated Control Mappings Beyond Aggregate Accuracy](https://cloudsecurityalliance.org/blog/2026/07/02/validating-llm-generated-control-mappings-beyond-aggregate-accuracy) (Cloud Security Alliance)

## The problem with aggregate accuracy

When an LLM maps controls from one taxonomy to another (e.g., CSA AI Controls Matrix to FAIR-CAM), the most common evaluation is simple accuracy: what percentage of labels match a reference set? This single number hides several failure modes:

- **Inflated by base rates.** If 60% of controls map to the same category, a classifier that always outputs that category scores 60% accuracy while understanding nothing.
- **Unstable across runs.** LLMs are stochastic. A classifier that scores 85% on one run might score 72% on the next, but aggregate accuracy from a single run cannot reveal this.
- **Insensitive to subtle distinctions.** Two controls may differ in one critical property, but accuracy treats a wrong label the same regardless of how close the inputs are.
- **Blind to structural violations.** A label might not exist in the target taxonomy, or a mapping might violate hierarchical constraints.
- **Silent on input sensitivity.** Accuracy says nothing about whether the classifier changes its answer when the input is paraphrased (it should not) or when the input semantics genuinely change (it should).

The five-dimension framework addresses each of these failure modes with a dedicated test.

## Framework architecture

The five dimensions are organized into two phases:

**Phase 1 — Foundation** (run sequentially):
1. Coherence
2. Consistency
3. Convergent validity

**Phase 2 — Advanced** (can run in parallel):
4. Adversarial discrimination
5. Stability and sensitivity

Each dimension produces a `DimensionReport` containing metrics, a verdict (PASS / MARGINAL / FAIL / SKIPPED), and per-item issues. The orchestrator (`runner.py`) consolidates all dimension reports into an `EvaluationReport` with an overall verdict. The overall verdict is determined by a configurable policy (default: worst across dimensions that produced results meaning any single FAIL fails the evaluation). Dimensions that had no input data return SKIPPED and do not affect the overall verdict.

All statistical computations use the Python standard library only (no numpy, scipy, or statsmodels dependency). This is a deliberate design choice for the framework to be installable without dependency conflicts.

## Dimension 1: Coherence

**Question:** Do raters (whether multiple LLM runs, human experts, or a mix) agree with each other?

**Why it matters:** LLM outputs are non-deterministic. Even with temperature=0, API-level sampling means two runs can produce different labels for the same input. But run-to-run agreement is only half the picture. When human domain experts independently classify the same items, coherence between their labels and the LLM's labels measures whether the model's understanding aligns with human judgement — not against a single reference answer (that's convergent validity), but as peers performing the same task. Low LLM-to-human coherence on items where humans agree with each other isolates where the model diverges from expert consensus.

The typical workflow should combine both: run the LLM multiple times, have human experts classify a stratified sample (see Stratified sampling below), then pass all raters into the coherence analysis together. This produces pairwise kappa for every combination — LLM-vs-LLM, human-vs-human, and LLM-vs-human — in a single analysis.

### Statistical method

The framework treats each rater (LLM run or human reviewer) as an independent source and applies standard inter-rater reliability statistics:

**Cohen's kappa** (pairwise, two raters):

```
kappa = (P_o - P_e) / (1 - P_e)
```

Where P_o is observed agreement and P_e is expected agreement under independence. Unlike raw percent agreement, kappa corrects for chance agreement which is a critical distinction when category base rates are uneven.

**Fleiss' kappa** (multi-rater generalization):

For N items, k categories, and n raters per item, Fleiss' kappa computes:

```
kappa = (P_bar - P_e_bar) / (1 - P_e_bar)
```

Where P_bar is the mean per-item agreement and P_e_bar is the expected agreement under random assignment proportional to the marginal category frequencies.

**Bootstrap confidence intervals:** The pairwise kappa values are resampled (percentile method, default 1000 iterations, seeded for reproducibility) to produce confidence intervals on the mean. This quantifies uncertainty in the agreement estimate without distributional assumptions.

**Note on sample size:** The bootstrap resamples over pairwise kappa values, not over items. With *r* raters you get C(*r*, 2) pairwise values — so 3 raters yield only 3 data points, producing very wide CIs. For tighter intervals, use 5+ raters (10+ pairwise values). In practice this means running the LLM classifier at least 5 times, or combining LLM runs with human expert ratings.

### Interpretation

The framework deliberately avoids the Landis & Koch qualitative bins ("slight", "moderate", "substantial"). These bins are arbitrary and context-dependent. Instead, verdicts are driven by configurable thresholds which can be set via YAML or Python dataclasses at evaluation time, and adjustable live in the UI dashboard with immediate verdict recalculation:

| Condition | Verdict |
|-----------|---------|
| mean_kappa >= target (default 0.65) | PASS |
| mean_kappa >= minimum (default 0.50) | MARGINAL |
| mean_kappa < minimum | FAIL |

### Per-item diagnostics

When item IDs are provided, the coherence report flags every item where raters disagree, listing each rater's label. This lets you identify *which* controls are unstable, not just that instability exists.

### Stratified sampling

For large classification tasks, having human experts review every item is impractical. The `sampling` module produces a stratified sample plan that selects which items need expert review, ensuring every mapping region is represented:

1. Items are grouped into strata by the cross-tabulation of source and target categories.
2. A configurable minimum number of items (default 3) is drawn from every stratum.
3. Remaining slots are allocated proportionally to stratum size, up to the minimum total sample size (default 20).
4. Sufficiency checks flag uncovered strata or undersized samples.

## Dimension 2: Consistency

**Question:** Do outputs satisfy structural and semantic rules that must hold for the classification to be valid?

**Why it matters:** Some errors cannot be caught by statistical agreement, they require domain knowledge encoded as deterministic rules. For example: a label must exist in the target taxonomy, a hierarchical mapping must be internally consistent (subdomain must belong to its claimed domain), or a required metadata field must be present.

### Rule engine design

Rules are registered via a decorator-based registry:

```python
registry = RuleRegistry()

@registry.rule("S-001", "Label exists in taxonomy", severity="error")
def valid_label(item: dict) -> list[RuleResult]:
    ...
```

Two rule types are supported:

- **Per-item rules:** Applied to each classification output independently. Used for structural checks (valid label, required fields, format constraints).
- **Batch rules:** Applied to the entire list at once. Used for cross-item checks (no duplicate mappings, coverage completeness, referential integrity).

Each rule returns a list of `RuleResult` objects with a severity level:
- `error` — hard failure, the classification is invalid
- `warning` — potential problem worth investigating
- `info` — informational note

### Verdict logic

- Any error-severity failure → FAIL (configurable via `fail_on_error`, default `true`)
- Any non-passing rule (regardless of severity) → MARGINAL, unless promoted to FAIL by the above
- When `fail_on_warning` is `true` (default `false`), warning-severity failures also trigger MARGINAL explicitly
- All rules pass → PASS

### Why not just unit tests?

Unit tests can check the same conditions, but they produce pass/fail per test, not structured `RuleResult` objects. The framework feeds rule results into the per-item issue aggregation, so the final report shows all problems for each control across all dimensions in one view.

## Dimension 3: Convergent validity

**Question:** Does the LLM's direct mapping converge with an independently derived mapping through a third framework?

**Why it matters:** Coherence (Dimension 1) measures whether raters agree with each other but especially when relying on multiple LLM runs, a model can consistently produce the same wrong answer across runs. Convergent validity tests whether the LLM's mapping is consistent with independent evidence that doesn't come from the LLM at all.

The core idea is triangulation through a third framework. Suppose the LLM maps Framework A controls directly to Framework B. Independently, peer-reviewed mappings exist from Framework A to Framework C and from Framework B to Framework C. Composing those two gives a transitive reference: Framework A → Framework C → Framework B. If the LLM's direct mapping agrees with this transitive path, that's convergent validity meaning two independent routes to the same answer.

The implementation compares the LLM's predicted labels against one reference set (typically the transitive mapping derived from peer-reviewed sources). The user constructs the transitive reference externally and passes it in. The framework uses chance-corrected agreement (kappa) rather than raw accuracy, and supports set-based comparison (Jaccard) for cases where a control maps to multiple categories.

### Categorical comparison

Cohen's kappa between the LLM's labels and the reference. The same kappa implementation as Dimension 1, but measuring agreement with an external source rather than peer agreement.

### Set-based comparison

When classifications are multi-label (e.g., a control maps to multiple taxonomy functions), Jaccard similarity measures set overlap:

```
Jaccard(A, B) = |A ∩ B| / |A ∪ B|
```

Mean Jaccard across all items is reported with bootstrap confidence intervals.

### Per-item diagnostics

Every label mismatch is reported as an `ItemIssue` with the predicted and reference values. For set comparisons, missing labels (in reference but not predicted) and extra labels (predicted but not in reference) are reported separately at different severity levels.

### Why both kappa and Jaccard?

Kappa captures categorical agreement corrected for chance. Jaccard captures overlap when items have multiple labels. Many real classification tasks involve both a primary category (categorical) and a set of tags or functions (set-based). Using both metrics gives a complete picture.

## Dimension 4: Adversarial discrimination

**Question:** Can the LLM distinguish between inputs that *should* be classified differently, and handle inputs that are genuinely ambiguous?

**Why it matters:** A classifier might achieve decent kappa by getting easy cases right while systematically confusing similar categories. Adversarial testing specifically tests these boundaries.

### Minimal pairs

A minimal pair consists of two inputs that differ in one critical dimension but should receive different labels. For example, two control descriptions that differ only in whether they describe "detection" vs. "response" capabilities.

The test passes if:
1. The classifier assigns different labels to the two inputs (discrimination), AND
2. If expected labels are provided, the assigned labels match them (correctness).

The **discrimination score** is the pass rate across all minimal pairs.

### Ambiguity cases

Some inputs are legitimately ambiguous and multiple correct classifications exist. An ambiguity case specifies an input and a set of acceptable labels. The test passes if the classifier's output falls within the acceptable set.

The **ambiguity score** is the pass rate across all ambiguity cases.

### Combined score

A weighted average of discrimination and ambiguity scores (default weights: 0.6 discrimination, 0.4 ambiguity). The weighting reflects that discrimination failures are more concerning than ambiguity tolerance.

### Verdict logic

Three independent thresholds are checked: discrimination score, ambiguity score, and combined score. The overall adversarial verdict is the worst of the three.

## Dimension 5: Stability and sensitivity

**Question:** Does the classifier produce the same output for semantically equivalent inputs (stability), and different output when the input semantics genuinely change (sensitivity)?

**Why it matters:** Stability and sensitivity are complementary. A classifier that never changes its answer is maximally stable but zero sensitivity. A classifier that changes its answer for every paraphrase has high sensitivity but zero stability. Both must be adequate simultaneously.

### Stability testing (paraphrases)

Paraphrased inputs are semantically equivalent rewrites of the original. The framework provides prompt templates for three paraphrase strategies:

- **Formal:** Technical language, passive voice, domain-standard terminology
- **Informal:** Conversational tone, active voice, plain language
- **Structural:** Clause reordering and sentence restructuring

The framework does not call LLM APIs directly — users generate paraphrases externally and pass them as `ParaphraseVariant` objects. This keeps the framework API-agnostic.

For each paraphrase, the classifier's output is compared against the base item's output across all tracked label dimensions. Agreement is measured per-dimension (exact match) and overall (Jaccard over all dimension:value pairs). Bootstrap confidence intervals are computed on the overall stability score.

### Sensitivity testing (perturbations)

Perturbations are meaningful modifications that *should* change the classification. Each `PerturbationVariant` includes an `ExpectedDirection` specifying which dimensions should change and (optionally) what the new values should be.

Three metrics are computed:

- **Change detection rate:** Fraction of perturbations where the expected change was detected.
- **Direction accuracy:** Of detected changes, fraction where the new label matches the expected value.
- **False change rate:** Fraction of no-op perturbations (expected to produce no change) where the classifier changed its answer anyway.

### Verdict logic

Each metric has its own threshold (stability, change_detection, direction_accuracy). The overall stability verdict is the worst across all metrics. False change rate is evaluated separately with binary logic (no MARGINAL zone): at or below `false_change_max` (default 0.15) is PASS, above is FAIL.

## Verdict system

### Per-dimension verdicts

Every numeric metric is evaluated against a two-threshold system:

```
value >= target  →  PASS
minimum <= value < target  →  MARGINAL
value < minimum  →  FAIL
```

Multiple metrics within a dimension are aggregated: any FAIL → FAIL, any MARGINAL → MARGINAL, all PASS → PASS.

### Overall verdict

The overall verdict is computed from the per-dimension verdicts using a configurable policy. The core library (`aggregate_verdicts`) uses the default policy; the UI dashboard exposes all four in the sidebar.

| Policy | Logic | Use case                                                                   |
|--------|-------|----------------------------------------------------------------------------|
| **All must PASS** (default) | Any FAIL → FAIL, any MARGINAL → MARGINAL, all PASS → PASS | Production readiness: every dimension must meet its target                 |
| **No FAIL** | Any FAIL → FAIL, otherwise PASS (MARGINAL is acceptable) | Screening: you want to catch hard failures but tolerate borderline results |
| **Majority** | More than half PASS → PASS, more than half FAIL → FAIL, otherwise MARGINAL | Exploratory: overall signal matters more than any single dimension         |
| **Weighted** | Each dimension has a configurable weight; PASS ratio ≥ 0.8 → PASS, FAIL ratio > 0.5 → FAIL, otherwise MARGINAL | When some dimensions matter more than others for your context              |

In all policies, dimensions can be marked as optional (not required). Optional dimensions are excluded from the overall verdict computation. This lets you run all five dimensions for visibility while only gating on the ones that matter for your use case.

Dimensions with no input data return SKIPPED. A dimension whose runner throws an exception returns ERROR. Both SKIPPED and ERROR are excluded from the overall verdict — they are treated as "no measurement," not as failures. This means the overall verdict reflects only dimensions that actually produced results. If a dimension errors, the exception message is captured in `DimensionReport.error` and surfaced in the UI, but it does not affect the overall verdict. If you consume the verdict programmatically (e.g., as a CI gate), check for ERROR dimensions separately:

```python
errored = [d for d in report.dimensions if d.verdict == Verdict.ERROR]
if errored:
    # handle — a dimension crashed, overall verdict may be incomplete
```

### Why three levels?

A kappa of 0.55 might be acceptable for a preliminary screen but not for production. MARGINAL lets users set aggressive targets while distinguishing "needs improvement" from "fundamentally broken."

## Configuration

All thresholds, bootstrap parameters, and runner settings are configurable via YAML or Python dataclasses at evaluation time. The `eval_config.yaml` file documents every parameter with its default value. The UI dashboard also exposes per-dimension target and minimum thresholds, verdict policy, and optional/required toggles and changes take effect immediately without re-running the evaluation.

### Default thresholds

| Dimension | Metric | Target | Minimum |
|-----------|--------|--------|---------|
| Coherence | mean_kappa | 0.65 | 0.50 |
| Convergent | jaccard | 0.60 | 0.45 |
| Convergent | kappa | 0.65 | 0.50 |
| Adversarial | discrimination | 0.85 | 0.70 |
| Adversarial | ambiguity | 0.75 | 0.60 |
| Adversarial | combined | 0.80 | 0.65 |
| Stability | stability | 0.85 | 0.70 |
| Stability | change_detection | 0.70 | 0.55 |
| Stability | direction_accuracy | 0.80 | 0.65 |
| Stability | false_change_max | 0.15 | — |

These defaults are calibrated for control-mapping tasks where misclassification has operational consequences. For exploratory or low-stakes use cases, consider relaxing the minimums.

### Bootstrap settings

| Parameter | Default | Notes                                                                |
|-----------|---------|----------------------------------------------------------------------|
| iterations | 1000 | Higher values (5000+) for production; lower (200) for fast iteration |
| confidence | 0.90 | 90% CI; use 0.95 for stricter reporting                              |
| seed | 42 | Set to `None` for non-deterministic behavior (not recommended)       |

## Per-item issue aggregation

A key design choice: the framework tracks issues at the *item* level across all dimensions. The `EvaluationReport.items` list contains an `ItemReport` for every item that has at least one issue, aggregating problems from coherence disagreements, consistency violations, convergent mismatches, adversarial failures, and stability changes.

This makes the report actionable: instead of "kappa is 0.72," you get "control AICM-042 has rater disagreement, violates hierarchy rule S-003, and changes label under paraphrase." The UI dashboard surfaces this per-item view alongside the dimension-level radar chart.

## Limitations

- **No LLM API integration.** The framework validates classification *outputs*, not the classification process. Users must generate the outputs (including paraphrases and multiple runs) externally.
- **Standard library only.** The kappa and bootstrap implementations are correct but not optimized for large datasets (10,000+ items). For very large evaluations, consider the tradeoff of adding scipy.
- **Binary/categorical labels only.** The framework does not handle ordinal or continuous outputs. Extend by writing custom rules in the consistency dimension.
- **Paraphrase quality is the user's responsibility.** If paraphrases are poor (change meaning, add information), stability results will be misleading.

## References

- Cohen, J. (1960). A coefficient of agreement for nominal scales. *Educational and Psychological Measurement*, 20(1), 37-46.
- Fleiss, J. L. (1971). Measuring nominal scale agreement among many raters. *Psychological Bulletin*, 76(5), 378-382.
- Jaccard, P. (1912). The distribution of the flora in the alpine zone. *New Phytologist*, 11(2), 37-50.
- Efron, B. & Tibshirani, R. J. (1993). *An Introduction to the Bootstrap*. Chapman & Hall.
- Artstein, R. & Poesio, M. (2008). Inter-coder agreement for computational linguistics. *Computational Linguistics*, 34(4), 555-596.
