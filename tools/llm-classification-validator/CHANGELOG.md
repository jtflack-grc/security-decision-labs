# Changelog

## v1.0.3 — 2026-10-21

### Fixed

- `__version__` (and the UI badge) was hardcoded at 1.0.0 regardless of the installed version. It is now resolved from the source tree's `pyproject.toml`, falling back to the installed package metadata — the same fix tef-estimator got for its issue #2.

## v1.0.2 — 2026-10-21

### Fixed

- Project links on PyPI (Homepage, Repository, Changelog) pointed to a repository that does not exist; they now point to this folder in security-decision-labs.

## v1.0.1 — 2026-07-01

Documentation and package metadata only; the code is unchanged.

- The PyPI page shows the README.
- More search keywords.
- Links to the companion Cloud Security Alliance blog post.

## v1.0.0 — 2026-06-18

First stable release.

### Framework

- Five-dimension validation: coherence, consistency, convergent validity, adversarial discrimination, stability/sensitivity
- Cohen's kappa and Fleiss' kappa with bootstrap confidence intervals
- Configurable thresholds per dimension with PASS / MARGINAL / FAIL verdicts
- Evaluation runner with foundation + advanced dimension orchestration
- Zero external dependencies (Python standard library only)

### Coherence

- Stratified sampling module for expert review coverage
- Automatic sufficiency checks (uncovered strata, underrepresented categories)
- Sample plan export for review coordination

### Consistency

- Pluggable rule engine with decorator-based registration
- Per-item and cross-item validation rules
- Severity levels (error, warning, info)

### Convergent validity

- Kappa and Jaccard similarity against external references
- Per-item agreement tracking with disagreement detail

### Adversarial discrimination

- Minimal pairs testing with expected label assertions
- Ambiguity cases with multiple acceptable answers
- Discrimination rate scoring

### Stability and sensitivity

- Paraphrase invariance testing
- Perturbation sensitivity with expected direction assertions
- Multi-dimension label comparison (domain, subdomain, function)

### UI

- NiceGUI dashboard with dimension radar chart
- Configurable thresholds with live verdict re-rendering
- Per-control issue view aggregated across dimensions
- Adversarial detail panel with minimal pair results
- Expert review coverage panel from sampling module

### Example

- AICM-to-FAIR-CAM demonstration: 20 CSA AI Controls Matrix controls mapped to FAIR-CAM functional domains
- Claude LLM classifier example (`examples/llm_classifier.py`)
