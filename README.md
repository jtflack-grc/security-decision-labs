[![Python versions](https://img.shields.io/pypi/pyversions/decision-security.svg)](https://pypi.org/project/decision-security/)
[![Organization](https://img.shields.io/badge/org-security--decision--science-blue)](https://github.com/security-decision-science)
[![Linkedin Badge](https://img.shields.io/badge/-LinkedIn-blue?style=flat-square&logo=Linkedin&logoColor=white&link=https://www.linkedin.com/in/voiculaura/)](https://www.linkedin.com/in/voiculaura/)

# Security Decision Labs

Built and maintained by Laura Voicu ([LinkedIn](https://www.linkedin.com/in/voiculaura/) · [ORCID](https://orcid.org/0009-0008-4623-2532)).
FAIR cyber risk quantification toolkit: agent-based control simulation, threat event frequency estimator, LLM classification validator, Monte Carlo risk engine.

Part of [Apropos Security](https://apropos-security.com) · [Notebooks](https://security-decision-science.github.io/security-decision-science/) · [Library (pip)](https://github.com/security-decision-science/decision-security) · [Blog](https://medium.com/apropos-security)

---

## Tools

### [FAIR Risk Quantification](tools/fair-simulator/README.md)
[![License](https://img.shields.io/badge/license-CC--BY--NC--SA%204.0-orange)](tools/fair-simulator/LICENSE)
[![Status](https://img.shields.io/badge/status-active-green)]()
[![Methodology](https://img.shields.io/badge/Methodology-FAIR-blue)]()

Monte Carlo simulation tool for FAIR (Factor Analysis of Information Risk) methodology with industry benchmarks.

**Features:** LEF/LM simulation, portfolio aggregation, sensitivity analysis, IRIS 2025 benchmarks

**License:** CC BY-NC-SA 4.0 (Non-Commercial Use Only)

[Read More](tools/fair-simulator/README.md) | [Setup](tools/fair-simulator/SETUP.md)

### [Control Systems Agent-Based Model](tools/control-systems-agent-based-model/README.md)
[![License](https://img.shields.io/badge/license-CC--BY--NC--SA%204.0-orange)](tools/control-systems-agent-based-model/LICENSE)
[![Status](https://img.shields.io/badge/status-active-green)]()
[![Methodology](https://img.shields.io/badge/Methodology-FAIR--CAM-blue)]()

Agent-based simulation of FAIR-CAM control dynamics. Reproduction package for Jones & Voicu (2026), "Control Physiology: An Agent-Based Model of FAIR-CAM Dynamics."

**Features:** 8 agent types, multiplicative defense-in-depth, three-source variance model, budget-constrained remediation, narrative causation engine, empirically calibrated loss magnitudes

**License:** CC BY-NC-SA 4.0 (Non-Commercial Use Only)

[Read More](tools/control-systems-agent-based-model/README.md) | [Reproduce](tools/control-systems-agent-based-model/REPRODUCE.md)

### [TEF Estimator](tools/tef-estimator/README.md)
[![PyPI](https://img.shields.io/pypi/v/tef-estimator)](https://pypi.org/project/tef-estimator/)
[![License](https://img.shields.io/badge/license-CC--BY--NC--SA%204.0-orange)](tools/tef-estimator/LICENSE)
[![Status](https://img.shields.io/badge/status-active-green)]()
[![Methodology](https://img.shields.io/badge/Methodology-FAIR-blue)]()

Data-grounded Threat Event Frequency estimation with vector decomposition. Produces defensible TEF estimates for FAIR risk quantification by decomposing threat frequency into four initial access vectors.

**Features:** Four-vector decomposition (exploitation, credential, phishing, supply chain), base rates counted on one population (US events ÷ US firms) with observed floors, cross-vector dampening (VERIS-calibrated), credibility blending with org telemetry, web UI, CLI, telemetry monitoring with live inputs (frozen by default)

**Install:** `pip install tef-estimator` · [PyPI](https://pypi.org/project/tef-estimator/)

**License:** CC BY-NC-SA 4.0 (Non-Commercial Use Only)

[Read More](tools/tef-estimator/README.md) | [User Guide](tools/tef-estimator/docs/user-guide.md) | [Technical Reference](tools/tef-estimator/docs/technical-reference.md)

### [LLM Classification Validator](tools/llm-classification-validator/README.md)
[![License](https://img.shields.io/badge/license-CC--BY--NC--SA%204.0-orange)](tools/llm-classification-validator/LICENSE)
[![Status](https://img.shields.io/badge/status-active-green)]()
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

Five-dimension psychometric validation framework for LLM-generated classifications. Tests whether an LLM's outputs are reliable enough to trust, using the same statistical methods applied to human raters.

**Features:** Coherence (inter-rater kappa), consistency (rule-based checks), convergent validity (reference comparison), adversarial discrimination (minimal pairs), stability and sensitivity (paraphrase invariance), interactive dashboard, configurable thresholds, bootstrap confidence intervals

**Install:** `pip install llm-classification-validator` · [PyPI](https://pypi.org/project/llm-classification-validator/)

**License:** CC BY-NC-SA 4.0 (Non-Commercial Use Only)

[Read More](tools/llm-classification-validator/README.md) | [Methodology](tools/llm-classification-validator/docs/METHODOLOGY.md) | [Examples](tools/llm-classification-validator/examples/)

---

## Licensing

**This repository uses multiple licenses.**

- **Individual tools**: Each has its own license (see tool directories)
