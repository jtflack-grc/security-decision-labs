"""llm-classification-validator: A 5-dimension evaluation framework for LLM classification outputs.

Dimensions:
1. Coherence    - Inter-rater agreement (Cohen's kappa, Fleiss' kappa)
2. Consistency  - Rule-based deterministic validation
3. Convergent   - External reference comparison (Jaccard, kappa)
4. Adversarial  - Minimal pair discrimination and edge case testing
5. Stability    - Paraphrase invariance and perturbation sensitivity
"""

from importlib.metadata import PackageNotFoundError, version as _package_version


def _resolve_version() -> str:
    # The version of the code actually running (same fix as tef-estimator issue #2: never hardcoded).
    # A source tree carries its own pyproject.toml, which stays correct even when
    # an older install's metadata shadows it; wheel installs have no pyproject
    # above the package and use the installed metadata, which there equals the code.
    import re
    from pathlib import Path

    try:
        text = (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text()
        if re.search(r'^name = "llm-classification-validator"', text, re.MULTILINE):
            match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
            if match:
                return match.group(1)
    except OSError:
        pass
    try:
        return _package_version("llm-classification-validator")
    except PackageNotFoundError:
        return "0+unknown"


__version__ = _resolve_version()

from llm_classification_validator.coherence.analysis import run_coherence_analysis
from llm_classification_validator.consistency.report import run_consistency_check
from llm_classification_validator.consistency.rules import RuleRegistry, rule
from llm_classification_validator.convergent.analysis import run_convergent_analysis
from llm_classification_validator.adversarial.pairs import (
    AmbiguityCase,
    MinimalPair,
    run_adversarial_analysis,
)
from llm_classification_validator.stability.analysis import run_stability_analysis
from llm_classification_validator.runner import run_evaluation
from llm_classification_validator.models import (
    CaseResult,
    DimensionReport,
    EvaluationReport,
    ItemIssue,
    ItemReport,
    MetricResult,
    RuleResult,
    Verdict,
)
from llm_classification_validator.config import (
    EvalConfig,
    RunnerConfig,
    SamplingConfig,
)

__all__ = [
    "AmbiguityCase",
    "CaseResult",
    "DimensionReport",
    "EvalConfig",
    "RunnerConfig",
    "SamplingConfig",
    "EvaluationReport",
    "ItemIssue",
    "ItemReport",
    "MetricResult",
    "MinimalPair",
    "RuleRegistry",
    "RuleResult",
    "Verdict",
    "rule",
    "run_adversarial_analysis",
    "run_coherence_analysis",
    "run_consistency_check",
    "run_convergent_analysis",
    "run_evaluation",
    "run_stability_analysis",
]
