"""
Scenario definitions for TEF estimation.

Each scenario defines its own vector proportions, base rate triangulation,
sector/revenue adjustments, and output templates. The engine consumes
scenario definitions and runs identically regardless of threat type.
"""

from tef_estimator.data.scenarios.base import ScenarioDefinition
from tef_estimator.data.scenarios.bec import BECScenario
from tef_estimator.data.scenarios.exfiltration import ExfiltrationScenario
from tef_estimator.data.scenarios.ransomware import RansomwareScenario
from tef_estimator.data.scenarios.web_app import WebAppScenario

# Built-in scenarios by slug
SCENARIO_CLASSES: dict[str, type[ScenarioDefinition]] = {
    "ransomware": RansomwareScenario,
    "bec": BECScenario,
    "exfiltration": ExfiltrationScenario,
    "web_app": WebAppScenario,
}

__all__ = [
    "ScenarioDefinition",
    "BECScenario",
    "ExfiltrationScenario",
    "RansomwareScenario",
    "WebAppScenario",
    "SCENARIO_CLASSES",
]
