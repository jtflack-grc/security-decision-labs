"""
tef-estimator: Data-grounded Threat Event Frequency estimation.

Vector-decomposed ransomware TEF estimation using public empirical data
from IRIS, DBIR, Unit42, Mandiant, CrowdStrike, Beazley, IBM, Coalition, DShield, and GreyNoise.

Point-in-time estimates — refresh quarterly.
"""

from importlib.metadata import PackageNotFoundError, version as _package_version


def _resolve_version() -> str:
    # The version of the code actually running (issue #2: never hardcoded).
    # A source tree carries its own pyproject.toml, which stays correct even when
    # an older install's metadata shadows it; wheel installs have no pyproject
    # above the package and use the installed metadata, which there equals the code.
    import re
    from pathlib import Path

    try:
        text = (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text()
        if re.search(r'^name = "tef-estimator"', text, re.MULTILINE):
            match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
            if match:
                return match.group(1)
    except OSError:
        pass
    try:
        return _package_version("tef-estimator")
    except PackageNotFoundError:
        return "0+unknown"


__version__ = _resolve_version()

from tef_estimator.profile import OrganizationProfile
from tef_estimator.engine import TEFEngine
from tef_estimator.result import TEFResult
from tef_estimator.credibility import OrgTelemetry, VectorObservation

__all__ = ["OrganizationProfile", "TEFEngine", "TEFResult", "OrgTelemetry", "VectorObservation"]
