"""
Empirical reference data for TEF estimation.

This module re-exports from common.py and the default ransomware scenario
for backward compatibility. New code should import from data.common or
data.scenarios directly.
"""

from tef_estimator.data.common import (
    DATA_VINTAGE,
    DampeningConfig,
    FLOOR_ANCHORS,
    GEO_MULTIPLIERS,
    Geography,
    PERTRange,
    PROFILE_MULTIPLIERS,
    REVENUE_BAND_DATA,
    RemoteAccessType,
    RevenueBand,
    RevenueBandData,
    Sector,
    SectorData,
    SECTOR_DATA,
    TECH_MULTIPLIERS,
)
from tef_estimator.data.scenarios.ransomware import RansomwareScenario

# Default scenario instance for backward compat
_DEFAULT_SCENARIO = RansomwareScenario()

# Re-export ransomware-specific data at module level for backward compat
VECTOR_PROPORTIONS = _DEFAULT_SCENARIO.vector_proportions
BASE_RATE_TRIANGULATION = _DEFAULT_SCENARIO.base_rate_triangulation
CREDENTIAL_TEMPO = _DEFAULT_SCENARIO.credential_tempo
EXPLOITATION_SCANNING = _DEFAULT_SCENARIO.exploitation_scanning

__all__ = [
    # Enums
    "Sector",
    "RevenueBand",
    "Geography",
    "RemoteAccessType",
    # Types
    "PERTRange",
    "SectorData",
    "RevenueBandData",
    "DampeningConfig",
    # Data
    "DATA_VINTAGE",
    "SECTOR_DATA",
    "REVENUE_BAND_DATA",
    "FLOOR_ANCHORS",
    "TECH_MULTIPLIERS",
    "GEO_MULTIPLIERS",
    "PROFILE_MULTIPLIERS",
    # Ransomware-specific (backward compat)
    "VECTOR_PROPORTIONS",
    "BASE_RATE_TRIANGULATION",
    "CREDENTIAL_TEMPO",
    "EXPLOITATION_SCANNING",
]
