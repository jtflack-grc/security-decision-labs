"""
Scenario-INDEPENDENT empirical reference data.

Every number is loaded from JSON files under data/reference/.
This module contains data that applies regardless of threat type:

- IRIS 2025 all-incident sector multipliers
- Revenue band multipliers
- Geographic multipliers
- Technology exposure multipliers
- Floor anchors (overall, not scenario-adjusted)
- Dampening configuration
- Data vintage tracking
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple

from tef_estimator.data.loader import load_reference, pert_from_list


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Sector(str, Enum):
    """NAICS 2-digit sector codes mapped to IRIS/Verizon labels."""
    EDUCATION = "education"
    INFORMATION = "information"
    PROFESSIONAL = "professional"
    FINANCIAL = "financial"
    HEALTHCARE = "healthcare"
    PUBLIC = "public"
    RETAIL = "retail"
    HOSPITALITY = "hospitality"
    MANAGEMENT = "management"
    MANUFACTURING = "manufacturing"
    TRADE = "trade"
    ENTERTAINMENT = "entertainment"
    REAL_ESTATE = "real_estate"
    ADMINISTRATIVE = "administrative"
    AGRICULTURE = "agriculture"
    CONSTRUCTION = "construction"
    TRANSPORTATION = "transportation"
    MINING = "mining"
    UTILITIES = "utilities"
    OTHER = "other"


class RevenueBand(str, Enum):
    """Revenue bands aligned to IRIS segmentation."""
    UNDER_10M = "under_10m"
    R_10M_100M = "10m_100m"
    R_100M_1B = "100m_1b"
    R_1B_10B = "1b_10b"
    R_10B_100B = "10b_100b"
    OVER_100B = "over_100b"


class Geography(str, Enum):
    US = "us"
    WESTERN_EUROPE = "western_europe"
    ASIA_PACIFIC = "asia_pacific"
    OTHER = "other"


class RemoteAccessType(str, Enum):
    FORTINET = "fortinet"
    PALO_ALTO = "palo_alto"
    CISCO = "cisco"
    SONICWALL = "sonicwall"
    CITRIX = "citrix"
    OTHER_VPN = "other_vpn"
    RDP = "rdp"
    NONE = "none"


# ---------------------------------------------------------------------------
# Range tuple for PERT parameterisation
# ---------------------------------------------------------------------------

class PERTRange(NamedTuple):
    """(min, mode, max) for PERT distribution sampling."""
    low: float
    mode: float
    high: float


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SectorData:
    """Scenario-independent sector parameters from IRIS 2025."""
    all_incident_multiplier: float
    event_count_2019_2023: int | None = None

    @property
    def tef_multiplier_range(self) -> PERTRange:
        m = self.all_incident_multiplier
        return PERTRange(low=max(0.1, m * 0.7), mode=m, high=m * 1.3)


@dataclass(frozen=True)
class RevenueBandData:
    """Scenario-independent revenue band parameters from IRIS 2025."""
    all_incident_multiplier: float

    @property
    def tef_multiplier_range(self) -> PERTRange:
        m = self.all_incident_multiplier
        return PERTRange(low=max(0.05, m * 0.7), mode=m, high=m * 1.3)


# ---------------------------------------------------------------------------
# Load all empirical data from JSON
# ---------------------------------------------------------------------------

def _load_common_data() -> tuple:
    """Load all scenario-independent data from JSON reference files."""
    iris = load_reference("iris")
    at_bay = load_reference("at_bay")
    common = load_reference("common")

    # Sector multipliers — IRIS 2025
    sector_data: dict[Sector, SectorData] = {}
    for sector_key, vals in iris["sector_multipliers"].items():
        if sector_key.startswith("_"):
            continue
        sector = Sector(sector_key)
        sector_data[sector] = SectorData(
            all_incident_multiplier=vals["all_incident_multiplier"],
            event_count_2019_2023=vals.get("event_count_2019_2023"),
        )

    # Revenue band multipliers — IRIS 2025
    revenue_data: dict[RevenueBand, RevenueBandData] = {}
    for band_key, vals in iris["revenue_band_multipliers"].items():
        if band_key.startswith("_"):
            continue
        band = RevenueBand(band_key)
        revenue_data[band] = RevenueBandData(
            all_incident_multiplier=vals["all_incident_multiplier"],
        )

    # Floor anchors — IRIS overall
    floor_anchors = {
        k: v for k, v in iris["floor_anchors"].items() if not k.startswith("_")
    }

    # Tech multipliers — At-Bay 2025 + Beazley Q3 2025
    tech_multipliers = {
        k: PERTRange(*pert_from_list(v))
        for k, v in at_bay["tech_multipliers"].items()
        if not k.startswith("_")
    }

    # Geo multipliers — judgment-informed
    geo_multipliers: dict[Geography, PERTRange] = {}
    for geo_key, vals in common["geo_multipliers"].items():
        if geo_key.startswith("_"):
            continue
        geo = Geography(geo_key)
        geo_multipliers[geo] = PERTRange(*pert_from_list(vals))

    # Profile multipliers — judgment-informed
    profile_multipliers = {
        k: PERTRange(*pert_from_list(v))
        for k, v in common["profile_multipliers"].items()
        if not k.startswith("_")
    }

    # Dampening config defaults
    dampening_defaults = common["dampening_config"]

    # Data vintage
    data_vintage = common["data_vintage"]

    return (
        sector_data,
        revenue_data,
        floor_anchors,
        tech_multipliers,
        geo_multipliers,
        profile_multipliers,
        dampening_defaults,
        data_vintage,
    )


(
    SECTOR_DATA,
    REVENUE_BAND_DATA,
    FLOOR_ANCHORS,
    TECH_MULTIPLIERS,
    GEO_MULTIPLIERS,
    PROFILE_MULTIPLIERS,
    _DAMPENING_DEFAULTS,
    DATA_VINTAGE,
) = _load_common_data()


@dataclass
class DampeningConfig:
    """Controls how correlated multipliers are compressed.

    Defaults come from the bundled ``common`` reference data; pass explicit
    values to override (e.g. a sensitivity sweep). The ``*_source`` fields
    carry the provenance string used in the audit trail.
    """
    factor_k: float = _DAMPENING_DEFAULTS["factor_k"]
    vector_k: float = _DAMPENING_DEFAULTS["vector_k"]
    max_composite: float = _DAMPENING_DEFAULTS["max_composite"]
    factor_k_source: str = _DAMPENING_DEFAULTS["factor_k_source"]
    vector_k_source: str = _DAMPENING_DEFAULTS["vector_k_source"]
    max_composite_source: str = _DAMPENING_DEFAULTS["max_composite_source"]
