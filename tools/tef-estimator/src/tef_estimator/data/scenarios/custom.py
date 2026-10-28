"""
Custom scenario loaded from a user-provided JSON file.

Allows analysts to define their own threat scenarios without writing Python.
Provides sensible defaults for fields that are difficult to estimate
(credential tempo, exploitation scanning) based on the ransomware scenario
baseline, scaled by the custom scenario's vector proportions.
"""

from __future__ import annotations

import json
from pathlib import Path

from tef_estimator.data.common import (
    PERTRange,
    RevenueBand,
    REVENUE_BAND_DATA,
    Sector,
    SECTOR_DATA,
)
from tef_estimator.data.loader import normalized_proportions, pert_from_list


_DEFAULT_CREDENTIAL_TEMPO = {
    "global_campaigns_per_month": PERTRange(500, 1000, 2000),
    "credential_proportion": PERTRange(0.30, 0.40, 0.50),
    "addressable_population": PERTRange(5_000_000, 10_000_000, 15_000_000),
}

_DEFAULT_EXPLOITATION_SCANNING: dict[str, PERTRange | float] = {
    "grn_malicious_rate": PERTRange(0.20, 0.28, 0.35),  # shared by all scenarios
    "grn_session_malicious_rate": 0.037,
    "campaign_ip_ratio_lognormal_mu": 4.0,
    "campaign_ip_ratio_lognormal_sigma": 1.5,
    "poa_ransomware": PERTRange(0.3, 0.5, 0.7),
    "ransomware_proportion_of_scanning": PERTRange(0.10, 0.20, 0.30),
}

_DEFAULT_OUTPUT_TEMPLATES = {
    "scenario_label": "Custom",
    "attempt_verb": "attempt to attack",
    "one_sentence": (
        "Based on industry data, threat actors {attempt_verb} organizations "
        "matching your profile {recurrence} (range: {low} to {high})."
    ),
}


def load_custom_scenario(path: Path | str) -> "CustomScenario":
    path = Path(path)
    with open(path) as f:
        data = json.load(f)
    return CustomScenario(data, source_path=path)


class CustomScenario:
    """Scenario loaded from a user-provided JSON definition.

    Required JSON fields::

        {
          "scenario_name": "Data Exfiltration",
          "scenario_slug": "data_exfil",
          "vector_proportions": {
            "exploitation": [low, mode, high],
            "credential": [low, mode, high],
            "phishing": [low, mode, high],
            "supply_chain": [low, mode, high]
          },
          "base_rate": {
            "consensus": [low, mode, high]
          },
          "overall_share": 0.10
        }

    Optional fields (defaults provided if missing):
        - sector_shares: per-sector share of this scenario type
        - revenue_shares: per-revenue-band share
        - credential_tempo: operational tempo parameters
        - exploitation_scanning: scanning telemetry parameters
        - output_templates: language templates for output
        - base_rate.operational_tempo, base_rate.anchor_2, base_rate.anchor_3:
          additional anchors for triangulation
    """

    def __init__(self, data: dict, source_path: Path | None = None):
        self._data = data
        self._source_path = source_path
        self._validate()

    def _validate(self):
        required = ["scenario_name", "scenario_slug", "vector_proportions",
                     "base_rate", "overall_share"]
        missing = [k for k in required if k not in self._data]
        if missing:
            raise ValueError(
                f"Custom scenario missing required fields: {', '.join(missing)}"
            )

        vp = self._data["vector_proportions"]
        valid_vectors = {"exploitation", "credential", "phishing", "supply_chain"}
        unknown = set(k for k in vp.keys() if not k.startswith("_")) - valid_vectors
        if unknown:
            raise ValueError(f"Unknown vectors: {', '.join(unknown)}")

        if not set(vp.keys()) & valid_vectors:
            raise ValueError("At least one vector must be defined")

        br = self._data["base_rate"]
        if "consensus" not in br:
            raise ValueError("base_rate must include 'consensus' key with [low, mode, high]")

        modes = [PERTRange(*pert_from_list(v)).mode
                 for k, v in vp.items() if not k.startswith("_")]
        total = sum(modes)
        if not 0.85 <= total <= 1.15:
            raise ValueError(
                f"Vector proportion modes sum to {total:.2f}, expected ~1.0 (0.85-1.15)"
            )

    @property
    def scenario_name(self) -> str:
        return self._data["scenario_name"]

    @property
    def scenario_slug(self) -> str:
        return self._data["scenario_slug"]

    @property
    def active_vectors(self) -> list[str]:
        return [k for k in self._data["vector_proportions"]
                if not k.startswith("_")]

    @property
    def vector_proportions(self) -> dict[str, PERTRange]:
        return {k: PERTRange(*t)
                for k, t in normalized_proportions(self._data["vector_proportions"]).items()}

    @property
    def base_rate_triangulation(self) -> dict[str, PERTRange]:
        return {
            k: PERTRange(*pert_from_list(v))
            for k, v in self._data["base_rate"].items()
            if not k.startswith("_") and isinstance(v, list)
        }

    @property
    def overall_share(self) -> float:
        return self._data["overall_share"]

    @property
    def sector_shares(self) -> dict[Sector, float | None]:
        raw = self._data.get("sector_shares", {})
        result: dict[Sector, float | None] = {}
        for sector in Sector:
            val = raw.get(sector.value)
            result[sector] = val
        return result

    @property
    def sector_loss_shares(self) -> dict[Sector, float | None]:
        return self.sector_shares

    @property
    def revenue_shares(self) -> dict[RevenueBand, float]:
        raw = self._data.get("revenue_shares", {})
        result: dict[RevenueBand, float] = {}
        for band in RevenueBand:
            result[band] = raw.get(band.value, self.overall_share)
        return result

    @property
    def revenue_prob_gte2(self) -> dict[RevenueBand, float | None]:
        raw = self._data.get("revenue_prob_gte2", {})
        return {band: raw.get(band.value) for band in RevenueBand}

    @property
    def credential_tempo(self) -> dict[str, PERTRange]:
        raw = self._data.get("credential_tempo")
        if raw:
            return {
                k: PERTRange(*pert_from_list(v))
                for k, v in raw.items()
                if not k.startswith("_") and isinstance(v, list)
            }
        return dict(_DEFAULT_CREDENTIAL_TEMPO)

    @property
    def exploitation_scanning(self) -> dict[str, PERTRange | float]:
        raw = self._data.get("exploitation_scanning")
        if raw:
            result: dict[str, PERTRange | float] = {}
            for k, v in raw.items():
                if k.startswith("_"):
                    continue
                if isinstance(v, list):
                    result[k] = PERTRange(*pert_from_list(v))
                elif isinstance(v, (int, float)):
                    result[k] = v
            return result
        return dict(_DEFAULT_EXPLOITATION_SCANNING)

    @property
    def output_templates(self) -> dict[str, str]:
        raw = self._data.get("output_templates", {})
        templates = dict(_DEFAULT_OUTPUT_TEMPLATES)
        templates["scenario_label"] = self.scenario_name
        templates.update(raw)
        return templates

    def adjusted_sector_multiplier(self, sector: Sector) -> float:
        common_mult = SECTOR_DATA[sector].all_incident_multiplier
        share = self.sector_shares.get(sector)
        if share is not None:
            return common_mult * (share / self.overall_share)
        return common_mult

    def adjusted_sector_multiplier_range(self, sector: Sector) -> PERTRange:
        m = self.adjusted_sector_multiplier(sector)
        return PERTRange(low=max(0.1, m * 0.7), mode=m, high=m * 1.3)

    def adjusted_revenue_multiplier(self, band: RevenueBand) -> float:
        common_mult = REVENUE_BAND_DATA[band].all_incident_multiplier
        share = self.revenue_shares.get(band, self.overall_share)
        return common_mult * (share / self.overall_share)

    def adjusted_revenue_multiplier_range(self, band: RevenueBand) -> PERTRange:
        m = self.adjusted_revenue_multiplier(band)
        return PERTRange(low=max(0.05, m * 0.7), mode=m, high=m * 1.3)


def generate_template(path: Path | str) -> None:
    """Write a template custom scenario JSON file."""
    template = {
        "_instructions": (
            "Fill in the fields below to define a custom threat scenario. "
            "Vector proportions should sum to ~1.0. Base rate consensus is "
            "the estimated number of attempts (threat events) per organization "
            "per year in the addressable population. See the user guide "
            "for detailed field descriptions."
        ),
        "scenario_name": "My Custom Scenario",
        "scenario_slug": "my_custom",
        "vector_proportions": {
            "_note": "PERT ranges [low, mode, high] — must sum to ~1.0",
            "exploitation": [0.10, 0.20, 0.30],
            "credential": [0.30, 0.40, 0.50],
            "phishing": [0.15, 0.25, 0.35],
            "supply_chain": [0.05, 0.15, 0.20],
        },
        "base_rate": {
            "_note": "Threat events (attempts) per organization per year, addressable population",
            "consensus": [0.005, 0.015, 0.04],
        },
        "overall_share": 0.10,
    }
    path = Path(path)
    with open(path, "w") as f:
        json.dump(template, f, indent=2)
