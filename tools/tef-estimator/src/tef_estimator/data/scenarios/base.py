"""
ScenarioDefinition protocol — the contract every scenario must fulfill.

A scenario is a data definition, not an engine. The engine, vector computation,
dampening, floor enforcement, and output formatting are all scenario-agnostic.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from tef_estimator.data.common import PERTRange, Sector, RevenueBand


@runtime_checkable
class ScenarioDefinition(Protocol):
    """Protocol that every threat scenario must implement."""

    @property
    def scenario_name(self) -> str:
        """Human-readable scenario name (e.g., 'Ransomware')."""
        ...

    @property
    def scenario_slug(self) -> str:
        """Machine-readable identifier (e.g., 'ransomware')."""
        ...

    @property
    def active_vectors(self) -> list[str]:
        """Which vectors are active: e.g. ['exploitation', 'credential', 'phishing', 'supply_chain']."""
        ...

    @property
    def vector_proportions(self) -> dict[str, PERTRange]:
        """Proportion of this scenario's incidents attributed to each vector."""
        ...

    @property
    def base_rate_triangulation(self) -> dict[str, PERTRange]:
        """Base-rate inputs: 'susceptibility_prior', plus the anchors and 'consensus'
        for a scenario without a ``base_rate_lef`` recipe (base_rate.py)."""
        ...

    @property
    def overall_share(self) -> float:
        """This scenario's share of all cyber incidents (e.g. 0.317 for ransomware)."""
        ...

    @property
    def sector_shares(self) -> dict[Sector, float | None]:
        """Proportion of incidents in each sector that are this scenario type.

        None means no data — falls back to overall_share.
        """
        ...

    @property
    def revenue_shares(self) -> dict[RevenueBand, float]:
        """Scenario's share of losses by revenue band (e.g. ransomware loss share)."""
        ...

    @property
    def revenue_prob_gte2(self) -> dict[RevenueBand, float | None]:
        """Annual probability of >=2 events by revenue band (floor anchor data)."""
        ...

    @property
    def credential_tempo(self) -> dict[str, PERTRange]:
        """Operational tempo parameters for credential vector ceiling."""
        ...

    @property
    def exploitation_scanning(self) -> dict[str, PERTRange | float]:
        """Scanning telemetry parameters for exploitation vector ceiling."""
        ...

    @property
    def output_templates(self) -> dict[str, str]:
        """Language templates for output rendering.

        Keys: 'one_sentence', 'scenario_label', 'attempt_verb'.
        """
        ...

    def adjusted_sector_multiplier(self, sector: Sector) -> float:
        """Runtime composition: common.all_incident_mult x (sector_share / overall_share)."""
        ...

    def adjusted_revenue_multiplier(self, band: RevenueBand) -> float:
        """Runtime composition: common.all_incident_mult x (revenue_share / overall_share)."""
        ...
