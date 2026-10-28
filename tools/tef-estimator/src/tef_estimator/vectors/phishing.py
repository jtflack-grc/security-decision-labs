"""
Phishing vector: email-based social engineering delivering ransomware loaders.

~15-20% of ransomware initial access (multi-source IR reports).
Partially observable -- email volume is measurable but campaign initiation is not.
"""

from __future__ import annotations

from tef_estimator.base_rate import geo_multiplier, scenario_floor
from tef_estimator.data.common import (
    PERTRange,
    TECH_MULTIPLIERS,
    DampeningConfig,
)
from tef_estimator.data.scenarios.base import ScenarioDefinition
from tef_estimator.distributions import dampen_composite
from tef_estimator.profile import OrganizationProfile
from tef_estimator.trace import CalculationTrace
from tef_estimator.vectors.base import VectorEstimate


class PhishingVector:
    """Estimate TEF for the phishing/social engineering vector.

    Employee count legitimately affects TEF here through Probability of Action:
    more recipients = higher probability at least one takes the bait within
    a single campaign.

    Floor: observed LEF (scenario_floor) x phishing proportion
    Ceiling: anti-phishing vendor campaign volume data (Proofpoint, Cofense)
    Positioning: base rate x phishing proportion x profile multipliers
    """

    def __init__(self, dampening: DampeningConfig | None = None):
        self.dampening = dampening or DampeningConfig()

    def estimate(
        self,
        profile: OrganizationProfile,
        base_rate: PERTRange,
        scenario: ScenarioDefinition,
    ) -> VectorEstimate:
        trace = CalculationTrace(vector_name="Phishing")

        adjusted_sector = scenario.adjusted_sector_multiplier(profile.sector)
        phish_proportion = scenario.vector_proportions["phishing"]

        # --- Floor ---
        overall_floor = scenario_floor(scenario, profile.revenue_band)
        floor = overall_floor * phish_proportion.mode * adjusted_sector
        trace.add_step("Observed floor", overall_floor, "=", "observed LEF lower bound for the revenue tier", overall_floor)
        trace.add_step("Phishing proportion", phish_proportion.mode, "x", "IR report vector split", overall_floor * phish_proportion.mode)
        trace.add_step("Sector adjustment", adjusted_sector, "x", f"IRIS x {scenario.scenario_name} share", floor)

        # --- Ceiling ---
        ceiling = 0.05
        trace.add_step("Ceiling (phishing)", ceiling, "=", "Proofpoint campaign volume bound", ceiling)

        # --- Positioning ---
        drivers = []
        multipliers = []

        # Sector (scenario-adjusted)
        sector_mult = scenario.adjusted_sector_multiplier_range(profile.sector)
        multipliers.append(sector_mult)

        # Revenue band (scenario-adjusted)
        rev_mult = scenario.adjusted_revenue_multiplier_range(profile.revenue_band)
        multipliers.append(rev_mult)

        # Employee count -- directly relevant for phishing PoA
        tech_label = None
        tech_source = None
        if profile.has_large_email_footprint:
            email_mult = TECH_MULTIPLIERS["large_email_footprint"]
            multipliers.append(email_mult)
            tech_label = "Large email footprint"
            tech_source = f"{profile.employee_count:,} employees"
            drivers.append(
                f"Large email footprint ({profile.employee_count:,} employees): "
                f"{email_mult.mode}x (more recipients = higher PoA per campaign)"
            )
        elif profile.employee_count and profile.employee_count < 50:
            small_mult = PERTRange(0.5, 0.7, 0.9)
            multipliers.append(small_mult)
            tech_label = "Small employee count"
            tech_source = "Fewer phishing targets"
            drivers.append(f"Small employee count: {small_mult.mode}x (fewer phishing targets)")

        # Geography
        geo_mult = geo_multiplier(scenario, profile.geography)
        multipliers.append(geo_mult)

        # Trace multipliers
        phish_base_mode = base_rate.mode * phish_proportion.mode
        trace.add_step("Base rate (mode)", base_rate.mode, "=", "scenario base rate (see base rate derivation)", base_rate.mode)
        trace.add_step("Phishing proportion", phish_proportion.mode, "x", "Vector split", phish_base_mode)
        running = phish_base_mode
        mult_meta = [
            ("Sector multiplier", "IRIS x scenario share"),
            ("Revenue multiplier", "IRIS x scenario share"),
        ]
        if tech_label:
            mult_meta.append((tech_label, tech_source))
        mult_meta.append(("Geography", "IRIS geo distribution"))
        for i, m in enumerate(multipliers):
            running *= m.mode
            label, source = mult_meta[i] if i < len(mult_meta) else (f"Multiplier {i}", "")
            trace.add_step(label, m.mode, "x", source, running)

        # Compute
        raw_composite = 1.0
        for m in multipliers:
            raw_composite *= m.mode
        composite = dampen_composite(raw_composite, self.dampening.factor_k, self.dampening.max_composite)
        trace.add_step("Raw composite", raw_composite, "=", "Product of all multipliers", raw_composite)
        trace.add_step("Dampened composite", composite, "dampened()", f"k={self.dampening.factor_k}, max={self.dampening.max_composite}", composite)

        positioned_median = phish_base_mode * composite
        trace.add_step("Positioned median", positioned_median, "=", "base x proportion x composite", positioned_median)

        positioned_low = base_rate.low * phish_proportion.low * dampen_composite(
            _product([m.low for m in multipliers]),
            self.dampening.factor_k, self.dampening.max_composite,
        )
        positioned_high = base_rate.high * phish_proportion.high * dampen_composite(
            _product([m.high for m in multipliers]),
            self.dampening.factor_k, self.dampening.max_composite,
        )

        result = VectorEstimate(
            vector_name="Phishing",
            floor=floor,
            ceiling=ceiling,
            positioned_low=positioned_low,
            positioned_median=positioned_median,
            positioned_high=positioned_high,
            primary_drivers=drivers,
            data_sources=[
                "IR reports (phishing as RW initial access: 15-20%)",
                "Proofpoint State of the Phish (campaign volume by sector)",
                "IRIS 2025 (sector/size multipliers)",
            ],
            trace=trace,
        )
        result.enforce_bounds()
        return result


def _product(values: list[float]) -> float:
    result = 1.0
    for v in values:
        result *= v
    return result
