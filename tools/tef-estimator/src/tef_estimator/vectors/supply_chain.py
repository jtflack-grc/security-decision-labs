"""
Supply chain vector: third-party / vendor compromise as ransomware pathway.

~5-8% of ransomware initial access (IR reports: 30% third-party involvement across all breaches).
Not directly observable -- occurs through trusted channels.
"""

from __future__ import annotations

from tef_estimator.base_rate import geo_multiplier, scenario_floor
from tef_estimator.data.common import (
    FLOOR_ANCHORS,
    PERTRange,
    PROFILE_MULTIPLIERS,
    DampeningConfig,
)
from tef_estimator.data.scenarios.base import ScenarioDefinition
from tef_estimator.distributions import dampen_composite
from tef_estimator.profile import OrganizationProfile
from tef_estimator.trace import CalculationTrace
from tef_estimator.vectors.base import VectorEstimate


class SupplyChainVector:
    """Estimate TEF for the supply chain / third-party vector.

    This is the smallest proportion (~5-8%) and the hardest to estimate
    from external data. Stays as a simpler model given data limitations.

    Floor: observed LEF (scenario_floor) x supply chain proportion
    Ceiling: IR report third-party involvement rate x base rate
    Positioning: base rate x supply chain proportion x binary profile adjustment
    """

    def __init__(self, dampening: DampeningConfig | None = None):
        self.dampening = dampening or DampeningConfig()

    def estimate(
        self,
        profile: OrganizationProfile,
        base_rate: PERTRange,
        scenario: ScenarioDefinition,
    ) -> VectorEstimate:
        trace = CalculationTrace(vector_name="Supply Chain")

        adjusted_sector = scenario.adjusted_sector_multiplier(profile.sector)
        sc_proportion = scenario.vector_proportions["supply_chain"]

        # --- Floor ---
        overall_floor = scenario_floor(scenario, profile.revenue_band)
        floor = overall_floor * sc_proportion.mode * adjusted_sector
        trace.add_step("Observed floor", overall_floor, "=", "observed LEF lower bound for the revenue tier", overall_floor)
        trace.add_step("Supply chain proportion", sc_proportion.mode, "x", "IR report vector split", overall_floor * sc_proportion.mode)
        trace.add_step("Sector adjustment", adjusted_sector, "x", f"IRIS x {scenario.scenario_name} share", floor)

        # --- Ceiling ---
        ceiling = FLOOR_ANCHORS["overall_upper_bound"] * 0.30
        trace.add_step("Ceiling (third-party)", ceiling, "=", "IRIS upper bound x 30% third-party rate", ceiling)

        # --- Positioning ---
        drivers = []
        multipliers = []

        # Sector (scenario-adjusted)
        sector_mult = scenario.adjusted_sector_multiplier_range(profile.sector)
        multipliers.append(sector_mult)

        # Revenue band (scenario-adjusted)
        rev_mult = scenario.adjusted_revenue_multiplier_range(profile.revenue_band)
        multipliers.append(rev_mult)

        # Supply chain role -- binary adjustment
        sc_provider_label = None
        if profile.supply_chain_provider:
            sc_mult = PROFILE_MULTIPLIERS["supply_chain_provider"]
            multipliers.append(sc_mult)
            sc_provider_label = ("Supply chain provider", "IR reports: 30% third-party involvement")
            drivers.append(
                f"Supply chain provider to large enterprises: {sc_mult.mode}x "
                f"(IR reports: 30% third-party involvement in breaches)"
            )

        # Geography
        geo_mult = geo_multiplier(scenario, profile.geography)
        multipliers.append(geo_mult)

        # Trace multipliers
        sc_base_mode = base_rate.mode * sc_proportion.mode
        trace.add_step("Base rate (mode)", base_rate.mode, "=", "scenario base rate (see base rate derivation)", base_rate.mode)
        trace.add_step("Supply chain proportion", sc_proportion.mode, "x", "Vector split", sc_base_mode)
        running = sc_base_mode
        mult_meta = [
            ("Sector multiplier", "IRIS x scenario share"),
            ("Revenue multiplier", "IRIS x scenario share"),
        ]
        if sc_provider_label:
            mult_meta.append(sc_provider_label)
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

        positioned_median = sc_base_mode * composite
        trace.add_step("Positioned median", positioned_median, "=", "base x proportion x composite", positioned_median)

        positioned_low = base_rate.low * sc_proportion.low * dampen_composite(
            _product([m.low for m in multipliers]),
            self.dampening.factor_k, self.dampening.max_composite,
        )
        positioned_high = base_rate.high * sc_proportion.high * dampen_composite(
            _product([m.high for m in multipliers]),
            self.dampening.factor_k, self.dampening.max_composite,
        )

        result = VectorEstimate(
            vector_name="Supply Chain",
            floor=floor,
            ceiling=ceiling,
            positioned_low=positioned_low,
            positioned_median=positioned_median,
            positioned_high=positioned_high,
            primary_drivers=drivers,
            data_sources=[
                "IR reports (30% third-party involvement in breaches)",
                "IRIS 2025 (sector/size multipliers)",
            ],
            notes=[
                "Smallest vector (~5-8%) and hardest to bound from external data.",
                "Binary adjustment -- future versions should model vendor ecosystem size.",
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
