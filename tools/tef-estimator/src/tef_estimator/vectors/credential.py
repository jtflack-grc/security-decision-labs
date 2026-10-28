"""
Credential vector: stolen/purchased VPN/RDP/SSO credentials from IABs.

~50-55% of ransomware initial access (Beazley Q3 2025).
Invisible to scanning telemetry -- bounded by operational tempo / addressable population.
"""

from __future__ import annotations

from tef_estimator.config import TEFConfig, get_config
from tef_estimator.base_rate import geo_multiplier, scenario_floor, tier_concentration
from tef_estimator.data.common import (
    GEO_MULTIPLIERS,
    Geography,
    PERTRange,
    TECH_MULTIPLIERS,
    DampeningConfig,
)
from tef_estimator.data.scenarios.base import ScenarioDefinition
from tef_estimator.distributions import dampen_composite
from tef_estimator.profile import OrganizationProfile
from tef_estimator.trace import CalculationTrace
from tef_estimator.vectors.base import VectorEstimate


class CredentialVector:
    """Estimate TEF for the credential-based initial access vector.

    This is the largest single pathway and the one most
    directly bounded by attacker operational tempo data.

    Floor: observed LEF (scenario_floor) x credential vector proportion
    Ceiling: operational tempo x credential proportion / addressable population
    Positioning: base rate x credential proportion x profile multipliers
    """

    def __init__(self, dampening: DampeningConfig | None = None, config: TEFConfig | None = None):
        self.dampening = dampening or DampeningConfig()
        self.config = config or get_config()

    def estimate(
        self,
        profile: OrganizationProfile,
        base_rate: PERTRange,
        scenario: ScenarioDefinition,
    ) -> VectorEstimate:
        trace = CalculationTrace(vector_name="Credential")

        adjusted_sector = scenario.adjusted_sector_multiplier(profile.sector)
        cred_proportion = scenario.vector_proportions["credential"]

        # --- Floor ---
        overall_floor = scenario_floor(scenario, profile.revenue_band)
        floor = overall_floor * cred_proportion.mode * adjusted_sector
        trace.add_step("Observed floor", overall_floor, "=", "observed LEF lower bound for the revenue tier", overall_floor)
        trace.add_step("Credential proportion", cred_proportion.mode, "x", "IR report vector split", overall_floor * cred_proportion.mode)
        trace.add_step("Sector adjustment", adjusted_sector, "x", f"IRIS x {scenario.scenario_name} share", floor)

        # --- Ceiling (operational tempo method) ---
        tempo = scenario.credential_tempo
        ceiling_high = (
            tempo["global_campaigns_per_month"].high
            * tempo["credential_proportion"].high
            * 12
            / tempo["addressable_population"].low
        )
        # Sector and geography adjust the ceiling as they adjust the positioning,
        # so the audit-trail check compares like with like. The campaign counts
        # are claimed victims, i.e. attacks that succeeded; a ceiling on threat
        # events (attempts) divides by susceptibility, as the base-rate anchors
        # do, at its low end because this is a maximum.
        # A campaign count from one country (BEC: US IC3 complaints) already carries
        # that country's level: geography relative to it; worldwide counts: absolute.
        home = getattr(scenario, "credential_tempo_geography", None)
        geo_adjust = GEO_MULTIPLIERS[profile.geography].mode / (
            GEO_MULTIPLIERS[Geography(home)].mode if home else 1.0)
        tier = tier_concentration(scenario, profile.revenue_band)
        susceptibility_low = self.config.susceptibility_prior.low
        ceiling = ceiling_high * adjusted_sector * geo_adjust * tier / susceptibility_low
        trace.add_step("Ceiling (operational tempo)", ceiling, "=",
                       f"credential campaigns / addressable pop {ceiling_high:.5f} "
                       f"× sector {adjusted_sector:.2f} × geography {geo_adjust:.2f} "
                       f"× revenue tier {tier:.2f} "
                       f"÷ susceptibility {susceptibility_low:.2f} (attempts, not successes)",
                       ceiling)

        # --- Positioning ---
        drivers = []
        multipliers = []

        # Sector (scenario-adjusted)
        sector_mult = scenario.adjusted_sector_multiplier_range(profile.sector)
        multipliers.append(sector_mult)
        if adjusted_sector > 1.2:
            drivers.append(
                f"{profile.sector.value.title()} sector: {adjusted_sector:.2f}x "
                f"(scenario-adjusted)"
            )

        # Revenue band (scenario-adjusted)
        rev_mult = scenario.adjusted_revenue_multiplier_range(profile.revenue_band)
        multipliers.append(rev_mult)

        # Technology -- credential-specific
        tech_label = None
        tech_source = None
        if profile.has_vpn:
            if profile.has_vulnerable_vpn_vendor:
                tech_mult = TECH_MULTIPLIERS["vpn_vulnerable_vendor"]
                tech_label = "Vulnerable VPN vendor"
                tech_source = "Beazley Q3 2025"
                drivers.append(
                    f"VPN with vulnerable vendor: {tech_mult.mode}x "
                    f"(Beazley: VPN credentials = 48% of RW initial access)"
                )
            else:
                tech_mult = PERTRange(1.0, 1.2, 1.4)
                tech_label = "VPN (non-vulnerable)"
                tech_source = "At-Bay 2025"
                drivers.append("VPN present (non-vulnerable vendor): 1.2x")
            multipliers.append(tech_mult)
        elif profile.has_rdp:
            tech_mult = TECH_MULTIPLIERS["rdp_exposed"]
            multipliers.append(tech_mult)
            tech_label = "Exposed RDP"
            tech_source = "Beazley Q3 2025"
            drivers.append(f"Exposed RDP: {tech_mult.mode}x (credential brute force target)")
        elif profile.has_no_remote_access:
            tech_mult = TECH_MULTIPLIERS["no_remote_access"]
            multipliers.append(tech_mult)
            tech_label = "No remote access"
            tech_source = "Reduces credential pathway"
            drivers.append(
                f"No remote access: {tech_mult.mode}x (removes dominant credential pathway)"
            )

        # Geography
        geo_mult = geo_multiplier(scenario, profile.geography)
        multipliers.append(geo_mult)

        # Trace multipliers
        cred_base_mode = base_rate.mode * cred_proportion.mode
        trace.add_step("Base rate (mode)", base_rate.mode, "=", "scenario base rate (see base rate derivation)", base_rate.mode)
        trace.add_step("Credential proportion", cred_proportion.mode, "x", "Vector split", cred_base_mode)
        running = cred_base_mode
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

        # Compute composite
        raw_composite = 1.0
        for m in multipliers:
            raw_composite *= m.mode
        composite = dampen_composite(raw_composite, self.dampening.factor_k, self.dampening.max_composite)
        trace.add_step("Raw composite", raw_composite, "=", "Product of all multipliers", raw_composite)
        trace.add_step("Dampened composite", composite, "dampened()", f"k={self.dampening.factor_k}, max={self.dampening.max_composite}", composite)

        # Positioned estimate
        positioned_median = cred_base_mode * composite
        trace.add_step("Positioned median", positioned_median, "=", "base x proportion x composite", positioned_median)

        positioned_low = base_rate.low * cred_proportion.low * dampen_composite(
            _product([m.low for m in multipliers]),
            self.dampening.factor_k, self.dampening.max_composite,
        )
        positioned_high = base_rate.high * cred_proportion.high * dampen_composite(
            _product([m.high for m in multipliers]),
            self.dampening.factor_k, self.dampening.max_composite,
        )

        result = VectorEstimate(
            vector_name="Credential",
            floor=floor,
            ceiling=ceiling,
            positioned_low=positioned_low,
            positioned_median=positioned_median,
            positioned_high=positioned_high,
            primary_drivers=drivers,
            data_sources=[
                "Ransomware.live / Recorded Future (claimed victims, credential ceiling)",
                "Beazley Q3 2025 (48% VPN credentials as initial access)",
                "At-Bay 2025 (VPN in 80% of RW attacks)",
                "IRIS 2025 (sector/size multipliers)",
            ],
            notes=[
                "Credential ceiling is analytically tight -- each campaign targets "
                "a specific org, unlike scanning which sweeps broadly.",
                "This vector is invisible to scanning telemetry.",
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
